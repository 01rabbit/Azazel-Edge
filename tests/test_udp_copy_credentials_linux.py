"""ACTUAL socket/credential controls; target controls are not observer evidence."""

import json
import os
from pathlib import Path
import platform
import sys
import time

import pytest
from azazel_edge.benchmark.udp_payload_copy import evaluate_udp_payload_copy
from udp_copy_credential_lab import transferred_socket
from udp_payload_copy_data import make_inputs, PAYLOAD
from test_udp_payload_copy_linux import (
    ready,
    SENSOR_WORKER,
    command,
    line,
    digest,
    wire,
    _assert_unqualified,
)
import test_udp_payload_copy_linux as copy_lab

import test_udp_queue_linux as queue_lab

copy_object, lab = copy_lab.copy_object, copy_lab.lab

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux Root and existing BPF/UID setup profile required",
)
CASES = json.loads(
    (Path(__file__).parent / "fixtures/udp-copy-credentials/v1/cases.json").read_bytes()
)["cases"]

# Fixed sender setup is a test actor, separate from the read-only observer.
# Assert its actual nonroot/capability state and fix NNP even when the CI parent
# itself did not inherit the container's no-new-privileges setting.
SENDER_WORKER = (
    r"""
import ctypes,os
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'sender NNP')
if os.getuid()!=61001 or os.geteuid()!=61001:raise ValueError('sender UID')
status={k:v.strip() for k,v in (line.split(':',1) for line in open('/proc/self/status') if ':' in line)}
if status['NoNewPrivs']!='1' or any(int(status[n],16) for n in ('CapInh','CapPrm','CapEff','CapAmb')):
 raise ValueError('sender capability/NNP guard')
"""
    + queue_lab.SENDER_WORKER
)


def identity(metadata):
    t = metadata["target"]
    return dict(
        inode=t["socket_inode"],
        cookie=t["socket_cookie"],
        netns_cookie=t["netns_cookie"],
        uid=t["uid"],
    )


def credentials(observed, real_uid, effective_uid):
    assert observed["real_uid"] == real_uid
    assert observed["effective_uid"] == observed["saved_uid"] == effective_uid
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert int(observed[name], 16) == 0
    assert str(observed["NoNewPrivs"]) == "1"


def capture(
    lab,
    copy_object,
    shared,
    sender,
    source_port,
    receiver,
    receiver_ready,
    label,
    expected,
):
    net, pid, tim = [
        os.stat("/proc/self/ns/" + name) for name in ("net", "pid", "time")
    ]
    offsets = {
        p[0]: int(p[1]) * 1_000_000_000 + int(p[2])
        for p in (
            line.split()
            for line in Path("/proc/self/timens_offsets").read_text().splitlines()
        )
    }
    assert offsets == dict(monotonic=0, boottime=0)
    assert shared.creator_reaped is True and shared.creator_returncode == 0
    metadata = shared.metadata
    assert receiver_ready["control_only"] is True
    assert receiver_ready["socket_identity"] == identity(metadata)
    assert receiver_ready["port"] == metadata["port"]
    assert receiver_ready["receiver"]["pid"] != metadata["target"]["pid"]
    assert receiver_ready["receiver"]["pid_namespace"] == dict(
        device=pid.st_dev, inode=pid.st_ino
    )
    assert receiver_ready["receiver"]["network_namespace"] == dict(
        device=net.st_dev, inode=net.st_ino
    )
    now = time.monotonic_ns()
    contract, plan, _ = make_inputs(
        net.st_dev,
        net.st_ino,
        Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        source_port,
        metadata["port"],
        now - 1_000_000,
        now + 4_000_000_000,
        PAYLOAD,
        metadata["target"],
        platform.release(),
        digest(Path("/sys/kernel/btf/vmlinux").read_bytes()),
        digest(copy_object.read_bytes()),
        pidns=dict(device=pid.st_dev, inode=pid.st_ino),
        timens=dict(
            device=tim.st_dev,
            inode=tim.st_ino,
            monotonic_offset_ns=0,
            boottime_offset_ns=0,
        ),
    )
    c, p = json.loads(contract), json.loads(plan)
    c["scope"]["run_id"] = "credential-" + label
    c["scope"]["scope_ref"] = "credential-scope-" + label
    for category, channel in c["channels"].items():
        channel["capture_id"] = "credential-capture-" + label + "-" + category
        channel["channel_id"] = "credential-channel-" + label + "-" + category
    c["opportunities"]["protected_escape"][0]["id"] = "credential-op-" + label
    contract = wire(c)
    p.update(
        contract_sha256=digest(contract),
        opportunity_id="credential-op-" + label,
        max_duration_ns=1_000_000_000,
    )
    plan = wire(p)
    pins = dict(
        expected_contract_sha256=digest(contract), expected_plan_sha256=digest(plan)
    )
    sensor = lab(SENSOR_WORKER)
    sensor.stdin.write(
        json.dumps(
            dict(
                contract=contract.decode(),
                plan=plan.decode(),
                object_path=str(copy_object),
                **pins,
            )
        )
    )
    sensor.stdin.close()
    ready(sensor)
    assert (
        command(sender, dict(port=metadata["port"], payload_hex=PAYLOAD.hex()))["sent"]
        is True
    )
    before_receive = time.monotonic_ns()
    control = command(receiver, dict(op="copy", mode="iovec"))
    after_receive = time.monotonic_ns()
    assert control["control_only"] is True
    assert control["ret"] == 64 and control["errno"] == 0
    assert control["payload_hex"] == PAYLOAD.hex()
    assert (
        control["socket_identity_before"]
        == control["socket_identity"]
        == identity(metadata)
    )
    assert control["credentials_before"] == control["credentials"]
    credentials(
        control["credentials"],
        receiver_ready["credentials"]["real_uid"],
        receiver_ready["credentials"]["effective_uid"],
    )
    outcome = line(sensor)
    sensor.wait(timeout=5)
    assert sensor.returncode == 0 and "report" in outcome, outcome
    raw = outcome["report"].encode()
    report = json.loads(raw)
    opportunity = c["opportunities"]["protected_escape"][0]
    deadline = min(report["started_ns"] + p["max_duration_ns"], opportunity["end_ns"])
    # A null observation after timeout/loss is not a credential-branch control.
    # Enclose the entire real read inside the original signed capture window,
    # and refuse any loss/early-detach condition instead of calling it negative.
    assert (
        report["started_ns"]
        <= before_receive
        <= after_receive
        <= min(deadline, report["finished_ns"])
    )
    assert report["partial_reasons"] == ["timeout"]
    assert report["counters"]["correlation_loss"] == 0
    assert report["counters"]["overflow"] == 0
    result = evaluate_udp_payload_copy(contract, plan, raw, **pins)
    assert result["protocol_payload_copy_observed_count"] == expected
    _assert_unqualified(result)
    if expected is None:
        assert report["events"] == []
    else:
        assert len(report["events"]) == 1
        event = report["events"][0]
        assert (
            before_receive
            <= event["entered_ns"]
            <= event["consumed_ns"]
            <= event["exited_ns"]
            <= after_receive
        )
        assert (
            event["receiver_tgid"]
            == control["receiver"]["pid"]
            != metadata["target"]["pid"]
        )
        assert event["receiver_tid"] == control["receiver"]["tid"]
        assert (
            event["receiver_real_uid"]
            == event["receiver_effective_uid"]
            == event["socket_uid"]
            == 61002
        )
        assert event["receiver_start_boottime_ns"] > 0
        assert event["payload_hex"] == PAYLOAD.hex()
        assert event["socket_inode"] == metadata["target"]["socket_inode"]
        assert event["socket_cookie"] == metadata["target"]["socket_cookie"]
        assert event["netns_cookie"] == metadata["target"]["netns_cookie"]
    return contract, plan, raw, pins


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_actual_socket_copy_credential_and_exited_locator_controls(
    lab, copy_object, case
):
    with transferred_socket() as shared:
        assert shared.creator_reaped is True and shared.creator_returncode == 0
        assert shared.metadata["target"]["uid"] == 61002
        assert shared.metadata["control_only"] is True
        credentials(shared.metadata["creator_credentials"], 61002, 61002)
        sender = lab(SENDER_WORKER, uid=queue_lab.PRODUCER)
        source_port = line(sender)["port"]
        prior = None
        if case["expected_copy_count"] is None:
            # Independent eligibility control on this SAME socket, with its own
            # window and IDs, completes before the credential-negative trial.
            with shared.receiver(61002, 61002) as (receiver, observed):
                credentials(observed["credentials"], 61002, 61002)
                prior = capture(
                    lab,
                    copy_object,
                    shared,
                    sender,
                    source_port,
                    receiver,
                    observed,
                    case["id"] + "-positive",
                    1,
                )
            prior_bytes = prior[2]
            prior_sha = digest(prior_bytes)
        with shared.receiver(case["real_uid"], case["effective_uid"]) as (
            receiver,
            observed,
        ):
            credentials(
                observed["credentials"], case["real_uid"], case["effective_uid"]
            )
            current = capture(
                lab,
                copy_object,
                shared,
                sender,
                source_port,
                receiver,
                observed,
                case["id"],
                case["expected_copy_count"],
            )
        if prior is not None:
            assert prior[2] == prior_bytes and digest(prior[2]) == prior_sha
            assert (
                prior[3]["expected_plan_sha256"] != current[3]["expected_plan_sha256"]
            )
            assert (
                evaluate_udp_payload_copy(prior[0], prior[1], prior[2], **prior[3])[
                    "protocol_payload_copy_observed_count"
                ]
                == 1
            )
