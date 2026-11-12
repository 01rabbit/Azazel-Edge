"""ACTUAL owned-link FD faults; no global disappearance or coverage claim."""

import json
import os
from pathlib import Path
import platform
import time

import pytest
from azazel_edge.benchmark.udp_payload_copy import evaluate_udp_payload_copy
from udp_payload_copy_data import make_inputs, PAYLOAD
from udp_payload_copy_lab import COPY_TARGET_WORKER
from udp_copy_link_lab import WORKER
from test_udp_copy_credentials_linux import SENDER_WORKER
import test_udp_payload_copy_linux as base

copy_object, lab = base.copy_object, base.lab
line, command, digest, wire = base.line, base.command, base.digest, base.wire
pytestmark = base.pytestmark
CASES = json.loads(
    (
        Path(__file__).parent / "fixtures/udp-copy-link-lifecycle/v1/cases.json"
    ).read_bytes()
)["cases"]
TARGET_WORKER = (
    r"""
import ctypes,os
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'target NNP')
if os.getresuid()!=(61002,61002,61002):raise ValueError('target UID')
status={k:v.strip() for k,v in (row.split(':',1) for row in open('/proc/self/status') if ':' in row)}
if status['NoNewPrivs']!='1' or any(int(status[n],16) for n in ('CapInh','CapPrm','CapEff','CapAmb')):
 raise ValueError('target capability/NNP guard')
"""
    + COPY_TARGET_WORKER
)


def start(lab, copy_object, case):
    target = lab(TARGET_WORKER, ["allow"], uid=61002)
    meta = line(target)
    sender = lab(SENDER_WORKER, uid=61001)
    source_port = line(sender)["port"]
    net, pid, tim = [
        os.stat("/proc/self/ns/" + name) for name in ("net", "pid", "time")
    ]
    offsets = {
        p[0]: int(p[1]) * 1_000_000_000 + int(p[2])
        for p in (
            row.split()
            for row in Path("/proc/self/timens_offsets").read_text().splitlines()
        )
    }
    assert offsets == dict(monotonic=0, boottime=0)
    now = time.monotonic_ns()
    contract, plan, _ = make_inputs(
        net.st_dev,
        net.st_ino,
        Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        source_port,
        meta["port"],
        now - 1_000_000,
        now + 4_000_000_000,
        PAYLOAD,
        meta["target"],
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
    label = case["id"]
    c["scope"].update(
        run_id="copy-link-run-" + label, scope_ref="copy-link-scope-" + label
    )
    for category, d in c["channels"].items():
        d.update(
            channel_id="copy-link-channel-" + label + "-" + category,
            capture_id="copy-link-capture-" + label + "-" + category,
        )
    c["opportunities"]["protected_escape"][0]["id"] = "copy-link-op-" + label
    contract = wire(c)
    p.update(
        contract_sha256=digest(contract),
        opportunity_id="copy-link-op-" + label,
        max_duration_ns=1_000_000_000,
    )
    plan = wire(p)
    pins = dict(
        expected_contract_sha256=digest(contract), expected_plan_sha256=digest(plan)
    )
    fault = (
        "before_first"
        if not case["after_positive"]
        else "reuse"
        if case["reuse"]
        else {"copy_entry": "entry", "copy_consume": "consume", "copy_exit": "exit"}[
            case["link"]
        ]
    )
    sensor = lab(WORKER)
    sensor.stdin.write(
        json.dumps(
            dict(
                contract=contract.decode(),
                plan=plan.decode(),
                object_path=str(copy_object),
                fault=fault,
                **pins,
            )
        )
    )
    sensor.stdin.close()
    return target, sender, meta, sensor, contract, plan, pins


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_actual_three_hook_loss_preserves_completed_copy_and_never_reattaches(
    lab, copy_object, case
):
    target, sender, meta, sensor, contract, plan, pins = start(lab, copy_object, case)
    originals = (contract, plan, dict(pins))
    bracket = None
    control = None
    if case["after_positive"]:
        base.ready(sensor)
        assert (
            command(sender, dict(port=meta["port"], payload_hex=PAYLOAD.hex()))["sent"]
            is True
        )
        before = time.monotonic_ns()
        control = command(target, dict(op="copy", mode="iovec"))
        after = time.monotonic_ns()
        bracket = (before, after)
        assert control["control_only"] is True
        assert (
            control["ret"] == 64
            and control["errno"] == 0
            and control["payload_hex"] == PAYLOAD.hex()
        )
    # before_first deliberately sends/receives NOTHING before final fault/report.
    outcome = line(sensor)
    sensor.wait(timeout=5)
    assert sensor.returncode == 0 and "report" in outcome, outcome
    state = outcome["fault_state"]
    assert state["control_only"] is True and state["fault_applied"] is True
    assert state["attach_calls"] == 3
    assert state["link"] == case["link"]
    assert state["trigger"] == (
        "accepted_at_least_one" if case["after_positive"] else "before_first"
    )
    assert (
        state["accepted_at_fault"] >= 1
        if case["after_positive"]
        else state["accepted_at_fault"] == 0
    )
    assert state["fd_reused"] is case["reuse"]
    assert state["replacement_alive"] is (True if case["reuse"] else None)
    assert state["destroy_calls"] == dict(copy_entry=1, copy_consume=1, copy_exit=1)
    assert state["disconnect_calls"] == {
        name: int(name == case["link"])
        for name in ("copy_entry", "copy_consume", "copy_exit")
    }
    raw = outcome["report"].encode()
    rawsha = digest(raw)
    report = json.loads(raw)
    result = evaluate_udp_payload_copy(contract, plan, raw, **pins)
    assert result["protocol_payload_copy_observed_count"] == case["expected_copy_count"]
    base._assert_unqualified(result)
    assert report["partial_reasons"] == ["observer_link_lost"]
    assert report["counters"]["correlation_loss"] == report["counters"]["overflow"] == 0
    assert report["contract_sha256"] == pins["expected_contract_sha256"]
    assert report["plan_sha256"] == pins["expected_plan_sha256"]
    if case["after_positive"]:
        assert len(report["events"]) == 1
        event = report["events"][0]
        assert (
            report["started_ns"]
            <= bracket[0]
            <= event["entered_ns"]
            <= event["consumed_ns"]
            <= event["exited_ns"]
            <= bracket[1]
            <= report["finished_ns"]
        )
        assert bracket[1] <= min(
            report["started_ns"] + json.loads(plan)["max_duration_ns"],
            json.loads(contract)["opportunities"]["protected_escape"][0]["end_ns"],
        )
        assert event["receiver_tgid"] == control["receiver"]["pid"]
        assert event["receiver_tid"] == control["receiver"]["tid"]
        assert (
            event["receiver_real_uid"]
            == event["receiver_effective_uid"]
            == event["socket_uid"]
            == 61002
        )
        assert event["socket_inode"] == meta["target"]["socket_inode"]
        assert event["socket_cookie"] == meta["target"]["socket_cookie"]
        assert event["netns_cookie"] == meta["target"]["netns_cookie"]
        assert event["payload_hex"] == PAYLOAD.hex()
    else:
        assert report["events"] == []
    assert (contract, plan, pins) == originals
    assert digest(raw) == rawsha
    assert evaluate_udp_payload_copy(contract, plan, raw, **pins) == result
