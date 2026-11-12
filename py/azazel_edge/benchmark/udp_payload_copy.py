"""Socket-bound protocol payload-copy assertions, never syscall/app delivery."""

import hashlib
import os
import re
import time

from azazel_edge.outcome.input_auth import public_hex, sign, verify_signature
from azazel_edge.outcome.journal import _json
from . import safety_observations as safety
from . import protected_ingress as ingress
from . import udp_queue as queue
from . import udp_payload_copy_bpf as provider

DOMAIN = b"azazel-edge:udp-protocol-userspace-payload-copy:v1\x00"
LAYER = "udp_protocol_userspace_payload_copy"
COUNTERS = "entry_matches consume_matches accepted rejected correlation_loss overflow"
REASONS = {
    "timeout",
    "event_bound",
    "correlation_loss",
    "event_overflow",
    "observer_link_lost",
}


class UDPPayloadCopyError(ValueError):
    """Unsupported or invalid evidence: never a zero observation."""


def _need(value, message):
    if not value:
        raise UDPPayloadCopyError(message)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


_role = queue._role
_read_object = queue._read_object


def _namespace(value):
    safety._fields(value, "device inode")
    for number in value.values():
        safety._int(number, 1, 2**64 - 1)


def _time_namespace(value):
    safety._fields(value, "device inode monotonic_offset_ns boottime_offset_ns")
    _namespace({name: value[name] for name in ("device", "inode")})
    for name in ("monotonic_offset_ns", "boottime_offset_ns"):
        safety._int(value[name], 0, 0)


def _inputs(contract_raw, plan_raw, contract_hash, plan_hash):
    safety._hex(contract_hash)
    safety._hex(plan_hash)
    _need(
        _digest(contract_raw) == contract_hash and _digest(plan_raw) == plan_hash,
        "external input pin differs",
    )
    contract = safety._wire(contract_raw, 128 * 1024)
    keys = contract.get("keypins")
    safety._fields(
        keys, "observer_public_key source_producer_public_key source_witness_public_key"
    )
    for key in keys.values():
        safety._hex(key)
    _need(len(set(keys.values())) == 3, "key roles overlap")
    safety._contract(contract, keys)
    plan = safety._wire(plan_raw, 32 * 1024)
    safety._fields(
        plan,
        "schema_version contract_sha256 observation_layer opportunity_id kernel_release btf_sha256 object_sha256 socket_identity locator receiver_pid_namespace observer_time_namespace challenge_payload_hex max_duration_ns max_events",
    )
    _need(
        plan["schema_version"] == "edge-udp-payload-copy-plan/v1"
        and plan["contract_sha256"] == contract_hash
        and plan["observation_layer"] == LAYER,
        "plan binding differs",
    )
    for name in ("btf_sha256", "object_sha256"):
        safety._hex(plan[name])
    _need(
        type(plan["kernel_release"]) is str and 0 < len(plan["kernel_release"]) <= 256,
        "kernel release",
    )
    identity = plan["socket_identity"]
    safety._fields(identity, "inode cookie uid netns_cookie")
    for name, number in identity.items():
        safety._int(number, 1, 2**32 - 1 if name == "uid" else 2**64 - 1)
    _need(
        identity["uid"] != contract["scope"]["owner"]["producer_uid"],
        "socket owner and producer overlap",
    )
    locator = plan["locator"]
    safety._fields(locator, "pid start_ticks fd")
    for name, number in locator.items():
        safety._int(
            number,
            0 if name == "fd" else 1,
            2**64 - 1 if name == "start_ticks" else 2**32 - 1,
        )
    _namespace(plan["receiver_pid_namespace"])
    _time_namespace(plan["observer_time_namespace"])
    opportunities = contract["opportunities"]["protected_escape"]
    _need(
        len(opportunities) == 1
        and all(
            not contract["opportunities"][c]
            for c in safety.CATEGORIES
            if c != "protected_escape"
        ),
        "single payload-copy opportunity required",
    )
    opportunity = opportunities[0]
    _need(opportunity["id"] == plan["opportunity_id"], "opportunity differs")
    tuple_ = opportunity["predicate"]["protected_tuple"]
    _need(
        tuple_["src_ip"] == tuple_["dst_ip"] == "127.0.0.1"
        and tuple_["protocol"] == "UDP",
        "loopback IPv4 UDP required",
    )
    safety._hex(plan["challenge_payload_hex"], 128)
    _need(
        _digest(bytes.fromhex(plan["challenge_payload_hex"]))
        == opportunity["challenge_sha256"],
        "challenge differs",
    )
    reference = dict(
        observation_layer=LAYER,
        protected_tuple=tuple_,
        **{
            name: plan[name]
            for name in (
                "socket_identity",
                "locator",
                "receiver_pid_namespace",
                "observer_time_namespace",
            )
        },
    )
    _need(
        _digest(_json(reference)) == opportunity["reference_sha256"],
        "payload-copy reference differs",
    )
    safety._int(plan["max_duration_ns"], 1, 5_000_000_000)
    safety._int(plan["max_events"], 1, 16)
    return contract, plan, opportunity, tuple_


def _environment(contract, plan):
    env = queue._environment(contract, plan)
    pid = os.stat("/proc/self/ns/pid")
    timens = os.stat("/proc/self/ns/time")
    offsets = {}
    for line in (
        ingress._proc_bytes("/proc/self/timens_offsets", 4096)
        .decode("ascii")
        .splitlines()
    ):
        fields = line.split()
        _need(
            len(fields) == 3
            and fields[0] in {"monotonic", "boottime"}
            and fields[0] not in offsets,
            "time namespace offsets shape",
        )
        _need(
            all(re.fullmatch(r"-?[0-9]+", v) for v in fields[1:]),
            "time namespace offsets type",
        )
        seconds, nanoseconds = map(int, fields[1:])
        _need(seconds == nanoseconds == 0, "nonzero time namespace offset")
        offsets[fields[0]] = 0
    _need(set(offsets) == {"monotonic", "boottime"}, "time namespace offsets missing")
    env.update(
        receiver_pid_namespace=dict(device=pid.st_dev, inode=pid.st_ino),
        observer_time_namespace=dict(
            device=timens.st_dev,
            inode=timens.st_ino,
            monotonic_offset_ns=0,
            boottime_offset_ns=0,
        ),
    )
    _need(
        _json(env["receiver_pid_namespace"]) == _json(plan["receiver_pid_namespace"])
        and _json(env["observer_time_namespace"])
        == _json(plan["observer_time_namespace"]),
        "PID/time namespace differs",
    )
    return env


def capture_udp_payload_copy(
    contract_raw,
    plan_raw,
    *,
    expected_contract_sha256,
    expected_plan_sha256,
    observer_private_key,
    object_path,
):
    try:
        contract, plan, opportunity, tuple_ = _inputs(
            contract_raw, plan_raw, expected_contract_sha256, expected_plan_sha256
        )
        _need(
            public_hex(observer_private_key)
            == contract["keypins"]["observer_public_key"],
            "signing key differs",
        )
        _role()
        env = _environment(contract, plan)
        started = time.monotonic_ns()
        _need(
            opportunity["start_ns"] <= started < opportunity["end_ns"],
            "capture outside window",
        )
        deadline = min(started + plan["max_duration_ns"], opportunity["end_ns"])
        identity = plan["socket_identity"]
        configuration = dict(
            socket_inode=identity["inode"],
            socket_cookie=identity["cookie"],
            socket_uid=identity["uid"],
            netns_cookie=identity["netns_cookie"],
            netns_inode=tuple_["namespace_inode"],
            pidns_device=plan["receiver_pid_namespace"]["device"],
            pidns_inode=plan["receiver_pid_namespace"]["inode"],
            src_ip=tuple_["src_ip"],
            dst_ip=tuple_["dst_ip"],
            src_port=tuple_["src_port"],
            dst_port=tuple_["dst_port"],
            payload_hex=plan["challenge_payload_hex"],
            started_ns=started,
            deadline_ns=deadline,
            max_events=plan["max_events"],
        )
        with _read_object(object_path, plan["object_sha256"]) as raw:
            captured = provider._capture_events(configuration, raw)
            safety._fields(
                captured, "started_ns finished_ns events counters partial_reasons"
            )
            safety._int(captured["started_ns"], 0, 2**64 - 1)
            _need(captured["started_ns"] == started, "provider start differs")
            _role()
            _need(
                _json(_environment(contract, plan)) == _json(env),
                "observer environment changed",
            )
            report = dict(
                schema_version="edge-udp-payload-copy-report/v1",
                contract_sha256=expected_contract_sha256,
                plan_sha256=expected_plan_sha256,
                observation_layer=LAYER,
                **env,
                object_sha256=plan["object_sha256"],
                capture_id=contract["channels"]["protected_escape"]["capture_id"],
                started_ns=started,
                finished_ns=captured["finished_ns"],
                events=captured["events"],
                counters=captured["counters"],
                partial_reasons=captured["partial_reasons"],
            )
            report["signature"] = sign(observer_private_key, DOMAIN, report)
            result = _json(report) + b"\n"
            evaluate_udp_payload_copy(
                contract_raw,
                plan_raw,
                result,
                expected_contract_sha256=expected_contract_sha256,
                expected_plan_sha256=expected_plan_sha256,
            )
        return result
    except Exception as exc:
        raise UDPPayloadCopyError(str(exc)) from exc


def evaluate_udp_payload_copy(
    contract_raw,
    plan_raw,
    report_raw,
    *,
    expected_contract_sha256,
    expected_plan_sha256,
):
    try:
        contract, plan, opportunity, tuple_ = _inputs(
            contract_raw, plan_raw, expected_contract_sha256, expected_plan_sha256
        )
        report = safety._wire(report_raw, 64 * 1024)
        safety._fields(
            report,
            "schema_version contract_sha256 plan_sha256 observation_layer kernel_release btf_sha256 object_sha256 kernel_boot_id namespace receiver_pid_namespace observer_time_namespace capture_id started_ns finished_ns events counters partial_reasons signature",
        )
        _need(
            report["schema_version"] == "edge-udp-payload-copy-report/v1"
            and report["contract_sha256"] == expected_contract_sha256
            and report["plan_sha256"] == expected_plan_sha256
            and report["observation_layer"] == LAYER,
            "report binding differs",
        )
        for name in ("kernel_release", "btf_sha256", "object_sha256"):
            _need(report[name] == plan[name], "report kernel/object differs")
        _namespace(report["namespace"])
        _namespace(report["receiver_pid_namespace"])
        _time_namespace(report["observer_time_namespace"])
        _need(
            report["kernel_boot_id"] == contract["scope"]["kernel_boot_id"]
            and report["namespace"]
            == dict(device=tuple_["namespace_device"], inode=tuple_["namespace_inode"])
            and report["capture_id"]
            == contract["channels"]["protected_escape"]["capture_id"],
            "report context differs",
        )
        for name in ("receiver_pid_namespace", "observer_time_namespace"):
            _need(
                _json(report[name]) == _json(plan[name]),
                "report PID/time namespace differs",
            )
        verify_signature(
            contract["keypins"]["observer_public_key"],
            report["signature"],
            DOMAIN,
            {k: v for k, v in report.items() if k != "signature"},
        )
        started, finished = report["started_ns"], report["finished_ns"]
        safety._int(started, 0, 2**64 - 1)
        safety._int(finished, 0, 2**64 - 1)
        _need(
            opportunity["start_ns"] <= started < opportunity["end_ns"]
            and finished >= started,
            "report window",
        )
        deadline = min(started + plan["max_duration_ns"], opportunity["end_ns"])
        safety._fields(report["counters"], COUNTERS)
        for number in report["counters"].values():
            safety._int(number, 0, 2**64 - 1)
        _need(
            type(report["events"]) is list
            and len(report["events"]) <= plan["max_events"]
            and len(report["events"]) <= report["counters"]["accepted"],
            "event bound",
        )
        identity = plan["socket_identity"]
        for event in report["events"]:
            safety._fields(
                event,
                "entered_ns consumed_ns exited_ns socket_inode socket_cookie netns_cookie netns_inode receiver_start_boottime_ns socket_uid receiver_real_uid receiver_effective_uid receiver_tgid receiver_tid src_ip dst_ip src_port dst_port payload_hex",
            )
            for name in (
                "entered_ns",
                "consumed_ns",
                "exited_ns",
                "socket_inode",
                "socket_cookie",
                "netns_cookie",
                "netns_inode",
                "receiver_start_boottime_ns",
            ):
                safety._int(event[name], 1, 2**64 - 1)
            for name in (
                "socket_uid",
                "receiver_real_uid",
                "receiver_effective_uid",
                "receiver_tgid",
                "receiver_tid",
            ):
                safety._int(event[name], 1, 2**32 - 1)
            for name in ("src_port", "dst_port"):
                safety._int(event[name], 1, 65535)
            _need(
                started
                <= event["entered_ns"]
                <= event["consumed_ns"]
                <= event["exited_ns"]
                <= min(deadline, finished),
                "event outside deadline",
            )
            _need(
                event["socket_inode"] == identity["inode"]
                and event["socket_cookie"] == identity["cookie"]
                and event["netns_cookie"] == identity["netns_cookie"]
                and event["netns_inode"] == tuple_["namespace_inode"],
                "event socket differs",
            )
            _need(
                all(
                    event[name] == identity["uid"]
                    for name in (
                        "socket_uid",
                        "receiver_real_uid",
                        "receiver_effective_uid",
                    )
                ),
                "event receiver credentials differ",
            )
            _need(
                all(
                    event[name] == tuple_[name]
                    for name in ("src_ip", "dst_ip", "src_port", "dst_port")
                )
                and event["payload_hex"] == plan["challenge_payload_hex"],
                "event challenge/tuple differs",
            )
        reasons = report["partial_reasons"]
        _need(
            type(reasons) is list
            and all(type(v) is str and v in REASONS for v in reasons)
            and len(set(reasons)) == len(reasons),
            "partial reasons",
        )
        empty = dict(
            schema_version="edge-finite-safety-observations/v1",
            contract_sha256=expected_contract_sha256,
            scope=contract["scope"],
            channels={},
        )
        safe = safety.evaluate_safety_observations(
            contract_raw,
            _json(empty) + b"\n",
            expected_contract_sha256=expected_contract_sha256,
            expected_stream_heads=dict.fromkeys(safety.CATEGORIES),
            **contract["keypins"],
        )
        return dict(
            schema_version="edge-udp-payload-copy-evaluation/v1",
            status="unqualified_udp_payload_copy_diagnostic",
            observation_layer=LAYER,
            protocol_payload_copy_observed_count=1 if report["events"] else None,
            successful_syscall_count=None,
            application_delivery_count=None,
            qualified_safety_count=None,
            independently_measured=False,
            safety_evaluation=safe,
            **safety.FLAGS,
        )
    except Exception as exc:
        raise UDPPayloadCopyError(str(exc)) from exc
