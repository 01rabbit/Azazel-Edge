"""Read-only kernel queue-admission evidence, never application delivery or safety."""

from contextlib import contextmanager
import hashlib
import os
import time

from azazel_edge.outcome.input_auth import public_hex, sign, verify_signature
from azazel_edge.outcome.journal import _json
from . import safety_collection as collection
from . import safety_observations as safety
from . import protected_ingress as ingress
from . import udp_queue_bpf as provider

DOMAIN = b"azazel-edge:udp-socket-queue-admission:v1\x00"
LAYER = "udp_socket_queue_admission"
COUNTERS = "entry_matches accepted rejected correlation_loss overflow"
REASONS = {
    "timeout",
    "event_bound",
    "correlation_loss",
    "event_overflow",
    "target_lifecycle_changed",
}


class UDPQueueError(ValueError):
    """Unavailable or invalid observation; no qualifying result exists."""


def _need(value, message):
    if not value:
        raise UDPQueueError(message)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


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
        "schema_version contract_sha256 observation_layer opportunity_id kernel_release btf_sha256 object_sha256 target challenge_payload_hex max_duration_ns max_events",
    )
    _need(
        plan["schema_version"] == "edge-udp-queue-plan/v1"
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
    target = plan["target"]
    safety._fields(
        target, "pid start_ticks uid fd socket_inode socket_cookie netns_cookie"
    )
    for name, value in target.items():
        safety._int(
            value,
            0 if name == "fd" else 1,
            2**32 - 1 if name in ("pid", "uid", "fd") else 2**64 - 1,
        )
    _need(
        target["uid"] != contract["scope"]["owner"]["producer_uid"],
        "target and producer UID overlap",
    )
    opportunities = contract["opportunities"]["protected_escape"]
    _need(
        len(opportunities) == 1
        and all(
            not contract["opportunities"][c]
            for c in safety.CATEGORIES
            if c != "protected_escape"
        ),
        "single queue opportunity required",
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
    reference = dict(observation_layer=LAYER, protected_tuple=tuple_, target=target)
    _need(
        _digest(_json(reference)) == opportunity["reference_sha256"],
        "queue layer reference differs",
    )
    safety._int(plan["max_duration_ns"], 1, 5_000_000_000)
    safety._int(plan["max_events"], 1, 16)
    return contract, plan, opportunity, tuple_


def _role():
    _need(os.geteuid() == 0, "root BPF observer required")
    lines = ingress._proc_bytes("/proc/self/status", 65536).decode("ascii").splitlines()
    required = {"Uid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
    fields = {}
    for line in lines:
        key, separator, value = line.partition(":")
        if separator and key in required:
            _need(key not in fields, "duplicate role field")
            fields[key] = value.strip()
    _need(
        set(fields) == required
        and fields["Uid"].split() == ["0"] * 4
        and fields["NoNewPrivs"] == "1",
        "root/NNP required",
    )
    for key in ("CapPrm", "CapEff", "CapBnd"):
        _need(int(fields[key], 16) == (1 << 38 | 1 << 39), "BPF+PERFMON only required")
    for key in ("CapInh", "CapAmb"):
        _need(int(fields[key], 16) == 0, "ambient/inheritable forbidden")


def _environment(contract, plan):
    ns = os.stat("/proc/self/ns/net")
    env = dict(
        kernel_boot_id=collection._kernel_boot_id(),
        namespace=dict(device=ns.st_dev, inode=ns.st_ino),
        kernel_release=os.uname().release,
        btf_sha256=_digest(
            ingress._proc_bytes("/sys/kernel/btf/vmlinux", 16 * 1024 * 1024)
        ),
    )
    tuple_ = contract["opportunities"]["protected_escape"][0]["predicate"][
        "protected_tuple"
    ]
    _need(
        env["kernel_boot_id"] == contract["scope"]["kernel_boot_id"]
        and env["namespace"]
        == dict(device=tuple_["namespace_device"], inode=tuple_["namespace_inode"])
        and env["kernel_release"] == plan["kernel_release"]
        and env["btf_sha256"] == plan["btf_sha256"],
        "kernel/namespace/boot differs",
    )
    return env


def _target_alive(target):
    try:
        raw = ingress._proc_bytes(f"/proc/{target['pid']}/stat", 8192).decode("ascii")
        _need(raw.startswith(str(target["pid"]) + " ("), "PID identity")
        fields = raw[raw.rfind(")") + 2 :].split()
        if int(fields[19]) != target["start_ticks"] or fields[0] in ("Z", "X"):
            return False
        lines = (
            ingress._proc_bytes(f"/proc/{target['pid']}/status", 65536)
            .decode("ascii")
            .splitlines()
        )
        values = [line.split()[1:] for line in lines if line.startswith("Uid:")]
        return len(values) == 1 and values[0] == [str(target["uid"])] * 4
    except (OSError, ValueError, IndexError):
        return False


@contextmanager
def _read_object(path, expected_sha):
    held = collection._HeldFiles()
    try:
        raw = held.read(path, 2 * 1024 * 1024)
        _need(_digest(raw) == expected_sha, "object pin differs")
        yield raw
        held.verify()
    finally:
        errors = held.close()
        _need(not errors, "object FD close failed")


def capture_udp_queue(
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
        _need(_target_alive(plan["target"]), "initial target identity unavailable")
        started = time.monotonic_ns()
        _need(
            opportunity["start_ns"] <= started < opportunity["end_ns"],
            "capture outside window",
        )
        deadline = min(started + plan["max_duration_ns"], opportunity["end_ns"])
        target = plan["target"]
        configuration = dict(
            socket_inode=target["socket_inode"],
            socket_cookie=target["socket_cookie"],
            socket_uid=target["uid"],
            netns_cookie=target["netns_cookie"],
            netns_inode=tuple_["namespace_inode"],
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
            _need(captured["started_ns"] == started, "provider start differs")
            reasons = list(captured["partial_reasons"])
            if not _target_alive(target):
                reasons.append("target_lifecycle_changed")
            _role()
            _need(_environment(contract, plan) == env, "observer environment changed")
            report = dict(
                schema_version="edge-udp-queue-report/v1",
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
                partial_reasons=sorted(set(reasons)),
            )
            report["signature"] = sign(observer_private_key, DOMAIN, report)
            result = _json(report) + b"\n"
            evaluate_udp_queue(
                contract_raw,
                plan_raw,
                result,
                expected_contract_sha256=expected_contract_sha256,
                expected_plan_sha256=expected_plan_sha256,
            )
        return result
    except Exception as exc:
        raise UDPQueueError(str(exc)) from exc


def evaluate_udp_queue(
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
            "schema_version contract_sha256 plan_sha256 observation_layer kernel_release btf_sha256 object_sha256 kernel_boot_id namespace capture_id started_ns finished_ns events counters partial_reasons signature",
        )
        _need(
            report["schema_version"] == "edge-udp-queue-report/v1"
            and report["contract_sha256"] == expected_contract_sha256
            and report["plan_sha256"] == expected_plan_sha256
            and report["observation_layer"] == LAYER,
            "report binding differs",
        )
        for key in ("kernel_release", "btf_sha256", "object_sha256"):
            _need(report[key] == plan[key], "report kernel/object differs")
        _need(
            report["kernel_boot_id"] == contract["scope"]["kernel_boot_id"]
            and report["namespace"]
            == dict(device=tuple_["namespace_device"], inode=tuple_["namespace_inode"])
            and report["capture_id"]
            == contract["channels"]["protected_escape"]["capture_id"],
            "report context differs",
        )
        safety._fields(report["namespace"], "device inode")
        for value in report["namespace"].values():
            safety._int(value, 1)
        verify_signature(
            contract["keypins"]["observer_public_key"],
            report["signature"],
            DOMAIN,
            {k: v for k, v in report.items() if k != "signature"},
        )
        started, finished = report["started_ns"], report["finished_ns"]
        safety._int(started)
        safety._int(finished)
        _need(
            opportunity["start_ns"] <= started < opportunity["end_ns"]
            and finished >= started,
            "report window",
        )
        deadline = min(started + plan["max_duration_ns"], opportunity["end_ns"])
        safety._fields(report["counters"], COUNTERS)
        for value in report["counters"].values():
            safety._int(value, 0, 2**64 - 1)
        _need(
            type(report["events"]) is list
            and len(report["events"]) <= plan["max_events"]
            and len(report["events"]) <= report["counters"]["accepted"],
            "event bound",
        )
        target = plan["target"]
        for event in report["events"]:
            safety._fields(
                event,
                "entered_ns exited_ns socket_inode socket_cookie netns_cookie netns_inode socket_uid src_ip dst_ip src_port dst_port payload_hex",
            )
            for key in (
                "entered_ns",
                "exited_ns",
                "socket_inode",
                "socket_cookie",
                "netns_cookie",
                "netns_inode",
                "socket_uid",
                "src_port",
                "dst_port",
            ):
                safety._int(event[key], 1, 2**64 - 1)
            _need(
                started
                <= event["entered_ns"]
                <= event["exited_ns"]
                <= min(deadline, finished),
                "event outside deadline",
            )
            _need(
                all(
                    event[k] == target[k]
                    for k in ("socket_inode", "socket_cookie", "netns_cookie")
                )
                and event["socket_uid"] == target["uid"]
                and event["netns_inode"] == tuple_["namespace_inode"],
                "event socket differs",
            )
            _need(
                all(
                    event[k] == tuple_[k]
                    for k in ("src_ip", "dst_ip", "src_port", "dst_port")
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
            schema_version="edge-udp-queue-evaluation/v1",
            status="unqualified_udp_queue_diagnostic",
            observation_layer=LAYER,
            queue_admission_observed_count=1 if report["events"] else None,
            application_delivery_count=None,
            qualified_safety_count=None,
            independently_measured=False,
            safety_evaluation=safe,
        )
    except Exception as exc:
        raise UDPQueueError(str(exc)) from exc


def collect_udp_queue(
    enrollment_path,
    plan_path,
    report_path,
    *,
    expected_enrollment_sha256,
    expected_checkpoint_sha256,
    expected_plan_sha256,
    expected_report_sha256,
):
    held = collection._HeldFiles()
    failure = None
    result = None
    try:
        for value in (
            expected_enrollment_sha256,
            expected_checkpoint_sha256,
            expected_plan_sha256,
            expected_report_sha256,
        ):
            safety._hex(value)
        uid, boot = os.geteuid(), collection._kernel_boot_id()
        _need(uid > 0, "nonroot reader required")
        enrollment_path = collection._physical_path(enrollment_path)[0]
        raw = held.read(enrollment_path, 32 * 1024)
        _need(_digest(raw) == expected_enrollment_sha256, "enrollment pin differs")
        enrollment = safety._wire(raw, 32 * 1024)
        safety._fields(
            enrollment, "schema_version contract_sha256 scope observer_uid paths"
        )
        safety._fields(enrollment["paths"], "contract observations checkpoint")
        paths = {
            k: collection._physical_path(v)[0] for k, v in enrollment["paths"].items()
        }
        plan_path = collection._physical_path(plan_path)[0]
        report_path = collection._physical_path(report_path)[0]
        _need(
            len(set([enrollment_path, *paths.values(), plan_path, report_path])) == 6,
            "six distinct paths required",
        )
        contract = held.read(paths["contract"], 128 * 1024)
        observations = held.read(paths["observations"], 2 * 1024 * 1024)
        checkpoint = held.read(paths["checkpoint"], 32 * 1024)
        plan = held.read(plan_path, 32 * 1024)
        report = held.read(report_path, 64 * 1024)
        _need(
            _digest(plan) == expected_plan_sha256
            and _digest(report) == expected_report_sha256
            and _digest(checkpoint) == expected_checkpoint_sha256,
            "artifact pin differs",
        )
        obs = safety._wire(observations, 2 * 1024 * 1024)
        check = safety._wire(checkpoint, 32 * 1024)
        _need(
            obs.get("channels") == {}
            and type(check.get("stream_heads")) is dict
            and set(check["stream_heads"]) == set(safety.CATEGORIES)
            and all(v is None for v in check["stream_heads"].values()),
            "delivery sensor must be absent",
        )
        collected = collection.collect_registered_safety(
            enrollment_path,
            expected_enrollment_sha256=expected_enrollment_sha256,
            expected_checkpoint_sha256=expected_checkpoint_sha256,
        )
        _need(
            collected["provenance"]["observer_uid"] == uid
            and collected["provenance"]["kernel_boot_id"] == boot
            and collected["provenance"]["contract_sha256"]
            == enrollment["contract_sha256"],
            "reader context differs",
        )
        held.verify()
        queue = evaluate_udp_queue(
            contract,
            plan,
            report,
            expected_contract_sha256=enrollment["contract_sha256"],
            expected_plan_sha256=expected_plan_sha256,
        )
        _need(
            os.geteuid() == uid and collection._kernel_boot_id() == boot,
            "reader UID/boot changed",
        )
        held.verify()
        result = dict(
            schema_version="edge-udp-queue-collection/v1",
            status="unqualified_udp_queue_collection",
            collection=collected,
            queue=queue,
        )
    except BaseException as exc:
        failure = exc
    finally:
        errors = held.close()
    if failure is not None or errors:
        raise UDPQueueError(
            "sealed queue join failed"
            + (f": {failure}" if failure else "")
            + ("; FD close failure" if errors else "")
        ) from failure
    return result
