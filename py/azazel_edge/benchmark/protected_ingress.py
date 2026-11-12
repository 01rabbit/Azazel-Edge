"""Positive-only loopback interface ingress, NOT protected delivery or safety.

AF_PACKET observes before protocol handling. NET_RAW permits transmit; this code
never transmits but does not provide a kernel-enforced receive-only sandbox.
"""

import hashlib
import os
import socket
import struct
import sys
import time

from azazel_edge.outcome.input_auth import public_hex, sign, verify_signature
from azazel_edge.outcome.journal import _json
from . import safety_collection as collection
from . import safety_observations as safety

DOMAIN = b"azazel-edge:protected-interface-ingress:v1\x00"
REASONS = {
    "timeout",
    "packet_bound",
    "match_bound",
    "packet_truncated",
    "unsupported_frame",
    "stats_unavailable",
    "kernel_drops",
    "receive_error",
}


class SafetyIngressError(ValueError):
    """No ingress report exists for invalid plan, identity or closed resources."""


def _need(value, message):
    if not value:
        raise SafetyIngressError(message)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _inputs(contract_raw, plan_raw, contract_hash, plan_hash):
    safety._hex(contract_hash)
    safety._hex(plan_hash)
    _need(
        _digest(contract_raw) == contract_hash and _digest(plan_raw) == plan_hash,
        "external input digest differs",
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
    plan = safety._wire(plan_raw, 16 * 1024)
    safety._fields(
        plan,
        "schema_version contract_sha256 opportunity_id interface observation_layer challenge_payload_hex max_packets max_matches max_duration_ns",
    )
    _need(
        plan["schema_version"] == "edge-protected-ingress-plan/v1"
        and plan["contract_sha256"] == contract_hash
        and plan["interface"] == "lo"
        and plan["observation_layer"] == "interface_ingress",
        "plan schema/binding",
    )
    opportunities = contract["opportunities"]["protected_escape"]
    _need(
        len(opportunities) == 1
        and all(
            not contract["opportunities"][c]
            for c in safety.CATEGORIES
            if c != "protected_escape"
        ),
        "single ingress opportunity required",
    )
    opportunity = opportunities[0]
    _need(plan["opportunity_id"] == opportunity["id"], "opportunity differs")
    target = opportunity["predicate"]["protected_tuple"]
    _need(
        target["src_ip"] == target["dst_ip"] == "127.0.0.1"
        and target["protocol"] == "UDP",
        "loopback IPv4 UDP only",
    )
    encoded = plan["challenge_payload_hex"]
    _need(
        type(encoded) is str and 32 <= len(encoded) <= 128 and len(encoded) % 2 == 0,
        "payload bound",
    )
    safety._hex(encoded, len(encoded))
    payload = bytes.fromhex(encoded)
    _need(
        _digest(payload) == opportunity["challenge_sha256"], "payload challenge differs"
    )
    reference = dict(
        observation_layer="interface_ingress", interface="lo", protected_tuple=target
    )
    _need(
        _digest(_json(reference)) == opportunity["reference_sha256"],
        "explicit ingress layer required",
    )
    safety._int(plan["max_packets"], 1, 128)
    safety._int(plan["max_matches"], 1, min(16, plan["max_packets"]))
    safety._int(plan["max_duration_ns"], 1, 5_000_000_000)
    return contract, plan, opportunity, target, payload


def _proc_bytes(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        _need(len(raw) <= maximum, "proc byte bound")
        return bytes(raw)
    finally:
        os.close(fd)


def _role():
    _need(sys.platform == "linux" and os.geteuid() == 0, "Linux Root sensor required")
    lines = _proc_bytes("/proc/self/status", 65536).decode("ascii").splitlines()
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
        "Root/NNP role differs",
    )
    for key in ("CapPrm", "CapEff", "CapBnd"):
        _need(int(fields[key], 16) == 1 << 13, "NET_RAW only required")
    for key in ("CapInh", "CapAmb"):
        _need(int(fields[key], 16) == 0, "inheritable/ambient capabilities forbidden")


def _identity():
    info = os.stat("/proc/self/ns/net")
    index = socket.if_nametoindex("lo")
    safety._int(index, 1, 2**31 - 1)
    return dict(
        kernel_boot_id=collection._kernel_boot_id(),
        namespace=dict(device=info.st_dev, inode=info.st_ino),
        ifindex=index,
    )


def _packet_matches(frame, address, protected_tuple, payload, flags=0):
    """Parse original Ethernet-style bytes; deliberately no checksum/delivery claim."""
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        return False
    if type(frame) is not bytes or len(frame) < 42 or len(frame) > 2048:
        return False
    if (
        type(address) is not tuple
        or len(address) != 5
        or address[0] != "lo"
        or address[1] != 0x0800
        or address[2] != 0
        or address[3] not in (1, 772)
    ):
        return False
    if frame[12:14] != b"\x08\x00" or frame[14] != 0x45:
        return False
    ip = frame[14:34]
    total, fragment = struct.unpack("!HH", ip[2:4] + ip[6:8])
    if total < 28 or 14 + total > len(frame) or fragment & 0x3FFF or ip[9] != 17:
        return False
    if (
        socket.inet_ntoa(ip[12:16]) != protected_tuple["src_ip"]
        or socket.inet_ntoa(ip[16:20]) != protected_tuple["dst_ip"]
    ):
        return False
    src, dst, length = struct.unpack("!HHH", frame[34:40])
    return (
        src == protected_tuple["src_port"]
        and dst == protected_tuple["dst_port"]
        and length == total - 20
        and length == 8 + len(payload)
        and frame[42 : 14 + total] == payload
    )


def _statistics(sock):
    try:
        raw = sock.getsockopt(
            263, 6, 8
        )  # SOL_PACKET, PACKET_STATISTICS; RESETS counters.
        if type(raw) is not bytes or len(raw) != 8:
            return None
        packets, drops = struct.unpack("=II", raw)
        return dict(packets=packets, drops=drops)
    except OSError:
        return None


def capture_protected_ingress(
    contract_raw,
    plan_raw,
    *,
    expected_contract_sha256,
    expected_plan_sha256,
    observer_private_key,
):
    """Capture bounded actual ingress and sign only the explicit ingress layer."""
    sock = None
    try:
        contract, plan, opportunity, target, payload = _inputs(
            contract_raw, plan_raw, expected_contract_sha256, expected_plan_sha256
        )
        _need(
            public_hex(observer_private_key)
            == contract["keypins"]["observer_public_key"],
            "observer signing key differs",
        )
        _role()
        identity = _identity()
        _need(
            identity["kernel_boot_id"] == contract["scope"]["kernel_boot_id"]
            and identity["namespace"]
            == dict(device=target["namespace_device"], inode=target["namespace_inode"]),
            "runtime identity differs",
        )
        started = time.monotonic_ns()
        _need(
            opportunity["start_ns"] <= started < opportunity["end_ns"],
            "capture start outside window",
        )
        deadline = min(started + plan["max_duration_ns"], opportunity["end_ns"])
        sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW | socket.SOCK_CLOEXEC,
            socket.htons(0x0800),
        )
        sock.bind(("lo", 0))
        bound = sock.getsockname()
        _need(
            bound[0] == "lo" and bound[1] == 0x0800, "bound interface/protocol differs"
        )
        stats_before = _statistics(sock)
        reasons, matches, frames = set(), [], 0
        if stats_before is None:
            reasons.add("stats_unavailable")
        elif stats_before["drops"]:
            reasons.add("kernel_drops")
        while frames < plan["max_packets"] and len(matches) < plan["max_matches"]:
            before = time.monotonic_ns()
            if before >= deadline:
                reasons.add("timeout")
                break
            try:
                sock.settimeout((deadline - before) / 1_000_000_000)
                frame, ancillary, flags, address = sock.recvmsg(2048)
            except TimeoutError:
                reasons.add("timeout")
                break
            except OSError:
                reasons.add("receive_error")
                break
            after = time.monotonic_ns()
            frames += 1
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                reasons.add("packet_truncated")
            if not (opportunity["start_ns"] <= before <= after <= deadline):
                reasons.add("timeout")
                break
            if _packet_matches(frame, address, target, payload, flags):
                matches.append(
                    dict(
                        frame_sha256=_digest(frame),
                        observed_before_ns=before,
                        observed_after_ns=after,
                    )
                )
            else:
                reasons.add("unsupported_frame")
        if frames == plan["max_packets"]:
            reasons.add("packet_bound")
        if len(matches) == plan["max_matches"]:
            reasons.add("match_bound")
        finished = time.monotonic_ns()
        stats_after = _statistics(sock)
        if stats_after is None:
            reasons.add("stats_unavailable")
        elif stats_after["drops"]:
            reasons.add("kernel_drops")
        _role()
        _need(_identity() == identity, "runtime identity changed")
        sock.close()
        sock = None
        report = dict(
            schema_version="edge-protected-ingress-report/v1",
            contract_sha256=expected_contract_sha256,
            plan_sha256=expected_plan_sha256,
            **identity,
            interface="lo",
            capture_id=contract["channels"]["protected_escape"]["capture_id"],
            observation_layer="interface_ingress",
            started_ns=started,
            finished_ns=finished,
            frames_seen=frames,
            matches=matches,
            partial_reasons=sorted(reasons),
            stats_before=stats_before,
            stats_after=stats_after,
        )
        report["signature"] = sign(observer_private_key, DOMAIN, report)
        return _json(report) + b"\n"
    except Exception as exc:
        raise SafetyIngressError(str(exc)) from exc
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception as exc:
                raise SafetyIngressError("capture socket close failed") from exc


def evaluate_ingress_capture(
    contract_raw,
    plan_raw,
    report_raw,
    *,
    expected_contract_sha256,
    expected_plan_sha256,
):
    """Authenticate ingress assertions without interpreting them as delivery facts."""
    try:
        contract, plan, opportunity, target, payload = _inputs(
            contract_raw, plan_raw, expected_contract_sha256, expected_plan_sha256
        )
        report = safety._wire(report_raw, 32 * 1024)
        safety._fields(
            report,
            "schema_version contract_sha256 plan_sha256 kernel_boot_id namespace interface ifindex capture_id observation_layer started_ns finished_ns frames_seen matches partial_reasons stats_before stats_after signature",
        )
        _need(
            report["schema_version"] == "edge-protected-ingress-report/v1"
            and report["contract_sha256"] == expected_contract_sha256
            and report["plan_sha256"] == expected_plan_sha256
            and report["kernel_boot_id"] == contract["scope"]["kernel_boot_id"]
            and report["interface"] == "lo"
            and report["observation_layer"] == "interface_ingress"
            and report["capture_id"]
            == contract["channels"]["protected_escape"]["capture_id"],
            "report binding differs",
        )
        safety._fields(report["namespace"], "device inode")
        for value in report["namespace"].values():
            safety._int(value, 1)
        _need(
            report["namespace"]
            == dict(device=target["namespace_device"], inode=target["namespace_inode"]),
            "report namespace differs",
        )
        safety._int(report["ifindex"], 1, 2**31 - 1)
        safety._int(report["started_ns"])
        safety._int(report["finished_ns"])
        started, finished = report["started_ns"], report["finished_ns"]
        _need(
            opportunity["start_ns"] <= started < opportunity["end_ns"]
            and finished >= started,
            "report capture window differs",
        )
        deadline = min(started + plan["max_duration_ns"], opportunity["end_ns"])
        safety._int(report["frames_seen"], 0, plan["max_packets"])
        _need(
            type(report["matches"]) is list
            and len(report["matches"])
            <= min(plan["max_matches"], report["frames_seen"]),
            "match bound",
        )
        previous = started
        for match in report["matches"]:
            safety._fields(match, "frame_sha256 observed_before_ns observed_after_ns")
            safety._hex(match["frame_sha256"])
            safety._int(match["observed_before_ns"])
            safety._int(match["observed_after_ns"])
            _need(
                previous
                <= match["observed_before_ns"]
                <= match["observed_after_ns"]
                <= min(deadline, finished),
                "late/reversed match",
            )
            previous = match["observed_after_ns"]
        _need(
            type(report["partial_reasons"]) is list
            and all(type(r) is str and r in REASONS for r in report["partial_reasons"])
            and len(set(report["partial_reasons"])) == len(report["partial_reasons"]),
            "partial reasons",
        )
        for key in ("stats_before", "stats_after"):
            stats = report[key]
            if stats is not None:
                safety._fields(stats, "packets drops")
                for value in stats.values():
                    safety._int(value, 0, 2**32 - 1)
        verify_signature(
            contract["keypins"]["observer_public_key"],
            report["signature"],
            DOMAIN,
            {k: v for k, v in report.items() if k != "signature"},
        )
        empty = dict(
            schema_version="edge-finite-safety-observations/v1",
            contract_sha256=expected_contract_sha256,
            scope=contract["scope"],
            channels={},
        )
        evaluation = safety.evaluate_safety_observations(
            contract_raw,
            _json(empty) + b"\n",
            expected_contract_sha256=expected_contract_sha256,
            expected_stream_heads=dict.fromkeys(safety.CATEGORIES),
            **contract["keypins"],
        )
        return dict(
            schema_version="edge-protected-ingress-evaluation/v1",
            status="unqualified_ingress_diagnostic",
            observation_layer="interface_ingress",
            interface_ingress_observed_count=1 if report["matches"] else None,
            qualified_safety_count=None,
            independently_measured=False,
            safety_evaluation=evaluation,
        )
    except Exception as exc:
        raise SafetyIngressError(str(exc)) from exc


def collect_protected_ingress(
    enrollment_path,
    plan_path,
    report_path,
    *,
    expected_enrollment_sha256,
    expected_checkpoint_sha256,
    expected_plan_sha256,
    expected_report_sha256,
):
    """Join six sealed Root artifacts; no ingress observation becomes delivery."""
    held = collection._HeldFiles()
    failure = None
    result = None
    try:
        reader_uid = os.geteuid()
        _need(
            type(reader_uid) is int and reader_uid > 0,
            "nonroot artifact reader required",
        )
        reader_boot = collection._kernel_boot_id()
        for value in (
            expected_enrollment_sha256,
            expected_checkpoint_sha256,
            expected_plan_sha256,
            expected_report_sha256,
        ):
            safety._hex(value)
        enrollment_path = collection._physical_path(enrollment_path)[0]
        enrollment_raw = held.read(enrollment_path, 32 * 1024)
        _need(
            _digest(enrollment_raw) == expected_enrollment_sha256,
            "enrollment digest differs",
        )
        enrollment = safety._wire(enrollment_raw, 32 * 1024)
        safety._fields(
            enrollment, "schema_version contract_sha256 scope observer_uid paths"
        )
        safety._fields(enrollment["paths"], "contract observations checkpoint")
        paths = {
            key: collection._physical_path(value)[0]
            for key, value in enrollment["paths"].items()
        }
        plan_path = collection._physical_path(plan_path)[0]
        report_path = collection._physical_path(report_path)[0]
        _need(
            len(set([enrollment_path, *paths.values(), plan_path, report_path])) == 6,
            "six distinct paths required",
        )
        contract_raw = held.read(paths["contract"], 128 * 1024)
        observations_raw = held.read(paths["observations"], 2 * 1024 * 1024)
        checkpoint_raw = held.read(paths["checkpoint"], 32 * 1024)
        plan_raw = held.read(plan_path, 16 * 1024)
        report_raw = held.read(report_path, 32 * 1024)
        _need(
            _digest(plan_raw) == expected_plan_sha256
            and _digest(report_raw) == expected_report_sha256
            and _digest(checkpoint_raw) == expected_checkpoint_sha256,
            "external artifact digest differs",
        )
        observations = safety._wire(observations_raw, 2 * 1024 * 1024)
        checkpoint = safety._wire(checkpoint_raw, 32 * 1024)
        _need(
            observations.get("channels") == {}
            and type(checkpoint.get("stream_heads")) is dict
            and set(checkpoint["stream_heads"]) == set(safety.CATEGORIES)
            and all(h is None for h in checkpoint["stream_heads"].values()),
            "delivery inputs must be empty",
        )
        collected = collection.collect_registered_safety(
            enrollment_path,
            expected_enrollment_sha256=expected_enrollment_sha256,
            expected_checkpoint_sha256=expected_checkpoint_sha256,
        )
        _need(
            collected["provenance"]["contract_sha256"] == enrollment["contract_sha256"],
            "joined contract differs",
        )
        _need(
            collected["provenance"]["observer_uid"] == reader_uid
            and collected["provenance"]["kernel_boot_id"] == reader_boot,
            "registered reader context differs",
        )
        held.verify()
        ingress = evaluate_ingress_capture(
            contract_raw,
            plan_raw,
            report_raw,
            expected_contract_sha256=enrollment["contract_sha256"],
            expected_plan_sha256=expected_plan_sha256,
        )
        _need(
            os.geteuid() == reader_uid and collection._kernel_boot_id() == reader_boot,
            "reader UID or boot changed during join",
        )
        held.verify()
        result = dict(
            schema_version="edge-protected-ingress-collection/v1",
            status="unqualified_ingress_collection",
            collection=collected,
            ingress=ingress,
        )
    except BaseException as exc:
        failure = exc
    finally:
        close_errors = held.close()
    if failure is not None or close_errors:
        raise SafetyIngressError(
            "sealed ingress join failed"
            + (f": {failure}" if failure is not None else "")
            + ("; FD close failure" if close_errors else "")
        ) from failure
    return result
