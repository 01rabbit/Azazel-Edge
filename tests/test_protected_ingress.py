"""SYNTHETIC packet/clock/role/netns runtime; real parser/signature/evaluator.

No actual socket capture, sender UID, delivery, independent sensor or safety proof.
"""

from copy import deepcopy
import json
from pathlib import Path
import socket
import struct

import pytest
from azazel_edge.benchmark import protected_ingress as p
from azazel_edge.outcome.input_auth import verify_signature
from azazel_edge.outcome.journal import _json
from protected_ingress_data import KEY, BOOT, PAYLOAD, make_inputs, ethernet_udp
from safety_observation_data import digest, wire

CASE_ROWS = json.loads(
    (Path(__file__).parent / "fixtures/protected-ingress/v1/cases.json").read_bytes()
)["cases"]
LINUX_CASES = {"sealed-positive-artifact-join"}
UNIT_CASES = [row for row in CASE_ROWS if row["id"] not in LINUX_CASES]
DOMAIN = b"azazel-edge:protected-interface-ingress:v1\x00"
ADDRESS = ("lo", 0x0800, 0, 772, b"\0" * 6)


def frame_for(case):
    frame, address, flags = bytearray(ethernet_udp()), ADDRESS, 0
    if case == "malformed-ipv4":
        frame[14] = 0x46
    elif case == "vlan-unsupported":
        frame[12:14] = b"\x81\x00"
    elif case == "ipv6-unsupported":
        frame[12:14] = b"\x86\xdd"
    elif case == "fragmented-ipv4":
        frame[20:22] = struct.pack("!H", 0x2000)
    elif case == "truncated-frame":
        frame = frame[:20]
        flags = socket.MSG_TRUNC
    elif case == "malformed-udp-length":
        frame[38:40] = struct.pack("!H", 999)
    elif case == "wrong-protected-tuple":
        frame = bytearray(ethernet_udp(source_port=40002))
    elif case in ("wrong-challenge-payload", "packet-bound-exhausted"):
        frame[-1] ^= 1
    elif case == "outgoing-not-ingress":
        address = ("lo", 0x0800, 4, 772, b"\0" * 6)
    return bytes(frame), address, flags


class Clock:
    def __init__(self, now):
        self.now = now

    def monotonic_ns(self):
        return self.now


class PassiveSocket:
    def __init__(self, clock, packets, drops=False):
        self.clock, self.packets, self.drops = clock, list(packets), drops
        self.timeout, self.closed, self.stats_calls = None, False, 0
        self.binds, self.timeouts = [], []

    def bind(self, address):
        self.binds.append(address)

    def getsockname(self):
        return ADDRESS

    def settimeout(self, value):
        self.timeout = value
        self.timeouts.append(value)
        assert 0 < value <= 1.0

    def getsockopt(self, level, option, length):
        self.stats_calls += 1
        return struct.pack(
            "II",
            1 if self.stats_calls > 1 else 0,
            1 if self.drops and self.stats_calls > 1 else 0,
        )

    def recvmsg(self, maximum):
        assert maximum <= 2048
        if not self.packets:
            self.clock.now += round(self.timeout * 1e9)
            raise TimeoutError("synthetic absolute timeout")
        frame, address, flags = self.packets.pop(0)
        self.clock.now += 1000
        return frame, [], flags, address

    def close(self):
        self.closed = True

    def __getattr__(self, name):
        if name in ("send", "sendto", "sendmsg", "connect", "setsockopt", "ioctl"):
            raise AssertionError("forbidden capture operation:" + name)
        raise AttributeError(name)


def runtime(monkeypatch, case):
    contract, plan, pins = make_inputs(
        4, 42, BOOT, 40001, 18080, 2_000_000_000, 4_000_000_000, PAYLOAD
    )
    clock = Clock(
        1_000_000_000
        if case == "before-window"
        else 5_000_000_000
        if case == "after-window"
        else 3_000_000_000
    )
    frame = frame_for(case)
    packets = (
        []
        if case in ("no-matching-packet", "absolute-deadline-no-extension")
        else [frame] * 4
        if case == "packet-bound-exhausted"
        else [frame]
    )
    capture = PassiveSocket(
        clock, packets, drops=case == "packet-loss-with-known-positive"
    )
    identities = []

    def identity():
        identities.append(1)
        return dict(
            kernel_boot_id="00000000-0000-4000-8000-000000000002"
            if case == "wrong-kernel-boot"
            else BOOT,
            namespace=dict(
                device=4, inode=43 if case == "wrong-network-namespace" else 42
            ),
            ifindex=1,
        )

    monkeypatch.setattr(
        p, "_role", lambda: None
    )  # Explicit SYNTHETIC root/cap/NNP facts.
    monkeypatch.setattr(
        p.socket, "AF_PACKET", 17, raising=False
    )  # Synthetic Linux constant on macOS.
    monkeypatch.setattr(
        p.socket, "SOCK_CLOEXEC", 0x80000, raising=False
    )  # Synthetic Linux constant.
    monkeypatch.setattr(p, "_identity", identity)
    monkeypatch.setattr(p.time, "monotonic_ns", clock.monotonic_ns)
    constructed = []

    def factory(*args, **kwargs):
        constructed.append(args)
        assert args[0] == socket.AF_PACKET and args[1] == (
            socket.SOCK_RAW | socket.SOCK_CLOEXEC
        )
        if case == "net-raw-permission-denied":
            raise PermissionError("synthetic NET_RAW absence")
        return capture

    monkeypatch.setattr(p.socket, "socket", factory)
    return contract, plan, pins, capture, clock, constructed


@pytest.mark.parametrize("expected", UNIT_CASES, ids=lambda row: row["id"])
def test_frozen_capture_cases_positive_ingress_never_delivery_or_safety(
    monkeypatch, expected
):
    contract, plan, pins, capture, clock, constructed = runtime(
        monkeypatch, expected["id"]
    )
    original = contract, plan, deepcopy(pins)
    if expected["expected"] == "rejected":
        with pytest.raises(p.SafetyIngressError):
            p.capture_protected_ingress(
                contract, plan, observer_private_key=KEY, **pins
            )
    else:
        raw = p.capture_protected_ingress(
            contract, plan, observer_private_key=KEY, **pins
        )
        report = json.loads(raw)
        assert raw == wire(report)
        verify_signature(
            json.loads(contract)["keypins"]["observer_public_key"],
            report["signature"],
            DOMAIN,
            {k: v for k, v in report.items() if k != "signature"},
        )
        assert capture.closed
        result = p.evaluate_ingress_capture(contract, plan, raw, **pins)
        assert result["status"] == expected["expected"]
        assert (
            result["interface_ingress_observed_count"]
            == expected["interface_ingress_observed_count"]
        )
        assert (
            result["qualified_safety_count"] is None
            and result["independently_measured"] is False
        )
        assert result["observation_layer"] == "interface_ingress"
        for category in result["safety_evaluation"]["categories"].values():
            assert category["observed_violation_count"] is None
            assert category["qualified_safety_count"] is None
        assert all(
            flag is False
            for flag in result["safety_evaluation"]["authority_flags"].values()
        )
        if expected["id"] == "packet-loss-with-known-positive":
            assert "kernel_drops" in report["partial_reasons"] and report["matches"]
        if expected["id"] == "absolute-deadline-no-extension":
            assert clock.now == 4_000_000_000 and not report["matches"]
    assert (contract, plan, pins) == original
    if constructed and expected["id"] != "net-raw-permission-denied":
        assert capture.closed


def test_frozen_case_mapping_and_machine_bound_challenge_reference():
    assert {row["id"] for row in UNIT_CASES} | LINUX_CASES == {
        row["id"] for row in CASE_ROWS
    }
    contract, plan, pins = make_inputs(
        4, 42, BOOT, 40001, 18080, 2_000_000_000, 4_000_000_000, PAYLOAD
    )
    parsed = json.loads(contract)
    opportunity = parsed["opportunities"]["protected_escape"][0]
    assert all(
        not value
        for category, value in parsed["opportunities"].items()
        if category != "protected_escape"
    )
    reference = dict(
        observation_layer="interface_ingress",
        interface="lo",
        protected_tuple=opportunity["predicate"]["protected_tuple"],
    )
    assert opportunity["reference_sha256"] == digest(_json(reference))
    assert opportunity["challenge_sha256"] == digest(PAYLOAD)
    assert pins == dict(
        expected_contract_sha256=digest(contract), expected_plan_sha256=digest(plan)
    )


@pytest.mark.parametrize(
    "fault",
    [
        "fragment-offset",
        "ip-version",
        "short-ethernet",
        "ip-total-length",
        "ip-udp-protocol",
        "address-kind",
        "hatype",
    ],
)
def test_parser_rejects_unsupported_or_inconsistent_bytes(fault):
    raw, address, flags = frame_for("exact-ipv4-udp-ingress")
    raw = bytearray(raw)
    if fault == "fragment-offset":
        raw[20:22] = struct.pack("!H", 1)
    elif fault == "ip-version":
        raw[14] = 0x65
    elif fault == "short-ethernet":
        raw = raw[:10]
    elif fault == "ip-total-length":
        raw[16:18] = struct.pack("!H", 1)
    elif fault == "ip-udp-protocol":
        raw[23] = 6
    elif fault == "address-kind":
        address = ("lo", 0x0800, 3, 772, b"\0" * 6)
    else:
        address = ("lo", 0x0800, 0, 999, b"\0" * 6)
    protected = json.loads(
        make_inputs(4, 42, BOOT, 40001, 18080, 2_000_000_000, 4_000_000_000, PAYLOAD)[0]
    )["opportunities"]["protected_escape"][0]["predicate"]["protected_tuple"]
    assert (
        p._packet_matches(bytes(raw), address, protected, PAYLOAD, flags=flags) is False
    )


@pytest.mark.parametrize(
    "fault",
    [
        "signature",
        "source-domain",
        "delivery-layer",
        "namespace",
        "boot",
        "plan-binding",
    ],
)
def test_layered_report_crypto_and_exact_bindings_cannot_be_promoted(
    monkeypatch, fault
):
    contract, plan, pins, _, _, _ = runtime(monkeypatch, "exact-ipv4-udp-ingress")
    report = json.loads(
        p.capture_protected_ingress(contract, plan, observer_private_key=KEY, **pins)
    )
    if fault == "signature":
        report["signature"] = ("0" if report["signature"][0] != "0" else "1") + report[
            "signature"
        ][1:]
    else:
        if fault == "delivery-layer":
            report["observation_layer"] = "delivery"
        elif fault == "namespace":
            report["namespace"]["inode"] += 1
        elif fault == "boot":
            report["kernel_boot_id"] = "00000000-0000-4000-8000-000000000002"
        elif fault == "plan-binding":
            report["plan_sha256"] = "f" * 64
        body = {key: value for key, value in report.items() if key != "signature"}
        report["signature"] = KEY.sign(
            (
                b"azazel-edge:input-capture:v1\x00"
                if fault == "source-domain"
                else DOMAIN
            )
            + _json(body)
        ).hex()
    with pytest.raises(p.SafetyIngressError):
        p.evaluate_ingress_capture(contract, plan, wire(report), **pins)


@pytest.mark.parametrize(
    "fault", ["stats-unavailable", "receive-error", "truncated-after-positive"]
)
def test_admissible_positive_survives_later_loss_or_capture_failure(monkeypatch, fault):
    contract, plan, pins, capture, _, _ = runtime(monkeypatch, "exact-ipv4-udp-ingress")
    value = json.loads(plan)
    value["max_matches"] = 2
    plan = wire(value)
    pins["expected_plan_sha256"] = digest(plan)
    original_receive = capture.recvmsg
    if fault == "stats-unavailable":
        original_stats = capture.getsockopt

        def statistics(*args):
            if capture.stats_calls:
                raise OSError("synthetic final stats unavailable")
            return original_stats(*args)

        monkeypatch.setattr(capture, "getsockopt", statistics)
    elif fault == "receive-error":

        def receive(maximum):
            if not capture.packets:
                raise OSError("synthetic receive failure")
            return original_receive(maximum)

        monkeypatch.setattr(capture, "recvmsg", receive)
    else:
        capture.packets.append((b"truncated", ADDRESS, socket.MSG_TRUNC))
    raw = p.capture_protected_ingress(contract, plan, observer_private_key=KEY, **pins)
    report = json.loads(raw)
    expected = {
        "stats-unavailable": "stats_unavailable",
        "receive-error": "receive_error",
        "truncated-after-positive": "packet_truncated",
    }[fault]
    assert (
        expected in report["partial_reasons"]
        and len(report["matches"]) == 1
        and capture.closed
    )
    result = p.evaluate_ingress_capture(contract, plan, raw, **pins)
    assert result["interface_ingress_observed_count"] == 1
    assert all(
        row["observed_violation_count"] is None
        for row in result["safety_evaluation"]["categories"].values()
    )
