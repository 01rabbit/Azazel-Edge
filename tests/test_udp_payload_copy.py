"""SYNTHETIC provider facts; actual parser/signature and evaluation only."""

from contextlib import contextmanager
from copy import deepcopy
import json
from types import SimpleNamespace
import pytest
from azazel_edge.benchmark import udp_payload_copy as q
from azazel_edge.benchmark import udp_queue as old
from azazel_edge.outcome.input_auth import sign
from udp_payload_copy_data import (
    make_inputs,
    KEY,
    BOOT,
    PAYLOAD,
    TARGET,
    PIDNS,
    TIMENS,
    DOMAIN,
)
from safety_observation_data import digest, wire

OBJECT = b"SYNTHETIC not an ELF or actual kernel fact"


def fixture(monkeypatch, positive=True):
    contract, plan, pins = make_inputs(
        4,
        42,
        BOOT,
        40001,
        18080,
        2_000_000_000,
        4_000_000_000,
        PAYLOAD,
        TARGET,
        "synthetic-kernel",
        "b" * 64,
        digest(OBJECT),
    )
    monkeypatch.setattr(q, "time", SimpleNamespace(monotonic_ns=lambda: 3_000_000_000))
    monkeypatch.setattr(q, "_role", lambda: None)
    env = dict(
        kernel_boot_id=BOOT,
        namespace=dict(device=4, inode=42),
        kernel_release="synthetic-kernel",
        btf_sha256="b" * 64,
        receiver_pid_namespace=PIDNS,
        observer_time_namespace=TIMENS,
    )
    monkeypatch.setattr(q, "_environment", lambda c, p: deepcopy(env))

    @contextmanager
    def obj(path, sha):
        assert sha == digest(OBJECT)
        yield OBJECT

    monkeypatch.setattr(q, "_read_object", obj)
    event = dict(
        entered_ns=3_000_000_100,
        consumed_ns=3_000_000_150,
        exited_ns=3_000_000_200,
        socket_inode=TARGET["socket_inode"],
        socket_cookie=TARGET["socket_cookie"],
        netns_cookie=TARGET["netns_cookie"],
        netns_inode=42,
        receiver_start_boottime_ns=100_000_000,
        socket_uid=TARGET["uid"],
        receiver_real_uid=TARGET["uid"],
        receiver_effective_uid=TARGET["uid"],
        receiver_tgid=900,
        receiver_tid=901,
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=40001,
        dst_port=18080,
        payload_hex=PAYLOAD.hex(),
    )
    facts = dict(
        started_ns=3_000_000_000,
        finished_ns=4_000_000_000,
        events=[event] if positive else [],
        counters=dict(
            entry_matches=1,
            consume_matches=1,
            accepted=1,
            rejected=0,
            correlation_loss=0,
            overflow=0,
        ),
        partial_reasons=["timeout"],
    )
    configurations = []

    def provider(config, raw):
        assert raw == OBJECT
        configurations.append(config)
        return deepcopy(facts)

    monkeypatch.setattr(q.provider, "_capture_events", provider)
    return contract, plan, pins, facts, env, configurations


def capture(c, p, pins):
    return q.capture_udp_payload_copy(
        c, p, object_path="/synthetic/object", observer_private_key=KEY, **pins
    )


def signed(report):
    body = {k: v for k, v in report.items() if k != "signature"}
    report["signature"] = sign(KEY, DOMAIN, body)
    return wire(report)


def test_positive_is_socket_copy_never_application_or_successful_syscall(monkeypatch):
    c, p, pins, facts, env, configs = fixture(monkeypatch)
    raw = capture(c, p, pins)
    report = json.loads(raw)
    result = q.evaluate_udp_payload_copy(c, p, raw, **pins)
    assert result["protocol_payload_copy_observed_count"] == 1
    for k in (
        "successful_syscall_count",
        "application_delivery_count",
        "qualified_safety_count",
    ):
        assert result[k] is None
    assert result["independently_measured"] is False
    assert all(
        v["observed_violation_count"] is None
        for v in result["safety_evaluation"]["categories"].values()
    )
    assert not any(result["safety_evaluation"]["authority_flags"].values())
    assert (
        report["events"][0]["receiver_tgid"] != TARGET["pid"]
    )  # actual receiver, locator data only
    assert configs[0]["pidns_device"] == PIDNS["device"]
    assert configs[0]["pidns_inode"] == PIDNS["inode"]
    assert "pid" not in configs[0] and "start_ticks" not in configs[0]
    with pytest.raises(old.UDPQueueError):
        old.evaluate_udp_queue(c, p, raw, **pins)


@pytest.mark.parametrize("positive", [False, True])
@pytest.mark.parametrize(
    "reason",
    [
        "timeout",
        "correlation_loss",
        "event_overflow",
        "observer_link_lost",
        "event_bound",
    ],
)
def test_partial_positive_preserved_missing_never_zero(monkeypatch, positive, reason):
    c, p, pins, facts, *_ = fixture(monkeypatch, positive)
    facts["partial_reasons"] = [reason]
    if reason == "correlation_loss":
        facts["counters"]["correlation_loss"] = 1
    if reason == "event_overflow":
        facts["counters"]["overflow"] = 1
    raw = capture(c, p, pins)
    assert q.evaluate_udp_payload_copy(c, p, raw, **pins)[
        "protocol_payload_copy_observed_count"
    ] == (1 if positive else None)


@pytest.mark.parametrize(
    "field,value",
    [
        ("entered_ns", True),
        ("consumed_ns", 3_000_000_050),
        ("exited_ns", 4_000_000_001),
        ("socket_inode", 42043),
        ("socket_cookie", 72),
        ("netns_cookie", 82),
        ("netns_inode", 43),
        ("socket_uid", 61004),
        ("receiver_real_uid", 61004),
        ("receiver_effective_uid", 61004),
        ("receiver_tgid", 0),
        ("receiver_tid", 0),
        ("receiver_start_boottime_ns", 0),
        ("src_ip", "127.0.0.2"),
        ("dst_ip", "127.0.0.2"),
        ("src_port", 40002),
        ("dst_port", 18081),
        ("payload_hex", "00" * 64),
    ],
)
def test_resigned_wrong_event_binding_rejected(monkeypatch, field, value):
    c, p, pins, *_ = fixture(monkeypatch)
    report = json.loads(capture(c, p, pins))
    report["events"][0][field] = value
    with pytest.raises(q.UDPPayloadCopyError):
        q.evaluate_udp_payload_copy(c, p, signed(report), **pins)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "edge-udp-queue-report/v1"),
        ("observation_layer", "udp_socket_queue_admission"),
        ("kernel_boot_id", "00000000-0000-4000-8000-000000000002"),
        ("object_sha256", "f" * 64),
        ("btf_sha256", "e" * 64),
        ("kernel_release", "other"),
        ("plan_sha256", "d" * 64),
        ("capture_id", "other"),
        ("namespace", dict(device=4, inode=True)),
        ("receiver_pid_namespace", dict(device=4, inode=True)),
        (
            "observer_time_namespace",
            dict(device=4, inode=52, monotonic_offset_ns=1, boottime_offset_ns=0),
        ),
        ("partial_reasons", ["unrecognized"]),
    ],
)
def test_resigned_report_context_and_types_rejected(monkeypatch, field, value):
    c, p, pins, *_ = fixture(monkeypatch)
    report = json.loads(capture(c, p, pins))
    report[field] = value
    with pytest.raises(q.UDPPayloadCopyError):
        q.evaluate_udp_payload_copy(c, p, signed(report), **pins)


@pytest.mark.parametrize(
    "case", ["signature", "domain", "duplicate", "oversized", "missing"]
)
def test_wire_and_crypto_fail_closed(monkeypatch, case):
    c, p, pins, *_ = fixture(monkeypatch)
    raw = capture(c, p, pins)
    if case == "signature":
        r = json.loads(raw)
        r["signature"] = "0" * 128
        raw = wire(r)
    elif case == "domain":
        r = json.loads(raw)
        body = {k: v for k, v in r.items() if k != "signature"}
        r["signature"] = sign(KEY, old.DOMAIN, body)
        raw = wire(r)
    elif case == "duplicate":
        raw = b'{"schema_version":1,"schema_version":2}\n'
    elif case == "oversized":
        raw = b" " * 65537
    else:
        raw = b""
    with pytest.raises(q.UDPPayloadCopyError):
        q.evaluate_udp_payload_copy(c, p, raw, **pins)


def test_post_capture_environment_drift_refuses_publication(monkeypatch):
    c, p, pins, *_ = fixture(monkeypatch)
    base = q._environment
    calls = []

    def drift(c, p):
        env = base(c, p)
        calls.append(1)
        if len(calls) > 1:
            env["receiver_pid_namespace"]["inode"] += 1
        return env

    monkeypatch.setattr(q, "_environment", drift)
    with pytest.raises(q.UDPPayloadCopyError):
        capture(c, p, pins)


def test_locator_never_read_and_reference_still_binds_it(monkeypatch):
    c, p, pins, *_ = fixture(monkeypatch)

    def forbidden(*args):
        raise AssertionError("locator must never be opened")

    monkeypatch.setattr(old, "_target_alive", forbidden)
    raw = capture(c, p, pins)
    assert (
        q.evaluate_udp_payload_copy(c, p, raw, **pins)[
            "protocol_payload_copy_observed_count"
        ]
        == 1
    )
    changed = json.loads(p)
    changed["locator"]["pid"] += 1
    p = wire(changed)
    pins["expected_plan_sha256"] = digest(p)
    with pytest.raises(q.UDPPayloadCopyError):
        capture(c, p, pins)


@pytest.mark.parametrize(
    "path,value",
    [
        (("observer_time_namespace", "monotonic_offset_ns"), 1),
        (("observer_time_namespace", "boottime_offset_ns"), -1),
        (("receiver_pid_namespace", "inode"), True),
        (("socket_identity", "uid"), True),
        (("socket_identity", "cookie"), 0),
        (("locator", "pid"), False),
        (("max_events",), 17),
        (("max_duration_ns",), 5_000_000_001),
        (("challenge_payload_hex",), "00"),
        (("observation_layer",), "udp_socket_queue_admission"),
        (("schema_version",), "edge-udp-queue-plan/v1"),
    ],
)
def test_plan_profile_rejected_even_when_reference_repinned(monkeypatch, path, value):
    from azazel_edge.outcome.journal import _json

    c, p, pins, *_ = fixture(monkeypatch)
    c, p = json.loads(c), json.loads(p)
    node = p
    for k in path[:-1]:
        node = node[k]
    node[path[-1]] = value
    # Recompute enrollment reference to exercise semantic checks, not just digest mismatch.
    ref = {
        k: p[k]
        for k in (
            "observation_layer",
            "socket_identity",
            "locator",
            "receiver_pid_namespace",
            "observer_time_namespace",
        )
    }
    op = c["opportunities"]["protected_escape"][0]
    ref["protected_tuple"] = op["predicate"]["protected_tuple"]
    op["reference_sha256"] = digest(_json(ref))
    c = wire(c)
    p["contract_sha256"] = digest(c)
    p = wire(p)
    pins = dict(expected_contract_sha256=digest(c), expected_plan_sha256=digest(p))
    with pytest.raises(q.UDPPayloadCopyError):
        capture(c, p, pins)


@pytest.mark.parametrize(
    "field",
    [
        "accepted",
        "entry_matches",
        "consume_matches",
        "rejected",
        "correlation_loss",
        "overflow",
    ],
)
def test_counter_bool_not_integer(monkeypatch, field):
    c, p, pins, *_ = fixture(monkeypatch)
    report = json.loads(capture(c, p, pins))
    report["counters"][field] = True
    with pytest.raises(q.UDPPayloadCopyError):
        q.evaluate_udp_payload_copy(c, p, signed(report), **pins)


@pytest.mark.parametrize(
    "offsets",
    [
        b"monotonic 1 0\nboottime 0 0\n",
        b"monotonic 0 1\nboottime 0 0\n",
        b"monotonic 0 0\nboottime -1 0\n",
        b"monotonic 0 0\n",
        b"monotonic 0 0\nmonotonic 0 0\nboottime 0 0\n",
        b"monotonic 0 0\nboottime 0 0\nunknown 0 0\n",
        b"monotonic 0.0 0\nboottime 0 0\n",
    ],
)
def test_actual_environment_parser_nonzero_incomplete_offsets_refused(
    monkeypatch, offsets
):
    # SYNTHETIC proc bytes exercise real environment gate, not real namespace changes.
    monkeypatch.setattr(q.queue, "_environment", lambda c, p: dict(kernel_boot_id=BOOT))
    monkeypatch.setattr(
        q.os,
        "stat",
        lambda p: SimpleNamespace(st_dev=4, st_ino=51 if p.endswith("/pid") else 52),
    )
    monkeypatch.setattr(q.ingress, "_proc_bytes", lambda p, bound: offsets)
    with pytest.raises(q.UDPPayloadCopyError):
        q._environment(
            {}, dict(receiver_pid_namespace=PIDNS, observer_time_namespace=TIMENS)
        )


def test_environment_opens_only_self_pid_time_namespace(monkeypatch):
    paths = []

    def stat(path):
        paths.append(path)
        assert path in ("/proc/self/ns/pid", "/proc/self/ns/time")
        return SimpleNamespace(st_dev=4, st_ino=51 if path.endswith("/pid") else 52)

    monkeypatch.setattr(q.queue, "_environment", lambda c, p: dict(kernel_boot_id=BOOT))
    monkeypatch.setattr(q.os, "stat", stat)

    def proc(path, bound):
        assert path == "/proc/self/timens_offsets"
        return b"monotonic 0 0\nboottime 0 0\n"

    monkeypatch.setattr(q.ingress, "_proc_bytes", proc)
    assert (
        q._environment(
            {}, dict(receiver_pid_namespace=PIDNS, observer_time_namespace=TIMENS)
        )["kernel_boot_id"]
        == BOOT
    )
    assert len(paths) == 2
