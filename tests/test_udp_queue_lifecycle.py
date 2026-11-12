"""SYNTHETIC provider faults and kernel metadata; no signal/BPF execution proof.

Actual SIGKILL/SIGSTOP/FD-loss/target-restart controls belong to Linux tests.
"""

import json
from pathlib import Path

import pytest
from azazel_edge.benchmark import udp_queue as q
from azazel_edge.outcome.journal import _json
from safety_observation_data import digest, wire
from test_udp_queue import fixture, capture
from udp_queue_data import KEY

CASES = json.loads(
    (Path(__file__).parent / "fixtures/udp-queue-lifecycle/v1/cases.json").read_bytes()
)["cases"]


@pytest.mark.parametrize("positive", [False, True])
def test_signed_link_loss_is_partial_lower_bound_or_unknown_never_zero(
    monkeypatch, positive
):
    contract, plan, pins, _, _ = fixture(
        monkeypatch, "exact-queue-admission" if positive else "empty-queue-unknown"
    )
    original = q.provider._capture_events

    def lost(*args):
        result = original(*args)
        result["partial_reasons"].append("observer_link_lost")
        return result

    monkeypatch.setattr(q.provider, "_capture_events", lost)
    raw = capture(contract, plan, pins)
    report = json.loads(raw)
    assert "observer_link_lost" in report["partial_reasons"]
    result = q.evaluate_udp_queue(contract, plan, raw, **pins)
    assert result["queue_admission_observed_count"] == (1 if positive else None)
    assert (
        result["application_delivery_count"] is result["qualified_safety_count"] is None
    )
    assert all(
        row["observed_violation_count"] is None
        for row in result["safety_evaluation"]["categories"].values()
    )


@pytest.mark.parametrize(
    "later_fault", ["observer-death", "link-loss", "target-restart"]
)
def test_published_report_bytes_remain_historical_not_fresh_or_reconstructed(
    monkeypatch, later_fault
):
    contract, plan, pins, _, configurations = fixture(
        monkeypatch, "exact-queue-admission"
    )
    raw = capture(contract, plan, pins)
    original_raw, original_sha = raw, digest(raw)

    def unavailable(*a, **kw):
        raise AssertionError("historical read must never recapture:" + later_fault)

    monkeypatch.setattr(q.provider, "_capture_events", unavailable)
    first = q.evaluate_udp_queue(contract, plan, raw, **pins)
    second = q.evaluate_udp_queue(contract, plan, raw, **pins)
    assert first == second and first["queue_admission_observed_count"] == 1
    assert raw == original_raw and digest(raw) == original_sha
    assert len(configurations) == 1
    assert (
        first["qualified_safety_count"] is first["application_delivery_count"] is None
    )


def test_provider_interruption_before_return_has_no_signed_replacement(monkeypatch):
    contract, plan, pins, _, _ = fixture(monkeypatch, "exact-queue-admission")
    calls = []

    def interrupted(*args):
        calls.append(1)
        raise RuntimeError("SYNTHETIC prepublication interruption")

    monkeypatch.setattr(q.provider, "_capture_events", interrupted)
    with pytest.raises(q.UDPQueueError):
        capture(contract, plan, pins)
    assert len(calls) == 1  # No retry, fallback or synthetic report filler.


def test_expired_plan_refuses_new_capture_while_old_bytes_stay_readable(monkeypatch):
    contract, plan, pins, _, configurations = fixture(
        monkeypatch, "exact-queue-admission"
    )
    raw = capture(contract, plan, pins)
    old_hash = digest(raw)
    monkeypatch.setattr(
        q,
        "time",
        type("Expired", (), {"monotonic_ns": staticmethod(lambda: 5_000_000_000)})(),
    )
    with pytest.raises(q.UDPQueueError):
        capture(contract, plan, pins)
    assert len(configurations) == 1
    assert (
        q.evaluate_udp_queue(contract, plan, raw, **pins)[
            "queue_admission_observed_count"
        ]
        == 1
    )
    assert digest(raw) == old_hash


def test_explicit_fresh_context_requires_new_binding_hashes_not_relabelled_old_report(
    monkeypatch,
):
    contract, plan, pins, _, _ = fixture(monkeypatch, "exact-queue-admission")
    old = capture(contract, plan, pins)
    value = json.loads(contract)
    new_plan = json.loads(plan)
    value["scope"]["run_id"] += "-fresh"
    value["scope"]["scope_ref"] += "-fresh"
    value["scope"]["session_ref"] = "fedcba9876543210fedcba9876543210"
    for channel in value["channels"].values():
        channel["capture_id"] += "-fresh"
    opportunity = value["opportunities"]["protected_escape"][0]
    opportunity["id"] += "-fresh"
    value["scope"]["interval"] = dict(start_ns=6_000_000_000, end_ns=8_000_000_000)
    opportunity.update(start_ns=6_000_000_000, end_ns=8_000_000_000)
    payload = bytes([99]) * 64
    opportunity["challenge_sha256"] = digest(payload)
    fresh_contract = wire(value)
    new_plan.update(
        contract_sha256=digest(fresh_contract),
        opportunity_id=opportunity["id"],
        challenge_payload_hex=payload.hex(),
    )
    fresh_plan = wire(new_plan)
    fresh_pins = dict(
        expected_contract_sha256=digest(fresh_contract),
        expected_plan_sha256=digest(fresh_plan),
    )
    assert fresh_pins != pins
    with pytest.raises(q.UDPQueueError):
        q.evaluate_udp_queue(fresh_contract, fresh_plan, old, **fresh_pins)
    assert (
        q.evaluate_udp_queue(contract, plan, old, **pins)[
            "queue_admission_observed_count"
        ]
        == 1
    )
    # No claim that an unexpired manual call is durably one-use: no such registry exists.


def test_unknown_new_partial_reason_remains_fatal(monkeypatch):
    contract, plan, pins, _, _ = fixture(monkeypatch, "exact-queue-admission")
    report = json.loads(capture(contract, plan, pins))
    report["partial_reasons"].append("invented-recovery-success")
    body = {k: v for k, v in report.items() if k != "signature"}
    report["signature"] = KEY.sign(
        b"azazel-edge:udp-socket-queue-admission:v1\x00" + _json(body)
    ).hex()
    with pytest.raises(q.UDPQueueError):
        q.evaluate_udp_queue(contract, plan, wire(report), **pins)


def test_frozen_lifecycle_case_ids_are_not_rewritten_or_synthetic_signal_claims():
    assert len(CASES) == 12 and len({row["id"] for row in CASES}) == 12
    assert all(
        row["automatic_reattach"] is False
        and row["missing_interval_count"] is None
        and row["application_delivery_count"] is None
        and row["qualified_safety_count"] is None
        for row in CASES
    )


@pytest.mark.parametrize(
    "state",
    [
        "retained",
        "missing",
        "missing-ebadfd77",
        "foreign",
        "einval-live-tracing",
        "einval-malformed",
        "einval-unreadable",
        "changed",
        "same-id-target-change",
        "fdinfo-unknown",
        "proc-read-ebadfd77",
        "query-unknown",
    ],
)
def test_actual_health_parser_uses_cached_fd_and_kernel_before_fdinfo(
    monkeypatch, state
):
    """SYNTHETIC kernel UAPI bytes, actual ctypes/parser/health classification."""
    import ctypes as C
    import errno
    import struct

    b = q.provider
    calls = []
    current = {"state": "retained"}

    class Library:
        def bpf_link__fd(self, link):
            calls.append("link-fd-once")
            return 1200

        def bpf_program__fd(self, program):
            return 800

        def bpf_obj_get_info_by_fd(self, fd, raw, length):
            calls.append(("kernel-info", fd))
            if fd == 1200 and current["state"] in (
                "missing",
                "missing-ebadfd77",
                "foreign",
                "einval-live-tracing",
                "einval-malformed",
                "einval-unreadable",
                "query-unknown",
            ):
                C.set_errno(
                    {
                        "missing": errno.EBADF,
                        "missing-ebadfd77": 77,  # Actual Linux6.8 BPF closed-FD errno, absent on macOS errno module.
                        "foreign": errno.EINVAL,
                        "einval-live-tracing": errno.EINVAL,
                        "einval-malformed": errno.EINVAL,
                        "einval-unreadable": errno.EINVAL,
                        "query-unknown": errno.EPERM,
                    }[current["state"]]
                )
                return -1
            payload = (
                struct.pack(
                    "=7I",
                    2,
                    56 if current["state"] == "changed" else 55,
                    88,
                    0,
                    24,
                    2 if current["state"] == "same-id-target-change" else 1,
                    99,
                )
                if fd == 1200
                else struct.pack("=7I", 26, 88, 0, 0, 0, 0, 0)
            )
            C.memmove(raw, payload, len(payload))
            return 0

    backend = object.__new__(b._Libbpf)
    backend.lib = Library()

    def proc(path, maximum):
        assert calls[-1] == ("kernel-info", 1200)
        calls.append("proc-fdinfo")
        if current["state"] in ("fdinfo-unknown", "einval-unreadable"):
            raise PermissionError("synthetic proc refusal")
        if current["state"] == "proc-read-ebadfd77":
            raise OSError(
                77, "synthetic proc read failure AFTER successful kernel object query"
            )
        basic = "pos:\t0\nflags:\t0100000\nmnt_id:\t23\nino:\t5\n"
        if current["state"] == "foreign":
            return basic.encode()
        if current["state"] == "einval-malformed":
            return b"pos:\t0\nflags:\t0100000\nmnt_id:\t23\n"  # Missing ino cannot prove a foreign file.
        return (
            basic
            + "link_type:\ttracing\nlink_id:\t"
            + ("56" if current["state"] == "changed" else "55")
            + "\nprog_id:\t88\nattach_type:\t24\ntarget_obj_id:\t"
            + ("2" if current["state"] == "same-id-target-change" else "1")
            + "\ntarget_btf_id:\t99\n"
        ).encode()

    monkeypatch.setattr(b, "_proc_bytes", proc)
    identity = backend.link_identity(200, 20, 24)
    assert identity == dict(
        fd=1200,
        type=2,
        link_id=55,
        prog_id=88,
        attach_type=24,
        target_obj_id=1,
        target_btf_id=99,
    )
    current["state"] = state
    assert backend.check_link(identity) == (
        "retained"
        if state == "retained"
        else "lost"
        if state in ("missing", "missing-ebadfd77", "foreign", "changed")
        else "unknown"
    )
    assert calls.count("link-fd-once") == 1
    if state in ("missing", "missing-ebadfd77"):
        assert (
            calls.count("proc-fdinfo") == 1
        )  # Baseline only; failed query must not open/reuse the closed FD.


@pytest.mark.parametrize("state", ["lost", "unknown"])
def test_still_owned_pointer_disconnects_before_destroy_without_closing_foreign_fd(
    tmp_path, state
):
    """Real foreign FD preservation, SYNTHETIC libbpf pointer ownership only."""
    import os
    from types import SimpleNamespace

    b = q.provider
    path = tmp_path / "unrelated-owned-file"
    path.write_bytes(b"foreign bytes")
    fd = os.open(path, os.O_RDONLY)
    before = os.fstat(fd)
    events = []
    disconnected = []

    def disconnect(pointer):
        events.append(("disconnect", pointer))
        disconnected.append(pointer)

    def destroy(pointer):
        events.append(("destroy", pointer))
        if pointer not in disconnected:
            os.close(fd)
        return 0

    backend = SimpleNamespace(
        check_link=lambda identity: state,
        lib=SimpleNamespace(bpf_link__disconnect=disconnect, bpf_link__destroy=destroy),
    )
    try:
        if state == "unknown":
            with pytest.raises(b.UDPQueueBPFError, match="ownership unknown"):
                b._release_link(backend, 200, dict(fd=fd))
        else:
            assert b._release_link(backend, 200, dict(fd=fd)) == "lost"
        assert events == [("disconnect", 200), ("destroy", 200)]
        assert os.fstat(fd).st_ino == before.st_ino
        assert os.read(fd, 64) == b"foreign bytes"
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


@pytest.mark.parametrize("health", ["unknown", "lost"])
def test_health_loss_stops_without_retry_and_attempts_all_cleanup(monkeypatch, health):
    """Actual provider orchestration, SYNTHETIC backend; no native/kernel execution."""
    import ctypes as C
    import errno
    import socket
    import struct
    from types import SimpleNamespace
    from udp_queue_data import TARGET, PAYLOAD

    b = q.provider
    config = dict(
        socket_inode=TARGET["socket_inode"],
        socket_cookie=TARGET["socket_cookie"],
        netns_cookie=TARGET["netns_cookie"],
        netns_inode=42,
        socket_uid=TARGET["uid"],
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=40001,
        dst_port=18080,
        payload_hex=PAYLOAD.hex(),
        started_ns=3_000_000_000,
        deadline_ns=4_000_000_000,
        max_events=16,
    )
    events = []

    class Library:
        def bpf_object__open_mem(self, *a):
            return 100

        def bpf_object__load(self, *a):
            return 0

        def bpf_map__fd(self, value):
            return value

        def bpf_map_update_elem(self, *a):
            events.append("config-once")
            return 0

        def bpf_program__attach(self, program):
            events.append(("attach", program))
            return program * 10

        def bpf_link__disconnect(self, link):
            events.append(("disconnect", link))

        def bpf_link__destroy(self, link):
            events.append(("destroy", link))
            return 0

        def bpf_object__close(self, obj):
            events.append(("object-close", obj))

        def bpf_map_get_next_key(self, *args):
            C.set_errno(errno.ENOENT)
            return -1

    class Backend:
        lib = Library()

        def pointer(self, value, stage):
            return value

        def inspect(self, obj):
            return dict(config=10, pending=11, events=12, stats=13), dict(
                queue_entry=20, queue_exit=21
            )

        def link_identity(self, link, program, attach):
            return dict(
                fd=link + 1000,
                type=2,
                link_id=link,
                prog_id=program,
                attach_type=attach,
                target_obj_id=1,
                target_btf_id=99,
            )

        def check_link(self, identity):
            return health if identity["attach_type"] == 24 else "retained"

        def lookup(self, fd, key, value):
            events.append("map-read")
            if isinstance(value, b.Counters):
                value.entry_matches = value.accepted = 1
            else:
                for name in (
                    "socket_inode",
                    "socket_cookie",
                    "netns_cookie",
                    "netns_inode",
                    "socket_uid",
                    "src_port",
                    "dst_port",
                ):
                    setattr(value, name, config[name])
                value.entered_ns, value.exited_ns = 3_100_000_000, 3_200_000_000
                value.src_ip = value.dst_ip = struct.unpack(
                    "=I", socket.inet_aton("127.0.0.1")
                )[0]
                value.payload[:] = PAYLOAD
            return value

    monkeypatch.setattr(b, "_Libbpf", Backend)
    monkeypatch.setattr(b, "_role", lambda: None)
    monkeypatch.setattr(
        b,
        "time",
        SimpleNamespace(
            monotonic_ns=lambda: 3_500_000_000,
            sleep=lambda _: pytest.fail("lost identity must stop without retry"),
        ),
    )
    raw = bytearray(64)
    raw[:6] = b"\x7fELF\x02\x01"
    raw[18:20] = b"\xf7\x00"
    if health == "unknown":
        with pytest.raises(b.UDPQueueBPFError, match="ownership unknown"):
            b._capture_events(config, bytes(raw))
    else:
        result = b._capture_events(config, bytes(raw))
        assert result["partial_reasons"] == ["observer_link_lost"]
        assert len(result["events"]) == 1
        assert result["events"][0]["socket_cookie"] == TARGET["socket_cookie"]
    assert events.count("config-once") == 1
    assert [row for row in events if isinstance(row, tuple) and row[0] == "attach"] == [
        ("attach", 21),
        ("attach", 20),
    ]
    assert [
        row for row in events if isinstance(row, tuple) and row[0] == "destroy"
    ] == [("destroy", 200), ("destroy", 210)]
    assert events.count(("disconnect", 200)) == 1
    assert events.count(("object-close", 100)) == 1
    assert ("map-read" in events) == (health == "lost")
