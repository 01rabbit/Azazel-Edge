"""SYNTHETIC provider/host guards; real signed facade/evaluator, no kernel claim."""

from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark import udp_queue as q
from azazel_edge.outcome.input_auth import verify_signature
from azazel_edge.outcome.journal import _json
from udp_queue_data import KEY, BOOT, PAYLOAD, TARGET, make_inputs
from safety_observation_data import digest, wire

ROWS = json.loads(
    (Path(__file__).parent / "fixtures/udp-queue/v1/cases.json").read_bytes()
)["cases"]
LINUX_ONLY = {"sealed-real-report-join"}
CASES = [row for row in ROWS if row["id"] not in LINUX_ONLY]
DOMAIN = b"azazel-edge:udp-socket-queue-admission:v1\x00"
OBJECT = b"SYNTHETIC object bytes; no ELF/kernel claim"
BTF = "b" * 64
RELEASE = "synthetic-kernel-1"
POSITIVE = {
    "exact-queue-admission",
    "readonly-nonconsuming-control",
    "overflow-with-known-positive",
}


def fixture(monkeypatch, case):
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
        RELEASE,
        BTF,
        digest(OBJECT),
    )
    if case in ("wrong-object-pin", "wrong-btf-pin"):
        value = json.loads(plan)
        value["object_sha256" if case == "wrong-object-pin" else "btf_sha256"] = (
            "f" * 64
        )
        plan = wire(value)
        pins["expected_plan_sha256"] = digest(plan)
    events = []
    clock = SimpleNamespace(
        now=5_000_000_000 if case == "window-expired" else 3_000_000_000
    )
    monkeypatch.setattr(q, "time", SimpleNamespace(monotonic_ns=lambda: clock.now))

    def role():
        events.append("role")
        if case == "capability-denied":
            raise q.UDPQueueError("synthetic capability denial")

    monkeypatch.setattr(q, "_role", role)

    def environment(contract, plan):
        events.append("environment")
        if plan["btf_sha256"] != BTF:
            raise q.UDPQueueError("synthetic actual BTF mismatch")
        return dict(
            kernel_boot_id=BOOT,
            namespace=dict(
                device=4,
                inode=43
                if case == "namespace-drift" and events.count("environment") > 1
                else 42,
            ),
            kernel_release=RELEASE,
            btf_sha256=BTF,
        )

    monkeypatch.setattr(q, "_environment", environment)
    alive = []

    def target_alive(target):
        alive.append(1)
        assert target == TARGET
        return not (
            case in ("target-restart-cookie-change", "target-lifecycle-change")
            and len(alive) > 1
        )

    monkeypatch.setattr(q, "_target_alive", target_alive)

    @contextmanager
    def object_file(path, expected):
        assert path == "/synthetic/pinned-observer.bpf.o"
        if expected != digest(OBJECT):
            raise q.UDPQueueError("synthetic object digest mismatch")
        events.append("object-open")
        try:
            yield OBJECT
        finally:
            events.append("object-closed")

    monkeypatch.setattr(q, "_read_object", object_file)
    configurations = []

    def provider(configuration, object_raw):
        configurations.append(deepcopy(configuration))
        assert object_raw == OBJECT
        assert configuration["socket_inode"] == TARGET["socket_inode"]
        assert (
            configuration["socket_cookie"] == TARGET["socket_cookie"]
            and configuration["socket_uid"] == TARGET["uid"]
        )
        assert (
            configuration["netns_cookie"] == TARGET["netns_cookie"]
            and configuration["netns_inode"] == 42
        )
        assert configuration["src_ip"] == configuration["dst_ip"] == "127.0.0.1"
        assert configuration["src_port"] == 40001 and configuration["dst_port"] == 18080
        assert bytes.fromhex(configuration["payload_hex"]) == PAYLOAD
        assert (
            configuration["started_ns"] == 3_000_000_000
            and configuration["deadline_ns"] == 4_000_000_000
        )
        match = dict(
            entered_ns=3_000_000_100,
            exited_ns=3_000_000_200,
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
        )
        positive = case in POSITIVE or case == "report-tamper"
        lost = case in ("entry-collision", "unmatched-exit", "truncated-or-lost-event")
        counters = dict(
            entry_matches=1
            if positive or lost or case == "negative-enqueue-return"
            else 0,
            accepted=int(positive),
            rejected=int(case == "negative-enqueue-return"),
            correlation_loss=int(lost),
            overflow=int(case == "overflow-with-known-positive"),
        )
        reasons = (
            ["correlation_loss"]
            if lost
            else ["event_overflow"]
            if case == "overflow-with-known-positive"
            else ["timeout"]
        )
        return dict(
            started_ns=3_000_000_000,
            finished_ns=4_000_000_000,
            events=[match] if positive else [],
            counters=counters,
            partial_reasons=reasons,
        )

    monkeypatch.setattr(q.provider, "_capture_events", provider)
    return contract, plan, pins, events, configurations


def capture(contract, plan, pins):
    return q.capture_udp_queue(
        contract,
        plan,
        observer_private_key=KEY,
        object_path="/synthetic/pinned-observer.bpf.o",
        **pins,
    )


@pytest.mark.parametrize("expected", CASES, ids=lambda row: row["id"])
def test_frozen_cases_provider_is_synthetic_report_crypto_and_evaluation_are_real(
    monkeypatch, expected
):
    case = expected["id"]
    contract, plan, pins, events, configuration = fixture(monkeypatch, case)
    originals = contract, plan, deepcopy(pins)
    if expected["outcome"] == "rejected" and case != "report-tamper":
        with pytest.raises(q.UDPQueueError):
            capture(contract, plan, pins)
    else:
        raw = capture(contract, plan, pins)
        report = json.loads(raw)
        assert raw == wire(report)
        verify_signature(
            json.loads(contract)["keypins"]["observer_public_key"],
            report["signature"],
            DOMAIN,
            {key: value for key, value in report.items() if key != "signature"},
        )
        if case == "report-tamper":
            report["signature"] = (
                "0" if report["signature"][0] != "0" else "1"
            ) + report["signature"][1:]
            with pytest.raises(q.UDPQueueError):
                q.evaluate_udp_queue(contract, plan, wire(report), **pins)
        else:
            result = q.evaluate_udp_queue(contract, plan, raw, **pins)
            assert result["status"] == expected["outcome"]
            assert (
                result["queue_admission_observed_count"]
                == expected["queue_admission_observed_count"]
            )
            assert (
                result["application_delivery_count"]
                is result["qualified_safety_count"]
                is None
            )
            assert result["independently_measured"] is False
            assert all(
                category["observed_violation_count"] is None
                for category in result["safety_evaluation"]["categories"].values()
            )
            assert all(
                flag is False
                for flag in result["safety_evaluation"]["authority_flags"].values()
            )
            if case == "overflow-with-known-positive":
                assert report["counters"]["overflow"] == 1 and report["events"]
            if case == "target-lifecycle-change":
                assert "target_lifecycle_changed" in report["partial_reasons"]
    assert (contract, plan, pins) == originals
    if "object-open" in events:
        assert "object-closed" in events


def test_helper_fixed64_layer_target_binding_and_frozen_case_mapping():
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
        RELEASE,
        BTF,
        digest(OBJECT),
    )
    value = json.loads(contract)
    opportunity = value["opportunities"]["protected_escape"][0]
    reference = dict(
        observation_layer="udp_socket_queue_admission",
        protected_tuple=opportunity["predicate"]["protected_tuple"],
        target=TARGET,
    )
    assert opportunity["reference_sha256"] == digest(_json(reference))
    assert opportunity["challenge_sha256"] == digest(PAYLOAD)
    assert (
        len(PAYLOAD) == 64
        and bytes.fromhex(json.loads(plan)["challenge_payload_hex"]) == PAYLOAD
    )
    assert {row["id"] for row in CASES} | LINUX_ONLY == {row["id"] for row in ROWS}
    assert pins == dict(
        expected_contract_sha256=digest(contract), expected_plan_sha256=digest(plan)
    )


@pytest.mark.parametrize(
    "fault",
    [
        "old-domain",
        "wrong-layer",
        "wrong-cookie",
        "wrong-inode",
        "wrong-payload",
        "outside-window",
    ],
)
def test_signed_report_is_not_admissible_with_wrong_layer_binding_or_time(
    monkeypatch, fault
):
    contract, plan, pins, _, _ = fixture(monkeypatch, "exact-queue-admission")
    report = json.loads(capture(contract, plan, pins))
    if fault == "wrong-layer":
        report["observation_layer"] = "application_delivery"
    elif fault == "wrong-cookie":
        report["events"][0]["socket_cookie"] += 1
    elif fault == "wrong-inode":
        report["events"][0]["socket_inode"] += 1
    elif fault == "wrong-payload":
        report["events"][0]["payload_hex"] = "00" * 64
    elif fault == "outside-window":
        report["events"][0]["exited_ns"] = 4_000_000_001
    domain = (
        b"azazel-edge:protected-interface-ingress:v1\x00"
        if fault == "old-domain"
        else DOMAIN
    )
    report["signature"] = KEY.sign(
        domain + _json({k: v for k, v in report.items() if k != "signature"})
    ).hex()
    with pytest.raises(q.UDPQueueError):
        q.evaluate_udp_queue(contract, plan, wire(report), **pins)


def test_aggregate_accepted_counter_without_matched_event_is_still_unknown(monkeypatch):
    contract, plan, pins, _, _ = fixture(monkeypatch, "exact-queue-admission")
    original = q.provider._capture_events

    def counter_only(*args):
        result = original(*args)
        result["events"] = []
        assert result["counters"]["accepted"] == 1
        return result

    monkeypatch.setattr(q.provider, "_capture_events", counter_only)
    raw = capture(contract, plan, pins)
    assert (
        q.evaluate_udp_queue(contract, plan, raw, **pins)[
            "queue_admission_observed_count"
        ]
        is None
    )


@pytest.mark.parametrize("fault", ["correlation-loss", "lifecycle-change"])
def test_valid_old_socket_event_survives_later_partial_evidence(monkeypatch, fault):
    contract, plan, pins, _, _ = fixture(monkeypatch, "exact-queue-admission")
    if fault == "correlation-loss":
        original = q.provider._capture_events

        def loss(*args):
            result = original(*args)
            result["counters"]["correlation_loss"] = 1
            result["partial_reasons"].append("correlation_loss")
            return result

        monkeypatch.setattr(q.provider, "_capture_events", loss)
    else:
        calls = []

        def alive(target):
            calls.append(1)
            return len(calls) == 1

        monkeypatch.setattr(q, "_target_alive", alive)
    raw = capture(contract, plan, pins)
    result = q.evaluate_udp_queue(contract, plan, raw, **pins)
    assert result["queue_admission_observed_count"] == 1
    assert (
        result["application_delivery_count"] is result["qualified_safety_count"] is None
    )
    expected = (
        "correlation_loss"
        if fault == "correlation-loss"
        else "target_lifecycle_changed"
    )
    assert expected in json.loads(raw)["partial_reasons"]


def test_initial_target_mismatch_never_invokes_provider(monkeypatch):
    contract, plan, pins, _, configurations = fixture(
        monkeypatch, "exact-queue-admission"
    )
    monkeypatch.setattr(q, "_target_alive", lambda _: False)
    with pytest.raises(q.UDPQueueError):
        capture(contract, plan, pins)
    assert configurations == []


def test_postcapture_namespace_drift_blocks_even_matched_positive(monkeypatch):
    contract, plan, pins, _, _ = fixture(monkeypatch, "exact-queue-admission")
    original = q._environment
    calls = []

    def drift(*args):
        value = original(*args)
        calls.append(1)
        if len(calls) > 1:
            value["namespace"]["inode"] += 1
        return value

    monkeypatch.setattr(q, "_environment", drift)
    with pytest.raises(q.UDPQueueError):
        capture(contract, plan, pins)
    assert len(calls) == 2


@pytest.mark.parametrize("failed_link", [200, 210, "both"])
def test_native_libbpf_destroy_nonzero_never_retries_freed_pointer(
    monkeypatch, failed_link
):
    """Real provider orchestration/ABI checks; synthetic libbpf, NO kernel execution."""
    real = q.provider
    configurations = []
    stats_reads = []
    # Build an ABI-valid configuration without invoking the mocked facade provider.
    configuration = dict(
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
    maps = {10: "config", 11: "pending", 12: "events", 13: "stats"}
    programs = {20: "queue_entry", 21: "queue_exit"}

    class Library:
        def libbpf_get_error(self, value):
            return 0

        def bpf_object__open_mem(self, *args):
            events.append("open")
            return 100

        def bpf_object__load(self, obj):
            events.append("load")
            return 0

        def bpf_object__next_map(self, obj, previous):
            keys = list(maps)
            return (
                keys[0]
                if previous is None
                else keys[keys.index(previous) + 1]
                if previous != keys[-1]
                else 0
            )

        def bpf_map__name(self, item):
            return maps[item].encode()

        def bpf_map__type(self, item):
            return real._MAPS[maps[item]][0]

        def bpf_map__key_size(self, item):
            return real._MAPS[maps[item]][1]

        def bpf_map__value_size(self, item):
            return real._MAPS[maps[item]][2]

        def bpf_map__max_entries(self, item):
            return real._MAPS[maps[item]][3]

        def bpf_map__map_flags(self, item):
            return 0

        def bpf_map__fd(self, item):
            return item

        def bpf_object__next_program(self, obj, previous):
            return 20 if previous is None else 21 if previous == 20 else 0

        def bpf_program__name(self, item):
            return programs[item].encode()

        def bpf_program__section_name(self, item):
            return real._PROGRAMS[programs[item]][0].encode()

        def bpf_program__type(self, item):
            return real._PROGRAMS[programs[item]][1]

        def bpf_program__expected_attach_type(self, item):
            return real._PROGRAMS[programs[item]][2]

        def bpf_map_update_elem(self, *args):
            configurations.append(args)
            return 0

        def bpf_program__attach(self, program):
            events.append(("attach", program))
            return program * 10

        def bpf_link__destroy(self, link):
            events.append(("destroy", link))
            return -1 if failed_link == link or failed_link == "both" else 0

        def bpf_object__close(self, obj):
            events.append(("close-object", obj))

        def bpf_map_lookup_elem(self, *args):
            stats_reads.append(args)
            return 0

    backend = object.__new__(real._Libbpf)
    backend.lib = Library()
    monkeypatch.setattr(real, "_Libbpf", lambda: backend)
    monkeypatch.setattr(real, "_role", lambda: None)
    ticks = iter([3_000_000_000] * 3 + [4_000_000_000])
    monkeypatch.setattr(
        real,
        "time",
        SimpleNamespace(
            monotonic_ns=lambda: next(ticks),
            sleep=lambda _: pytest.fail("fixed deadline must not sleep"),
        ),
    )
    raw = bytearray(64)
    raw[:6] = b"\x7fELF\x02\x01"
    raw[18:20] = b"\xf7\x00"
    with pytest.raises(real.UDPQueueBPFError, match="fixed program detach failed"):
        real._capture_events(configuration, bytes(raw))
    assert [
        row for row in events if isinstance(row, tuple) and row[0] == "destroy"
    ] == [("destroy", 200), ("destroy", 210)]
    assert [row for row in events if isinstance(row, tuple) and row[0] == "attach"] == [
        ("attach", 21),
        ("attach", 20),
    ]
    assert events.count(("close-object", 100)) == 1
    assert len(configurations) == 1
    assert stats_reads == []


@pytest.mark.parametrize(
    "schedule",
    [
        "three-before-exits",
        "third-inflight-across-collision",
        "prior-positive-then-three",
    ],
)
def test_sticky_collision_reference_model_three_entries_interleaved_exits(schedule):
    """Protocol reference model ONLY; does NOT execute or prove the BPF C program.

    The third cached entry may have passed its initial loss check before a second
    entry poisons correlation. Therefore the EXIT poison fence is also necessary.
    """
    pending, emitted = {}, []
    poisoned = False

    def entry(key, snapshot, cached_before_loss=False):
        nonlocal poisoned
        if poisoned and not cached_before_loss:
            return
        if key in pending:
            poisoned = True
            pending.pop(key)
        else:
            pending[key] = snapshot

    def exit(key, ret=0):
        snapshot = pending.pop(key, None)
        if snapshot is not None and not poisoned and ret == 0:
            emitted.append(snapshot)

    if schedule == "prior-positive-then-three":
        entry("distinct-prior", "known-prior")
        exit("distinct-prior")
    entry("same-invocation-key", "first")
    # Third entry's initial check can precede the second entry's collision.
    entry("same-invocation-key", "second")
    assert poisoned
    if schedule == "third-inflight-across-collision":
        entry("same-invocation-key", "third", cached_before_loss=True)
        exit("same-invocation-key")  # Old first exit must NOT publish third snapshot.
    else:
        entry("same-invocation-key", "third")
        exit("same-invocation-key")
    exit("same-invocation-key")
    exit("same-invocation-key")
    assert not pending
    assert emitted == (
        ["known-prior"] if schedule == "prior-positive-then-three" else []
    )
