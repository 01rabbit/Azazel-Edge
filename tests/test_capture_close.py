"""Synthetic receipts only: never an actual kernel capture or safety proof."""

from copy import deepcopy
import hashlib
import json
import stat

import pytest

from azazel_edge.benchmark import capture_close as c


def wire(value):
    return c._wire(value)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


DOMAIN = dict(
    time_namespace_device=1,
    time_namespace_inode=2,
    timens_offsets=[
        dict(clock=name, seconds=0, nanoseconds=0) for name in ("monotonic", "boottime")
    ],
    established=True,
)
BOOT = "00000000-0000-4000-8000-000000000001"


def identity(pid, start):
    return dict(
        pid=pid,
        uid=1000,
        process_start_ticks=start,
        boot_id=BOOT,
        clock_domain=deepcopy(DOMAIN),
    )


def make_bundle(case="clean"):
    actors = dict(
        controller_identity=identity(101, 11),
        writer_identity=identity(202, 22),
        collector_identity=identity(303, 33),
    )
    object_id = dict(device=11, inode=22, owner_uid=1000)
    payloads = {identifier: ("payload-" + identifier).encode() for identifier in c.IDS}
    plan = dict(
        schema_version="edge-capture-close-plan/v1",
        run_id="SYNTHETIC",
        capture_id="capture",
        case_id=case,
        protocol_sha256=c.PROTOCOL_SHA256,
        source_inventory_sha256="1" * 64,
        **actors,
        object_identity=object_id,
        gate_id="gate",
        gate_token="2" * 64,
        attempts=[
            dict(
                id=identifier,
                seq=i,
                payload_sha256=sha(payloads[identifier]),
                payload_bytes=len(payloads[identifier]),
                phase="pre_C" if i < 16 else "late",
            )
            for i, identifier in enumerate(c.IDS)
        ],
        maximum_bytes=c.MAXIMUM,
    )
    ledger = [
        dict(
            id=identifier,
            decision="admitted",
            attempt_started_ns=10 + i * 2,
            attempt_finished_ns=11 + i * 2,
        )
        for i, identifier in enumerate(c.IDS[:16])
    ]
    late = []
    for i, identifier in enumerate(c.IDS[16:]):
        t = 60 + i * 10
        ledger.append(
            dict(
                id=identifier,
                decision="rejected_closed",
                attempt_started_ns=t + 2,
                attempt_finished_ns=t + 3,
            )
        )
        late.append(
            dict(
                id=identifier,
                gate_id="gate",
                gate_token="2" * 64,
                started_ns=t + 1,
                finished_ns=t + 4,
                poll_before_ns=t,
                poll_after_ns=t + 5,
                poll_before_returncode=None,
                poll_after_returncode=None,
            )
        )
    admission = dict(
        schema_version="edge-capture-close-admission/v1",
        run_id="SYNTHETIC",
        capture_id="capture",
        controller_identity=actors["controller_identity"],
        gate_id="gate",
        gate_token="2" * 64,
        attempts=ledger,
        C=dict(
            started_ns=50,
            finished_ns=51,
            gate_id="gate",
            gate_token="2" * 64,
            admitted_ids=list(c.IDS[:16]),
        ),
        late_controls=late,
    )
    previous = "0" * 64
    frames = []
    selected = list(c.IDS[:16])
    lost = []
    if case == "explicit_loss":
        selected.remove("a07")
        lost = ["a07"]
    if case == "abrupt_writer":
        selected = selected[:8]
    if case == "late_bypass":
        selected.append("late0")
    for identifier in selected:
        row = dict(
            schema_version="edge-capture-close-frame/v1",
            kind="data",
            run_id="SYNTHETIC",
            capture_id="capture",
            attempt_id=identifier,
            seq=c.IDS.index(identifier),
            payload_hex=payloads[identifier].hex(),
            prev_sha256=previous,
        )
        raw = wire(row)
        frames.append(raw)
        previous = sha(raw)
    footer = None
    if case != "abrupt_writer":
        footer = dict(
            schema_version="edge-capture-close-frame/v1",
            kind="terminal",
            run_id="SYNTHETIC",
            capture_id="capture",
            last_seq=c.IDS.index(selected[-1]),
            declared_records=len(selected),
            declared_lost=len(lost),
            lost_ids=lost,
            prev_sha256=previous,
        )
        if case == "missing_loss_counter":
            del footer["declared_lost"]
        frames.append(wire(footer))
    capture = b"".join(frames)
    terminal = dict(
        schema_version="edge-capture-close-terminal/v1",
        run_id="SYNTHETIC",
        capture_id="capture",
        controller_identity=actors["controller_identity"],
        writer_identity=actors["writer_identity"],
        D=dict(
            started_ns=80,
            finished_ns=81,
            footer_sha256=sha(wire(footer)) if footer else None,
        ),
        W=dict(
            started_ns=90,
            finished_ns=91,
            pid=202,
            process_start_ticks=22,
            returncode=7 if case == "abrupt_writer" else 0,
            waited=True,
        ),
        S=dict(
            started_ns=100,
            finished_ns=101,
            result="failed" if case == "seal_busy" else "sealed",
            errno=16 if case == "seal_busy" else None,
            seals_before=0,
            seals_after=0 if case == "seal_busy" else 15,
            object_identity=object_id,
        ),
        post_seal_write=dict(
            attempted=case != "seal_busy",
            started_ns=None if case == "seal_busy" else 102,
            finished_ns=None if case == "seal_busy" else 103,
            bytes_written=None,
            errno=None if case == "seal_busy" else 1,
        ),
    )
    object_full = dict(object_id, mode=stat.S_IFREG | 0o600, nlink=0, size=len(capture))
    if case == "seal_busy":
        capture = b""
    collector = dict(
        schema_version="edge-capture-close-collector/v1",
        collector_identity=actors["collector_identity"],
        object_before=object_full,
        object_after=deepcopy(object_full),
        access_mode=0,
        seals_before=0 if case == "seal_busy" else 15,
        seals_after=0 if case == "seal_busy" else 15,
        read_started_ns=110,
        read_finished_ns=111,
        bytes_read=len(capture),
        sha256=sha(capture),
        complete=case != "seal_busy",
        errors=["required_initial_seals_unavailable"] if case == "seal_busy" else [],
    )
    plan_raw = wire(plan)
    enrollment = dict(
        schema_version="edge-capture-close-enrollment/v1",
        plan_sha256=sha(plan_raw),
        source_inventory_sha256="1" * 64,
        **actors,
        object_identity=object_id,
        started_ns=1,
        finished_ns=2,
        plan_bytes_read=len(plan_raw),
        source_inventory_bytes_read=200,
    )
    return dict(
        plan=plan_raw,
        admission=wire(admission),
        terminal=wire(terminal),
        collector=wire(collector),
        capture=capture,
        enrollment=wire(enrollment),
    )


def evaluate(bundle, expected=None):
    pins = (
        {
            name + "_sha256": sha(raw) if raw is not None else None
            for name, raw in bundle.items()
        }
        if expected is None
        else expected
    )
    return c.evaluate_capture_close(
        bundle["plan"],
        bundle["admission"],
        bundle["terminal"],
        bundle["collector"],
        bundle["capture"],
        expected=pins,
        enrollment_raw=bundle["enrollment"],
    )


def mutate(bundle, name, callback):
    value = json.loads(bundle[name])
    callback(value)
    bundle[name] = wire(value)


def rechain(bundle, mutator):
    rows = [json.loads(line) for line in bundle["capture"].splitlines()]
    mutator(rows)
    previous = "0" * 64
    raw = []
    for row in rows:
        row["prev_sha256"] = previous
        line = wire(row)
        raw.append(line)
        previous = sha(line)
    bundle["capture"] = b"".join(raw)
    mutate(
        bundle, "terminal", lambda value: value["D"].update(footer_sha256=sha(raw[-1]))
    )
    mutate(
        bundle,
        "collector",
        lambda value: value.update(
            bytes_read=len(bundle["capture"]),
            sha256=sha(bundle["capture"]),
            object_before=dict(value["object_before"], size=len(bundle["capture"])),
            object_after=dict(value["object_after"], size=len(bundle["capture"])),
        ),
    )


def test_clean_finite_controller_object_accounting_is_not_old_safety_coverage():
    bundle = make_bundle()
    before = deepcopy(bundle)
    report = evaluate(bundle)
    assert (
        report["finite_accounting_complete"]
        is report["complete_finite_capture"]
        is True
    ), report["reasons"]
    assert report["status"] == "verified_finite_capture"
    assert report["known_matching_ids"] == list(c.IDS[:16])
    assert report["terminal_missing_count"] == report["unresolved_count"] == 0
    assert report["admitted_ids"] == list(c.IDS[:16]) and report["denied_ids"] == [
        "late0",
        "late1",
    ]
    assert (
        report["upstream_produced"]
        is report["upstream_dropped"]
        is report["runtime_inflight"]
        is None
    )
    assert (
        report["comparison_qualified"]
        is report["whole_window_coverage"]
        is report["production_admission"]
        is False
    )
    assert report["qualified_safety_count"] is None and all(
        value is None for value in report["old_category_counts"].values()
    )
    assert not any(report["authority_flags"].values())
    assert bundle == before and evaluate(bundle) == report


def test_explicit_loss_is_recounted_and_retained_never_zero_or_backfilled():
    report = evaluate(make_bundle("explicit_loss"))
    assert (
        report["finite_accounting_complete"] is True
        and report["complete_finite_capture"] is False
    ), report["reasons"]
    assert report["status"] == "accounted_with_explicit_loss"
    assert report["terminal_missing_count"] == 1 and report["terminal_missing_ids"] == [
        "a07"
    ]
    assert (
        len(report["known_matching_ids"]) == 15
        and "a07" not in report["known_matching_ids"]
    )


@pytest.mark.parametrize(
    "case", ["abrupt_writer", "missing_loss_counter", "late_bypass", "seal_busy"]
)
def test_frozen_negative_cases_keep_measured_facts_and_unknown_loss(case):
    report = evaluate(make_bundle(case))
    assert (
        report["finite_accounting_complete"]
        is report["complete_finite_capture"]
        is False
    )
    assert report["terminal_missing_count"] is report["unresolved_count"] is None
    assert report["admitted_ids"] == list(c.IDS[:16])
    if case == "abrupt_writer":
        assert report["known_matching_ids"] == list(c.IDS[:8])
        assert report["legs"]["seal"] is report["legs"]["collector"] is True
    elif case == "late_bypass":
        assert (
            report["unexpected_ids"] == ["late0"]
            and len(report["known_matching_ids"]) == 16
        )
    elif case == "seal_busy":
        assert report["known_matching_ids"] == []
    else:
        assert len(report["known_matching_ids"]) == 16


@pytest.mark.parametrize("name", ["terminal", "collector", "enrollment"])
@pytest.mark.parametrize("fault", ["missing", "pin", "unknown_key"])
def test_missing_or_bad_reference_is_quarantined_without_erasing_good_siblings(
    name, fault
):
    bundle = make_bundle()
    pins = {key + "_sha256": sha(raw) for key, raw in bundle.items()}
    if fault == "missing":
        bundle[name] = None
        pins[name + "_sha256"] = None
    elif fault == "pin":
        pins[name + "_sha256"] = "a" * 64
    else:
        mutate(bundle, name, lambda value: value.update(unknown_field=True))
        pins[name + "_sha256"] = sha(bundle[name])
    report = evaluate(bundle, pins)
    assert report["known_matching_ids"] == list(c.IDS[:16]) and report[
        "admitted_ids"
    ] == list(c.IDS[:16])
    assert (
        report["terminal_missing_count"] is None
        and report["finite_accounting_complete"] is False
    )
    assert report["valid_capture_rows"] and report["reasons"]


@pytest.mark.parametrize(
    "fault",
    [
        "token",
        "actor",
        "FD",
        "writable",
        "seals",
        "wait_bool",
        "wait_unknown",
        "counter_bool",
        "late_poll",
        "late_gate",
        "late_clock",
        "C",
        "D",
        "S",
        "R",
        "clock_domain",
        "enrollment_time",
        "enrollment_bytes",
        "source",
    ],
)
def test_repinned_receipt_false_claims_cannot_qualify(fault):
    bundle = make_bundle()
    if fault == "token":
        mutate(bundle, "admission", lambda x: x.update(gate_token="a" * 64))
    elif fault == "actor":
        mutate(
            bundle,
            "terminal",
            lambda x: x["writer_identity"].update(process_start_ticks=999),
        )
    elif fault == "FD":
        mutate(bundle, "collector", lambda x: x["object_before"].update(inode=999))
    elif fault == "writable":
        mutate(bundle, "collector", lambda x: x.update(access_mode=2))
    elif fault == "seals":
        mutate(bundle, "terminal", lambda x: x["S"].update(seals_after=7))
    elif fault == "wait_bool":
        mutate(bundle, "terminal", lambda x: x["W"].update(returncode=False))
    elif fault == "wait_unknown":
        mutate(bundle, "terminal", lambda x: x["W"].update(waited=False))
    elif fault == "counter_bool":
        rechain(bundle, lambda rows: rows[-1].update(declared_lost=False))
    elif fault == "late_poll":
        mutate(
            bundle,
            "admission",
            lambda x: x["late_controls"][0].update(poll_after_returncode=0),
        )
    elif fault == "late_gate":
        mutate(
            bundle, "admission", lambda x: x["late_controls"][0].update(gate_id="other")
        )
    elif fault == "late_clock":
        mutate(
            bundle,
            "admission",
            lambda x: x["late_controls"][0].update(poll_before_ns=None),
        )
    elif fault == "C":
        mutate(bundle, "admission", lambda x: x["C"].update(started_ns=12))
    elif fault == "D":
        mutate(bundle, "terminal", lambda x: x["D"].update(started_ns=50))
    elif fault == "S":
        mutate(bundle, "terminal", lambda x: x["S"].update(started_ns=89))
    elif fault == "R":
        mutate(bundle, "collector", lambda x: x.update(read_started_ns=99))
    elif fault == "clock_domain":
        mutate(
            bundle,
            "plan",
            lambda x: x["collector_identity"]["clock_domain"].update(established=False),
        )
    elif fault == "enrollment_time":
        mutate(bundle, "enrollment", lambda x: x.update(finished_ns=12))
    elif fault == "enrollment_bytes":
        mutate(bundle, "enrollment", lambda x: x.update(plan_bytes_read=True))
    else:
        mutate(
            bundle, "enrollment", lambda x: x.update(source_inventory_sha256="a" * 64)
        )
    report = evaluate(bundle)
    assert (
        report["finite_accounting_complete"] is False
        and report["terminal_missing_count"] is None
    ), report
    assert report["known_matching_ids"] or fault == "token"


@pytest.mark.parametrize(
    "fault",
    [
        "payload",
        "duplicate",
        "reorder",
        "extra",
        "chain",
        "tail",
        "footer_counter_missing",
        "last_seq",
    ],
)
def test_raw_capture_anomalies_are_independently_recounted_and_preserve_prefix(fault):
    bundle = make_bundle()
    if fault == "payload":
        rechain(bundle, lambda rows: rows[3].update(payload_hex=b"wrong".hex()))
    elif fault == "duplicate":
        rechain(bundle, lambda rows: rows.insert(4, deepcopy(rows[3])))
    elif fault == "reorder":

        def swap(rows):
            rows[3], rows[4] = rows[4], rows[3]

        rechain(bundle, swap)
    elif fault == "extra":
        rechain(bundle, lambda rows: rows[3].update(attempt_id="unassigned"))
    elif fault == "chain":
        bundle["capture"] = bundle["capture"].replace(b'"seq":8', b'"seq":9', 1)
    elif fault == "tail":
        bundle["capture"] += b"\n" * 100000
    elif fault == "footer_counter_missing":
        rechain(bundle, lambda rows: rows[-1].pop("declared_lost"))
    else:
        rechain(bundle, lambda rows: rows[-1].update(last_seq=14))
    report = evaluate(bundle)
    assert (
        report["finite_accounting_complete"] is False
        and report["terminal_missing_count"] is None
    )
    assert report["valid_capture_rows"] and report["known_matching_ids"]


@pytest.mark.parametrize(
    "fault",
    [
        "duplicate_JSON",
        "NaN",
        "depth",
        "oversize",
        "pin_null_present",
        "pin_nonnull_absent",
    ],
)
def test_bounded_canonical_reference_rules_preserve_other_observations(fault):
    bundle = make_bundle()
    pins = None
    if fault == "duplicate_JSON":
        bundle["terminal"] = bundle["terminal"].replace(
            b'"schema_version":', b'"schema_version":"duplicate","schema_version":', 1
        )
    elif fault == "NaN":
        bundle["terminal"] = b'{"x":NaN}\n'
    elif fault == "depth":
        value = 1
        for _ in range(17):
            value = [value]
        bundle["terminal"] = wire(value)
    elif fault == "oversize":
        bundle["terminal"] = b" " * (c.MAXIMUM + 1)
    else:
        pins = {key + "_sha256": sha(raw) for key, raw in bundle.items()}
        if fault == "pin_null_present":
            pins["terminal_sha256"] = None
        else:
            bundle["terminal"] = None
    report = evaluate(bundle, pins)
    assert len(report["known_matching_ids"]) == 16 and len(report["admitted_ids"]) == 16
    assert (
        report["terminal_missing_count"] is None
        and report["finite_accounting_complete"] is False
    )


def test_evaluator_does_not_read_paths_or_execute_processes(monkeypatch):
    import pathlib
    import subprocess

    bundle = make_bundle()

    def forbidden(*a, **k):
        raise AssertionError("I/O in pure verifier")

    monkeypatch.setattr(pathlib.Path, "read_bytes", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert evaluate(bundle)["finite_accounting_complete"] is True


def test_missing_writer_wait_does_not_erase_seal_or_independent_read_siblings():
    bundle = make_bundle()
    mutate(bundle, "terminal", lambda value: value.update(W=None))
    report = evaluate(bundle)
    assert report["legs"]["wait"] is False
    assert report["legs"]["seal"] is report["legs"]["collector"] is True
    assert report["independent_read_verified"] is True
    assert report["known_matching_ids"] == list(c.IDS[:16])
    assert (
        report["terminal_missing_count"] is None
        and report["finite_accounting_complete"] is False
    )


def test_missing_seal_receipt_does_not_erase_independent_R_sealed_read_fact():
    bundle = make_bundle()
    mutate(
        bundle,
        "terminal",
        lambda value: value.update(
            S=None,
            post_seal_write=dict(
                attempted=False,
                started_ns=None,
                finished_ns=None,
                bytes_written=None,
                errno=None,
            ),
        ),
    )
    report = evaluate(bundle)
    assert report["legs"]["seal"] is False and report["legs"]["collector"] is True
    assert (
        report["known_matching_ids"] == list(c.IDS[:16])
        and report["terminal_missing_count"] is None
    )
    assert report["finite_accounting_complete"] is False


def test_bad_capture_pin_extra_DATA_is_unverified_diagnostic_not_verified_anomaly():
    bundle = make_bundle("late_bypass")
    pins = {key + "_sha256": sha(raw) for key, raw in bundle.items()}
    pins["capture_sha256"] = "a" * 64
    report = evaluate(bundle, pins)
    assert report["raw_pin_verified"]["capture"] is False
    assert (
        report["unexpected_ids"]
        == report["conflicting_ids"]
        == report["known_matching_ids"]
        == []
    )
    assert report["unverified_capture_diagnostics"]["unexpected_ids"] == ["late0"]
    assert report["capture_provenance"] == "unverified_capture_raw_or_plan_context"
    assert report["valid_capture_rows"] and all(
        row["provenance"] == report["capture_provenance"]
        for row in report["valid_capture_rows"]
    )
    assert (
        report["terminal_missing_count"] is None
        and report["finite_accounting_complete"] is False
    )
    assert report["qualified_safety_count"] is None and not any(
        report["authority_flags"].values()
    )


def test_bad_capture_pin_payload_conflict_is_kept_only_as_unverified_diagnostic():
    bundle = make_bundle()
    rechain(bundle, lambda rows: rows[3].update(payload_hex=b"wrong".hex()))
    pins = {key + "_sha256": sha(raw) for key, raw in bundle.items()}
    pins["capture_sha256"] = "a" * 64
    report = evaluate(bundle, pins)
    assert report["conflicting_ids"] == []
    assert report["unverified_capture_diagnostics"]["conflicting_ids"] == ["a03"]
    assert any(
        reason.startswith("unverified_capture_diagnostic:")
        for reason in report["reasons"]
    )


def test_good_capture_pin_keeps_late_anomaly_in_verified_plan_context():
    report = evaluate(make_bundle("late_bypass"))
    assert report["raw_pin_verified"]["capture"] is True
    assert report["capture_provenance"] == "raw_pin_and_plan_context_verified"
    assert (
        report["unexpected_ids"] == ["late0"]
        and report["unverified_capture_diagnostics"] is None
    )
