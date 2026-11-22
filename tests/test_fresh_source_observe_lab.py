"""Synthetic timing/FD/custody seams; never actual native admission evidence."""

import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

REAL = Path(__file__).parent / "real_systemd"
sys.path.insert(0, str(REAL))
import fresh_source_observe as lab  # noqa:E402
from azazel_edge.benchmark import fresh_source_observe as core  # noqa:E402


def writer_fixture(tmp_path, monkeypatch, case="fresh-controls"):
    instance = object.__new__(lab.FreshSourceObserveLab)
    instance.core = core
    instance.nonalerts = core.nonalert_lines()
    path = tmp_path / "eve.json"
    path.write_bytes(b"")
    instance.eve_path = lambda: path
    context = dict(
        controller=dict(case_id=case),
        load={},
        ingress=dict(
            writer=[],
            held_fd=dict(
                object=lab.accounting.source_metadata(path.stat(), detailed=True)
            ),
        ),
        timestamps=dict(
            schema_version="edge-fresh-timestamp-receipts/v1",
            case_id=case,
            protocol_sha256=lab.PROTOCOL_SHA256,
            input_recipe_sha256=lab.RECIPE_SHA256,
            rows=[],
            errors=[],
        ),
        materialized_rows={},
    )
    clock = SimpleNamespace(ns=1_000_000_000, epoch=1_800_000_000_000_000_000)
    monkeypatch.setattr(lab.time, "monotonic_ns", lambda: clock.ns)
    monkeypatch.setattr(lab.time, "time_ns", lambda: clock.epoch + clock.ns)

    def sleep(seconds):
        clock.ns += round(seconds * 1e9)

    monkeypatch.setattr(lab.time, "sleep", sleep)
    return instance, context, path, clock


@pytest.mark.parametrize("case", lab.CASES)
def test_actual_dynamic_writer_timestamps_spans_and_fixed_schedule(
    tmp_path, monkeypatch, case
):
    instance, context, path, clock = writer_fixture(tmp_path, monkeypatch, case)
    thread, writer, ingress = instance.paced_writer(context)
    thread.join(5)
    assert not thread.is_alive() and writer["error"] is None
    raw = path.read_bytes()
    assert writer["sha256"] == lab.accounting.sha256(raw) and writer[
        "written_bytes"
    ] == len(raw)
    assert writer["nonalert_records"] == 27004 and writer["per_class"] == dict.fromkeys(
        ("flow", "dns", "stats", "http"), 6751
    )
    assert (
        writer["marker_one_before_ns"] - writer["first_write_before_ns"]
        >= 3_000_000_000
    )
    assert (
        writer["final_nonalert_after_ns"] - writer["marker_one_before_ns"]
        >= 6_000_000_000
    )
    markers, population = core._actual_population(raw, context["timestamps"], case)
    assert len(markers) == len(core.event_specs(case))
    for row in context["timestamps"]["rows"]:
        assert (
            raw[row["start_offset"] : row["end_offset"]]
            == context["materialized_rows"][row["event_ref"]]
        )
    if case == "fresh-controls":
        one, two = context["timestamps"]["rows"][4:6]
        assert (
            one["raw_sha256"] == two["raw_sha256"]
            and one["end_offset"] == two["start_offset"]
        )
        assert (
            two["generation_anchor"] is None and two["duplicate_of"] == "duplicate-one"
        )
        assert (
            context["timestamps"]["rows"][1]["timestamp_epoch_ns"]
            == context["timestamps"]["rows"][1]["generation_anchor"]["epoch_ns"]
            // 1000
            * 1000
            - 600_000_000_000
        )


def test_dynamic_generation_changes_between_materializations_without_retiming(
    tmp_path, monkeypatch
):
    instance, context, path, clock = writer_fixture(tmp_path, monkeypatch)
    t, writer, _ = instance.paced_writer(context)
    t.join(5)
    first = path.read_bytes()
    first_ts = context["timestamps"]["rows"][0]["timestamp"]
    path.write_bytes(b"")
    context["timestamps"]["rows"] = []
    context["materialized_rows"] = {}
    clock.epoch += 1_000_000_000
    t, writer, _ = instance.paced_writer(context)
    t.join(5)
    assert path.read_bytes() != first
    assert context["timestamps"]["rows"][0]["timestamp"] != first_ts
    assert (
        context["timestamps"]["rows"][0]["timestamp_epoch_ns"]
        == context["timestamps"]["rows"][0]["generation_anchor"]["epoch_ns"]
        // 1000
        * 1000
    )


def test_write_failure_keeps_actual_prefix_not_generated_population(
    tmp_path, monkeypatch
):
    instance, context, path, clock = writer_fixture(tmp_path, monkeypatch)
    original = os.write
    count = []

    def failing(fd, data):
        count.append(True)
        if len(count) > 1:
            raise OSError("synthetic writer failure")
        return original(fd, data)

    monkeypatch.setattr(lab.os, "write", failing)
    thread, writer, _ = instance.paced_writer(context)
    thread.join(5)
    assert writer["written_bytes"] == 600 and writer["nonalert_records"] == 1
    assert writer["sha256"] == lab.accounting.sha256(path.read_bytes())
    assert writer["error"]["type"] == "OSError" and context["timestamps"]["rows"] == []


def test_shared_observer_defaults_remain_old_and_fresh_selects_explicit_versions():
    assert lab.old.ObserverProcess.role_mode == "finite-load"
    assert (
        lab.old.ObserverProcess.bootstrap_schema
        == "edge-finite-load-observer-bootstrap/v1"
    )
    assert lab.old.ObserverProcess.go_schema == "edge-finite-load-observer-go/v1"
    assert lab.FreshObserverProcess.role_mode == "fresh-source"
    assert (
        lab.FreshObserverProcess.bootstrap_schema
        == "edge-fresh-source-observer-bootstrap/v1"
    )
    assert (
        len(lab.FreshObserverProcess.side_files) == 7
        and len(lab.old.ObserverProcess.side_files) == 6
    )


def test_fresh_collector_static48_names_and_new_limits():
    spec = importlib.util.spec_from_file_location(
        "fresh_collector_test",
        REAL.parents[1] / ".github/scripts/collect_fresh_source_observe.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.NAMES == core.FILES and len(module.NAMES) == 48
    assert module.CASES == lab.CASES
    assert module.file_limit("fresh-timestamp-receipts.json") == 65536
    assert module.file_limit("fresh-controller.json") == 131072
    assert module.file_limit("observer-input-calls.raw") == 4 * 1024 * 1024
    assert module.file_limit("root-custody.raw") == 32768
    assert module.file_limit("observer-context.raw") == 16384


def test_fresh_smoke_dispatch_keeps_both_old_modes(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "fresh_finish_dispatch", REAL / "armor.py"
    )
    armor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(armor)
    calls = []
    monkeypatch.setattr(armor.g, "guard", lambda: None)
    monkeypatch.setattr(armor, "configure", lambda: None)
    monkeypatch.setattr(lab, "finish", lambda g: calls.append("fresh"))
    monkeypatch.setattr(lab.old, "finish", lambda g: calls.append("load"))
    monkeypatch.setattr(lab.accounting, "finish", lambda g: calls.append("legacy"))
    for extra in (["--fresh-source-observe"], ["--finite-load-cost"], []):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "armor.py",
                "smoke-finish",
                "--allow-disposable-vm",
                "--native-core",
                *extra,
            ],
        )
        armor.main()
    assert calls == ["fresh", "load", "legacy"]


def test_original_context_prefix_tail_is_not_repaired():
    row = dict(
        schema_version="edge-fresh-input-record/v1",
        seq=1,
        prev="0" * 64,
        kind="begin",
        data={},
    )
    raw = lab.accounting.canonical(row)
    prefix, tail = lab.input_prefix(raw + b'{"partial":')
    assert prefix == [row] and tail == b'{"partial":'
    with pytest.raises(AssertionError):
        lab.input_prefix(raw.replace(b'"seq":1', b'"seq":2'))


@pytest.mark.parametrize("state", ["files_only", "no_fence", "unprotected", "ready"])
def test_readiness_requires_first_original_sample_and_protected_fence(
    monkeypatch, state
):
    instance = object.__new__(lab.FreshSourceObserveLab)
    context = dict(
        fresh=dict(readiness=None),
        observer_process=SimpleNamespace(
            process=SimpleNamespace(poll=lambda: None),
            receipt=dict(actor=dict(pid=123, start_ticks=7)),
        ),
    )
    monkeypatch.setattr(lab.accounting, "actor", lambda pid: dict(start_ticks=7))
    first = [] if state == "files_only" else [dict(seq=1, kind="sample", data={})]
    monkeypatch.setattr(
        lab,
        "decode_calls_prefix",
        lambda raw: dict(calls=first, complete_prefix=b"original calls\n"),
    )
    journal = (
        []
        if state == "no_fence"
        else [dict(seq=3, kind="input_ready", data=dict(offset=0, sha256="0" * 64))]
    )

    anchors = [dict(state=dict(journal_seq=2 if state == "unprotected" else 3))]

    def read(path, limit):
        if str(path).endswith("calls"):
            return b"original calls\n", {}
        if str(path).endswith("observations.journal"):
            return b"".join(lab.accounting.canonical(r) for r in journal), {}
        return b"".join(lab.accounting.canonical(r) for r in anchors), {}

    monkeypatch.setattr(lab, "stable_read", read)
    monkeypatch.setattr(
        lab.accounting,
        "witness_boundary",
        lambda raw: dict(source_checkpoint={}, anchor_checkpoint={}),
    )

    def wait(predicate):
        assert predicate() is (state == "ready")

    instance.g = SimpleNamespace(BUNDLE=Path("/synthetic/bundle"), wait_for=wait)
    instance.ready(context, dict(calls="/synthetic/calls"))
    assert (context["fresh"]["readiness"] is not None) is (state == "ready")
    if state == "ready":
        assert context["fresh"]["readiness"]["first_sample_seq"] == 1


@pytest.mark.parametrize("missing", ["return", "call", "cursor", "witness", "none"])
def test_interrupt_waits_for_original_return_call_cursor_and_witness(
    monkeypatch, missing
):
    instance = object.__new__(lab.FreshSourceObserveLab)
    position = dict(offset=400, sha256="a" * 64)
    event = dict(
        normalized=dict(sid=90233101), capture_origin=dict(session_ref="b" * 32)
    )
    callback = dict(
        call_seq=42,
        return_value=False,
        event_sha256=lab.accounting.sha256(lab.accounting.canonical(event)),
    )
    values = [("begin", {}), ("input_intent", dict(input_id=1))]
    if missing != "return":
        values.append(
            (
                "input_return",
                dict(input_id=1, cursor_after=position, callbacks=[callback]),
            )
        )
    raw = []
    previous = "0" * 64
    for seq, (kind, data) in enumerate(values, 1):
        row = lab.accounting.canonical(
            dict(
                schema_version="edge-fresh-input-record/v1",
                seq=seq,
                prev=previous,
                kind=kind,
                data=data,
            )
        )
        raw.append(row)
        previous = lab.accounting.sha256(row)
    input_raw = b"".join(raw)

    journal = (
        []
        if missing == "cursor"
        else [dict(seq=2, kind="cursor", data=dict(position=position))]
    )
    anchors = [dict(state=dict(journal_seq=1 if missing == "witness" else 2))]
    calls = (
        []
        if missing == "call"
        else [dict(seq=42, kind="event", data=dict(event=event, accepted=False))]
    )
    monkeypatch.setattr(lab, "decode_calls_prefix", lambda raw: dict(calls=calls))
    monkeypatch.setattr(
        lab.accounting,
        "witness_boundary",
        lambda raw: dict(source_checkpoint=dict(size=400), anchor_checkpoint={}),
    )

    def read(path, limit):
        if str(path).endswith("inputs"):
            return input_raw, {}
        if str(path).endswith("calls"):
            return b"original clockcalls\n", {}
        if str(path).endswith("observations.journal"):
            return b"".join(lab.accounting.canonical(r) for r in journal), {}
        return b"".join(lab.accounting.canonical(r) for r in anchors), {}

    monkeypatch.setattr(lab, "stable_read", read)

    def wait(predicate):
        assert predicate() is (missing == "none")

    instance.g = SimpleNamespace(BUNDLE=Path("/synthetic/bundle"), wait_for=wait)
    context = dict(
        files={
            "observer-config.json": lab.accounting.canonical(
                dict(
                    paths=dict(
                        input_calls="/synthetic/inputs", calls="/synthetic/calls"
                    )
                )
            )
        },
        load=dict(observer={}),
        fresh=dict(interrupt_boundary=None),
    )
    observation = dict(
        event_ref="interrupt-one",
        source_position=position,
        source_checkpoint=dict(size=400),
    )
    instance.interrupted_barrier(context, observation)
    assert (context["fresh"]["interrupt_boundary"] is not None) is (missing == "none")
    if missing == "none":
        assert context["fresh"]["interrupt_boundary"]["handler_id"] == 1
        assert context["fresh"]["interrupt_boundary"]["event_call_id"] == 42


def test_new_clock_oracle_recomputes_complete_synthetic_originals():
    from fresh_source_data import make_fresh_case, pins

    artifacts = make_fresh_case()
    result = lab.evaluate_fresh_observer_originals(artifacts, pins(artifacts))
    assert (
        result["normal_completion"] is True
        and result["clock"]["status"] == "qualified"
        and result["status"] == "qualified"
    ), result


@pytest.mark.parametrize(
    "fault",
    ["epoch", "domain", "exit", "old_schema", "input_missing", "pin", "bootstrap"],
)
def test_new_clock_oracle_withholds_missing_or_changed_originals(fault):
    import json
    from fresh_source_data import make_fresh_case, pins

    artifacts = make_fresh_case()
    controller = json.loads(artifacts["load-controller.json"])
    if fault == "epoch":
        controller["controller_anchors"]["after"]["epoch_ns"] += 6_000_000
    elif fault == "domain":
        controller["controller_identity"]["clock_domain"]["established"] = False
    elif fault == "exit":
        controller["observer"]["exit"]["ExecMainStatus"] = "9"
    elif fault == "old_schema":
        controller["schema_version"] = "edge-finite-load-controller/v1"
    elif fault == "bootstrap":
        controller["observer"]["bootstrap"]["schema_version"] = (
            "edge-finite-load-observer-bootstrap/v1"
        )
    elif fault == "input_missing":
        artifacts["observer-input-calls.raw"] = None
        controller["observer"]["sidecars"]["input_calls"] = None
    artifacts["load-controller.json"] = lab.accounting.canonical(controller)
    expected = pins(artifacts)
    if fault == "pin":
        expected["observer-calls.raw"] = "0" * 64
    result = lab.evaluate_fresh_observer_originals(artifacts, expected)
    assert result["status"] == "withheld", result
    if fault == "epoch":
        assert result["normal_completion"] is True
        assert "sampled_offset_envelope_exceeds_budget" in result["clock"]["reasons"]


def test_composed_new_core_and_clock_originals_are_both_required():
    from fresh_source_data import make_fresh_case, pins

    artifacts = make_fresh_case()
    expected = pins(artifacts)
    result = core.evaluate_fresh_source_case(artifacts, expected=expected)
    assert result["status"] == "bound_fresh_controls" and result["reasons"] == [], (
        result
    )
    assert result["observer"] is None
    result["observer"] = lab.evaluate_fresh_observer_originals(artifacts, expected)
    assert (
        result["observer"]["normal_completion"] is True
        and result["observer"]["clock"]["status"] == "qualified"
    ), result["observer"]
    assert (
        result["finite"]["whole_input_complete"] is True
        and result["load"]["status"] == result["intake"]["status"] == "qualified"
    )


def test_composed_interrupted_prefix_has_true_fault_and_no_clock_upgrade():
    from fresh_source_data import make_fresh_case, pins

    artifacts = make_fresh_case("fresh-interrupted")
    expected = pins(artifacts)
    result = core.evaluate_fresh_source_case(artifacts, expected=expected)
    assert result["status"] == "bound_interrupted_prefix" and result["reasons"] == [], (
        result
    )
    observed = lab.evaluate_fresh_observer_originals(artifacts, expected)
    assert (
        observed["fault_verified"] is True
        and observed["normal_completion"] is False
        and observed["clock"] is None
    ), observed


def test_wrong_interrupted_original_return_id_withholds_without_exception():
    import json
    from fresh_source_data import make_fresh_case, pins

    artifacts = make_fresh_case("fresh-interrupted")
    fresh = json.loads(artifacts["fresh-controller.json"])
    fresh["interrupt_boundary"]["handler_id"] = 999
    artifacts["fresh-controller.json"] = lab.accounting.canonical(fresh)
    result = lab.evaluate_fresh_observer_originals(artifacts, pins(artifacts))
    assert (
        result["status"] == "withheld"
        and result["fault_verified"] is False
        and result["clock"] is None
    ), result
