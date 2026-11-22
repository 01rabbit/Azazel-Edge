"""Pure protocol/negative fixtures; never actual Linux observation evidence."""

import hashlib
import json
from pathlib import Path

import pytest
from azazel_edge.benchmark import fresh_source_observe as fresh

ROOT = Path(__file__).parent / "real_systemd"


def test_exact_frozen_recipe_and_artifact_schema():
    raw = (ROOT / "fresh-source-observe-protocol-v1.json").read_bytes()
    p = json.loads(raw)
    assert fresh._sha(raw) == fresh.PROTOCOL_SHA256
    assert fresh._sha(fresh.wire(p["input_recipe"])) == fresh.RECIPE_SHA256
    assert len(fresh.FILES) == 48
    lines = fresh.nonalert_lines()
    assert len(lines) == 27004 and all(
        len(x) == 600 and x.endswith(b"\n") for x in lines
    )
    assert {json.loads(x)["event_type"] for x in lines} == set(
        ("flow", "dns", "stats", "http")
    )
    for case in fresh.CASES:
        specs = fresh.event_specs(case)
        recipe = p["input_recipe"][
            "controls" if case == fresh.CASES[0] else "interrupted"
        ]
        assert [{k: s[k] for k in item} for s, item in zip(specs, recipe)] == recipe


def test_actual_timestamp_rule_and_distinct_duplicate_recipe():
    specs = fresh.event_specs("fresh-controls")
    epoch = 1_790_000_000_123_456_789
    for spec in specs:
        if spec["kind"] == "duplicate":
            continue
        line = fresh.materialize_alert(spec, epoch)
        e = json.loads(line)
        assert e["timestamp"].endswith(".123456Z")
        assert e["alert"]["signature_id"] == spec["sid"]
    with pytest.raises(ValueError):
        fresh.materialize_alert(specs[-2], epoch)
    assert (
        specs[4]["sid"] == specs[5]["sid"]
        and specs[4]["occurrence"] == 1
        and specs[5]["occurrence"] == 2
    )


def test_prefix_and_partial_tail_are_not_a_footer():
    row = dict(
        schema_version="edge-fresh-input-record/v1",
        seq=1,
        prev="0" * 64,
        kind="begin",
        data={},
    )
    first = fresh.wire(row)
    nextrow = dict(
        row, seq=2, prev=hashlib.sha256(first).hexdigest(), kind="input_intent"
    )
    raw = first + fresh.wire(nextrow)[:-3]
    rows, tail, error = fresh._records(
        raw, schema=row["schema_version"], convention="full", maximum=256
    )
    assert rows == [row] and tail and error is None
    rows, tail, error = fresh._records(
        first + fresh.wire(dict(nextrow, prev="f" * 64)),
        schema=row["schema_version"],
        convention="full",
    )
    assert rows == [row] and error


def test_missing_originals_are_unknown_not_zero():
    a = dict.fromkeys(fresh.FILES)
    r = fresh.evaluate_fresh_source_case(a, expected=a)
    assert r["status"] == "withheld" and r["finite"] is None
    assert r["handler_facts"] is r["callback_facts"] is r["scope_facts"] is None
    assert r["load"] is r["intake"] is None and not any(r["authority_flags"].values())


def test_extra_input_and_bool_epoch_cannot_enter():
    a = dict.fromkeys(fresh.FILES)
    r = fresh.evaluate_fresh_source_case({**a, "extra": b""}, expected=a)
    assert r["reasons"] == ["exact48_original_pin_envelope"]
    with pytest.raises(ValueError):
        fresh.materialize_alert(fresh.event_specs("fresh-controls")[0], True)


@pytest.fixture(scope="module")
def controls():
    from fresh_source_data import make_fresh_case

    return make_fresh_case()


def analyze(artifacts):
    from fresh_source_data import pins

    return fresh.evaluate_fresh_source_case(artifacts, expected=pins(artifacts))


def changed(artifacts, name, mutate):
    updated = dict(artifacts)
    value = json.loads(updated[name])
    mutate(value)
    updated[name] = fresh.wire(value)
    return updated


def rewrite_inputs(artifacts, mutate):
    updated = dict(artifacts)
    rows = [
        json.loads(line) for line in updated["observer-input-calls.raw"].splitlines()
    ]
    mutate(rows)
    previous = "0" * 64
    output = []
    for seq, row in enumerate(rows, 1):
        row.update(seq=seq, prev=previous)
        line = fresh.wire(row)
        output.append(line)
        previous = fresh._sha(line)
    updated["observer-input-calls.raw"] = b"".join(output)
    return changed(
        updated,
        "fresh-controller.json",
        lambda c: c.update(
            input_calls_sha256=fresh._sha(updated["observer-input-calls.raw"])
        ),
    )


def test_synthetic_controls_bind_actual_handlers_without_authority(controls):
    r = analyze(controls)
    assert r["status"] == "bound_fresh_controls", r["reasons"]
    assert len(r["handler_facts"]) == 7 and len(r["callback_facts"]) == 5
    assert [f["event_ref"] for f in r["handler_facts"] if f["missed"]] == [
        "stale",
        "future",
    ]
    duplicates = [
        f for f in r["callback_facts"] if f["event_ref"].startswith("duplicate")
    ]
    assert (
        len(duplicates) == 2
        and duplicates[0]["source_position"] != duplicates[1]["source_position"]
    )
    assert r["observer"] is None and not any(r["authority_flags"].values())


@pytest.mark.parametrize(
    "field", ["input_recipe_sha256", "protocol_sha256", "session_ref"]
)
def test_wrong_fresh_identity_never_admits(controls, field):
    a = changed(
        controls, "fresh-controller.json", lambda c: c.update({field: "f" * 64})
    )
    r = analyze(a)
    assert r["status"] == "withheld" and r["callback_facts"] is None


def test_missing_input_context_retains_finite_source_not_callback_zero(controls):
    a = dict(controls, **{"observer-input-calls.raw": None})
    r = analyze(a)
    assert r["status"] == "withheld" and r["callback_facts"] is None
    assert r["finite"]["whole_input_complete"] is True


def test_bad_later_return_keeps_verified_callback_prefix(controls):
    def mutate(rows):
        returns = [r for r in rows if r["kind"] == "input_return"]
        returns[-1]["data"]["cursor_after"] = {"offset": 1, "sha256": "0" * 64}

    r = analyze(rewrite_inputs(controls, mutate))
    assert (
        r["status"] == "withheld" and r["scope_facts"]["observation_complete"] is False
    )
    assert len(r["callback_facts"]) == 5
    assert r["scope_facts"]["later_callbacks"] is None


def test_replayed_original_position_is_rejected_without_backfill(controls):
    def mutate(rows):
        intents = [r for r in rows if r["kind"] == "input_intent"]
        intents[-1]["data"].update(position=intents[0]["data"]["position"])

    r = analyze(rewrite_inputs(controls, mutate))
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 4
    assert r["scope_facts"]["later_callbacks"] is None


@pytest.mark.parametrize("field", ["supplied_now", "live_floor"])
def test_recorded_handler_time_cannot_be_replaced(controls, field):
    def mutate(rows):
        row = next(r for r in rows if r["kind"] == "input_intent")
        row["data"][field] += 600

    r = analyze(rewrite_inputs(controls, mutate))
    assert r["status"] == "withheld"


def test_forged_readiness_witness_is_not_file_existence(controls):
    a = changed(
        controls,
        "fresh-controller.json",
        lambda c: c["readiness"].update(witness_boundary={}),
    )
    r = analyze(a)
    assert r["status"] == "withheld" and r["callback_facts"] is None


def test_short_load_not_promoted_by_complete_callback_count(controls):
    a = changed(
        controls,
        "load-controller.json",
        lambda c: c["writer"].update(
            final_nonalert_after_ns=c["writer"]["marker_one_before_ns"] + 1
        ),
    )
    r = analyze(a)
    assert r["status"] == "withheld"


def test_synthetic_interrupt_retains_one_callback_and_unknown_later():
    from fresh_source_data import make_fresh_case

    r = analyze(make_fresh_case("fresh-interrupted"))
    assert r["status"] == "bound_interrupted_prefix", r["reasons"]
    assert len(r["callback_facts"]) == 1
    assert r["scope_facts"]["later_callbacks"] is None
    assert r["scope_facts"]["observation_complete"] is False
    assert r["finite"]["whole_input_complete"] is True


def test_later_clock_chain_corruption_keeps_verified_callback_prefix(controls):
    a = dict(controls)
    a["observer-calls.raw"] += b'{"damaged":true}\n'
    r = analyze(a)
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 5
    assert r["scope_facts"]["later_callbacks"] is None


def test_partial_input_tail_never_completes_normal_case(controls):
    a = dict(controls)
    lines = a["observer-input-calls.raw"].splitlines(keepends=True)
    a["observer-input-calls.raw"] = b"".join(lines[:-1]) + lines[-1][:-2]
    a = changed(
        a,
        "fresh-controller.json",
        lambda c: c.update(
            input_calls_sha256=fresh._sha(a["observer-input-calls.raw"])
        ),
    )
    r = analyze(a)
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 5
    assert r["scope_facts"]["partial_tail_bytes"] > 0
    assert r["scope_facts"]["later_callbacks"] is None


def test_changed_original_without_new_pin_is_rejected(controls):
    from fresh_source_data import pins

    expected = pins(controls)
    a = dict(
        controls,
        **{"observer-input-calls.raw": controls["observer-input-calls.raw"] + b"x"},
    )
    r = fresh.evaluate_fresh_source_case(a, expected=expected)
    assert r["status"] == "withheld" and r["callback_facts"] is None


def test_synthetic_wire_replay_rejected_but_equal_eve_spans_remain_distinct(controls):
    from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
    from azazel_edge.outcome.journal import OutcomeJournalError

    source = controls["source-after.raw"]
    verifier = SourceVerifier(TrustPolicy(json.loads(controls["trust.json"])))
    verifier.verify(source)
    rows = source.splitlines(keepends=True)
    events = [json.loads(x)["event"] for x in rows]
    duplicated = [e for e in events if e.get("normalized", {}).get("sid") == 90233005]
    assert len(duplicated) == 2
    spans = [e["ingress_origin"] for e in duplicated]
    assert spans[0]["raw_sha256"] == spans[1]["raw_sha256"]
    assert spans[0]["start_offset"] != spans[1]["start_offset"]
    with pytest.raises(OutcomeJournalError):
        verifier.verify(source + rows[0])


def test_boolean_completed_input_id_cannot_impersonate_integer_one(controls):
    def mutate(rows):
        next(r for r in rows if r["kind"] == "input_return")["data"]["input_id"] = True

    r = analyze(rewrite_inputs(controls, mutate))
    assert r["status"] == "withheld" and r["callback_facts"] == []


def test_load_collection_error_is_not_overridden_by_successful_inputs(controls):
    a = changed(
        controls,
        "load-controller.json",
        lambda c: c.update(errors=[{"stage": "case", "type": "OSError"}]),
    )
    r = analyze(a)
    assert r["status"] == "withheld" and r["load"] is None
    assert len(r["callback_facts"]) == 5
