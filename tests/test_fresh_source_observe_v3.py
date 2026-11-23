"""Synthetic only: all-four-stream committed barriers and explicit profile v3."""

import json
from pathlib import Path

import pytest
from azazel_edge.benchmark import fresh_source_observe as v1
from azazel_edge.benchmark import fresh_source_observe_v2 as v2
from azazel_edge.benchmark import fresh_source_observe_v3 as fresh
from test_fresh_source_observe_v2 import mutate_publication


def pins(a):
    return {k: v1._sha(v) if v is not None else None for k, v in a.items()}


def analyze(a):
    return fresh.evaluate_fresh_source_case(a, expected=pins(a))


@pytest.fixture(scope="module")
def controls():
    from fresh_source_data_v3 import make_fresh_case

    return make_fresh_case()


def change_stream(original, stream, mutate):
    """Repinned synthetic tamper; never loads acquired raw originals."""
    a = dict(original)
    name = fresh.STREAMS[stream]
    prior = a[name]
    rows = [json.loads(line) for line in prior.splitlines()]
    mutate(rows)
    previous = "0" * 64
    lines = []
    for row in rows:
        row["prev"] = previous
        line = fresh.wire(row)
        lines.append(line)
        previous = v1._sha(line)
    raw = b"".join(lines)
    a[name] = raw
    load = json.loads(a["load-controller.json"])
    meta = load["observer"]["sidecars"][stream]
    meta.update(size=len(raw), sha256=v1._sha(raw))
    for when in ("before", "after"):
        meta[when]["size"] = len(raw)
    a["load-controller.json"] = fresh.wire(load)
    c = json.loads(a["fresh-controller.json"])
    for boundary in (c["readiness"], c["interrupt_boundary"]):
        if boundary is not None and stream + "_checkpoint" in boundary:
            cp = boundary[stream + "_checkpoint"]
            count = prior[: cp["size"]].count(b"\n")
            prefix = b"".join(lines[:count])
            boundary[stream + "_checkpoint"] = dict(
                size=len(prefix), sha256=v1._sha(prefix)
            )
    a["fresh-controller.json"] = fresh.wire(c)
    if a["observer-completion.json"] is not None:
        done = json.loads(a["observer-completion.json"])
        done["sidecars"][stream] = dict(bytes=len(raw), sha256=v1._sha(raw))
        a["observer-completion.json"] = fresh.wire(done)

    def update_pub(pub):
        for row in pub:
            if row["kind"] == "commit" and row["data"]["stream"] == stream:
                d = row["data"]
                count = prior[: d["bytes"]].count(b"\n")
                prefix = b"".join(lines[:count])
                d.update(bytes=len(prefix), sha256=v1._sha(prefix))
            if row["kind"] == "end":
                for wm in row["data"]["streams"][stream].values():
                    wm.update(bytes=len(raw), sha256=v1._sha(raw))

    return mutate_publication(a, update_pub)


def test_frozen_v3_gates_recipe_and_four_stream_budget():
    root = Path(__file__).parent / "real_systemd"
    b = (root / "fresh-source-observe-protocol-v3.json").read_bytes()
    p = json.loads(b)
    old = json.loads((root / "fresh-source-observe-protocol-v2.json").read_bytes())
    assert v1._sha(b) == fresh.PROTOCOL_SHA256
    assert (
        p["gates"] == old["gates"]
        and p["sampling"] == old["sampling"]
        and p["input_recipe"] == old["input_recipe"]
    )
    assert set(fresh.STREAMS) == {"calls", "input_calls", "phase", "context"}
    assert (
        fresh.LIMITS["queue_rows"] == sum(fresh.LIMITS["stream_rows"].values()) == 5254
    )
    assert (
        fresh.LIMITS["queue_bytes"]
        == sum(fresh.LIMITS["stream_bytes"].values())
        == 12599296
    )


def test_synthetic_positive_controls_commit_all_four(controls):
    r = analyze(controls)
    assert r["status"] == "bound_fresh_controls", r["reasons"]
    assert (
        r["publication"]["normal_complete"] is True
        and len(r["publication"]["streams"]) == 4
    )
    assert all(v is not None for v in r["publication"]["streams"].values())
    assert len(r["callback_facts"]) == 5 and not any(r["authority_flags"].values())


def test_synthetic_interrupted_four_prefixes_later_unknown():
    from fresh_source_data_v3 import make_fresh_case

    r = analyze(make_fresh_case("fresh-interrupted"))
    assert r["status"] == "bound_interrupted_prefix", r["reasons"]
    assert r["publication"]["interrupt_verified"] is True
    assert r["scope_facts"]["later_callbacks"] is None
    assert r["publication"]["normal_complete"] is False


@pytest.mark.parametrize("stream", ["phase", "context"])
def test_visible_without_commit_never_satisfies_barrier(controls, stream):
    def mutate(rows):
        rows[:] = [
            r
            for r in rows
            if not (r["kind"] == "commit" and r["data"]["stream"] == stream)
        ]

    r = analyze(mutate_publication(controls, mutate))
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 5
    assert r["publication"]["streams"][stream] is None


@pytest.mark.parametrize("stream", ["phase", "context"])
def test_missing_root_checkpoint_cannot_be_inferred_from_other_stream(controls, stream):
    a = dict(controls)
    c = json.loads(a["fresh-controller.json"])
    c["readiness"][stream + "_checkpoint"] = None
    a["fresh-controller.json"] = fresh.wire(c)
    r = analyze(a)
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 5


def test_phase_enqueue_cost_never_mislabeled_as_legacy_write_cost(controls):
    def mutate(rows):
        for row in rows:
            row["data"]["previous_write_cost"] = row["data"].pop(
                "previous_enqueue_cost"
            )

    r = analyze(change_stream(controls, "phase", mutate))
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 5
    assert any("enqueue_cost" in x for x in r["publication"]["reasons"])


def test_completed_phase_must_match_exact_original_sample(controls):
    def mutate(rows):
        for row in rows:
            if (
                row["kind"] in ("intent", "span")
                and row["data"].get("phase") == "observation_sample"
            ):
                row["data"]["phase"] = "input_snapshot"

    r = analyze(change_stream(controls, "phase", mutate))
    assert r["status"] == "withheld" and r["publication"]["readiness_verified"] is False


@pytest.mark.parametrize("stream", ["phase", "context"])
def test_normal_close_cannot_invent_missing_stream_footer(controls, stream):
    def mutate(rows):
        rows[-1]["kind"] = "uncommitted_end"

    r = analyze(change_stream(controls, stream, mutate))
    assert r["status"] == "withheld" and r["publication"]["normal_complete"] is False
    assert len(r["callback_facts"]) == 5


def test_v2_entry_does_not_cast_four_stream_v3_data(controls):
    r = v2.evaluate_fresh_source_case(controls, expected=pins(controls))
    assert r["status"] == "withheld" and r["callback_facts"] is None


def test_synthetic_whole_run_immutable_v3_envelope():
    from fresh_source_data_v3 import make_fresh_run

    r = fresh.evaluate_fresh_run_evidence(**make_fresh_run())
    assert r["status"] == "qualified", r["reasons"]
    assert all(
        v["schema_version"] == "edge-fresh-source-analysis/v3"
        for v in r["cases"].values()
    )
    assert not any(r["authority_flags"].values())


def test_interrupted_event_phase_cannot_be_an_unrelated_sample_span():
    from fresh_source_data_v3 import make_fresh_case

    a = make_fresh_case("fresh-interrupted")

    def mutate(rows):
        for row in rows:
            if (
                row["kind"] in ("intent", "span")
                and row["data"].get("phase") == "observation_event"
            ):
                row["data"]["phase"] = "observation_sample"

    r = analyze(change_stream(a, "phase", mutate))
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 1
    assert r["publication"]["readiness_verified"] is True
    assert r["publication"]["interrupt_verified"] is False


def test_matching_sample_phase_identity_must_use_integer_span_id(controls):
    def mutate(rows):
        for row in rows:
            if (
                row["kind"] in ("intent", "span")
                and row["data"].get("phase") == "observation_sample"
            ):
                row["data"]["span_id"] = True

    r = analyze(change_stream(controls, "phase", mutate))
    assert r["status"] == "withheld"


def test_absent_enqueue_measurement_is_not_a_zero_cost(controls):
    def mutate(rows):
        rows[1]["data"]["previous_enqueue_cost"] = None

    r = analyze(change_stream(controls, "phase", mutate))
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 5
    assert any("enqueue_not_missing" in s for s in r["publication"]["reasons"])


def test_context_must_precede_selected_call_within_actual_actor_lifetime(controls):
    def mutate(rows):
        anchor = rows[0]["data"]["anchor"]
        anchor.update(monotonic_before_ns=0, monotonic_after_ns=1)

    r = analyze(change_stream(controls, "context", mutate))
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 5


def test_context_metadata_cannot_be_replaced_by_another_run(controls):
    def mutate(rows):
        rows[0]["data"]["metadata"]["run_id"] = "f" * 32

    r = analyze(change_stream(controls, "context", mutate))
    assert r["status"] == "withheld" and r["publication"]["readiness_verified"] is False


def test_phase_return_cannot_precede_its_intent(controls):
    from copy import deepcopy

    def mutate(rows):
        intent = deepcopy(rows[1]["data"])
        span = deepcopy(rows[2]["data"])
        span["previous_enqueue_cost"] = intent["previous_enqueue_cost"]
        intent["previous_enqueue_cost"] = deepcopy(
            rows[2]["data"]["previous_enqueue_cost"]
        )
        rows[1].update(kind="span", data=span)
        rows[2].update(kind="intent", data=intent)

    r = analyze(change_stream(controls, "phase", mutate))
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 5
    assert any("prior_active_intent" in x for x in r["publication"]["reasons"])


def test_interruption_cannot_silently_have_a_normal_context_end():
    from fresh_source_data_v3 import make_fresh_case
    from copy import deepcopy

    a = make_fresh_case("fresh-interrupted")

    def mutate(rows):
        data = dict(anchor=deepcopy(rows[0]["data"]["anchor"]), normal_return=True)
        rows.append(
            dict(
                schema_version="edge-fresh-clock-context/v3",
                seq=2,
                prev="0" * 64,
                kind="end",
                data=data,
            )
        )

    r = analyze(change_stream(a, "context", mutate))
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 1
    assert any("normal_footer" in x for x in r["publication"]["reasons"])
