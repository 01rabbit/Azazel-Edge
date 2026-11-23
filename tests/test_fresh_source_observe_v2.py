"""Synthetic v2 profile/envelope checks; no actual Linux acquisition."""

from copy import deepcopy
import json

import pytest
from pathlib import Path

from azazel_edge.benchmark import fresh_source_observe as old
from azazel_edge.benchmark import fresh_source_observe_v2 as fresh


def test_v2_prospective_recipe_and_fixed_conditions():
    raw = (
        Path(__file__).parent / "real_systemd/fresh-source-observe-protocol-v2.json"
    ).read_bytes()
    protocol = json.loads(raw)
    prior = json.loads(
        (
            Path(__file__).parent / "real_systemd/fresh-source-observe-protocol-v1.json"
        ).read_bytes()
    )
    assert old._sha(raw) == fresh.PROTOCOL_SHA256
    assert old._sha(fresh.wire(protocol["input_recipe"])) == fresh.RECIPE_SHA256
    assert protocol["input_recipe"] == prior["input_recipe"]
    assert protocol["gates"] == prior["gates"]
    assert protocol["sampling"] == prior["sampling"]
    assert len(fresh.FILES) == 49 and old.FILES < fresh.FILES
    assert (
        protocol["publication"]["batch_interval_ns"]
        == fresh.LIMITS["batch_ns"]
        == 100000000
    )
    assert protocol["publication"]["close_timeout_seconds"] == 5


def test_missing_publication_not_durable_zero():
    a = dict.fromkeys(fresh.FILES)
    r = fresh.evaluate_fresh_source_case(a, expected=a)
    assert r["status"] == "withheld" and r["callback_facts"] is None
    assert r["publication"]["streams"] == dict(calls=None, input_calls=None)
    assert not any(r["authority_flags"].values())


def test_v1_entry_rejects_v2_slot_envelope():
    a = dict.fromkeys(fresh.FILES)
    r = old.evaluate_fresh_source_case(a, expected=a)
    assert r["reasons"] == ["exact48_original_pin_envelope"]


def test_missing_run_disposition_withholds_but_preserves_unknown_leaves():
    cases = {case: dict.fromkeys(fresh.FILES) for case in fresh.CASES}
    expected = dict(cases=cases, snapshots=dict.fromkeys(fresh.CASES), disposition=None)
    r = fresh.evaluate_fresh_run_evidence(
        cases, dict.fromkeys(fresh.CASES), None, expected=expected
    )
    assert r["status"] == "withheld" and r["disposition"] is None
    assert all(v["callback_facts"] is None for v in r["cases"].values())
    assert not any(r["authority_flags"].values())




@pytest.fixture(scope="module")
def controls():
    from fresh_source_data_v2 import make_fresh_case

    return make_fresh_case()


def analyze(a):
    return fresh.evaluate_fresh_source_case(
        a, expected={n: old._sha(v) if v is not None else None for n, v in a.items()}
    )


def mutate_publication(original, mutate):
    a = dict(original)
    before = a["observer-publication.raw"]
    rows = [json.loads(line) for line in before.splitlines()]
    control = json.loads(a["fresh-controller.json"])
    boundaries = [control["readiness"]]
    if control["interrupt_boundary"] is not None:
        boundaries.append(control["interrupt_boundary"])
    counts = [
        before[: b["publication_checkpoint"]["size"]].count(b"\n") for b in boundaries
    ]
    mutate(rows)
    previous, lines = "0" * 64, []
    for seq, row in enumerate(rows, 1):
        row.update(seq=seq, prev=previous)
        line = fresh.wire(row)
        lines.append(line)
        previous = old._sha(line)
    pub = b"".join(lines)
    a["observer-publication.raw"] = pub
    for boundary, count in zip(boundaries, counts):
        prefix = b"".join(lines[:count])
        boundary["publication_checkpoint"] = dict(
            size=len(prefix), sha256=old._sha(prefix)
        )
    a["fresh-controller.json"] = fresh.wire(control)
    load = json.loads(a["load-controller.json"])
    p = load["observer"]["sidecars"]["publication"]
    p.update(size=len(pub), sha256=old._sha(pub))
    for k in ("before", "after"):
        p[k]["size"] = len(pub)
    a["load-controller.json"] = fresh.wire(load)
    if a["observer-completion.json"] is not None:
        c = json.loads(a["observer-completion.json"])
        c["sidecars"]["publication"] = dict(bytes=len(pub), sha256=old._sha(pub))
        a["observer-completion.json"] = fresh.wire(c)
    return a


def test_synthetic_v2_controls_preserve_five_actual_returns_and_no_authority(controls):
    r = analyze(controls)
    assert r["status"] == "bound_fresh_controls", r["reasons"]
    assert len(r["callback_facts"]) == 5
    assert r["publication"]["normal_complete"] is True
    assert r["publication"]["status"] == "qualified"
    assert not any(r["authority_flags"].values())


def test_synthetic_interruption_requires_both_committed_prefixes():
    from fresh_source_data_v2 import make_fresh_case

    a = make_fresh_case("fresh-interrupted")
    r = analyze(a)
    assert r["status"] == "bound_interrupted_prefix", r["reasons"]
    assert r["publication"]["interrupt_verified"] is True
    assert r["scope_facts"]["later_callbacks"] is None
    assert r["publication"]["normal_complete"] is False

    def mutate(rows):
        rows[:] = [
            row
            for row in rows
            if not (row["kind"] == "commit" and row["data"]["stream"] == "input_calls")
        ]

    broken = analyze(mutate_publication(a, mutate))
    assert broken["status"] == "withheld" and len(broken["callback_facts"]) == 1


@pytest.mark.parametrize(
    "field", ["object", "sha256", "first_seq", "worker_native_tid", "fsync"]
)
def test_forged_commit_cannot_promote_visible_rows(controls, field):
    def mutate(rows):
        d = next(row["data"] for row in rows if row["kind"] == "commit")
        if field == "object":
            d[field]["inode"] += 1
        elif field == "sha256":
            d[field] = "f" * 64
        elif field == "first_seq":
            d[field] += 1
        elif field == "worker_native_tid":
            d[field] = json.loads(controls["load-controller.json"])["observer"][
                "identity"
            ]["native_tid"]
        elif field == "fsync":
            d[field]["end_ns"] = d[field]["start_ns"] - 1

    r = analyze(mutate_publication(controls, mutate))
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 5
    assert r["publication"]["status"] == "withheld"


def test_written_without_publication_keeps_return_facts_only(controls):
    a = dict(controls)
    a["observer-publication.raw"] = None
    r = analyze(a)
    assert r["status"] == "withheld" and len(r["callback_facts"]) == 5
    assert r["publication"]["streams"] == dict(calls=None, input_calls=None)


def test_missing_end_or_uncommitted_footer_blocks_normal_close(controls):
    def mutate(rows):
        rows.pop()

    r = analyze(mutate_publication(controls, mutate))
    assert r["status"] == "withheld" and r["publication"]["normal_complete"] is False
    assert len(r["callback_facts"]) == 5


def test_late_actual_owner_join_blocks_even_successful_worker_footer(controls):
    a = dict(controls)
    c = json.loads(a["observer-completion.json"])
    span = c["publication"]["owner_close"]
    span["end_ns"] = span["start_ns"] + 5000000001
    a["observer-completion.json"] = fresh.wire(c)
    r = analyze(a)
    assert r["status"] == "withheld" and r["publication"]["normal_complete"] is False


@pytest.fixture(scope="module")
def sealed_run():
    from fresh_source_data_v2 import make_fresh_run

    return make_fresh_run()


def test_synthetic_sealed_run_envelope(sealed_run):
    r = fresh.evaluate_fresh_run_evidence(**sealed_run)
    assert r["status"] == "qualified", r["reasons"]
    assert not any(r["authority_flags"].values())


@pytest.mark.parametrize("state", ["rejected", "cleanup_failed"])
def test_outer_failure_preserves_identical_verified_leaf_facts(sealed_run, state):
    run = deepcopy(sealed_run)
    d = json.loads(run["disposition"])
    d["cases"][0].update(
        state=state, error=dict(type="AssertionError", message="real post-seal failure")
    )
    run["disposition"] = fresh.wire(d)
    run["expected"]["disposition"] = old._sha(run["disposition"])
    r = fresh.evaluate_fresh_run_evidence(**run)
    assert (
        r["status"] == "withheld"
        and r["cases"][fresh.CASES[0]]["status"] == "bound_fresh_controls"
    )
    assert len(r["cases"][fresh.CASES[0]]["callback_facts"]) == 5
    assert (
        run["cases"] == sealed_run["cases"]
        and run["snapshots"] == sealed_run["snapshots"]
    )


@pytest.mark.parametrize(
    "mutation",
    ["null_slot", "snapshot_hash", "source_revision", "case_order", "false_accepted"],
)
def test_bad_immutable_envelope_never_accepts(sealed_run, mutation):
    run = deepcopy(sealed_run)
    case = fresh.CASES[0]
    if mutation == "null_slot":
        run["cases"][case]["failure.json"] = b'{"error":true}\n'
    elif mutation == "snapshot_hash":
        run["expected"]["snapshots"][case] = "f" * 64
    else:
        d = json.loads(run["disposition"])
        if mutation == "source_revision":
            d["source_revision"] = "f" * 40
        elif mutation == "case_order":
            d["cases"].reverse()
        else:
            d["cases"][0]["error"] = dict(type="OSError", message="failed")
        run["disposition"] = fresh.wire(d)
        run["expected"]["disposition"] = old._sha(run["disposition"])
    r = fresh.evaluate_fresh_run_evidence(**run)
    assert r["status"] == "withheld"


def test_not_run_assignment_is_unknown_and_prevents_whole_acceptance(sealed_run):
    run = deepcopy(sealed_run)
    case = fresh.CASES[1]
    run["cases"][case] = dict.fromkeys(fresh.FILES)
    run["expected"]["cases"][case] = dict.fromkeys(fresh.FILES)
    run["snapshots"][case] = run["expected"]["snapshots"][case] = None
    d = json.loads(run["disposition"])
    d["cases"][1].update(
        state="not_run", snapshot_manifest_sha256=None, evaluation_sha256=None
    )
    run["disposition"] = fresh.wire(d)
    run["expected"]["disposition"] = old._sha(run["disposition"])
    r = fresh.evaluate_fresh_run_evidence(**run)
    assert r["status"] == "withheld" and r["cases"][case]["callback_facts"] is None
