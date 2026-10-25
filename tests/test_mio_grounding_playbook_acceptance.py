"""#386 acceptance: explainable gap scoring, claim-to-ref audit, playbook/template
digests in provenance, generic fallback, and non-executable playbooks."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from azazel_edge.mio import (
    BoundedReasoningLoop,
    CapabilityBroker,
    CapabilitySpec,
    DEFAULT_PLAYBOOKS,
    GENERIC_PLAYBOOK,
    MioEvidenceGap,
    MioHypothesis,
    MioRecommendation,
    MioSituationFrame,
    ReasoningBudget,
    ReasoningState,
    audit_claims,
    playbook_digest,
    reasoning_provenance,
    run_selected,
    score_evidence_gaps,
    select_playbook,
    template_digest,
    validate_playbook,
)
from azazel_edge.mio import claim_audit, evidence_gap_scoring, playbook as playbook_mod
from azazel_edge.mio.replay import ReplayFixture, run_replay

ROOT = Path(__file__).resolve().parents[1]
AUTH = DEFAULT_PLAYBOOKS["auth-ambiguity-v1"]


def _frame(**overrides):
    base = dict(
        frame_id="f-386",
        trace_id="t-386",
        created_at="2026-10-25T00:00:00Z",
        mission="protect site",
        current_defensive_state="OBSERVE",
        threat_level="MEDIUM",
        soc_summary="repeated ssh login failures",
        evidence_refs=["ev:ssh:1", "ev:ssh:2"],
    )
    base.update(overrides)
    return MioSituationFrame.build(**base)


def _h(hid, *, status="proposed", sup=(), con=(), fals=("x",)):
    return MioHypothesis.from_mapping(
        {"hypothesis_id": hid, "statement": hid, "status": status, "supporting_evidence_refs": list(sup),
         "contradicting_evidence_refs": list(con), "falsification_conditions": list(fals)},
        ordinal=1,
    )


def _gap(gid, cap, hyps, priority=50):
    return MioEvidenceGap(gap_id=gid, question="q?", discriminates_hypothesis_ids=tuple(hyps), capability=cap, priority=priority)


def _events(outcome, kind):
    return [e for e in outcome.trace if e.kind == kind]


# --- explainable evidence-gap scoring --------------------------------------

def test_gap_score_is_itemised_and_sums_to_total():
    hyps = (_h("h1"), _h("h2"))
    (score,) = score_evidence_gaps(
        [_gap("g1", "query_recent_alerts", ["h1", "h2"], priority=80)],
        hypotheses=hyps, allowed_capabilities=AUTH.allowed_capabilities,
        registered_capabilities=["query_recent_alerts"], remaining_broker_calls=3,
    )
    rules = dict(score.reasons)
    assert rules == {"base": 50, "discriminates_multiple_hypotheses": 20, "targets_falsifiable_hypothesis": 10,
                     "model_priority_hint": 8, "cost_low": 0}
    assert score.score == sum(rules.values()) == 88
    assert score.eligible and score.rank == 1
    assert score.to_dict()["reasons"][0] == {"rule": "base", "delta": 50}


def test_cheap_discriminating_falsification_outranks_expensive_confirmation_even_with_lower_model_priority():
    hyps = (_h("h1"), _h("h2", fals=()))
    reg = ["query_recent_alerts", "request_trace"]
    scores = score_evidence_gaps(
        [_gap("confirm", "request_trace", ["h2"], priority=100), _gap("falsify", "query_recent_alerts", ["h1", "h2"], priority=10)],
        hypotheses=hyps, allowed_capabilities=reg, registered_capabilities=reg, remaining_broker_calls=3,
    )
    assert [s.gap_id for s in scores if s.eligible] == ["falsify", "confirm"]


def test_gap_scoring_is_deterministic_and_order_independent():
    hyps = (_h("h1"), _h("h2"))
    reg = list(AUTH.allowed_capabilities)
    gaps = [_gap("b", "query_flow_summary", ["h1"]), _gap("a", "query_flow_summary", ["h1"]), _gap("c", "query_recent_alerts", ["h1", "h2"])]
    kw = dict(hypotheses=hyps, allowed_capabilities=reg, registered_capabilities=reg, remaining_broker_calls=3)
    first = score_evidence_gaps(gaps, **kw)
    assert first == score_evidence_gaps(list(reversed(gaps)), **kw)
    assert [s.gap_id for s in first] == ["c", "a", "b"]  # ties broken by gap_id


@pytest.mark.parametrize(
    "gap,allowed,registered,budget,reason",
    [
        (_gap("g", "query_recent_alerts", ["h1"]), (), ["query_recent_alerts"], 3, "capability_not_allowed_by_playbook"),
        (_gap("g", "query_recent_alerts", ["h1"]), ["query_recent_alerts"], [], 3, "capability_not_registered_in_broker"),
        (_gap("g", "query_recent_alerts", []), ["query_recent_alerts"], ["query_recent_alerts"], 3, "cannot_change_hypothesis_state"),
        (_gap("g", "query_recent_alerts", ["h1"]), ["query_recent_alerts"], ["query_recent_alerts"], 0, "cycle_broker_budget_exhausted"),
    ],
)
def test_ineligible_gaps_carry_explicit_reason(gap, allowed, registered, budget, reason):
    (score,) = score_evidence_gaps([gap], hypotheses=(_h("h1"),), allowed_capabilities=allowed,
                                   registered_capabilities=registered, remaining_broker_calls=budget)
    assert not score.eligible and score.rank == 0
    assert reason in score.ineligible_reasons


def test_low_value_gap_is_terminated_rather_than_queried():
    (score,) = score_evidence_gaps([_gap("g", "request_trace", ["h1"], priority=0)], hypotheses=(_h("h1", fals=()),),
                                   allowed_capabilities=["request_trace"], registered_capabilities=["request_trace"], remaining_broker_calls=3)
    assert score.score < evidence_gap_scoring.MIN_ELIGIBLE_SCORE
    assert score.ineligible_reasons == ("insufficient_expected_value",)


def test_scoring_policy_digest_changes_with_weights(monkeypatch):
    before = evidence_gap_scoring.scoring_policy_digest()
    monkeypatch.setattr(evidence_gap_scoring, "WEIGHTS", {**evidence_gap_scoring.WEIGHTS, "base": 51})
    assert evidence_gap_scoring.scoring_policy_digest() != before


# --- claim-to-reference audit ----------------------------------------------

def test_claim_audit_records_claim_refs_origin_and_verdict():
    frame = _frame(knowledge_refs=["kb:1"], knowledge_status="available", provenance={"knowledge_refs": ["knowledge"]})
    rec = MioRecommendation.from_mapping(
        {"summary": "s", "recommended_action": "OBSERVE", "rationale": "r", "evidence_refs": ["ev:ssh:1", "ev:flow:1", "kb:1"]},
        advisory_id="a1",
    )
    audit = audit_claims(frame, hypotheses=(_h("h1"),), recommendation=rec, imported_refs=["ev:flow:1"])
    assert audit.ok
    body = audit.to_dict()
    assert body["policy"] == "reject"
    h_claim, r_claim = body["claims"]
    assert h_claim["verdict"] == "inference_unreferenced" and h_claim["material"] is False
    assert r_claim["verdict"] == "supported"
    assert [r["origin"] for r in r_claim["refs"]] == ["frame_evidence", "broker_imported", "frame_knowledge"]


@pytest.mark.parametrize(
    "hyp,verdict",
    [
        (_h("h1", status="strengthened"), "unsupported_missing_refs"),
        (_h("h1", status="strengthened", con=["ev:ssh:1"]), "unsupported_missing_refs"),
        (_h("h1", status="falsified", sup=["ev:ssh:1"]), "unsupported_missing_refs"),
        (_h("h1", status="weakened"), "unsupported_missing_refs"),
        (_h("h1", sup=["ev:elsewhere"]), "unsupported_unknown_ref"),
    ],
)
def test_unsupported_claims_are_flagged(hyp, verdict):
    audit = audit_claims(_frame(), hypotheses=(hyp,))
    assert not audit.ok
    assert audit.records[0].verdict == verdict
    assert audit.errors() == (f"unsupported_claim:hypothesis:h1:{verdict}",)


def test_recommendation_without_refs_is_unsupported():
    rec = MioRecommendation.from_mapping({"summary": "s", "recommended_action": "OBSERVE", "rationale": "r", "evidence_refs": []}, advisory_id="a")
    audit = audit_claims(_frame(), recommendation=rec)
    assert audit.errors() == ("unsupported_claim:recommendation:a:unsupported_missing_refs",)


def _loop_model(final_status="strengthened", final_refs=("ev:ssh:1",)):
    def model(task, prompt):
        if task == "generate_hypotheses":
            return {"hypotheses": [{"hypothesis_id": "h1", "statement": "attack", "supporting_evidence_refs": ["ev:ssh:1"], "falsification_conditions": ["admin"]},
                                   {"hypothesis_id": "h2", "statement": "benign", "supporting_evidence_refs": ["ev:ssh:2"]}]}
        if task == "identify_evidence_gaps":
            return {"evidence_gaps": [{"gap_id": "g1", "question": "flow?", "discriminates_hypothesis_ids": ["h1", "h2"], "capability": "query_flow_summary", "priority": 50}]}
        if task == "update_hypotheses":
            return {"hypotheses": [{"hypothesis_id": "h1", "statement": "attack", "status": final_status, "supporting_evidence_refs": list(final_refs)},
                                   {"hypothesis_id": "h2", "statement": "benign", "supporting_evidence_refs": ["ev:ssh:2"]}]}
        return {"summary": "observe", "recommended_action": "OBSERVE", "rationale": "bounded", "evidence_refs": ["ev:ssh:1", "ev:flow:1"]}
    return model


def _broker():
    return CapabilityBroker({"query_flow_summary": CapabilitySpec(lambda _: {"evidence_refs": ["ev:flow:1"]})})


def test_loop_records_claim_audit_and_score_trace_on_success():
    outcome = BoundedReasoningLoop(model=_loop_model(), broker=_broker()).run(frame=_frame(), playbook=AUTH, cycle_id="ok")
    assert outcome.state is ReasoningState.COMPLETE
    (audit,) = _events(outcome, "claim_audit")
    assert audit.payload["ok"] is True
    assert {c["claim_id"] for c in audit.payload["claims"]} == {"hypothesis:h1", "hypothesis:h2", "recommendation:ok:advisory"}
    (scores,) = _events(outcome, "evidence_gap_scores")
    assert scores.payload["scores"][0]["gap_id"] == "g1" and scores.payload["scores"][0]["eligible"] is True
    assert scores.payload["policy_digest"].startswith("sha256:")


def test_loop_rejects_strengthened_hypothesis_without_supporting_refs():
    outcome = BoundedReasoningLoop(model=_loop_model(final_refs=()), broker=_broker()).run(frame=_frame(), playbook=AUTH, cycle_id="bad")
    assert outcome.state is ReasoningState.VALIDATION_REJECTED
    assert "unsupported_claim:hypothesis:h1:unsupported_missing_refs" in outcome.errors
    (audit,) = _events(outcome, "claim_audit")
    assert audit.payload["ok"] is False


# --- provenance digests ----------------------------------------------------

def test_provenance_carries_playbook_and_template_version_and_digest():
    outcome = BoundedReasoningLoop(model=_loop_model(), broker=_broker()).run(frame=_frame(), playbook=AUTH, cycle_id="p")
    (prov,) = _events(outcome, "reasoning_provenance")
    assert prov.payload == reasoning_provenance(AUTH)
    assert prov.payload["playbook_version"] == "1.0.0"
    assert prov.payload["playbook_digest"] == playbook_digest(AUTH)
    assert prov.payload["template_version"] == playbook_mod.PROMPT_TEMPLATE_VERSION
    assert prov.payload["template_digest"] == template_digest()
    assert prov.payload["selection_mode"] == "explicit"


def test_playbook_digest_is_stable_and_changes_with_any_content_change():
    assert playbook_digest(AUTH) == playbook_digest(replace(AUTH))
    digests = {playbook_digest(p) for p in [*DEFAULT_PLAYBOOKS.values(), GENERIC_PLAYBOOK]}
    assert len(digests) == len(DEFAULT_PLAYBOOKS) + 1
    for field, value in [("version", "1.0.1"), ("purpose", AUTH.purpose + "."), ("allowed_capabilities", AUTH.allowed_capabilities[:-1]),
                         ("claim_boundaries", AUTH.claim_boundaries + ("do not guess",))]:
        assert playbook_digest(replace(AUTH, **{field: value})) != playbook_digest(AUTH), field


def test_template_digest_changes_when_rules_or_version_change(monkeypatch):
    before = template_digest()
    monkeypatch.setattr(playbook_mod, "TRUSTED_RULES", playbook_mod.TRUSTED_RULES + ("extra rule",))
    assert template_digest() != before
    monkeypatch.undo()
    assert template_digest() == before
    monkeypatch.setattr(playbook_mod, "PROMPT_TEMPLATE_VERSION", "9.9.9")
    assert template_digest() != before


def test_template_digest_covers_rules_actually_compiled():
    prompt = playbook_mod.PromptCompiler().compile(frame=_frame(), playbook=AUTH, task="recommend")
    for rule in playbook_mod.TRUSTED_RULES:
        assert rule in prompt


# --- generic fallback ------------------------------------------------------

def test_specialised_playbook_selected_for_single_family_match():
    sel = select_playbook(_frame())
    assert sel.playbook is AUTH and sel.mode == "matched" and not sel.is_generic_fallback


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"soc_summary": "unclassified anomaly"}, "no_family_match"),
        ({"soc_summary": "login failures and port scan"}, "ambiguous_family_match"),
    ],
)
def test_generic_fallback_when_no_or_ambiguous_match(overrides, reason):
    sel = select_playbook(_frame(**overrides))
    assert sel.playbook is GENERIC_PLAYBOOK and sel.mode == "generic_fallback" and sel.reason == reason
    assert sel.is_generic_fallback


def test_unknown_requested_playbook_falls_back_to_generic_and_says_so():
    sel = select_playbook(_frame(), requested_id="model-invented-v9")
    assert sel.playbook is GENERIC_PLAYBOOK and sel.reason == "requested_playbook_not_registered"


def test_generic_fallback_is_visible_in_provenance_and_runs_to_completion():
    frame = _frame(soc_summary="unclassified anomaly")
    outcome = run_selected(BoundedReasoningLoop(model=_loop_model(), broker=_broker()), frame, cycle_id="gen")
    assert outcome.state is ReasoningState.COMPLETE
    (prov,) = _events(outcome, "reasoning_provenance")
    assert prov.payload["generic_fallback"] is True
    assert prov.payload["playbook_id"] == "generic-evidence-first-v1"
    assert prov.payload["selection_reason"] == "no_family_match"
    assert prov.payload["playbook_digest"] == playbook_digest(GENERIC_PLAYBOOK)


def test_replay_still_refuses_unknown_fixture_playbook():
    with pytest.raises(ValueError):
        run_replay(BoundedReasoningLoop(model=_loop_model(), broker=_broker()), ReplayFixture("x", _frame(), "nope"))


# --- playbooks are non-executable ------------------------------------------

def test_shipped_playbooks_pass_static_validation():
    for pb in [*DEFAULT_PLAYBOOKS.values(), GENERIC_PLAYBOOK]:
        assert validate_playbook(pb) == (), pb.playbook_id


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("purpose", "fetch http://evil.example/x", "forbidden_content:url"),
        ("stop_conditions", ("isolate the client",), "directive_language"),
        ("discriminating_questions", ("read /etc/shadow?",), "forbidden_content:filesystem_path"),
        ("falsification_patterns", ("$(id) result",), "forbidden_content:shell_syntax"),
        ("hypothesis_prompts", ("api_key=abc",), "forbidden_content:secret_material"),
        ("claim_boundaries", ("activate deception profile Y",), "directive_language"),
        ("hypothesis_prompts", (print,), "non_text_item"),
        ("allowed_capabilities", ("exec;rm -rf",), "invalid_capability_name"),
    ],
)
def test_forbidden_playbook_content_is_rejected(field, value, code):
    errors = validate_playbook(replace(GENERIC_PLAYBOOK, **{field: value}))
    assert any(e.startswith(code) for e in errors), errors


def test_playbook_capability_must_be_registered_when_checked():
    errors = validate_playbook(replace(AUTH, allowed_capabilities=("query_recent_alerts", "made_up_cap")), registered_capabilities=["query_recent_alerts"])
    assert errors == ("capability_not_registered:made_up_cap",)


def test_playbook_cannot_reach_capabilities_outside_broker_or_exceed_budgets():
    calls: list[str] = []

    def handler(name):
        def _h(_):
            calls.append(name)
            return {"evidence_refs": [f"ev:{name}"]}
        return _h

    # A playbook that "allows" an unregistered, enforcement-sounding capability and many registered ones.
    greedy = replace(GENERIC_PLAYBOOK, playbook_id="greedy-v1",
                     allowed_capabilities=("query_recent_alerts", "query_flow_summary", "get_host_health", "isolate_client"))
    broker = CapabilityBroker(
        {"query_recent_alerts": CapabilitySpec(handler("a")), "query_flow_summary": CapabilitySpec(handler("b")),
         "get_host_health": CapabilitySpec(handler("c"))},
        max_total_calls=2,
    )

    def model(task, prompt):
        if task == "generate_hypotheses":
            return {"hypotheses": [{"hypothesis_id": "h1", "statement": "x", "supporting_evidence_refs": ["ev:ssh:1"], "falsification_conditions": ["y"]},
                                   {"hypothesis_id": "h2", "statement": "z"}]}
        if task == "identify_evidence_gaps":
            return {"evidence_gaps": [
                {"gap_id": "g0", "question": "q", "discriminates_hypothesis_ids": ["h1", "h2"], "capability": "isolate_client", "priority": 100},
                {"gap_id": "g1", "question": "q", "discriminates_hypothesis_ids": ["h1", "h2"], "capability": "query_recent_alerts"},
                {"gap_id": "g2", "question": "q", "discriminates_hypothesis_ids": ["h1", "h2"], "capability": "query_flow_summary"},
                {"gap_id": "g3", "question": "q", "discriminates_hypothesis_ids": ["h1", "h2"], "capability": "get_host_health"},
            ]}
        if task == "update_hypotheses":
            return {"hypotheses": [{"hypothesis_id": "h1", "statement": "x", "supporting_evidence_refs": ["ev:ssh:1"]}]}
        return {"summary": "s", "recommended_action": "OBSERVE", "rationale": "r", "evidence_refs": ["ev:ssh:1"]}

    outcome = BoundedReasoningLoop(model=model, broker=broker, budget=ReasoningBudget(max_broker_calls=3, max_gaps=4)).run(
        frame=_frame(), playbook=greedy, cycle_id="greedy"
    )
    assert "gap_not_eligible:g0:capability_not_registered_in_broker" in outcome.errors
    assert len(calls) == 2  # broker's own total budget wins over the loop/playbook
    assert {r["capability"] for r in broker.audit_records()} <= {"query_recent_alerts", "query_flow_summary", "get_host_health"}
    assert outcome.recommendation is None or outcome.recommendation.executable is False


def test_playbook_dataclass_has_no_executable_surface():
    fields = set(GENERIC_PLAYBOOK.__dataclass_fields__)
    assert not any(callable(getattr(GENERIC_PLAYBOOK, f)) for f in fields)
    assert not ({"handler", "command", "script", "action", "executable"} & fields)


# --- documentation ---------------------------------------------------------

@pytest.mark.parametrize(
    "doc,symbols",
    [
        ("mio-grounding-and-evidence-gaps.md", ["score_evidence_gaps", "audit_claims", "scoring_policy_digest", "MIN_ELIGIBLE_SCORE"]),
        ("mio-reasoning-playbooks.md", ["validate_playbook", "select_playbook", "playbook_digest", "template_digest", "reasoning_provenance", "SELECTION_RULES", "TRUSTED_RULES"]),
    ],
)
def test_architecture_docs_exist_and_name_real_symbols(doc, symbols):
    text = (ROOT / "docs" / "architecture" / doc).read_text(encoding="utf-8")
    for symbol in symbols:
        assert f"`{symbol}" in text, symbol
        assert any(hasattr(m, symbol) for m in (evidence_gap_scoring, playbook_mod, claim_audit)), symbol
    assert "non-executable" in text.lower()
    assert str(evidence_gap_scoring.MIN_ELIGIBLE_SCORE) in (ROOT / "docs/architecture/mio-grounding-and-evidence-gaps.md").read_text(encoding="utf-8")


def test_playbook_doc_lists_every_shipped_playbook_and_rejection_code():
    text = (ROOT / "docs" / "architecture" / "mio-reasoning-playbooks.md").read_text(encoding="utf-8")
    for pid in [*DEFAULT_PLAYBOOKS, GENERIC_PLAYBOOK.playbook_id]:
        assert f"`{pid}`" in text, pid
    for code, _ in playbook_mod._FORBIDDEN_CONTENT:
        assert f"forbidden_content:{code}" in text


def test_compiled_context_is_byte_identical_for_identical_inputs():
    compiler = playbook_mod.PromptCompiler()
    assert compiler.compile(frame=_frame(), playbook=AUTH, task="recommend") == compiler.compile(frame=_frame(), playbook=AUTH, task="recommend")


def test_scoring_doc_lists_actual_weights():
    text = (ROOT / "docs" / "architecture" / "mio-grounding-and-evidence-gaps.md").read_text(encoding="utf-8")
    for rule, delta in evidence_gap_scoring.WEIGHTS.items():
        assert f"`{rule}`" in text and str(delta) in text, rule
    assert evidence_gap_scoring.SCORING_POLICY_VERSION in text
