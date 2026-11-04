from __future__ import annotations

import json
import time
from unittest.mock import patch

import pytest

from azazel_edge_ai.mio_live_auxiliary import LiveMioAuxiliary
from azazel_edge_ai.mio_live_auxiliary import _binding_matches, _safe_edge_event, _safe_event, _source_context
from azazel_edge_ai import agent


EVENT = {
    "normalized": {"event_type": "alert", "sid": 42, "severity": 2, "src_ip": "203.0.113.7"},
    "defense": {"action": "notify"},
    "enforcement": {"trace_id": "rust-trace-1"},
}


@pytest.mark.parametrize("bad", ["x" * 10000, {"nested": "value"}, "<script>alert(1)</script>"])
def test_edge_action_metadata_rejects_unbounded_nested_or_markup_values(bad):
    candidate = {"defense": {"action": bad}, "enforcement": {"result": bad, "status": bad, "trace_id": bad}}
    safe = _safe_edge_event(candidate)
    assert safe == {"unknown_fields": True}
    assert len(json.dumps(safe)) < 100


def test_edge_action_metadata_uses_known_enums_and_fixed_unknown_marker():
    safe = _safe_edge_event({"defense": {"action": "notify"}, "enforcement": {
        "mode": "dry_run", "result": "planned_not_applied", "trace_id": "trace-17",
        "result_markup": "<b>unknown</b>", "nested": {"x": 1},
    }})
    assert safe == {"action": "notify", "mode": "dry_run", "result": "planned_not_applied",
                    "trace_id": "trace-17", "unknown_fields": True}


def test_a_valid_selected_action_is_known_and_not_exported():
    safe = _safe_edge_event({"defense": {"action": "isolate"}, "enforcement": {
        "mode": "dry_run", "result": "planned_not_applied", "trace_id": "trace-18",
        "selected_action": "isolate",
    }})
    assert safe == {"action": "isolate", "mode": "dry_run", "result": "planned_not_applied",
                    "trace_id": "trace-18"}
    assert "selected_action" not in safe and "unknown_fields" not in safe


@pytest.mark.parametrize("bad", ["bogus", "<b>isolate</b>", "ISOLATE ", "", None, 3, ["notify"], {"a": 1}])
def test_a_malformed_selected_action_is_marked_unknown(bad):
    safe = _safe_edge_event({"defense": {"action": "notify"}, "enforcement": {
        "mode": "dry_run", "result": "planned_not_applied", "trace_id": "trace-19",
        "selected_action": bad,
    }})
    assert safe == {"action": "notify", "mode": "dry_run", "result": "planned_not_applied",
                    "trace_id": "trace-19", "unknown_fields": True}




def test_fast_frame_uses_edge_risk_level_and_factors_without_reclassification():
    frame = _safe_event(EVENT, score=72, factors=["known_class", "corr_repeat_src_ip=4/300s"], risk_level="CRITICAL")
    assert frame["knowledge_status"] == "not_provided"
    assert frame["knowledge_refs"] == []
    assert frame["threat_level"] == "CRITICAL"
    assert frame["soc_summary"] == (
        "Edge tactical scorer derived risk score: 72; factors=known_class,corr_repeat_src_ip=4/300s"
    )
    assert frame["evidence_refs"] == ["suricata_sid:42"]
    assert frame["provenance"]["evidence_refs"] == ["caller"]


def test_fast_frame_keeps_observed_outcome_separate_from_defensive_state():
    event = {**EVENT, "normalized": {**EVENT["normalized"], "action": "allowed"}}
    frame = _safe_event(event, score=72, factors=["known_class"], risk_level="HIGH")

    assert "Observed normalized event outcome: allowed" in frame["known_facts"]
    assert frame["current_defensive_state"] == "NOTIFY"
    assert frame["evidence_refs"] == ["suricata_sid:42"]
    assert frame["provenance"] == {
        "known_facts": ["caller"], "evidence_refs": ["caller"],
    }


def test_submit_preserves_only_allowlisted_outcome_through_production_frame_builder():
    from types import SimpleNamespace

    adapter = LiveMioAuxiliary()

    class Frame:
        def __init__(self, payload):
            self.payload = payload
            self.frame_id = payload["frame_id"]
            self.trace_id = payload["trace_id"]

        @classmethod
        def from_dict(cls, payload):
            return cls(payload)

        def to_dict(self):
            return dict(self.payload)

    class Core:
        def explain(self, frame, **kwargs):
            assert kwargs.get("knowledge_attempted") is False
            return SimpleNamespace(to_dict=lambda: {
                "schema_version": "mio.assistance.v1", "frame_id": frame.frame_id,
                "trace_id": frame.trace_id, "dependency_outcome": {"knowledge": "not_queried"},
            })

    adapter._frame_type, adapter._core = Frame, Core()
    adapter._knowledge_statuses = frozenset({"not_queried"})
    allowed_event = {**EVENT, "normalized": {**EVENT["normalized"], "action": "allowed"}}
    accepted = adapter.submit(allowed_event, score=72, factors=["known_class"], risk_level="HIGH")
    deadline = time.monotonic() + 1
    frame = None
    while time.monotonic() < deadline and frame is None:
        frame = adapter.frame_snapshot(accepted["generation"])
        if frame is None:
            time.sleep(0.005)

    assert frame is not None
    assert "Observed normalized event outcome: allowed" in frame["known_facts"]
    assert frame["current_defensive_state"] == "NOTIFY"
    assert frame["evidence_refs"] == ["suricata_sid:42"]
    assert frame["provenance"] == {
        "known_facts": ["caller"], "evidence_refs": ["caller"],
    }
    deadline = time.monotonic() + 1
    result = adapter.snapshot()
    while time.monotonic() < deadline and result["status"] in {"pending", "queued"}:
        time.sleep(0.005)
        result = adapter.snapshot()
    assert result["knowledge"] == {"status": "not_queried", "refs": []}
    assert '"status": "not_queried"' in json.dumps(result, sort_keys=True)

    raw_outcome = "allowed <script>alert(1)</script>"
    disallowed_event = {**EVENT, "normalized": {**EVENT["normalized"], "action": raw_outcome}}
    rejected = adapter.submit(disallowed_event, score=72, factors=["known_class"], risk_level="HIGH")
    deadline = time.monotonic() + 1
    rejected_frame = None
    while time.monotonic() < deadline and rejected_frame is None:
        rejected_frame = adapter.frame_snapshot(rejected["generation"])
        if rejected_frame is None:
            time.sleep(0.005)

    assert rejected_frame is not None
    assert not any("normalized event outcome" in fact for fact in rejected_frame["known_facts"])
    assert raw_outcome not in json.dumps(rejected_frame)
    assert rejected_frame["current_defensive_state"] == "NOTIFY"


def test_frame_refs_require_real_numeric_event_identifier_and_never_use_frame_ids():
    frame = _safe_event({"normalized": {"event_id": 108, "event_type": "alert"}}, 5, [], "LOW")
    assert frame["evidence_refs"] == ["ev:alert:108"]
    no_ids = _safe_event({"normalized": {"event_type": "alert"}}, 5, [], "LOW")
    assert no_ids["evidence_refs"] == []
    assert no_ids["frame_id"] not in no_ids["evidence_refs"]
    assert no_ids["trace_id"] not in no_ids["evidence_refs"]


def test_allowlisted_context_has_field_level_provenance_and_explicit_unavailable_values():
    event = {"normalized": {
        "event_type": "alert", "sid": 42, "severity": 2, "attack_type": "ET SCAN Example",
        "category": "Attempted Information Leak", "protocol": "TCP", "target_port": 443,
        "technique_ids": ["T1046", "bad"], "ts": "2026-10-31T10:20:30Z",
        "src_ip": "203.0.113.99", "payload": "must not pass",
    }}
    context = _source_context(event)
    assert context["fields"]["attack_type"] == {
        "value": "ET SCAN Example", "status": "observed", "provenance": "rust_core_normalized_event",
    }
    assert context["fields"]["technique_ids"]["value"] == ["T1046"]
    assert context["fields"]["protocol"]["status"] == "observed"
    assert context["fields"]["target_port"]["value"] == 443
    assert context["fields"]["category"]["provenance"] == "rust_core_normalized_event"
    assert "src_ip" not in json.dumps(context) and "must not pass" not in json.dumps(context)
    missing = _source_context({"normalized": {"event_type": "alert", "sid": 42}})
    assert missing["fields"]["attack_type"] == {
        "value": None, "status": "unavailable", "provenance": "rust_core_normalized_event",
    }
    frame = _safe_event({"normalized": {"event_type": "alert", "sid": 42}}, 12, [], "LOW")
    assert "SOURCE_FIELD_UNAVAILABLE:attack_type" in frame["unknowns"]


def test_handoff_binding_matches_same_edge_event_and_flags_tampering():
    payload = {
        "status": "complete", "generation": "7", "trace_id": "edge-trace-7",
        "source_context": {"event_key": "event-7"},
        "edge_event": {"trace_id": "edge-trace-7", "action": "notify", "mode": "dry_run", "result": "planned_not_applied"},
        "advisory": {"trace_id": "mio-trace-7", "frame_id": "frame-7"},
        "handoff_binding": {"status": "matched", "generation": "7", "event_key": "event-7",
                            "edge_trace_id": "edge-trace-7", "edge_action": "notify",
                            "edge_mode": "dry_run", "edge_result": "planned_not_applied",
                            "mio_trace_id": "mio-trace-7", "frame_id": "frame-7"},
    }
    assert _binding_matches(payload)
    altered = json.loads(json.dumps(payload))
    altered["handoff_binding"]["edge_result"] = "applied"
    assert not _binding_matches(altered)
    mismatched = json.loads(json.dumps(payload))
    mismatched["edge_event"]["trace_id"] = "other-edge-trace"
    assert not _binding_matches(mismatched)


@pytest.mark.parametrize("marker", ["trace_id", "action", "mode", "result"])
def test_handoff_binding_requires_nonempty_edge_correlation_markers(marker):
    payload = {
        "status": "complete", "generation": "7", "trace_id": "edge-trace-7",
        "source_context": {"event_key": "event-7"},
        "edge_event": {"trace_id": "edge-trace-7", "action": "notify", "mode": "dry_run", "result": "planned_not_applied"},
        "advisory": {"trace_id": "mio-trace-7", "frame_id": "frame-7"},
        "handoff_binding": {"status": "matched", "generation": "7", "event_key": "event-7",
                            "edge_trace_id": "edge-trace-7", "edge_action": "notify",
                            "edge_mode": "dry_run", "edge_result": "planned_not_applied",
                            "mio_trace_id": "mio-trace-7", "frame_id": "frame-7"},
    }
    edge_key = marker
    binding_key = {"trace_id": "edge_trace_id", "action": "edge_action",
                   "mode": "edge_mode", "result": "edge_result"}[marker]
    payload["edge_event"][edge_key] = None
    payload["handoff_binding"][binding_key] = None
    assert not _binding_matches(payload)

def test_actual_tactical_scorer_all_eleven_factors_reach_fast_frame():
    features = {
        "suricata_sev": 2, "suricata_sid": 9901101,
        "suricata_signature": "beacon exfil arp spoof port scan brute phish",
        "suricata_category": "attempted-admin", "target_port": 22,
        "suricata_action": "blocked",
    }
    score, factors = agent.TacticalScorer().score_with_features(features)
    assert len(factors) == 11
    frame = _safe_event(EVENT, score, factors, agent._risk_level(score))
    assert frame["soc_summary"] == (
        "Edge tactical scorer derived risk score: 93; factors=" + ",".join(factors)
    )
    assert frame["truncated"] is False
    assert len(frame["soc_summary"]) <= 480


def test_fast_frame_marks_factor_truncation_within_shared_summary_cap():
    factors = [f"factor-{index}-" + ("x" * 96) for index in range(12)]
    frame = _safe_event(EVENT, score=72, factors=factors, risk_level="HIGH")
    assert len(frame["soc_summary"]) <= 480
    assert frame["truncated"] is True
    assert "FACTORS_TRUNCATED" in frame["soc_summary"]


def test_complete_result_envelope_cap_includes_advisory_and_edge_provenance():
    from types import SimpleNamespace

    adapter = LiveMioAuxiliary()
    entered = time.monotonic() + 1
    while time.monotonic() < entered and adapter._frame_type is None:
        time.sleep(0.01)

    class Frame:
        @classmethod
        def from_dict(cls, payload):
            return SimpleNamespace(frame_id=payload["frame_id"], trace_id=payload["trace_id"])

    class Core:
        def explain(self, frame, **kwargs):
            return SimpleNamespace(to_dict=lambda: {
                "schema_version": "mio.assistance.v1", "frame_id": frame.frame_id,
                "trace_id": frame.trace_id, "dependency_outcome": {"knowledge": "absent"},
                "padding": "x" * 16000,
            })

    adapter._frame_type, adapter._core = Frame, Core()
    adapter._knowledge_statuses = frozenset({"absent"})
    adapter.submit(EVENT, score=70, factors=[], risk_level="HIGH")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and adapter.snapshot()["status"] in {"pending", "queued", "starting"}:
        time.sleep(0.01)
    result = adapter.snapshot()
    assert result["reason"] == "result_too_large"
    assert len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")) <= 16 * 1024


def test_core_completion_after_max_age_is_degraded_and_never_current():
    from types import SimpleNamespace

    adapter = LiveMioAuxiliary(max_age_seconds=0.08)
    class Frame:
        @classmethod
        def from_dict(cls, payload):
            return SimpleNamespace(frame_id=payload["frame_id"], trace_id=payload["trace_id"])
    class Core:
        def explain(self, frame, **kwargs):
            time.sleep(0.12)
            return SimpleNamespace(to_dict=lambda: {
                "schema_version": "mio.assistance.v1", "frame_id": frame.frame_id,
                "trace_id": frame.trace_id, "dependency_outcome": {"knowledge": "absent"},
            })
    adapter._frame_type, adapter._core = Frame, Core()
    adapter._knowledge_statuses = frozenset({"absent"})
    adapter.submit(EVENT, score=60, factors=[], risk_level="HIGH")
    deadline = time.monotonic() + 1
    result = adapter.snapshot()
    while time.monotonic() < deadline and result.get("status") in {"pending", "queued"}:
        time.sleep(0.01)
        result = adapter.snapshot()
    assert result["status"] == "degraded"
    assert result["reason"] == "stale_job"
    assert result["advisory"] is None
    assert result["is_current"] is False


class _DecisionLayers:
    def enrich_with_second_pass(self, event, advisory):
        return {"status": "completed"}


class _DecisionLogger:
    def log_decision(self, record):
        return True


class _Scorer:
    class Result:
        score = 72
        factors = ["known_class"]
        shadow = {"status": "complete", "score": 72, "matches": True,
                  "factors": [f"factor-{index}-" + ("x" * 200) for index in range(14)]}

    def score(self, features):
        return self.Result()


class _Adapter:
    def __init__(self, status):
        self.status = status
        self.calls = []

    def submit(self, event, *, score, factors, risk_level):
        self.calls.append((event, score, list(factors), risk_level))
        return {
            "schema_version": "azazel.mio_auxiliary.v1", "status": self.status,
            "reason": "", "authority": "read_only_advisory", "source": "mio_shared_core",
            "generation": "1", "max_age_seconds": 10.0, "trace_id": "rust-trace-1",
            "provenance": {"observations": ["rust_core_normalized_event"], "derived_signals": ["edge_tactical_scorer_v1"]},
            "knowledge": {"status": "not_provided", "refs": []}, "advisory": None,
        }


def _build(adapter, event=EVENT):
    with patch.object(agent, "SCORER", _Scorer()), patch.object(
        agent, "DECISION_LAYERS", _DecisionLayers()
    ), patch.object(agent, "DECISION_LOGGER", _DecisionLogger()), patch.object(
        agent, "LIVE_MIO_AUXILIARY", adapter
    ), patch.object(agent, "_evaluate_correlation", return_value={"force_llm": False}), patch.object(
        agent, "_metrics_inc"
    ), patch.object(agent, "_LAST_RISK_SCORE", 0), patch.object(agent, "_LAST_STATE_NAME", "NORMAL"):
        return agent._build_advisory(event)


def test_live_event_consumer_enqueues_core_advisory_after_edge_score():
    adapter = _Adapter("queued")
    result = _build(adapter)
    assert len(adapter.calls) == 1
    assert adapter.calls[0][1:] == (72, ["known_class"], "HIGH")
    assert result["mio_auxiliary"]["authority"] == "read_only_advisory"
    assert result["mio_auxiliary"]["provenance"]["derived_signals"] == ["edge_tactical_scorer_v1"]
    assert result["score_engine"] == "tactical_scorer_v1"
    assert result["mio_score_comparison"]["edge_score"] == result["risk_score"]
    assert result["mio_score_comparison"]["matches"] is True
    assert len(result["mio_score_comparison"]["mio_factors"]) == 12
    assert all(len(item) <= 96 for item in result["mio_score_comparison"]["mio_factors"])




def test_build_advisory_passes_nondefault_edge_risk_level_and_exact_factors_to_mio():
    adapter = _Adapter("queued")
    with patch.object(agent, "CRITICAL_MIN", 70):
        result = _build(adapter)
    assert result["risk_score"] == 72
    assert result["risk_level"] == "CRITICAL"
    assert adapter.calls == [(EVENT, 72, ["known_class"], "CRITICAL")]


def test_nondefault_critical_threshold_reaches_production_frame_with_provenance():
    from types import SimpleNamespace

    adapter = LiveMioAuxiliary()

    class Frame:
        def __init__(self, payload):
            self.payload = payload
            self.frame_id = payload["frame_id"]
            self.trace_id = payload["trace_id"]

        @classmethod
        def from_dict(cls, payload):
            return cls(payload)

        def to_dict(self):
            return dict(self.payload)

    class Core:
        def explain(self, frame, **kwargs):
            return SimpleNamespace(to_dict=lambda: {
                "schema_version": "mio.assistance.v1", "frame_id": frame.frame_id,
                "trace_id": frame.trace_id, "dependency_outcome": {"knowledge": "absent"},
                "hypotheses": [{"summary": "review elevated tactical score", "verification": "unverified"}],
            })

    adapter._frame_type, adapter._core = Frame, Core()
    adapter._knowledge_statuses = frozenset({"absent"})
    event = {**EVENT, "enforcement": {
        **EVENT.get("enforcement", {}), "mode": "dry_run", "result": "no_disruptive_action",
    }}
    try:
        with patch.object(agent, "CRITICAL_MIN", 70):
            result = _build(adapter, event)

        assert result["risk_score"] == 72
        assert result["risk_level"] == "CRITICAL"
        assert result["mio_auxiliary"]["status"] == "queued"
        generation = result["mio_auxiliary"]["generation"]

        deadline = time.monotonic() + 1
        completed = adapter.snapshot()
        while time.monotonic() < deadline and completed["status"] not in {"complete", "degraded", "unavailable"}:
            time.sleep(0.005)
            completed = adapter.snapshot()

        assert completed["status"] == "complete"
        assert completed["generation"] == generation
        assert completed["is_current"] is True
        assert completed["provenance"]["derived_signals"] == ["edge_tactical_scorer_v1"]
        assert completed["advisory"]["hypotheses"][0]["verification"] == "unverified"
        assert completed["handoff_binding"]["valid"] is True

        frame = adapter.frame_snapshot(generation)
        assert frame is not None
        assert frame["threat_level"] == "CRITICAL"
        assert frame["soc_summary"] == (
            "Edge tactical scorer derived risk score: 72; factors=known_class"
        )
        assert frame["known_facts"] == [
            "Observed event type: alert", "Observed Suricata SID: 42", "Observed Suricata severity: 2",
        ]
        assert frame["evidence_refs"] == ["suricata_sid:42"]
        assert frame["provenance"] == {
            "known_facts": ["caller"], "evidence_refs": ["caller"],
        }
    finally:
        adapter._queue.join()

def test_completed_mio_result_is_persisted_and_reaches_validated_ui_snapshot_overlay(tmp_path):
    from azazel_edge_control import daemon
    original = (agent.LIVE_MIO_AUXILIARY, agent.SNAPSHOT_PATH, agent.ADVISORY_PATH,
                daemon.AGENT_SNAPSHOT_PATH, daemon.AGENT_SNAPSHOT_KEYS,
                daemon.AGENT_SNAPSHOT_VALIDATORS.get("mio_auxiliary"))
    try:
        class CompletedAdapter:
            def snapshot(self):
                return {"schema_version": "azazel.mio_auxiliary.v1", "status": "complete",
                        "reason": "", "authority": "read_only_advisory", "source": "mio_shared_core",
                        "generation": "1", "max_age_seconds": 10.0, "trace_id": "rust-trace-1",
                        "provenance": {"observations": ["rust_core_normalized_event"],
                                       "derived_signals": ["edge_tactical_scorer_v1"]},
                        "knowledge": {"status": "not_provided", "refs": []},
                        "advisory": {"hypotheses": [{"verification": "unverified"}]},
                        "edge_event": {"action": "notify", "trace_id": "rust-trace-1"}}

            def current_generation(self):
                return 2

        adapter = CompletedAdapter()
        agent.LIVE_MIO_AUXILIARY = adapter
        agent.SNAPSHOT_PATH = tmp_path / "ai_snapshot.json"
        agent.ADVISORY_PATH = tmp_path / "ai_advisory.json"
        agent._write_json(agent.ADVISORY_PATH, {"risk_score": 51, "recommendation": "Observe"})
        agent._update_ui_snapshot({"risk_score": 51, "recommendation": "Observe"}, count_suricata=False)
        data = json.loads(agent.SNAPSHOT_PATH.read_text(encoding="utf-8"))
        assert data["mio_auxiliary"]["status"] == "complete"
        assert data["mio_auxiliary"]["authority"] == "read_only_advisory"
        assert data["mio_auxiliary"]["edge_event"]["action"] == "notify"
        assert data["mio_auxiliary"]["is_current"] is False
        assert data["mio_auxiliary"]["edge_action_label"].startswith("Edge action/result")

        daemon.AGENT_SNAPSHOT_PATH = agent.SNAPSHOT_PATH
        if "mio_auxiliary" not in daemon.AGENT_SNAPSHOT_KEYS:
            daemon.AGENT_SNAPSHOT_KEYS = (*daemon.AGENT_SNAPSHOT_KEYS, "mio_auxiliary")
        daemon.AGENT_SNAPSHOT_VALIDATORS["mio_auxiliary"] = daemon._valid_object
        merged = daemon._overlay_agent_snapshot({"existing": True})
        assert merged["mio_auxiliary"]["advisory"]["hypotheses"][0]["verification"] == "unverified"
    finally:
        (agent.LIVE_MIO_AUXILIARY, agent.SNAPSHOT_PATH, agent.ADVISORY_PATH,
         daemon.AGENT_SNAPSHOT_PATH, daemon.AGENT_SNAPSHOT_KEYS, prior_validator) = original
        if prior_validator is None:
            daemon.AGENT_SNAPSHOT_VALIDATORS.pop("mio_auxiliary", None)
        else:
            daemon.AGENT_SNAPSHOT_VALIDATORS["mio_auxiliary"] = prior_validator


def test_edge_decision_fields_are_identical_when_mio_is_missing_failing_slow_or_full():
    baseline = _build(_Adapter("queued"))
    for condition in ("unavailable", "mio_failure", "stale_job", "queue_full"):
        candidate = _build(_Adapter(condition))
        for key in ("risk_score", "risk_level", "recommendation", "state_name", "user_state", "score_factors", "score_engine", "trace_id"):
            assert candidate[key] == baseline[key]


def test_score_comparison_is_attached_only_to_matching_generation_and_trace():
    comparison = {"schema_version": "azazel.edge_score_comparison.v1", "authority": "comparison_only",
                  "generation": "3", "trace_id": "trace-3"}
    original = {"generation": "3", "trace_id": "trace-3", "status": "complete"}
    attached = agent._attach_current_score_comparison(original, {"generation": "3", "trace_id": "trace-3"}, comparison)
    assert attached["edge_score_comparison"] == comparison
    assert "edge_score_comparison" not in original
    stale = agent._attach_current_score_comparison(original, {"generation": "2", "trace_id": "trace-3"}, comparison)
    assert "edge_score_comparison" not in stale
    uncorrelated = agent._attach_current_score_comparison(original, {"generation": "3", "trace_id": "trace-other"}, comparison)
    assert "edge_score_comparison" not in uncorrelated


def test_missing_or_failing_shared_core_returns_explicit_safe_status():
    adapter = LiveMioAuxiliary()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and adapter._core is None and not adapter._import_error:
        time.sleep(0.01)
    adapter._core = None
    adapter._import_error = "package_unavailable"
    adapter.submit(EVENT, score=72, factors=["derived"], risk_level="HIGH")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and adapter.snapshot()["status"] in {"starting", "queued", "pending"}:
        time.sleep(0.01)
    assert adapter.snapshot()["status"] == "unavailable"
    assert adapter.snapshot()["reason"] == "package_unavailable"
    assert adapter.snapshot()["authority"] == "read_only_advisory"


def test_slow_worker_is_latest_only_and_trace_generation_is_bounded():
    adapter = LiveMioAuxiliary(max_age_seconds=10)
    entered = __import__("threading").Event()
    release = __import__("threading").Event()

    class SlowCore:
        def explain(self, frame, **kwargs):
            entered.set()
            release.wait(0.5)
            raise RuntimeError("fixture")

    class Frame:
        @classmethod
        def from_dict(cls, value):
            return value

    adapter._core, adapter._frame_type = SlowCore(), Frame
    adapter.submit(EVENT, score=70, factors=[], risk_level="HIGH")
    assert entered.wait(1)
    baseline = _build(_Adapter("baseline"))
    started = time.monotonic()
    while_busy = _build(adapter)
    assert time.monotonic() - started < 0.2
    for key in ("risk_score", "risk_level", "recommendation", "state_name", "trace_id"):
        assert while_busy[key] == baseline[key]
    for i in range(20):
        event = {**EVENT, "enforcement": {"trace_id": f"trace-{i}"}}
        queued = adapter.submit(event, score=i, factors=[], risk_level="LOW")
        assert queued["max_age_seconds"] == 10
        assert queued["trace_id"] == f"trace-{i}"
        assert queued["authority"] == "read_only_advisory"
    release.set()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not adapter.snapshot().get("reason", "").startswith("mio_failure"):
        time.sleep(0.01)
    assert adapter.snapshot()["reason"].startswith("mio_failure")
    assert adapter.snapshot()["advisory"] is None


def test_installed_shared_candidate_core_returns_advisory_with_typed_knowledge_status():
    adapter = LiveMioAuxiliary()
    adapter.submit(EVENT, score=72, factors=["known_class"], risk_level="HIGH")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and adapter.snapshot()["status"] in {"pending", "starting", "queued"}:
        time.sleep(0.01)
    result = adapter.snapshot()
    assert result["status"] == "complete", result.get("reason")
    assert result["authority"] == "read_only_advisory"
    assert result["knowledge"]["status"] == "not_queried"
    assert result["knowledge"]["refs"] == []
    assert '"status": "not_queried"' in json.dumps(result, sort_keys=True)
    assert result["provenance"]["observations"] == ["rust_core_normalized_event"]
    assert result["provenance"]["derived_signals"] == ["edge_tactical_scorer_v1"]
    assert result["advisory"]["hypotheses"]
    assert all(hypothesis.get("verification") == "unverified" for hypothesis in result["advisory"]["hypotheses"])


@pytest.mark.parametrize("forged_status", ["forged-private-secret", None])
def test_invalid_shared_knowledge_status_is_rejected_without_echo_or_logging(forged_status, caplog):
    adapter = LiveMioAuxiliary()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and adapter._frame_type is None:
        time.sleep(0.01)
    assert adapter._frame_type is not None

    class ForgedCore:
        def explain(self, frame, **kwargs):
            return type("Assistance", (), {"to_dict": lambda self: {
                "schema_version": "mio.assistance.v1",
                "frame_id": frame.frame_id,
                "trace_id": frame.trace_id,
                "dependency_outcome": {"knowledge": forged_status},
            }})()

    adapter._core = ForgedCore()
    adapter.submit(EVENT, score=72, factors=["known_class"], risk_level="HIGH")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and adapter.snapshot()["reason"] != "invalid_knowledge_status":
        time.sleep(0.01)

    result = adapter.snapshot()
    serialized = json.dumps(result, sort_keys=True)
    assert result["status"] == "degraded"
    assert result["reason"] == "invalid_knowledge_status"
    assert result["knowledge"]["status"] == "rejected"
    assert result["advisory"] is None
    assert "forged-private-secret" not in serialized
    assert "forged-private-secret" not in caplog.text


@pytest.mark.parametrize("oversized_edge", [False, True])
def test_combined_snapshot_envelope_remains_bounded_after_prose_removal(tmp_path, monkeypatch, oversized_edge):
    import json
    from azazel_edge_ai import agent
    from azazel_edge_ai.mio_live_auxiliary import MAX_RESULT_BYTES

    class Fast:
        def current_generation(self):
            return "1"
        def snapshot(self):
            return {"status": "complete", "generation": "1", "is_current": True,
                    "knowledge": {"status": "not_queried", "refs": []},
                    "advisory": {"summary": "x" * (MAX_RESULT_BYTES - 450)},
                    "edge_event": {"unexpected": "y" * MAX_RESULT_BYTES} if oversized_edge else {}}
    class Model:
        def snapshot(self):
            return {"summary": "z" * 300, "request_count": 2, "metered_request_count": 1,
                    "prompt_tokens": 41, "completion_tokens": 12, "model": "fixture",
                    "unknowns": ["evidence gap"]}
    monkeypatch.setattr(agent, "LIVE_MIO_AUXILIARY", Fast())
    monkeypatch.setattr(agent, "LIVE_MIO_MODEL_LANE", Model())
    monkeypatch.setattr(agent, "SNAPSHOT_PATH", tmp_path / "snapshot.json")
    monkeypatch.setattr(agent, "_default_route_info", lambda: {})
    agent._update_ui_snapshot({"risk_score": 51}, count_suricata=False)
    mio = json.loads(agent.SNAPSHOT_PATH.read_text())["mio_auxiliary"]
    assert len(json.dumps(mio, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")) <= MAX_RESULT_BYTES
    assert mio["status"] == "degraded" and mio["is_current"] is False
    assert mio["authority"] == "read_only_advisory"
    assert mio["model_analysis"]["prompt_tokens"] == 41
    # Prose-drop path: unknowns is omitted entirely (never [] = "no gap").
    assert mio["model_analysis"]["reason"] == "envelope_size_limit"
    assert mio["model_analysis"].get("summary", "") == ""
    assert "unknowns" not in mio["model_analysis"]
    assert mio["knowledge"]["status"] == "not_provided"


def test_combined_model_prose_trim_omits_unknowns_and_marks_model_noncurrent(tmp_path, monkeypatch):
    import json
    from azazel_edge_ai import agent
    from azazel_edge_ai.mio_live_auxiliary import MAX_RESULT_BYTES

    class Fast:
        def current_generation(self):
            return "1"
        def snapshot(self):
            return {"status": "complete", "generation": "1", "is_current": True,
                    "knowledge": {"status": "not_queried", "refs": []},
                    "advisory": {"summary": "fixed fast summary"}, "edge_event": {}}

    class Model:
        def snapshot(self):
            return {"schema_version": "azazel.mio_model_analysis.v1", "status": "complete",
                    "is_current": True, "fast_generation": "1", "summary": "z" * MAX_RESULT_BYTES,
                    "request_count": 2, "metered_request_count": 1, "prompt_tokens": 41,
                    "completion_tokens": 12, "model": "fixture", "unknowns": ["evidence gap"]}

    monkeypatch.setattr(agent, "LIVE_MIO_AUXILIARY", Fast())
    monkeypatch.setattr(agent, "LIVE_MIO_MODEL_LANE", Model())
    monkeypatch.setattr(agent, "SNAPSHOT_PATH", tmp_path / "snapshot.json")
    monkeypatch.setattr(agent, "_default_route_info", lambda: {})
    agent._update_ui_snapshot({"risk_score": 51}, count_suricata=False)
    mio = json.loads(agent.SNAPSHOT_PATH.read_text())["mio_auxiliary"]
    assert len(json.dumps(mio, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")) <= MAX_RESULT_BYTES
    assert mio["status"] == "complete" and mio["is_current"] is True
    assert mio["model_analysis"]["status"] == "degraded" and mio["model_analysis"]["is_current"] is False
    assert mio["model_analysis"]["reason"] == "envelope_size_limit"
    assert mio["model_analysis"]["summary"] == ""
    assert "unknowns" not in mio["model_analysis"]
    assert mio["model_analysis"]["prompt_tokens"] == 41


def test_not_queried_status_is_persisted_in_agent_snapshot(tmp_path, monkeypatch):
    import json
    from azazel_edge_ai import agent

    class Fast:
        def current_generation(self):
            return "1"
        def snapshot(self):
            return {"status": "complete", "generation": "1", "is_current": True,
                    "knowledge": {"status": "not_queried", "refs": []},
                    "advisory": None, "edge_event": {}}
    class Model:
        def snapshot(self):
            return {"status": "disabled"}
    monkeypatch.setattr(agent, "LIVE_MIO_AUXILIARY", Fast())
    monkeypatch.setattr(agent, "LIVE_MIO_MODEL_LANE", Model())
    monkeypatch.setattr(agent, "SNAPSHOT_PATH", tmp_path / "snapshot.json")
    monkeypatch.setattr(agent, "_default_route_info", lambda: {})
    agent._update_ui_snapshot({"risk_score": 51}, count_suricata=False)
    serialized = agent.SNAPSHOT_PATH.read_text()
    mio = json.loads(serialized)["mio_auxiliary"]
    assert mio["knowledge"] == {"status": "not_queried", "refs": []}
    assert '"status": "not_queried"' in serialized


# ----------------------------------------------------------------------------
# Isolation of optional MIO lanes from Edge persistence (_handle_event).

_ISOLATION_SECRET = "SECRET-model-enqueue-7f3a"


def _isolation_event() -> dict:
    import pathlib
    fixture = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "rust_core_event_v1.json"
    return json.loads(fixture.read_text(encoding="utf-8"))


@pytest.fixture
def isolated_edge(tmp_path, monkeypatch):
    for name in ("ADVISORY_PATH", "EVENT_LOG_PATH", "SNAPSHOT_PATH", "METRICS_PATH", "POLICY_PATH",
                 "LLM_DEFERRED_LOG_PATH", "LLM_RESULT_LOG_PATH"):
        monkeypatch.setattr(agent, name, tmp_path / name.lower())
    monkeypatch.setattr(agent, "_route_llm", lambda event, advisory: None)
    monkeypatch.setattr(agent, "CORE_RECORDER", None)
    log_dir = tmp_path / "log-ai"
    log_dir.mkdir()
    monkeypatch.setattr(agent, "DECISION_EXPLANATIONS_PATH", log_dir / "decision-explanations.jsonl")
    monkeypatch.setattr(agent, "DECISION_EXPLANATIONS", None)
    assert agent._start_decision_explanations() is not None
    # Deterministic, non-networked auxiliary: fixed degraded status, no worker thread.
    monkeypatch.setattr(agent.LIVE_MIO_AUXILIARY, "submit",
                        lambda *a, **k: {"status": "unavailable", "reason": "test_stub", "generation": ""})
    return tmp_path


def test_model_enqueue_failure_still_persists_event_advisory_and_snapshot(isolated_edge, monkeypatch, caplog):
    def boom(*_a, **_k):
        raise RuntimeError(_ISOLATION_SECRET)

    monkeypatch.setattr(agent.LIVE_MIO_MODEL_LANE, "submit", boom)
    caplog.set_level("WARNING", logger="azazel-edge-ai-agent")
    agent._handle_event(_isolation_event())

    event_log = isolated_edge / "event_log_path"
    advisory_path = isolated_edge / "advisory_path"
    snapshot = isolated_edge / "snapshot_path"
    assert event_log.exists() and event_log.read_text(encoding="utf-8").strip()
    assert advisory_path.exists()
    assert snapshot.exists()
    # Fixed degraded indication only; the exception text never leaks.
    assert "mio model enqueue degraded" in caplog.text
    assert _ISOLATION_SECRET not in caplog.text
    assert _ISOLATION_SECRET not in advisory_path.read_text(encoding="utf-8")
    assert _ISOLATION_SECRET not in snapshot.read_text(encoding="utf-8")


def test_model_enqueue_failure_leaves_edge_decision_fields_unchanged(isolated_edge, monkeypatch):
    fields = ("risk_score", "risk_level", "recommendation", "state_name", "score_engine")
    advisory_path = isolated_edge / "advisory_path"

    monkeypatch.setattr(agent.LIVE_MIO_MODEL_LANE, "submit", lambda *a, **k: {"status": "queued"})
    agent._handle_event(_isolation_event())
    baseline = json.loads(advisory_path.read_text(encoding="utf-8"))

    def boom(*_a, **_k):
        raise RuntimeError(_ISOLATION_SECRET)

    monkeypatch.setattr(agent.LIVE_MIO_MODEL_LANE, "submit", boom)
    agent._handle_event(_isolation_event())
    failed = json.loads(advisory_path.read_text(encoding="utf-8"))

    for key in fields:
        assert failed.get(key) == baseline.get(key), key


def test_knowledge_failure_does_not_suppress_model_lane(isolated_edge, monkeypatch):
    def knowledge_boom(*_a, **_k):
        raise RuntimeError(_ISOLATION_SECRET)

    calls = []
    monkeypatch.setattr(agent.LIVE_MIO_AUXILIARY, "submit", knowledge_boom)
    monkeypatch.setattr(agent.LIVE_MIO_MODEL_LANE, "submit",
                        lambda *a, **k: calls.append(a) or {"status": "queued"})
    agent._handle_event(_isolation_event())

    assert len(calls) == 1
    assert (isolated_edge / "event_log_path").exists()
    assert (isolated_edge / "advisory_path").exists()
    assert (isolated_edge / "snapshot_path").exists()
    assert _ISOLATION_SECRET not in (isolated_edge / "advisory_path").read_text(encoding="utf-8")


class _FakeGovernance:
    def __init__(self):
        self.calls = []

    def record_structured_result(self, **kwargs):
        self.calls.append(kwargs)


def _run_model_analyze(monkeypatch, result, governance):
    monkeypatch.setattr(agent, "AI_GOVERNANCE", governance)
    monkeypatch.setattr(agent, "_analyze_mio_fast_result", lambda *a, **k: dict(result))
    return agent._governed_mio_model_analyze({"trace_id": "t-1"}, 5.0)


def test_truncated_model_output_audits_as_degraded_not_adopted(monkeypatch):
    governance = _FakeGovernance()
    _run_model_analyze(monkeypatch, {"outcome": "completed", "mio_state": "complete",
                                     "truncated_count": 1, "request_count": 1, "metered_request_count": 1},
                       governance)
    assert len(governance.calls) == 1
    assert governance.calls[0]["decision"] == "degraded"
    assert governance.calls[0]["metadata"]["truncated_count"] == 1


def test_untruncated_complete_model_output_is_still_adopted(monkeypatch):
    governance = _FakeGovernance()
    _run_model_analyze(monkeypatch, {"outcome": "completed", "mio_state": "complete",
                                     "truncated_count": 0, "request_count": 1, "metered_request_count": 1},
                       governance)
    assert governance.calls[0]["decision"] == "adopted"


def test_model_result_knowledge_status_reaches_durable_audit(monkeypatch):
    governance = _FakeGovernance()
    _run_model_analyze(monkeypatch, {"outcome": "completed", "mio_state": "complete", "truncated_count": 0,
                                     "knowledge_status": "projected"}, governance)
    assert governance.calls[0]["metadata"]["knowledge_status"] == "projected"


class _RecordingAudit:
    def __init__(self):
        self.entries = []

    def log(self, event, **kwargs):
        self.entries.append((event, kwargs))


def test_record_structured_result_persists_allowlisted_knowledge_status():
    from azazel_edge.ai_governance import AIGovernance
    audit = _RecordingAudit()
    AIGovernance(audit).record_structured_result(
        trace_id="t-1", source="mio", candidate_scope="mio_read_only_advisory", decision="adopted",
        metadata={"knowledge_status": "projected"})
    assert audit.entries[0][1]["payload"]["knowledge_status"] == "projected"


def test_record_structured_result_drops_unknown_knowledge_status_text():
    from azazel_edge.ai_governance import AIGovernance
    audit = _RecordingAudit()
    AIGovernance(audit).record_structured_result(
        trace_id="t-1", source="mio", candidate_scope="mio_read_only_advisory", decision="degraded",
        metadata={"knowledge_status": "free text with " + _ISOLATION_SECRET})
    payload = audit.entries[0][1]["payload"]
    assert "knowledge_status" not in payload
    assert _ISOLATION_SECRET not in json.dumps(payload)


@pytest.mark.parametrize("bad", ["not-a-number", "1.5", object(), float("nan"), 10**400])
def test_malformed_truncated_count_audits_as_degraded_without_raising(monkeypatch, bad):
    governance = _FakeGovernance()
    _run_model_analyze(monkeypatch, {"outcome": "completed", "mio_state": "complete",
                                     "truncated_count": bad, "request_count": 1, "metered_request_count": 1},
                       governance)
    assert len(governance.calls) == 1
    assert governance.calls[0]["decision"] == "degraded"
    assert governance.calls[0]["metadata"]["truncated_count"] == 4


@pytest.mark.parametrize("bad", ["", "1", 0.5, -1, 5, True, [], {}, None])
def test_non_integer_or_out_of_range_truncated_count_is_treated_as_truncated(monkeypatch, bad):
    governance = _FakeGovernance()
    _run_model_analyze(monkeypatch, {"outcome": "completed", "mio_state": "complete",
                                     "truncated_count": bad, "request_count": 1,
                                     "metered_request_count": 1}, governance)
    assert governance.calls[0]["decision"] == "degraded"
    assert governance.calls[0]["metadata"]["truncated_count"] == 4
