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




def test_fast_frame_uses_edge_risk_level_and_factors_without_reclassification():
    frame = _safe_event(EVENT, score=72, factors=["known_class", "corr_repeat_src_ip=4/300s"], risk_level="CRITICAL")
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
            return SimpleNamespace(to_dict=lambda: {
                "schema_version": "mio.assistance.v1", "frame_id": frame.frame_id,
                "trace_id": frame.trace_id, "dependency_outcome": {"knowledge": "absent"},
            })

    adapter._frame_type, adapter._core = Frame, Core()
    adapter._knowledge_statuses = frozenset({"absent"})
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
    def score_with_features(self, features):
        return 72, ["known_class"]


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
    assert result["knowledge"]["status"] == "absent"
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
                    "advisory": {"summary": "x" * (MAX_RESULT_BYTES - 450)},
                    "edge_event": {"unexpected": "y" * MAX_RESULT_BYTES} if oversized_edge else {}}
    class Model:
        def snapshot(self):
            return {"summary": "z" * 300, "request_count": 2, "metered_request_count": 1,
                    "prompt_tokens": 41, "completion_tokens": 12, "model": "fixture"}
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
    assert mio["knowledge"]["status"] == "not_provided"
