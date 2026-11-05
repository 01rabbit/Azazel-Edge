from __future__ import annotations

import json

import pytest

from azazel_edge.audit.logger import P0AuditLogger
from azazel_edge.ai_governance import AIGovernance
from azazel_edge_ai import agent


def _advisory(score=55):
    return {"trace_id": "trace-model-test", "risk_score": score,
            "risk_level": "MEDIUM", "signature": "synthetic alert",
            "category": "synthetic", "summary": "synthetic summary"}


def _bound_fast(generation, edge_trace, frame_id, frame_trace):
    """A complete, producer-bound fast envelope for model-lane tests."""
    event_key = "a1b2c3d4e5f60718293a4b5c"
    return {"status": "complete", "generation": str(generation), "is_current": True,
        "trace_id": edge_trace,
        "edge_event": {"action": "notify", "mode": "dry_run", "result": "planned_not_applied",
                       "trace_id": edge_trace},
        "source_context": {"event_key": event_key},
        "advisory": {"frame_id": frame_id, "trace_id": frame_trace},
        "handoff_binding": {"status": "matched", "valid": True, "generation": str(generation),
            "event_key": event_key, "edge_trace_id": edge_trace, "edge_action": "notify",
            "edge_mode": "dry_run", "edge_result": "planned_not_applied",
            "mio_trace_id": frame_trace, "frame_id": frame_id}}


def test_ambiguous_synthetic_event_passes_existing_governance_even_when_legacy_llm_off(tmp_path, monkeypatch):
    log_path = tmp_path / "ai-audit.jsonl"
    audit = P0AuditLogger(log_path)
    governance = AIGovernance(audit)
    monkeypatch.setattr(agent, "AI_GOVERNANCE", governance)
    monkeypatch.setattr(agent, "LLM_ENABLED", False)
    allowed, reason = agent._authorize_mio_model_event(_advisory())
    assert allowed is True
    assert reason == "ambiguous_azazel_core_mio_advisory"
    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert entries[-1]["stage"] == "input"
    assert entries[-1]["source"] == "azazel_core"
    assert entries[-1]["decision"] == "ambiguous_azazel_core_mio_advisory"


def test_nonambiguous_event_is_denied_by_existing_governance(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(tmp_path / "audit.jsonl")))
    allowed, reason = agent._authorize_mio_model_event(_advisory(score=10))
    assert not allowed
    assert reason == "advice_requires_ambiguous_suricata"


def test_edge_correlation_force_llm_allows_low_risk_and_audits_only_minimal_payload(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(log_path)))
    result = agent._authorize_mio_model_event({
        **_advisory(score=25), "correlation_force_llm": True,
    })
    assert result == (True, "ambiguous_azazel_core_mio_advisory")
    entry = json.loads(log_path.read_text().splitlines()[0])
    assert entry["payload"] == {
        "trace_id": "trace-model-test", "source": "azazel_core", "intent": "advice",
        "subject": "synthetic alert", "risk_score": 25, "category": "synthetic",
        "summary": "synthetic summary",
    }
    assert "correlation_force_llm" not in entry["payload"]
    assert "correlation" not in entry["payload"]


def test_low_risk_correlation_flag_requires_true_boolean(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(tmp_path / "audit.jsonl")))
    for value in (None, False, 1, "true"):
        advisory = _advisory(score=25)
        if value is not None:
            advisory["correlation_force_llm"] = value
        allowed, reason = agent._authorize_mio_model_event(advisory)
        assert not allowed
        assert reason == "advice_requires_ambiguous_suricata"


def test_risk_ambiguity_range_remains_unchanged_without_correlation_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(tmp_path / "audit.jsonl")))
    for score in (40, 55, 79):
        allowed, reason = agent._authorize_mio_model_event(_advisory(score=score))
        assert allowed
        assert reason == "ambiguous_azazel_core_mio_advisory"


def test_authorization_ignores_raw_correlation_and_accepts_only_private_strict_true(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(tmp_path / "audit.jsonl")))
    for raw_force in (1, "true"):
        for private_force in (None, False, 1, "true"):
            advisory = {**_advisory(score=25), "correlation": {"force_llm": raw_force}}
            if private_force is not None:
                advisory["correlation_force_llm"] = private_force
            allowed, reason = agent._authorize_mio_model_event(advisory)
            assert not allowed
            assert reason == "advice_requires_ambiguous_suricata"

        allowed, reason = agent._authorize_mio_model_event({
            **_advisory(score=25), "correlation": {"force_llm": raw_force},
            "correlation_force_llm": True,
        })
        assert allowed
        assert reason == "ambiguous_azazel_core_mio_advisory"

    # A malformed raw correlation value cannot disturb the ordinary risk band.
    allowed, reason = agent._authorize_mio_model_event({
        **_advisory(score=55), "correlation": {"force_llm": "true"},
    })
    assert allowed
    assert reason == "ambiguous_azazel_core_mio_advisory"


def test_azazel_core_mio_policy_is_narrow_and_denies_other_scopes_sources_and_risks(tmp_path):
    governance = AIGovernance(P0AuditLogger(tmp_path / "audit.jsonl"))
    allowed, reason = governance.should_invoke({"source": "azazel_core", "intent": "advice",
        "risk_band": "uncertain", "candidate_scope": "mio_read_only_advisory"})
    assert allowed and reason == "ambiguous_azazel_core_mio_advisory"
    for context in (
        {"source": "azazel_core", "intent": "advice", "risk_band": "low",
         "candidate_scope": "mio_read_only_advisory"},
        {"source": "azazel_core", "intent": "advice", "risk_band": "ambiguous",
         "candidate_scope": "other"},
        {"source": "azazel_core", "intent": "summary", "risk_band": "ambiguous",
         "candidate_scope": "mio_read_only_advisory"},
        {"source": "other", "intent": "advice", "risk_band": "ambiguous",
         "candidate_scope": "mio_read_only_advisory"},
    ):
        allowed, _ = governance.should_invoke(context)
        assert not allowed


def test_model_submission_defers_governance_authorization_to_worker(monkeypatch):
    calls = []

    class Lane:
        def submit(self, generation, trace_id, *, skip_reason="", authorization_payload=None, source_trace_id=""):
            calls.append((generation, trace_id, skip_reason, authorization_payload, source_trace_id))
            return {"status": "skipped"}

    monkeypatch.setattr(agent, "LIVE_MIO_MODEL_LANE", Lane())
    monkeypatch.setattr(agent, "MIO_MODEL_ENABLED", True)
    def should_not_run_here(_):
        raise AssertionError("authorization must run on the model worker")
    monkeypatch.setattr(agent, "_authorize_mio_model_event", should_not_run_here)
    agent._submit_governed_mio_model(_advisory(), {"generation": "7"})
    assert calls == [("7", "trace-model-test", "", {
        "trace_id": "trace-model-test", "edge_source_trace_id": "trace-model-test",
        "risk_score": 55, "correlation_force_llm": False, "risk_level": "MEDIUM",
        "signature": "synthetic alert", "category": "synthetic", "summary": "synthetic summary",
    }, "trace-model-test")]


def test_submission_propagates_only_edge_computed_correlation_boolean(monkeypatch):
    calls = []

    class Lane:
        def submit(self, generation, trace_id, *, skip_reason="", authorization_payload=None, source_trace_id=""):
            calls.append(authorization_payload)
            return {"status": "queued"}

    monkeypatch.setattr(agent, "LIVE_MIO_MODEL_LANE", Lane())
    monkeypatch.setattr(agent, "MIO_MODEL_ENABLED", True)
    advisory = {**_advisory(score=25), "correlation": {
        "force_llm": True, "hits_in_window": 32, "src_ip": "10.0.0.8",
        "history": [{"sid": 1, "secret": "must not propagate"}],
    }}
    agent._submit_governed_mio_model(advisory, {"generation": "7"})
    assert calls[0]["correlation_force_llm"] is True
    assert set(calls[0]) == {
        "trace_id", "edge_source_trace_id", "risk_score", "correlation_force_llm",
        "risk_level", "signature", "category", "summary",
    }
    assert "history" not in str(calls[0])
    assert "secret" not in str(calls[0])
    assert "src_ip" not in str(calls[0])


def test_governance_input_and_output_audits_share_edge_trace_while_frame_trace_is_preserved(tmp_path, monkeypatch):
    import time
    from azazel_edge_ai.mio_model_lane import LiveMioModelLane

    edge_trace = "edge-source-trace-42"
    frame_trace = "mio-generated-frame-trace"
    log_path = tmp_path / "audit.jsonl"
    governance = AIGovernance(P0AuditLogger(log_path))
    monkeypatch.setattr(agent, "AI_GOVERNANCE", governance)
    monkeypatch.setattr(agent, "MIO_MODEL_ENABLED", True)
    monkeypatch.setattr(agent, "_legacy_ollama_skip_reason", lambda _advisory: "")
    monkeypatch.setattr(agent, "_analyze_mio_fast_result", lambda payload, remaining, stale_check=None: {
        "summary": "completed", "uncertainties": [], "confidence": 0.0,
        "request_count": 1, "metered_request_count": 1, "unknown_usage_request_count": 0,
        "truncated_count": 0, "prompt_tokens": 10, "completion_tokens": 5,
        "usage_status": "complete", "outcome": "completed", "mio_state": "complete",
        "generation_method": "model", "frame_id": payload["frame_id"], "trace_id": payload["trace_id"],
    })
    lane = LiveMioModelLane(enabled=True, analyze=agent._governed_mio_model_analyze,
        fast_snapshot=lambda: _bound_fast("9", edge_trace, "frame-9", frame_trace),
        frame_snapshot=lambda _: {"frame_id": "frame-9", "trace_id": frame_trace,
                                  "evidence_refs": []},
        authorize=agent._authorize_mio_model_event)
    monkeypatch.setattr(agent, "LIVE_MIO_MODEL_LANE", lane)
    queued = agent._submit_governed_mio_model(_advisory(), {
        "generation": "9", "trace_id": edge_trace,
    })
    assert queued["status"] == "queued"
    deadline = time.monotonic() + 1
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] not in {"complete", "partial", "degraded", "skipped"}:
        time.sleep(0.005)
        result = lane.snapshot()
    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert [entry["stage"] for entry in entries] == ["input", "output"]
    assert [entry["trace_id"] for entry in entries] == [edge_trace, edge_trace]
    assert result["status"] == "complete"
    assert result["frame_trace_id"] == frame_trace


def test_lane_authorization_failure_skips_model_analysis():
    import time
    from azazel_edge_ai.mio_model_lane import LiveMioModelLane

    authorization_entered = __import__("threading").Event()
    release_authorization = __import__("threading").Event()
    model_calls = []

    def authorize(_payload):
        authorization_entered.set()
        release_authorization.wait(1)
        raise OSError("private audit detail")

    lane = LiveMioModelLane(enabled=True, analyze=lambda *args: model_calls.append(args) or {},
        fast_snapshot=lambda: _bound_fast("7", "trace-model-test", "f", "trace-model-test"),
        frame_snapshot=lambda _: {"frame_id": "f", "trace_id": "trace-model-test"},
        authorize=authorize)
    queued = lane.submit("7", "trace-model-test", authorization_payload={"risk_score": 55})
    assert queued["status"] == "queued"
    assert authorization_entered.wait(1)
    release_authorization.set()
    deadline = time.monotonic() + 1
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] != "skipped":
        time.sleep(0.005)
        result = lane.snapshot()
    assert result["status"] == "skipped"
    assert result["reason"] == "governance_denied:audit_failed"
    assert model_calls == []
    assert "private audit detail" not in str(result)


def test_lane_authorized_analysis_starts_only_after_authorization_succeeds():
    import threading
    import time
    from azazel_edge_ai.mio_model_lane import LiveMioModelLane

    authorized = threading.Event()
    order = []

    def authorize(_payload):
        order.append("authorized")
        authorized.set()
        return True, "ambiguous_suricata"

    def analyze(_payload, _remaining):
        assert authorized.is_set()
        order.append("model")
        return {"outcome": "completed", "mio_state": "complete", "generation_method": "model",
                "truncated_count": 0,
                "frame_id": "f", "trace_id": "trace-model-test"}

    lane = LiveMioModelLane(enabled=True, analyze=analyze,
        fast_snapshot=lambda: _bound_fast("7", "trace-model-test", "f", "trace-model-test"),
        frame_snapshot=lambda _: {"frame_id": "f", "trace_id": "trace-model-test"},
        authorize=authorize)
    lane.submit("7", "trace-model-test", authorization_payload={"risk_score": 55})
    deadline = time.monotonic() + 1
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] not in {"complete", "partial", "degraded"}:
        time.sleep(0.005)
        result = lane.snapshot()
    assert order == ["authorized", "model"]
    assert result["status"] == "complete"


def test_event_logging_and_snapshot_do_not_wait_for_governance_audit(tmp_path, monkeypatch):
    import threading
    import time
    from azazel_edge_ai.mio_model_lane import LiveMioModelLane

    entered = threading.Event()
    release = threading.Event()
    model_calls = []
    event_log = tmp_path / "events.jsonl"
    advisory_path = tmp_path / "advisory.json"

    def authorize(_payload):
        entered.set()
        release.wait(2)
        return False, "audit_failed"

    lane = LiveMioModelLane(enabled=True, analyze=lambda *args: model_calls.append(args) or {},
        fast_snapshot=lambda: _bound_fast("7", "trace-model-test", "f", "trace-model-test"),
        frame_snapshot=lambda _: {"frame_id": "f", "trace_id": "trace-model-test"},
        authorize=authorize)
    advisory = {**_advisory(), "mio_auxiliary": {"generation": "7"}}
    monkeypatch.setattr(agent, "LIVE_MIO_MODEL_LANE", lane)
    monkeypatch.setattr(agent, "MIO_MODEL_ENABLED", True)
    monkeypatch.setattr(agent, "EVENT_LOG_PATH", event_log)
    monkeypatch.setattr(agent, "ADVISORY_PATH", advisory_path)
    monkeypatch.setattr(agent, "_record_core_decision", lambda _event: None)
    monkeypatch.setattr(agent, "_build_advisory", lambda _event: advisory)
    monkeypatch.setattr(agent, "_metrics_inc", lambda *_args: None)
    monkeypatch.setattr(agent, "_route_llm", lambda *_args: None)
    monkeypatch.setattr(agent, "_write_json", lambda path, value: path.write_text(json.dumps(value)))
    monkeypatch.setattr(agent, "_update_ui_snapshot", lambda *_args: None)
    monkeypatch.setattr(agent, "_persist_metrics", lambda: None)
    monkeypatch.setattr(agent, "_record_decision_explanation", lambda *_args: None)

    started = time.monotonic()
    agent._handle_event({"id": "ordinary-event"})
    elapsed = time.monotonic() - started
    assert elapsed < 0.5
    assert event_log.exists()
    assert advisory_path.exists()
    assert entered.wait(1)
    release.set()
    deadline = time.monotonic() + 1
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] != "skipped":
        time.sleep(0.005)
        result = lane.snapshot()
    assert result["status"] == "skipped"
    assert model_calls == []


def test_superseded_authorization_is_diagnostic_only_and_latest_job_proceeds():
    import threading
    import time
    from azazel_edge_ai.mio_model_lane import LiveMioModelLane

    first_authorization = threading.Event()
    release_first = threading.Event()
    calls = []
    fast_generation = ["7"]
    fast_trace = ["trace-old"]

    def authorize(payload):
        if payload.get("event") == "old":
            first_authorization.set()
            release_first.wait(1)
        return True, "allowed"

    lane = LiveMioModelLane(enabled=True,
        analyze=lambda payload, remaining: calls.append(payload["trace_id"]) or {
            "outcome": "completed", "mio_state": "complete", "generation_method": "model",
            "truncated_count": 0,
            "frame_id": "frame-" + payload["trace_id"], "trace_id": payload["trace_id"]},
        fast_snapshot=lambda: _bound_fast(fast_generation[0], fast_trace[0],
            "frame-" + fast_trace[0], fast_trace[0]),
        frame_snapshot=lambda generation: {"frame_id": "frame-trace-new", "trace_id": "trace-new"},
        authorize=authorize)
    lane.submit("7", "trace-old", authorization_payload={"event": "old"})
    assert first_authorization.wait(1)
    fast_generation[0] = "8"
    fast_trace[0] = "trace-new"
    lane.submit("8", "trace-new", authorization_payload={"event": "new"})
    release_first.set()
    deadline = time.monotonic() + 1
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] != "complete":
        time.sleep(0.005)
        result = lane.snapshot()
    assert result["status"] == "complete"
    assert calls == ["trace-new"]
    assert any(item["reason"] == "superseded" for item in lane.diagnostics())


def test_fast_snapshot_failure_during_finalization_degrades_superseded_without_worker_loss():
    import time
    from azazel_edge_ai.mio_model_lane import LiveMioModelLane

    fast_generation = ["7"]
    snapshot_calls = [0]
    audited = []

    def fast_snapshot():
        # Call order for generation 7: pre-analysis poll (1), stale check before
        # analysis (2), stale check after analysis (3), finalization freshness (4).
        # Fail only the finalization call, once; later submissions must still work.
        snapshot_calls[0] += 1
        if snapshot_calls[0] == 4:
            raise RuntimeError("snapshot unavailable")
        return _bound_fast(fast_generation[0], "trace-" + fast_generation[0],
            "frame-" + fast_generation[0], "trace-" + fast_generation[0])

    def analyze(payload, remaining):
        return {"outcome": "completed", "mio_state": "complete", "generation_method": "model",
                "truncated_count": 0, "frame_id": payload["frame_id"], "trace_id": payload["trace_id"]}

    lane = LiveMioModelLane(enabled=True, analyze=analyze, fast_snapshot=fast_snapshot,
                            frame_snapshot=lambda generation: {
                                "frame_id": "frame-" + str(generation), "trace_id": "trace-" + str(generation)},
                            audit_result=lambda trace_id, result: audited.append(dict(result)))

    lane.submit("7", "trace-7")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not audited:
        time.sleep(0.005)
    assert len(audited) == 1
    assert audited[0]["status"] == "degraded"
    assert audited[0]["reason"] == "superseded"
    result = lane.snapshot()
    assert result["status"] == "degraded"
    assert result["reason"] == "superseded"
    assert any(item["reason"] == "superseded" for item in lane.diagnostics())

    # Worker survived: a new submission is processed to completion.
    fast_generation[0] = "8"
    lane.submit("8", "trace-8")
    deadline = time.monotonic() + 1
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] != "complete":
        time.sleep(0.005)
        result = lane.snapshot()
    assert result["status"] == "complete"
    assert result["generation"] == "2"
    assert result["fast_generation"] == "8"
    assert len(audited) == 2
    assert audited[1]["status"] == "complete"


def test_fast_snapshot_failure_before_analysis_degrades_and_worker_survives():
    import time
    from azazel_edge_ai.mio_model_lane import LiveMioModelLane

    fast_generation = ["7"]
    snapshot_calls = [0]
    audited = []

    def fast_snapshot():
        # The first pre-analysis poll raises; later calls return a valid complete fast result.
        snapshot_calls[0] += 1
        if snapshot_calls[0] == 1:
            raise RuntimeError("snapshot unavailable")
        return _bound_fast(fast_generation[0], "trace-" + fast_generation[0],
            "frame-" + fast_generation[0], "trace-" + fast_generation[0])

    def analyze(payload, remaining):
        return {"outcome": "completed", "mio_state": "complete", "generation_method": "model",
                "truncated_count": 0, "frame_id": payload["frame_id"], "trace_id": payload["trace_id"]}

    lane = LiveMioModelLane(enabled=True, analyze=analyze, fast_snapshot=fast_snapshot,
                            frame_snapshot=lambda generation: {
                                "frame_id": "frame-" + str(generation), "trace_id": "trace-" + str(generation)},
                            audit_result=lambda trace_id, result: audited.append(dict(result)))

    lane.submit("7", "trace-7")
    deadline = time.monotonic() + 1
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] in {"queued", "starting"}:
        time.sleep(0.005)
        result = lane.snapshot()
    assert result["status"] == "degraded"
    assert result["reason"] == "fast_result_unavailable"
    assert audited == []
    assert lane._thread.is_alive()

    # Worker survived: the next submission completes.
    fast_generation[0] = "8"
    lane.submit("8", "trace-8")
    deadline = time.monotonic() + 1
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] != "complete":
        time.sleep(0.005)
        result = lane.snapshot()
    assert result["status"] == "complete"
    assert result["generation"] == "2"
    assert result["fast_generation"] == "8"
    assert lane._thread.is_alive()
    assert len(audited) == 1
    assert audited[0]["status"] == "complete"


def test_authorized_model_result_is_audited_as_structured_metadata(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(log_path)))
    agent._audit_mio_model_result("trace-model-test", {
        "status": "complete", "summary": "synthetic answer", "model": "qwen3.5:2b",
        "request_count": 3, "metered_request_count": 2, "unknown_usage_request_count": 1,
        "truncated_count": 1, "prompt_tokens": 100, "completion_tokens": 45,
        "usage_status": "partial", "mio_state": "complete", "outcome": "completed",
        "prompt": "must not persist", "completion": "must not persist"})
    text = log_path.read_text()
    assert "synthetic answer" not in text
    assert "must not persist" not in text
    entry = json.loads(text.splitlines()[-1])
    assert entry["stage"] == "output"
    assert entry["decision"] == "adopted"
    assert entry["payload"]["model"] == "qwen3.5:2b"
    assert entry["source"] == "azazel_core"
    assert entry["payload"]["request_count"] == 3
    assert entry["payload"]["metered_request_count"] == 2
    assert entry["payload"]["unknown_usage_request_count"] == 1
    assert entry["payload"]["truncated_count"] == 1
    assert entry["payload"]["prompt_tokens"] == 100
    assert entry["payload"]["completion_tokens"] == 45
    assert entry["payload"]["usage_status"] == "partial"
    assert entry["payload"]["mio_state"] == "complete"
    assert entry["payload"]["outcome"] == "completed"


def test_failure_audit_with_missing_truncated_count_records_zero(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(log_path)))
    agent._audit_mio_model_result("trace-missing-truncated", {"status": "degraded", "reason": "deadline_exceeded"})
    entry = json.loads(log_path.read_text().splitlines()[-1])
    assert entry["decision"] == "degraded"
    assert entry["payload"]["truncated_count"] == 0


def test_audit_with_malformed_present_truncated_count_records_four(tmp_path, monkeypatch):
    for index, bad in enumerate((True, "1", 5, -1, 1.0, None)):
        log_path = tmp_path / f"audit-malformed-{index}.jsonl"
        monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(log_path)))
        agent._audit_mio_model_result("trace-malformed-truncated", {
            "status": "degraded", "outcome": "completed", "mio_state": "complete", "truncated_count": bad})
        entry = json.loads(log_path.read_text().splitlines()[-1])
        assert entry["payload"]["truncated_count"] == 4, bad
        assert entry["decision"] == "degraded", bad


def test_success_shaped_result_with_missing_truncated_count_audits_degraded_as_four(tmp_path, monkeypatch):
    log_path = tmp_path / "audit-success-missing.jsonl"
    monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(log_path)))
    monkeypatch.setattr(agent, "_analyze_mio_fast_result", lambda *a, **k: {
        "outcome": "completed", "mio_state": "complete", "summary": "s", "model": "m"})
    agent._governed_mio_model_analyze({"trace_id": "trace-x"}, 1.0)
    entry = json.loads(log_path.read_text().splitlines()[-1])
    assert entry["decision"] == "degraded"
    assert entry["payload"]["truncated_count"] == 4  # missing completeness evidence fails closed


def test_failure_record_without_truncated_count_stays_zero_on_direct_path(tmp_path, monkeypatch):
    log_path = tmp_path / "audit-failure-missing.jsonl"
    monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(log_path)))

    def deadline(*_a, **_k):
        raise TimeoutError("deadline_exceeded")
    monkeypatch.setattr(agent, "_analyze_mio_fast_result", deadline)
    with pytest.raises(TimeoutError):
        agent._governed_mio_model_analyze({"trace_id": "trace-x"}, 1.0)
    entry = json.loads(log_path.read_text().splitlines()[-1])
    assert entry["decision"] == "degraded"
    assert entry["payload"]["truncated_count"] == 0


def test_structured_result_audit_clamps_usage_and_rejects_unallowlisted_metadata(tmp_path):
    path = tmp_path / "audit.jsonl"
    governance = AIGovernance(P0AuditLogger(path))
    governance.record_structured_result(trace_id="trace", source="azazel_core",
        candidate_scope="mio_read_only_advisory", decision="degraded", metadata={
            "request_count": 999, "prompt_tokens": 999999999, "usage_status": "private prompt",
            "mio_state": "completion text <script>", "outcome": "degraded",
            "raw_prompt": "secret prompt", "completion": "secret completion"})
    text = path.read_text()
    assert "secret prompt" not in text and "secret completion" not in text
    payload = json.loads(text.splitlines()[-1])["payload"]
    assert payload["request_count"] == 4
    assert payload["prompt_tokens"] == 400000
    assert "usage_status" not in payload
    assert "mio_state" not in payload
    assert payload["outcome"] == "degraded"


def test_successful_model_result_fails_closed_when_output_audit_fails(monkeypatch):
    class BrokenGovernance:
        def record_structured_result(self, **kwargs):
            raise OSError("private audit details")

    monkeypatch.setattr(agent, "AI_GOVERNANCE", BrokenGovernance())
    monkeypatch.setattr(agent, "_analyze_mio_fast_result", lambda payload, remaining: {
        "summary": "must not escape", "uncertainties": [], "confidence": 0.9,
    })
    try:
        agent._governed_mio_model_analyze({"trace_id": "trace-audit-failure"}, 1.0)
    except RuntimeError as exc:
        assert "audit_failed" in str(exc)
    else:
        raise AssertionError("successful model output escaped without its audit record")

    from azazel_edge_ai.mio_model_lane import LiveMioModelLane
    import time
    lane = LiveMioModelLane(enabled=True,
        analyze=agent._governed_mio_model_analyze,
        fast_snapshot=lambda: _bound_fast("1", "trace-audit-failure",
            "frame-audit-failure", "trace-audit-failure"),
        frame_snapshot=lambda _: {"frame_id": "frame-audit-failure", "trace_id": "trace-audit-failure"})
    lane.submit("1", "trace-audit-failure")
    deadline = time.monotonic() + 1
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] not in {"complete", "degraded"}:
        time.sleep(0.01)
        result = lane.snapshot()
    assert result["status"] == "degraded"
    assert result["summary"] == ""
    assert "private audit details" not in str(result)


def test_record_structured_result_truncated_count_present_exact_int_else_four(tmp_path):
    path = tmp_path / "trunc.jsonl"
    governance = AIGovernance(P0AuditLogger(path))

    def last(metadata):
        governance.record_structured_result(trace_id="t", source="azazel_core", candidate_scope="s",
                                            decision="degraded", metadata=metadata)
        return json.loads(path.read_text().splitlines()[-1])["payload"]

    for value in (0, 1, 4):
        assert last({"truncated_count": value})["truncated_count"] == value
    for value in (-1, 5, True, False, "1", 1.0, None, [0], 2**70):
        assert last({"truncated_count": value})["truncated_count"] == 4, value
    assert "truncated_count" not in last({})


_GOOD = {"outcome": "completed", "mio_state": "complete", "truncated_count": 0, "generation_method": "model",
         "frame_id": "f", "trace_id": "tr", "summary": "s", "request_count": 1, "metered_request_count": 1}
_FRAME = {"frame_id": "f", "trace_id": "tr", "evidence_refs": []}


def _production_lane(monkeypatch, tmp_path, analyzed):
    from azazel_edge_ai.mio_model_lane import LiveMioModelLane
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(agent, "AI_GOVERNANCE", AIGovernance(P0AuditLogger(log_path)))

    def fake(*a, **k):
        return analyzed() if callable(analyzed) else dict(analyzed)
    monkeypatch.setattr(agent, "_analyze_mio_fast_result", fake)
    lane = LiveMioModelLane(enabled=True, analyze=agent._production_mio_model_analyze,
        fast_snapshot=lambda: _bound_fast("1", "tr", "f", "tr"),
        frame_snapshot=lambda g: _FRAME,
        audit_result=lambda t, r: agent._audit_mio_model_result(t, r))
    return lane, log_path


_TERMINAL_STATUSES = frozenset({"complete", "partial", "degraded", "skipped"})


def _wait_terminal(lane, timeout=2.0):
    """Poll until the lane publishes one of _TERMINAL_STATUSES; fail on timeout."""
    import time
    deadline = time.monotonic() + timeout
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] not in _TERMINAL_STATUSES:
        time.sleep(0.01)
        result = lane.snapshot()
    assert result["status"] in _TERMINAL_STATUSES, result["status"]
    return result


def _decisions(path):
    if not path.exists():
        return []
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    return [e["decision"] for e in entries if e.get("stage") == "output"]


def test_production_lane_audits_adopted_only_for_accepted_result(monkeypatch, tmp_path):
    lane, log = _production_lane(monkeypatch, tmp_path, _GOOD)
    lane.submit("1", "tr", source_trace_id="tr")
    assert _wait_terminal(lane)["status"] == "complete"
    assert _decisions(log) == ["adopted"]


_BINDING_CASES = {
    "frame_mismatch": {**_GOOD, "frame_id": "other"},
    "trace_mismatch": {**_GOOD, "trace_id": "other"},
    "missing_frame": {k: v for k, v in _GOOD.items() if k != "frame_id"},
    "missing_trace": {k: v for k, v in _GOOD.items() if k != "trace_id"},
}


@pytest.mark.parametrize("case", sorted(_BINDING_CASES))
def test_production_lane_binding_rejection_is_audited_degraded_not_adopted(monkeypatch, tmp_path, case):
    lane, log = _production_lane(monkeypatch, tmp_path, _BINDING_CASES[case])
    lane.submit("1", "tr", source_trace_id="tr")
    result = _wait_terminal(lane)
    assert result["status"] == "degraded" and result["reason"] == "frame_binding_rejected"
    assert _decisions(log) == ["degraded"]


def test_production_lane_supersession_during_analysis_is_never_adopted(monkeypatch, tmp_path):
    holder = {"submits": 0}

    def analyzed():
        if holder["submits"] == 0:
            holder["submits"] += 1
            holder["lane"].submit("2", "tr2")  # supersede exactly once, during analysis
        return dict(_GOOD)
    lane, log = _production_lane(monkeypatch, tmp_path, analyzed)
    holder["lane"] = lane
    lane.submit("1", "tr", source_trace_id="tr")
    result = _wait_terminal(lane)
    assert holder["submits"] == 1
    assert "adopted" not in _decisions(log)
    assert _decisions(log).count("degraded") >= 1
    assert result["status"] == "degraded"


def test_production_lane_newer_submit_is_not_blocked_by_durable_audit(monkeypatch, tmp_path):
    import threading
    lane, log = _production_lane(monkeypatch, tmp_path, _GOOD)
    in_audit, release, audit_finished = threading.Event(), threading.Event(), threading.Event()
    order = []
    audit_decisions = []

    def audit(trace_id, result):
        in_audit.set()
        assert release.wait(2)
        agent._audit_mio_model_result(trace_id, result)
        order.append("audited")
        audit_decisions.append(result["status"])
        if len(audit_decisions) == 2:
            audit_finished.set()
    lane._audit_result = audit
    lane.submit("1", "tr", source_trace_id="tr")
    assert in_audit.wait(2)
    done = threading.Event()
    started = threading.Event()

    def newer():
        started.set()
        lane.submit("2", "tr2")
        order.append("submitted")
        done.set()
    thread = threading.Thread(target=newer, daemon=True)
    thread.start()
    assert started.wait(2)  # the submitter is running before the blocking window is timed
    assert done.wait(0.2)  # the durable audit callback does not hold the lane lock
    assert lane.snapshot()["generation"] == "2" and lane.snapshot()["status"] == "queued"
    release.set()
    thread.join(2)
    assert audit_finished.wait(2)
    assert order == ["submitted", "audited", "audited"]
    assert audit_decisions == ["complete", "degraded"]
    assert _decisions(log) == ["adopted", "degraded"]
    snapshot = lane.snapshot()
    assert snapshot["generation"] == "2" and snapshot["status"] != "complete"


def test_fast_generation_change_during_durable_audit_is_compensated(monkeypatch, tmp_path):
    lane, log = _production_lane(monkeypatch, tmp_path, _GOOD)
    state = {"generation": "1"}
    lane._fast_snapshot = lambda: _bound_fast(state["generation"], "tr", "f", "tr")
    original_audit = lane._audit_result
    audited_statuses = []

    def audit(trace_id, result):
        original_audit(trace_id, result)
        audited_statuses.append(result["status"])
        if result["status"] == "complete":
            state["generation"] = "2"  # supersede while the durable audit is in progress

    lane._audit_result = audit
    lane.submit("1", "tr", source_trace_id="tr")
    result = _wait_terminal(lane)
    assert result["status"] == "degraded" and result["reason"] == "superseded"
    assert audited_statuses == ["complete", "degraded"]
    assert _decisions(log) == ["adopted", "degraded"]


def test_fast_generation_change_after_finalize_is_hidden_from_snapshots(monkeypatch, tmp_path):
    from azazel_edge_ai.mio_model_lane import LiveMioModelLane

    generation = {"value": "1"}
    lane = LiveMioModelLane(enabled=True, analyze=lambda *_args: dict(_GOOD),
        fast_snapshot=lambda: _bound_fast(generation["value"], "tr", "f", "tr"),
        current_fast_generation=lambda: generation["value"], frame_snapshot=lambda _g: _FRAME)
    lane.submit("1", "tr")
    assert _wait_terminal(lane)["status"] == "complete"
    assert lane.completed_async_generation() == "1"
    generation["value"] = "2"
    snapshot = lane.snapshot()
    assert snapshot["status"] == "degraded" and snapshot["reason"] == "superseded"
    assert snapshot["summary"] == "" and snapshot["is_current"] is False
    assert lane.completed_async_generation() == ""


def test_compensation_failure_is_visible_in_lane_diagnostics(monkeypatch, tmp_path):
    lane, log = _production_lane(monkeypatch, tmp_path, _GOOD)
    state = {"generation": "1"}
    lane._fast_snapshot = lambda: _bound_fast(state["generation"], "tr", "f", "tr")
    original_audit = lane._audit_result
    calls = []

    def audit(trace_id, result):
        calls.append(result["status"])
        if len(calls) == 1:
            original_audit(trace_id, result)
            state["generation"] = "2"
        else:
            raise OSError("synthetic compensation failure")

    lane._audit_result = audit
    lane.submit("1", "tr", source_trace_id="tr")
    assert _wait_terminal(lane)["reason"] == "superseded"
    assert calls == ["complete", "degraded"]
    assert lane.diagnostics()[-1]["audit_compensation_failed"] is True
    assert _decisions(log) == ["adopted"]


def test_production_lane_fast_generation_change_audits_superseded_degraded(monkeypatch, tmp_path):
    lane, log = _production_lane(monkeypatch, tmp_path, _GOOD)
    state = {"gen": "1"}
    lane._fast_snapshot = lambda: _bound_fast(state["gen"], "tr", "f", "tr")

    def analyzed():
        state["gen"] = "2"  # fast freshness changes after analysis, before finalization
        return dict(_GOOD)
    monkeypatch.setattr(agent, "_analyze_mio_fast_result", lambda *a, **k: analyzed())
    lane.submit("1", "tr", source_trace_id="tr")
    result = _wait_terminal(lane)
    assert result["status"] == "degraded"
    assert _decisions(log) == ["degraded"]


def test_stale_check_uses_lightweight_generation_accessor_not_snapshot(monkeypatch, tmp_path):
    import threading
    from azazel_edge_ai.mio_model_lane import LiveMioModelLane

    snapshot_calls = []
    generation = {"value": 1}
    entered = threading.Event()
    checked = threading.Event()

    def fast_snapshot():
        snapshot_calls.append(True)
        return _bound_fast("1", "tr", "f", "tr")

    def analyze(_payload, _remaining, stale_check):
        entered.set()
        generation["value"] = 2
        assert stale_check() is True
        checked.set()
        return dict(_GOOD)

    lane = LiveMioModelLane(enabled=True, analyze=analyze, fast_snapshot=fast_snapshot,
        current_fast_generation=lambda: generation["value"], frame_snapshot=lambda _g: _FRAME)
    lane.submit("1", "tr")
    assert entered.wait(1) and checked.wait(1)
    assert _wait_terminal(lane)["reason"] == "superseded"
    assert len(snapshot_calls) == 1  # model cancellation did not deep-copy another snapshot


def test_production_lane_audit_failure_prevents_complete_publication(monkeypatch, tmp_path):
    lane, log = _production_lane(monkeypatch, tmp_path, _GOOD)
    calls = []

    def broken(trace_id, result):
        calls.append(dict(result))
        raise OSError("private")
    lane._audit_result = broken
    lane.submit("1", "tr", source_trace_id="tr")
    result = _wait_terminal(lane)
    assert len(calls) == 1  # the output callback ran once for the accepted analysis attempt
    assert calls[0]["status"] == "complete"
    assert result["status"] == "degraded"
    assert result["reason"] == "mio_model_result_audit_failed"
    assert result["summary"] == ""
    assert "adopted" not in _decisions(log)
    assert "private" not in str(result)


def test_production_analyze_failure_still_audits_degraded(monkeypatch, tmp_path):
    def boom():
        raise RuntimeError("x")
    lane, log = _production_lane(monkeypatch, tmp_path, boom)
    lane.submit("1", "tr", source_trace_id="tr")
    assert _wait_terminal(lane)["reason"] == "model_error"
    assert _decisions(log) == ["degraded"]


def test_production_degraded_path_audit_failure_publishes_fail_closed_degraded(monkeypatch, tmp_path):
    def boom():
        raise RuntimeError("x")
    lane, log = _production_lane(monkeypatch, tmp_path, boom)
    calls = []

    def broken(trace_id, result):
        calls.append(trace_id)
        raise OSError("private degraded audit detail")
    lane._audit_result = broken
    lane.submit("1", "tr", source_trace_id="tr")
    result = _wait_terminal(lane)
    assert len(calls) == 1
    assert result["status"] == "degraded"
    assert result["reason"] == "mio_model_result_audit_failed"
    assert result["summary"] == ""
    assert "private degraded audit detail" not in str(result)
    assert "adopted" not in _decisions(log)
