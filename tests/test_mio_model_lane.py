from __future__ import annotations

import time

from azazel_edge_ai.mio_model_lane import LiveMioModelLane


def _fast(generation="7"):
    return {
        "status": "complete", "generation": generation, "is_current": True,
        "trace_id": "trace-abc", "knowledge": {"status": "absent"},
        "advisory": {"summary": "Static summary", "hypotheses": [{"statement": "possible probe"}],
                     "next_checks": [{"check": "review logs"}]},
    }


def _wait(lane, status, timeout=1.0):
    deadline = time.monotonic() + timeout
    result = lane.snapshot()
    while time.monotonic() < deadline and result["status"] != status:
        time.sleep(0.01)
        result = lane.snapshot()
    return result


def test_model_lane_keeps_queue_full_degraded_when_both_nonblocking_puts_fail(monkeypatch):
    import queue

    lane = LiveMioModelLane(enabled=True, analyze=lambda payload, remaining: {}, fast_snapshot=_fast)
    attempts = []

    def full(_item):
        attempts.append(True)
        raise queue.Full

    monkeypatch.setattr(lane._queue, "put_nowait", full)
    result = lane.submit("7", "trace-abc")
    assert len(attempts) == 2
    assert result["status"] == "degraded"
    assert result["reason"] == "queue_full"
    assert result["generation"] == "1"
    assert result["trace_id"] == "trace-abc"


def test_model_lane_is_opt_in_and_skip_does_not_call_transport():
    calls = []
    lane = LiveMioModelLane(enabled=False, analyze=lambda payload, remaining: calls.append(payload), fast_snapshot=_fast)
    assert lane.submit("7", "trace-abc")["status"] == "disabled"
    assert calls == []

    enabled = LiveMioModelLane(enabled=True, analyze=lambda payload, remaining: calls.append(payload) or {}, fast_snapshot=_fast)
    assert enabled.submit("7", "trace-abc", skip_reason="legacy_llm_already_routed")["reason"] == "legacy_llm_already_routed"
    assert calls == []


def test_model_lane_waits_for_fast_generation_and_exposes_only_bounded_measurements():
    calls = []
    lane = LiveMioModelLane(enabled=True, analyze=lambda payload, remaining: calls.append(payload) or {
        "summary": "measured summary", "uncertainties": ["unknown context"], "confidence": 0.7,
        "model": "qwen3.5:2b", "duration_ms": 44, "load_duration_ms": 12,
        "prompt_tokens": 20, "completion_tokens": 9, "outcome": "completed",
        "mio_state": "complete", "generation_method": "model",
        "frame_id": "frame-abc", "trace_id": "trace-abc",
    }, fast_snapshot=_fast, frame_snapshot=lambda generation: {
        "frame_id": "frame-abc", "trace_id": "trace-abc", "evidence_refs": ["suricata_sid:1"]})
    lane.submit("7", "trace-abc")
    result = _wait(lane, "complete")
    assert result["summary"] == "measured summary"
    assert result["trace_id"] == "trace-abc"
    assert result["fast_generation"] == "7"
    assert result["authority"] == "read_only_advisory"
    assert result["model"] == "qwen3.5:2b"
    assert result["prompt_tokens"] == 20 and result["completion_tokens"] == 9
    assert calls == [{"frame_id": "frame-abc", "trace_id": "trace-abc", "evidence_refs": ["suricata_sid:1"]}]
    assert lane.diagnostics()[0]["outcome"] == "completed"
    assert "static_summary" not in str(lane.diagnostics())
    assert "measured summary" not in str(lane.diagnostics())


def test_model_lane_discards_fast_result_from_a_superseded_generation():
    calls = []
    lane = LiveMioModelLane(enabled=True, analyze=lambda payload, remaining: calls.append(payload) or {},
                            fast_snapshot=lambda: _fast("8"))
    lane.submit("7", "trace-old")
    result = _wait(lane, "degraded")
    assert result["reason"] == "fast_result_unavailable"
    assert calls == []


def test_model_error_is_degraded_without_persisting_raw_exception_text():
    def fail(payload, remaining):
        raise RuntimeError("private completion and prompt content")
    lane = LiveMioModelLane(enabled=True, analyze=fail, fast_snapshot=_fast)
    lane.submit("7", "trace-abc")
    result = _wait(lane, "degraded")
    assert result["reason"] == "model_error"
    assert "private completion" not in str(result)
    assert "private completion" not in str(lane.diagnostics())


def test_validation_rejection_enum_is_allowlisted_bounded_and_does_not_promote_rejected_fields():
    secret = "private rejected statement / frame-ref-secret"
    lane = LiveMioModelLane(enabled=True, analyze=lambda payload, remaining: {
        "summary": "", "outcome": "degraded", "mio_state": "validation_rejected",
        "generation_method": "deterministic", "validation_rejection": "validation_rejected",
        "hypotheses": [{"hypothesis_alternative_id": secret, "frame_refs": [secret]}],
        "errors": [secret], "trace": [secret], "frame_id": "frame-abc", "trace_id": "trace-abc",
    }, fast_snapshot=_fast, frame_snapshot=lambda generation: {
        "frame_id": "frame-abc", "trace_id": "trace-abc", "evidence_refs": ["suricata_sid:1"]})
    lane.submit("7", "trace-abc")
    result = _wait(lane, "degraded")
    assert result["validation_rejection"] == "validation_rejected"
    assert result["hypotheses"] == []
    assert secret not in str(result)
    assert secret not in str(lane.diagnostics())


def test_validation_rejection_enum_rejects_unrecognized_values():
    lane = LiveMioModelLane(enabled=True, analyze=lambda payload, remaining: {
        "outcome": "degraded", "mio_state": "validation_rejected",
        "generation_method": "deterministic", "validation_rejection": "private-id-123",
        "frame_id": "frame-abc", "trace_id": "trace-abc",
    }, fast_snapshot=_fast, frame_snapshot=lambda generation: {
        "frame_id": "frame-abc", "trace_id": "trace-abc", "evidence_refs": ["suricata_sid:1"]})
    lane.submit("7", "trace-abc")
    assert _wait(lane, "degraded")["validation_rejection"] == ""


def test_core_state_maps_only_to_fixed_validation_rejection_enum():
    from azazel_edge_ai.agent import _mio_validation_rejection_code

    assert _mio_validation_rejection_code("validation_rejected") == "validation_rejected"
    assert _mio_validation_rejection_code("complete") == ""
    assert _mio_validation_rejection_code("validation_rejected:private-id") == ""
    assert _mio_validation_rejection_code(["validation_rejected"]) == ""


def test_model_transport_reuses_existing_edge_ollama_parser_and_usage_metadata(monkeypatch):
    import json
    from azazel_edge_ai import agent

    observed = {}
    data = {
        "model": "qwen3.5:2b", "load_duration": 12_000_000,
        "prompt_eval_count": 18, "eval_count": 7,
        "message": {"content": json.dumps({"summary": "synthetic", "uncertainties": [], "confidence": 0.5})},
    }
    monkeypatch.setattr(agent, "_llm_endpoint_target", lambda: ("http", "127.0.0.1", ("127.0.0.1",), 11434, ""))
    def fake_post(target, path, body, timeout_sec, deadline_monotonic=None):
        observed.update(target=target, path=path, timeout=timeout_sec, deadline=deadline_monotonic)
        return json.dumps(data).encode()
    monkeypatch.setattr(agent, "_post_to_llm_endpoint", fake_post)
    deadline = time.monotonic() + 2
    result = agent._ollama_chat(
        {"static_summary": "synthetic only"}, model="qwen3.5:2b", prompt_system="read-only",
        required_keys=("summary", "uncertainties", "confidence"), return_metadata=True,
        deadline_monotonic=deadline,
    )
    assert observed["path"] == "/api/chat"
    assert observed["deadline"] == deadline
    assert result["parsed"]["summary"] == "synthetic"
    assert result["model"] == "qwen3.5:2b"
    assert result["load_duration_ms"] == 12
    assert result["prompt_tokens"] == 18 and result["completion_tokens"] == 7


def test_shared_core_transport_compiles_task_schema_and_rejects_invalid_model_result(monkeypatch):
    import pytest
    from azazel_edge_ai import agent

    observed = []
    def fake_chat(payload, **kwargs):
        observed.append(kwargs)
        return {"parsed": {}, "model": "fixture", "load_duration_ms": 1,
                "prompt_tokens": 2, "completion_tokens": 3}
    monkeypatch.setattr(agent, "_ollama_chat", fake_chat)
    frame = {
        "schema_version": "mio.situation_frame.v2", "frame_id": "frame-current",
        "trace_id": "trace-current", "created_at": "2026-11-01T00:00:00Z",
        "mission": "Provide a read-only explanation of this accepted Edge event.",
        "current_defensive_state": "NOTIFY", "threat_level": "HIGH",
        "noc_summary": "No NOC evaluation supplied to this bounded live adapter.",
        "soc_summary": "Edge tactical scorer derived risk score: 72",
        "known_facts": ["Observed Suricata SID: 42"], "unknowns": ["LIVE_ADAPTER_CONTEXT_LIMITED"],
        "contradictions": [], "evidence_refs": ["suricata_sid:42"], "knowledge_refs": [],
        "knowledge_status": "not_provided", "deception_status": "not_provided",
        "provenance": {"known_facts": ["caller"], "evidence_refs": ["caller"]},
        "freshness_seconds": 0, "truncated": False, "actors": [], "actions": [],
        "deception_context": None,
    }
    result = agent._analyze_mio_fast_result(frame, 1.0)
    assert result["outcome"] == "degraded"
    assert result["validation_diagnostic"] == {
        "stage": "generate_hypotheses", "rejection_class": "alternative_slots"}
    assert result["request_count"] == 1
    assert result["metered_request_count"] == 0
    assert result["unknown_usage_request_count"] == 1
    assert observed and observed[0]["response_schema"]
    assert observed[0]["strict_object_decode"] is True
    assert observed[0]["user_content"].startswith("TRUSTED_CONTROL\n")
    assert "suricata_sid:42" in observed[0]["user_content"]


def test_valid_fake_transport_runs_full_shared_core_and_lane_preserves_validation_metrics(monkeypatch):
    import json
    from azazel_edge_ai import agent

    frame = {
        "schema_version": "mio.situation_frame.v2", "frame_id": "frame-current",
        "trace_id": "trace-current", "created_at": "2026-11-01T00:00:00Z",
        "mission": "Provide a read-only explanation of this accepted Edge event.",
        "current_defensive_state": "NOTIFY", "threat_level": "HIGH",
        "noc_summary": "No NOC evaluation supplied to this bounded live adapter.",
        "soc_summary": "Observed authentication login failures",
        "known_facts": ["Observed Suricata SID: 42"], "unknowns": ["LIVE_ADAPTER_CONTEXT_LIMITED"],
        "contradictions": [], "evidence_refs": ["suricata_sid:42"], "knowledge_refs": [],
        "knowledge_status": "not_provided", "deception_status": "not_provided",
        "provenance": {"known_facts": ["caller"], "evidence_refs": ["caller"]},
        "freshness_seconds": 0, "truncated": False, "actors": [], "actions": [],
        "deception_context": None,
    }
    calls = []
    def hypothesis(hid, alternative, statement):
        return {"hypothesis_id": hid, "hypothesis_alternative_id": alternative,
                "statement": statement, "status": "proposed",
                "supporting_evidence_refs": ["suricata_sid:42"],
                "contradicting_evidence_refs": [], "assumptions": [],
                "falsification_conditions": ["new evidence contradicts this"],
                "expected_observations": [], "missing_evidence": []}
    responses = {
        "generate_hypotheses": {"hypotheses": [
            hypothesis("h1", "credential_attack", "Possible credential attack"),
            hypothesis("h2", "misconfigured_automation", "Possible benign automation")]},
        "identify_evidence_gaps": {"evidence_gaps": []},
        "recommend": {"summary": "Review the observation", "recommended_action": "OBSERVE",
                      "rationale": "One alert is limited evidence.",
                      "evidence_refs": ["suricata_sid:42"], "limitations": ["Intent unknown."]},
    }
    def fake_chat(_payload, **kwargs):
        control = kwargs["user_content"].split("TRUSTED_CONTROL\n", 1)[1].split(
            "\nEND_TRUSTED_CONTROL", 1)[0]
        task = json.loads(control)["task"]
        calls.append((task, kwargs["response_schema"], kwargs["strict_object_decode"],
                      kwargs["num_predict"], kwargs["prompt_system"]))
        kwargs["metadata_callback"]({"model": "fixture-model", "load_duration_ms": 7,
                                     "prompt_tokens": 11, "completion_tokens": 5,
                                     "done_reason": "stop"})
        return {"parsed": responses[task], "model": "fixture-model", "load_duration_ms": 7,
                "prompt_tokens": 11, "completion_tokens": 5}
    monkeypatch.setattr(agent, "_ollama_chat", fake_chat)

    class Governance:
        def record_structured_result(self, **kwargs):
            return True
    monkeypatch.setattr(agent, "AI_GOVERNANCE", Governance())
    lane = LiveMioModelLane(enabled=True, analyze=agent._governed_mio_model_analyze,
        fast_snapshot=lambda: {"status": "complete", "generation": "19", "is_current": True,
                              "trace_id": "external-trace"},
        frame_snapshot=lambda generation: frame)
    lane.submit("19", "external-trace")
    result = _wait(lane, "complete")

    assert [item[0] for item in calls] == ["generate_hypotheses", "identify_evidence_gaps", "recommend"]
    assert all(schema and strict for _task, schema, strict, _limit, _system in calls)
    assert all(limit == 512 for _task, _schema, _strict, limit, _system in calls)
    assert all("Keep free-text values brief" in system
               for _task, _schema, _strict, _limit, system in calls)
    assert all("under 80 characters each" in system
               for _task, _schema, _strict, _limit, system in calls)
    assert result["trace_id"] == frame["trace_id"]
    assert result["frame_id"] == frame["frame_id"]
    assert result["mio_state"] == "complete"
    assert result["generation_method"] == "model"
    assert result["model"] == "fixture-model"
    assert result["prompt_tokens"] == 33 and result["completion_tokens"] == 15
    assert result["load_duration_ms"] == 21
    assert result["summary"] == "Shared M.I.O. analysis completed; hypotheses remain unverified."
    assert len(result["hypotheses"]) == 2
    assert [item["statement"] for item in result["hypotheses"]] == [
        _safe_alt("credential_attack"), _safe_alt("misconfigured_automation")]
    assert "Possible credential attack" not in json.dumps(result["hypotheses"])
    assert all(item["verification"] == "model_proposed_unverified" for item in result["hypotheses"])
    assert all(item["source"] == "mio_validated_alternative" for item in result["hypotheses"])
    assert all(item["frame_refs"] == ["suricata_sid:42"] for item in result["hypotheses"])
    assert result["next_checks"] and all(type(item) is str for item in result["next_checks"])
    assert result["unknowns"][0] == "LIVE_ADAPTER_CONTEXT_LIMITED"
    assert len(result["unknowns"]) <= 12
    assert "action" not in result and "enforcement" not in result


def test_reviewed_qwen_overclaim_is_replaced_by_frame_only_fallback_and_refs_stay_scoped():
    import json
    from azazel_edge_ai.mio_model_lane import _bounded_hypotheses

    frame = {
        "frame_id": "mio-f9cf4069e17cb6d0-1:frame",
        "trace_id": "mio-f9cf4069e17cb6d0-1",
        "known_facts": ["Observed Suricata SID: 42", "Observed Suricata severity: 4"],
        "unknowns": ["MODEL_NOT_AVAILABLE", "LIVE_ADAPTER_CONTEXT_LIMITED"],
        # The scorer derived admin_port=22, but it is not a known fact carrying
        # a model evidence reference and cannot support a specific port claim.
        "soc_summary": "Edge tactical scorer derived risk score: 85; factors=severity=4,sid_present,threat_class=cred(44),admin_port=22",
        "evidence_refs": ["suricata_sid:42"],
    }
    exact_qwen = [
        {"statement": "The Edge event is consistent with a live adapter context limit exceeded scenario, where the observed SID 42 represents an active attack vector against a specific admin port (22) within a constrained network environment.",
         "hypothesis_alternative_id": "credential_attack", "frame_refs": ["suricata_sid:42"]},
        {"statement": "A benign or configuration explanation remains unverified from the supplied frame.",
         "hypothesis_alternative_id": "misconfigured_automation", "frame_refs": ["suricata_sid:42"]},
    ]
    paraphrased_bypass = [
        {**exact_qwen[0], "statement": "Credential theft is underway on port 42 in a restricted network."},
        exact_qwen[1],
    ]
    projected = _bounded_hypotheses(exact_qwen, frame)
    paraphrased = _bounded_hypotheses(paraphrased_bypass, frame)
    assert projected == paraphrased
    assert len(projected) == 2
    first, second = projected
    assert first["source"] == "mio_validated_alternative"
    assert first["verification"] == "model_proposed_unverified"
    assert first["hypothesis_alternative_id"] == "credential_attack"
    assert first["statement"] == _safe_alt("credential_attack")
    assert second["hypothesis_alternative_id"] == "misconfigured_automation"
    assert second["statement"] == _safe_alt("misconfigured_automation")
    assert all(item["frame_refs"] == ["suricata_sid:42"] for item in projected)
    assert all("supporting_evidence_refs" not in item for item in projected)

    unknown_slot = [{"statement": exact_qwen[0]["statement"],
                     "hypothesis_alternative_id": "unreviewed_context_exceeded_attack",
                     "frame_refs": ["suricata_sid:42"]}]
    assert _bounded_hypotheses(unknown_slot, frame) == []
    generic_slots = _bounded_hypotheses([
        {"statement": "credential theft is underway", "hypothesis_alternative_id": "hostile_activity",
         "frame_refs": ["suricata_sid:42"]},
        {"statement": "restricted network", "hypothesis_alternative_id": "benign_activity",
         "frame_refs": ["suricata_sid:42"]},
        {"statement": "port 22", "hypothesis_alternative_id": "insufficient_evidence",
         "frame_refs": ["suricata_sid:42"]},
    ], frame)
    assert [item["hypothesis_alternative_id"] for item in generic_slots] == [
        "hostile_activity", "benign_activity", "insufficient_evidence"]
    assert [item["statement"] for item in generic_slots] == [
        _safe_alt("hostile_activity"), _safe_alt("benign_activity"), _safe_alt("insufficient_evidence")]
    assert all("42" not in item["statement"] for item in projected)
    assert "context" not in json.dumps(projected).lower()


def test_truncated_outer_usage_is_counted_once_and_core_error_fallback_is_partial(monkeypatch):
    import json
    from azazel_edge_ai import agent

    frame = {
        "schema_version": "mio.situation_frame.v2", "frame_id": "frame-telemetry",
        "trace_id": "trace-telemetry", "created_at": "2026-11-01T00:00:00Z",
        "mission": "Provide a read-only explanation of this accepted Edge event.",
        "current_defensive_state": "OBSERVE", "threat_level": "HIGH",
        "noc_summary": "No NOC evaluation supplied to this bounded live adapter.",
        "soc_summary": "Observed authentication login failures",
        "known_facts": ["Observed Suricata SID: 42"], "unknowns": ["LIVE_ADAPTER_CONTEXT_LIMITED"],
        "contradictions": [], "evidence_refs": ["suricata_sid:42"], "knowledge_refs": [],
        "knowledge_status": "not_provided", "deception_status": "not_provided",
        "provenance": {"known_facts": ["caller"], "evidence_refs": ["caller"]},
        "freshness_seconds": 0, "truncated": False, "actors": [], "actions": [],
        "deception_context": None,
    }
    def hypothesis(hid, alternative, statement):
        return {"hypothesis_id": hid, "hypothesis_alternative_id": alternative,
                "statement": statement, "status": "proposed",
                "supporting_evidence_refs": ["suricata_sid:42"],
                "contradicting_evidence_refs": [], "assumptions": [],
                "falsification_conditions": ["new evidence contradicts this"],
                "expected_observations": [], "missing_evidence": []}
    parsed = {
        "generate_hypotheses": {"hypotheses": [
            hypothesis("h1", "credential_attack", "possible credential theft"),
            hypothesis("h2", "misconfigured_automation", "insufficient evidence") ]},
        "identify_evidence_gaps": {"evidence_gaps": []},
    }
    usage = [(1547, 212, 11_520_791, "stop"),
             (1421, 8, 1_409_958, "stop"),
             (1467, 384, 1_592_167, "length")]
    requests = []
    def fake_post(_target, path, body, _timeout, deadline_monotonic=None):
        assert path == "/api/chat"
        request = json.loads(body)
        prompt = request["messages"][1]["content"]
        control = prompt.split("TRUSTED_CONTROL\n", 1)[1].split("\nEND_TRUSTED_CONTROL", 1)[0]
        task = json.loads(control)["task"]
        index = len(requests)
        requests.append(task)
        prompt_count, completion_count, load_ns, done_reason = usage[index]
        # The third completion is invalid inner JSON after a valid outer Ollama
        # response. Outer usage must be metered before strict decoding fails.
        content = json.dumps(parsed[task]) if index < 2 else "{truncated_completion"
        outer = {"model": "qwen3.5:0.8b", "message": {"content": content},
                 "prompt_eval_count": prompt_count, "eval_count": completion_count,
                 "load_duration": load_ns, "done_reason": done_reason}
        return json.dumps(outer).encode()

    class Governance:
        def __init__(self):
            self.records = []
        def record_structured_result(self, **kwargs):
            self.records.append(kwargs)
            return True
    governance = Governance()
    monkeypatch.setattr(agent, "_post_to_llm_endpoint", fake_post)
    monkeypatch.setattr(agent, "_mio_model_endpoint_target",
                        lambda: ("http", "127.0.0.1", ("127.0.0.1",), 11434, ""))
    monkeypatch.setattr(agent, "_select_analyst_model", lambda: "qwen3.5:0.8b")
    monkeypatch.setattr(agent, "AI_GOVERNANCE", governance)

    lane = LiveMioModelLane(enabled=True, analyze=agent._governed_mio_model_analyze,
        fast_snapshot=lambda: {"status": "complete", "generation": "1", "is_current": True,
                              "trace_id": "external-trace"},
        frame_snapshot=lambda _generation: frame)
    lane.submit("1", "external-trace")
    result = _wait(lane, "partial")

    assert requests == ["generate_hypotheses", "identify_evidence_gaps", "recommend"]
    assert result["status"] == "partial" and result["is_current"] is True
    assert result["mio_state"] == "error_fallback" and result["outcome"] == "partial"
    assert result["request_count"] == 3
    assert result["metered_request_count"] == 3 and result["unknown_usage_request_count"] == 0
    assert result["prompt_tokens"] == 4435 and result["completion_tokens"] == 604
    assert result["load_duration_ms"] == 13
    assert result["truncated_count"] == 1 and result["usage_status"] == "partial"
    assert len(result["hypotheses"]) == 2
    assert governance.records[-1]["candidate_scope"] == "mio_read_only_advisory"
    assert governance.records[-1]["decision"] == "degraded"
    metadata = governance.records[-1]["metadata"]
    assert metadata["request_count"] == 3 and metadata["truncated_count"] == 1
    assert "truncated_completion" not in json.dumps(result)
    diagnostics = json.dumps(lane.diagnostics()).lower()
    assert "trusted_control" not in diagnostics and "truncated_completion" not in diagnostics


def _safe_alt(alternative_id):
    from azazel_edge_ai.mio_model_lane import _ALTERNATIVE_ROLES, _ROLE_TEXT
    return _ROLE_TEXT[_ALTERNATIVE_ROLES[alternative_id]]


def test_missing_governance_actual_submit_and_snapshot_never_invokes_analyzer(monkeypatch):
    from azazel_edge_ai import agent

    calls = []
    lane = LiveMioModelLane(enabled=True,
        analyze=lambda payload, remaining: calls.append(payload) or {"summary": "must not surface"},
        fast_snapshot=lambda: _fast(), authorize=agent._authorize_mio_model_event)
    monkeypatch.setattr(agent, "LIVE_MIO_MODEL_LANE", lane)
    monkeypatch.setattr(agent, "AI_GOVERNANCE", None)
    monkeypatch.setattr(agent, "MIO_MODEL_ENABLED", True)
    agent._submit_governed_mio_model(_advisory_for_model_test(), {"generation": "7"})
    result = _wait(lane, "skipped")
    assert result["reason"] == "governance_denied:audit_unavailable"
    assert result["summary"] == ""
    assert calls == []


def _advisory_for_model_test():
    return {"trace_id": "trace-model-test", "risk_score": 55, "risk_level": "MEDIUM",
            "signature": "synthetic alert", "category": "synthetic", "summary": "synthetic summary"}


def _real_adapter_with_blocking_fake_core():
    import threading
    import time
    from types import SimpleNamespace
    from azazel_edge_ai.mio_live_auxiliary import LiveMioAuxiliary

    adapter = LiveMioAuxiliary(max_age_seconds=4)
    limit = time.monotonic() + 2
    while time.monotonic() < limit and adapter._frame_type is None:
        time.sleep(0.005)
    entered_first = threading.Event()
    entered_second = threading.Event()
    release = threading.Event()
    calls = []

    class Frame:
        def __init__(self, payload):
            self._payload = payload
            self.frame_id = payload["frame_id"]
            self.trace_id = payload["trace_id"]
        @classmethod
        def from_dict(cls, payload):
            return cls(payload)
        def to_dict(self):
            return dict(self._payload)

    class Core:
        def explain(self, frame, **kwargs):
            calls.append(frame.trace_id)
            (entered_first if len(calls) == 1 else entered_second).set()
            release.wait(2)
            return SimpleNamespace(to_dict=lambda: {
                "schema_version": "mio.assistance.v1", "frame_id": frame.frame_id,
                "trace_id": frame.trace_id, "dependency_outcome": {"knowledge": "not_provided"},
            })

    adapter._frame_type = Frame
    adapter._core = Core()
    adapter._knowledge_statuses = frozenset({"not_provided"})
    return adapter, entered_first, entered_second, release, calls


def _accepted_event(trace):
    return {"normalized": {"event_type": "alert", "sid": 42},
            "defense": {"action": "notify"}, "enforcement": {"trace_id": trace}}


def test_real_auxiliary_pending_generation_waits_for_matching_fast_completion():
    import time
    adapter, entered, _entered_second, release, _core_calls = _real_adapter_with_blocking_fake_core()
    analyzed = []
    request = adapter.submit(_accepted_event("rust-trace-current"), score=72,
                             factors=["fixture"], risk_level="HIGH")
    queued = adapter.snapshot()
    assert request["generation"] == queued["generation"] == "1"
    assert queued["status"] == "queued" and queued["trace_id"] == "rust-trace-current"
    assert queued["is_current"] is False

    def analyze(frame, remaining):
        analyzed.append((frame["frame_id"], frame["trace_id"]))
        return {"summary": "accepted fake result", "model": "fixture",
                "frame_id": frame["frame_id"], "trace_id": frame["trace_id"],
                "mio_state": "complete", "generation_method": "model", "outcome": "completed"}

    lane = LiveMioModelLane(enabled=True, analyze=analyze,
        fast_snapshot=adapter.snapshot, frame_snapshot=adapter.frame_snapshot, max_age_seconds=3)
    lane.submit(request["generation"], request["trace_id"])
    assert entered.wait(1)
    assert lane.snapshot()["status"] == "queued"
    assert analyzed == []
    release.set()
    result = _wait(lane, "complete", timeout=2)
    assert result["frame_generation"] == "1"
    assert result["frame_id"] == analyzed[0][0]
    assert result["trace_id"] == analyzed[0][1]
    assert len(analyzed) == 1


def test_real_auxiliary_new_queued_generation_clears_previous_freshness():
    import time
    adapter, entered_first, entered_second, release, _core_calls = _real_adapter_with_blocking_fake_core()
    first = adapter.submit(_accepted_event("trace-first"), score=60, factors=[], risk_level="MEDIUM")
    assert entered_first.wait(1)
    release.set()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and adapter.snapshot()["status"] != "complete":
        time.sleep(0.005)
    assert adapter.snapshot().get("completed_at")

    release.clear()
    second = adapter.submit(_accepted_event("trace-second"), score=61, factors=[], risk_level="MEDIUM")
    assert second["generation"] == "2"
    queued = adapter.snapshot()
    assert queued["status"] == "queued" and queued["is_current"] is False
    assert "completed_at" not in queued and "age_seconds" not in queued
    assert entered_second.wait(1)
    release.set()


def test_real_auxiliary_new_event_supersedes_old_slow_generation():
    import time
    adapter, entered_first, entered_second, release, core_calls = _real_adapter_with_blocking_fake_core()
    analyzed = []
    lane = LiveMioModelLane(enabled=True,
        analyze=lambda frame, remaining: analyzed.append((frame["frame_id"], frame["trace_id"])) or {
            "summary": "new current result", "model": "fixture",
            "frame_id": frame["frame_id"], "trace_id": frame["trace_id"],
            "mio_state": "complete", "generation_method": "model", "outcome": "completed"},
        fast_snapshot=adapter.snapshot, frame_snapshot=adapter.frame_snapshot, max_age_seconds=3)
    old = adapter.submit(_accepted_event("rust-trace-old"), score=72, factors=[], risk_level="HIGH")
    lane.submit(old["generation"], old["trace_id"])
    assert entered_first.wait(1)

    new = adapter.submit(_accepted_event("rust-trace-new"), score=73, factors=[], risk_level="HIGH")
    assert new["generation"] == "2"
    assert adapter.snapshot()["generation"] == "2"
    assert adapter.snapshot()["status"] == "queued"
    assert adapter.frame_snapshot("1") is None
    lane.submit(new["generation"], new["trace_id"])
    release.set()
    assert entered_second.wait(1)
    result = _wait(lane, "complete", timeout=2)
    assert result["frame_generation"] == "2"
    assert result["trace_id"] == analyzed[0][1]
    assert len(analyzed) == 1
    assert analyzed[0][1] != core_calls[0]
    assert adapter.snapshot()["status"] == "complete"
    assert adapter.snapshot()["generation"] == "2"


def test_lane_skips_both_legacy_llm_and_ops_coach_queued_requests():
    from azazel_edge_ai import agent

    assert agent._legacy_ollama_skip_reason({"llm": {"status": "queued"}}) == "legacy_llm_already_routed"
    assert agent._legacy_ollama_skip_reason({
        "llm": {"status": "skipped_non_ambiguous"},
        "ops_coach": {"status": "queued"},
    }) == "legacy_ops_coach_already_routed"
    assert agent._legacy_ollama_skip_reason({"llm": {"status": "skipped_non_ambiguous"}}) == ""


def test_accrued_failure_metrics_survive_governance_and_worker(monkeypatch):
    import json
    from azazel_edge_ai import agent
    from azazel_edge_ai.mio_model_lane import MioModelFailure

    for reason in ("model_error", "deadline_exceeded"):
        audits = []
        def fail(*args):
            raise MioModelFailure(reason, {"model": "fixture", "request_count": 2,
                "metered_request_count": 1, "prompt_tokens": 37, "completion_tokens": 11,
                "summary": "private completion", "prompt": "private prompt"})
        monkeypatch.setattr(agent, "_analyze_mio_fast_result", fail)
        monkeypatch.setattr(agent, "_audit_mio_model_result", lambda trace, result: audits.append(result))
        lane = LiveMioModelLane(enabled=True, analyze=agent._governed_mio_model_analyze,
            fast_snapshot=_fast, frame_snapshot=lambda _: {"trace_id": "trace-abc"})
        lane.submit("7", "trace-abc")
        result = _wait(lane, "degraded")
        assert result["reason"] == reason
        for measured in (result, audits[0], lane.diagnostics()[0]):
            assert measured["request_count"] == 2
            assert measured["metered_request_count"] == 1
            assert measured["prompt_tokens"] == 37
            assert measured["completion_tokens"] == 11
            assert measured["model"] == "fixture"
            assert "private" not in json.dumps(measured)
        assert result["unknown_usage_request_count"] == 1
        assert result["summary"] == ""


def test_validated_alternatives_without_refs_keep_only_fixed_unverified_context():
    import json
    from azazel_edge_ai.mio_model_lane import _bounded_hypotheses
    result = _bounded_hypotheses([
        {"hypothesis_alternative_id": "credential_attack", "statement": "private model claim"},
        {"hypothesis_alternative_id": "misconfigured_automation", "frame_refs": []},
        {"hypothesis_alternative_id": "invented", "statement": "private model claim"},
    ], {"evidence_refs": ["sid:42"]})
    assert len(result) == 2
    assert all(item["frame_refs"] == [] and item["context_only"] for item in result)
    assert all(item["verification"] == "model_proposed_unverified" for item in result)
    assert all("does not establish it" in item["statement"] for item in result)
    assert "private" not in json.dumps(result)


def test_analyzer_preserves_outer_usage_when_core_or_deadline_fails(monkeypatch):
    import pytest
    from azazel_edge_ai import agent
    from azazel_edge_ai.mio_model_lane import MioModelFailure
    from azazel_mio.assistant import AssistantCore
    monkeypatch.setattr(agent, "_mio_model_endpoint_target", lambda: None)
    frame = {
        "schema_version": "mio.situation_frame.v2", "frame_id": "frame-current",
        "trace_id": "trace-current", "created_at": "2026-11-01T00:00:00Z",
        "mission": "Provide a read-only explanation of this accepted Edge event.",
        "current_defensive_state": "NOTIFY", "threat_level": "HIGH",
        "noc_summary": "No NOC evaluation supplied to this bounded live adapter.",
        "soc_summary": "Edge tactical scorer derived risk score: 72",
        "known_facts": ["Observed Suricata SID: 42"], "unknowns": ["LIVE_ADAPTER_CONTEXT_LIMITED"],
        "contradictions": [], "evidence_refs": ["suricata_sid:42"], "knowledge_refs": [],
        "knowledge_status": "not_provided", "deception_status": "not_provided",
        "provenance": {"known_facts": ["caller"], "evidence_refs": ["caller"]},
        "freshness_seconds": 0, "truncated": False, "actors": [], "actions": [],
        "deception_context": None,
    }

    for failure in (RuntimeError("private completion"), TimeoutError("private prompt")):
        def explain(self, frame, **kwargs):
            assert kwargs.get("knowledge_attempted") is False
            # Exercise the real transport metadata callback before core failure.
            self.model("hypotheses", "private request")
            raise failure
        def chat(*args, **kwargs):
            kwargs["metadata_callback"]({"model": "fixture", "prompt_tokens": 17,
                "completion_tokens": 9, "load_duration_ms": 3})
            return {"parsed": {}, "model": "fixture"}
        monkeypatch.setattr(AssistantCore, "explain", explain)
        monkeypatch.setattr(agent, "_ollama_chat", chat)
        import azazel_mio.playbook as playbook
        monkeypatch.setattr(playbook, "compiled_model_response_schema", lambda *args: {})
        with pytest.raises(MioModelFailure) as caught:
            agent._analyze_mio_fast_result(frame, 1.0)
        assert caught.value.metrics["request_count"] == 1
        assert caught.value.metrics["prompt_tokens"] == 17
        assert caught.value.metrics["completion_tokens"] == 9
        assert caught.value.metrics["model"] == "fixture"
        assert caught.value.reason == ("deadline_exceeded" if isinstance(failure, TimeoutError) else "model_error")


def test_validation_diagnostic_closed_vocabulary_and_strict_shape():
    from azazel_edge_ai.mio_model_lane import bounded_validation_diagnostic

    stages = ("unknown", "playbook", "generate_hypotheses", "identify_evidence_gaps",
              "update_hypotheses", "recommend")
    classes = ("unknown", "output_shape", "alternative_slots", "model_identifier",
               "evidence_grounding", "raw_payload", "hypothesis_structure", "evidence_gap",
               "hypothesis_lifecycle", "recommendation_structure", "unsupported_claim")
    for stage in stages:
        for rejection_class in classes:
            value = {"stage": stage, "rejection_class": rejection_class}
            assert bounded_validation_diagnostic(value) == value
    valid = {"stage": "recommend", "rejection_class": "unsupported_claim"}
    for malformed in (None, [], "private user text", {}, {"stage": "recommend"},
                      {**valid, "errors": "private model/error text"},
                      {**valid, "stage": "recommend:private"},
                      {**valid, "rejection_class": "unsupported_claim:private"},
                      {**valid, "stage": True}, {**valid, "stage": ["recommend"]},
                      {**valid, "rejection_class": 1}, {**valid, "rejection_class": {}},
                      {**valid, "stage": "x" * 100_000}):
        assert bounded_validation_diagnostic(malformed) == {}


def test_validation_diagnostic_lane_propagates_only_closed_fields():
    valid = {"stage": "generate_hypotheses", "rejection_class": "alternative_slots"}
    for diagnostic in (valid, {**valid, "raw": "private model/user/error text"}):
        lane = LiveMioModelLane(enabled=True, analyze=lambda payload, remaining: {
            "outcome": "degraded", "mio_state": "validation_rejected",
            "generation_method": "deterministic", "validation_rejection": "validation_rejected",
            "validation_diagnostic": diagnostic, "errors": ["private model/user/error text"],
            "frame_id": "frame-abc", "trace_id": "trace-abc",
        }, fast_snapshot=_fast, frame_snapshot=lambda generation: {
            "frame_id": "frame-abc", "trace_id": "trace-abc", "evidence_refs": []})
        lane.submit("7", "trace-abc")
        result = _wait(lane, "degraded")
        assert result["reason"] == "mio_no_model_contribution"
        assert result["validation_rejection"] == "validation_rejected"
        assert result["authority"] == "read_only_advisory"
        assert result.get("validation_diagnostic") == (valid if diagnostic == valid else None)
        assert "private model/user/error text" not in str(result) + str(lane.diagnostics())
