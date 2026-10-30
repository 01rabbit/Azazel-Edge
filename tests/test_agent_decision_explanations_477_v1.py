"""The AI agent writes v2 decision explanations of the core's decisions (Edge#477).

The Web UI's Booth Focus and ``audit_review`` read v2 explanations
(``DecisionExplainer``); before #477 only the scenario replay wrote them. The
agent now writes one per core decision event, beside its audit logs, in the
format of the scenario replay. These tests drive the agent's event handler
with the core's event (tests/fixtures/rust_core_event_v1.json) and check that
the readers show and verify what the agent actually wrote, that the record
is the core's decision copied (nothing re-decided), that a write failure
never stops the event handling, that the file is bounded, and that writer,
readers, unit, tmpfiles and installer name the same path.
"""

from __future__ import annotations

import io
import json
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from azazel_edge import audit_review  # noqa: E402
from azazel_edge.audit import P0AuditLogger  # noqa: E402
from azazel_edge.decision_layers import DecisionLayers  # noqa: E402
from azazel_edge.explanations import LIVE_DECISION_EXPLANATIONS_PATH, validate_v2_explanation  # noqa: E402
from azazel_edge.explanations import live  # noqa: E402
from azazel_edge.explanations.fabric_adapter import DECISION_PROJECTION_NAME, TRUST_PROJECTION_NAME  # noqa: E402
from azazel_edge.notify import core_decisions  # noqa: E402
from azazel_edge.notify.core_decisions import CoreDecisionRecorder  # noqa: E402
from azazel_edge_ai import agent as agent_mod  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "rust_core_event_v1.json"
UNIT = ROOT / "systemd" / "azazel-edge-ai-agent.service"
TMPFILES = ROOT / "systemd" / "azazel-edge-agent.tmpfiles.conf"


def core_event(action: str = "redirect", effective: str | None = None, sid: int = 9477001) -> dict:
    event = json.loads(FIXTURE.read_text(encoding="utf-8"))
    event["defense"]["action"] = action
    event["enforcement"]["selected_action"] = action if effective is None else effective
    event["normalized"]["sid"] = sid
    return event


def _rows(path: Path) -> list:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


@pytest.fixture
def agent(tmp_path, monkeypatch):
    for name in ("ADVISORY_PATH", "EVENT_LOG_PATH", "SNAPSHOT_PATH", "METRICS_PATH", "POLICY_PATH",
                 "LLM_DEFERRED_LOG_PATH", "LLM_RESULT_LOG_PATH"):
        monkeypatch.setattr(agent_mod, name, tmp_path / name.lower())
    monkeypatch.setattr(agent_mod, "_route_llm", lambda event, advisory: None)
    monkeypatch.setattr(agent_mod, "CORE_RECORDER", None)
    log_dir = tmp_path / "log-ai"
    log_dir.mkdir()
    monkeypatch.setattr(agent_mod, "DECISION_EXPLANATIONS_PATH", log_dir / "decision-explanations.jsonl")
    monkeypatch.setattr(agent_mod, "DECISION_EXPLANATIONS", None)
    assert agent_mod._start_decision_explanations() is not None
    return log_dir / "decision-explanations.jsonl"


# ------------------------------------------------------------- the record

def test_the_agent_writes_a_valid_v2_explanation_of_the_cores_decision(agent):
    event = core_event("redirect")
    agent_mod._handle_event(event)
    rows = _rows(agent)
    assert len(rows) == 1
    rec = rows[0]
    assert validate_v2_explanation(rec) == []
    trace_id, payload = core_decisions.core_decision_payload(event)
    # The core's decision, copied: the action the P0 rule reads, its trace.
    assert rec["trace_id"] == trace_id
    assert rec["selected_action"] == event["enforcement"]["selected_action"] == "redirect"
    # The fixture is a dry run: planned, not applied, and the record says so.
    assert rec["reason"] == event["defense"]["reason"] + " [NOT APPLIED - planned only (dry_run)]"
    assert rec["policy_profile"] == "azazel-edge-core/rust_event_engine_v1"
    assert re.fullmatch(r"[0-9a-f]{64}", rec["config_hash"])
    arbiter = rec["machine"]["arbiter"]
    assert arbiter["source"] == "azazel-edge-core"
    assert arbiter["core_trace_id"] == event["enforcement"]["trace_id"]
    assert arbiter["control_mode"] == "dry_run" and arbiter["enforce_dry_run"] is True
    assert arbiter["applied_state"] == "not_applied"
    assert rec["release_condition"] == "NOT APPLIED - planned only (dry_run)"
    assert "core lease" not in json.dumps(rec)
    assert "NOT APPLIED - planned only (dry_run)" in rec["operator_wording"]
    assert arbiter["policy"]["hash_basis"] == "enforcement_settings"
    # The second pass's SOC evaluation is the evidence.
    assert rec["machine"]["soc_summary"]["status"]
    assert rec["evidence_ids"] and rec["evidence_ids"] == arbiter["chosen_evidence_ids"]
    # Same shape as the scenario replay's records.
    assert rec["format_version"] == "v2" and rec["trust_capsule"]["trace_id"] == trace_id


def test_nothing_of_the_command_plan_or_release_metadata_is_copied(agent):
    event = core_event("redirect")
    agent_mod._handle_event(event)
    text = agent.read_text(encoding="utf-8")
    enforcement = event["enforcement"]
    for secretish in (enforcement["metadata"]["release_owner_token"], enforcement["metadata"]["release_task_id"],
                      enforcement["metadata"]["release_resource_key"], "nft insert", "nft delete",
                      "AZAZEL_DEFENSE_ENFORCE_LEVEL"):
        assert secretish not in text, secretish


def test_a_fallback_is_shown_as_the_decided_action_not_taken(agent):
    agent_mod._handle_event(core_event("redirect", effective="notify"))
    rec = _rows(agent)[0]
    assert rec["selected_action"] == "notify"
    assert rec["rejected_actions"] == ["redirect"]
    assert rec["why_not_others"][0]["reason"].startswith("core fallback: ")


def test_the_config_hash_follows_the_enforcement_settings_the_core_reported():
    a, b = core_event(), core_event()
    assert live.core_config_hash(a) == live.core_config_hash(b)
    b["enforcement_status"]["dry_run"] = False
    assert live.core_config_hash(a) != live.core_config_hash(b)


def test_an_event_that_is_not_a_core_decision_is_not_explained(agent):
    event = core_event()
    event.pop("enforcement")
    agent_mod._handle_event(event)
    agent_mod._handle_event({"normalized": {"sid": 1, "severity": 3}})
    assert not agent.exists()


def test_a_failed_second_pass_still_explains_the_cores_decision(agent, monkeypatch):
    class Broken:
        def enrich_with_second_pass(self, event, advisory):
            raise RuntimeError("second pass down")

    monkeypatch.setattr(agent_mod, "DECISION_LAYERS", Broken())
    agent_mod._handle_event(core_event("isolate"))
    rec = _rows(agent)[0]
    assert validate_v2_explanation(rec) == []
    assert rec["selected_action"] == "isolate" and rec["evidence_ids"] == []


# --------------------------------------------- display and audit only

def test_the_explanation_changes_nothing_the_agent_decides_or_records(tmp_path, agent, monkeypatch):
    """Same event with and without the writer: the same advisory (score,
    recommendation, state, second pass) and the same chain record."""

    def run(with_writer: bool, sub: str) -> tuple:
        monkeypatch.setattr(agent_mod, "_LAST_RISK_SCORE", 0)
        monkeypatch.setattr(agent_mod, "_LAST_STATE_NAME", "NORMAL")
        monkeypatch.setattr(agent_mod, "CORR_STATE", {})
        monkeypatch.setattr(agent_mod, "DECISION_LAYERS", DecisionLayers())  # the SOC evaluator keeps state
        if not with_writer:
            monkeypatch.setattr(agent_mod, "DECISION_EXPLANATIONS", None)
        chain = tmp_path / sub / "core-decision-audit.jsonl"
        chain.parent.mkdir()
        recorder = CoreDecisionRecorder(P0AuditLogger(chain), None, None).start()
        monkeypatch.setattr(agent_mod, "CORE_RECORDER", recorder)
        try:
            agent_mod._handle_event(core_event("isolate"))
        finally:
            recorder.stop()
        advisory = json.loads(agent_mod.ADVISORY_PATH.read_text(encoding="utf-8"))
        for key in ("ts", "trace_id"):
            advisory.pop(key, None)
        # What the core decided and the P0 path records (not the record's own time stamps).
        keys = set(core_decisions.core_decision_payload(core_event("isolate"))[1]) | {"kind", "trace_id", "source"}
        records = [{k: v for k, v in r.items() if k in keys}
                   for r in _rows(chain) if r.get("kind") == "action_decision"]
        return advisory, records

    with_writer = run(True, "a")
    without_writer = run(False, "b")
    assert with_writer == without_writer
    assert with_writer[1] and with_writer[1][0]["action"] == "isolate"


def test_a_write_failure_never_stops_the_event_handling(tmp_path, monkeypatch, caplog):
    for name in ("ADVISORY_PATH", "EVENT_LOG_PATH", "SNAPSHOT_PATH", "METRICS_PATH", "POLICY_PATH"):
        monkeypatch.setattr(agent_mod, name, tmp_path / name.lower())
    monkeypatch.setattr(agent_mod, "_route_llm", lambda event, advisory: None)
    monkeypatch.setattr(agent_mod, "CORE_RECORDER", None)
    target = tmp_path / "log-ai" / "decision-explanations.jsonl"
    target.mkdir(parents=True)  # a directory where the file should be: every append fails
    monkeypatch.setattr(agent_mod, "DECISION_EXPLANATIONS_PATH", target)
    monkeypatch.setattr(agent_mod, "DECISION_EXPLANATIONS", None)
    writer = agent_mod._start_decision_explanations()
    with caplog.at_level("ERROR"):
        agent_mod._handle_event(core_event("isolate"))
        agent_mod._handle_event(core_event("isolate", sid=9477002))
    assert writer.failed_total == 2 and writer.written_total == 0
    assert (tmp_path / "event_log_path").read_text(encoding="utf-8").count("\n") == 2
    assert json.loads((tmp_path / "advisory_path").read_text(encoding="utf-8"))
    assert sum("decision explanation not written" in r.getMessage() for r in caplog.records) == 1


def test_an_unusable_directory_disables_the_writer_and_the_agent_runs_on(tmp_path, monkeypatch, caplog):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("", encoding="utf-8")
    monkeypatch.setattr(agent_mod, "DECISION_EXPLANATIONS_PATH", blocker / "decision-explanations.jsonl")
    monkeypatch.setattr(agent_mod, "DECISION_EXPLANATIONS", None)
    with caplog.at_level("ERROR"):
        assert agent_mod._start_decision_explanations() is None
    assert any("decision explanations not written" in r.getMessage() for r in caplog.records)
    # No /tmp fallback: a file nobody reads is not an explanation.
    assert agent_mod.DECISION_EXPLANATIONS is None


def test_nothing_is_written_until_the_service_starts(tmp_path, monkeypatch):
    for name in ("ADVISORY_PATH", "EVENT_LOG_PATH", "SNAPSHOT_PATH", "METRICS_PATH", "POLICY_PATH"):
        monkeypatch.setattr(agent_mod, name, tmp_path / name.lower())
    monkeypatch.setattr(agent_mod, "_route_llm", lambda event, advisory: None)
    monkeypatch.setattr(agent_mod, "CORE_RECORDER", None)
    monkeypatch.setattr(agent_mod, "DECISION_EXPLANATIONS", None)
    monkeypatch.setattr(agent_mod, "DECISION_EXPLANATIONS_PATH", tmp_path / "x" / "decision-explanations.jsonl")
    agent_mod._handle_event(core_event())
    assert not (tmp_path / "x").exists()


# ------------------------------------------------------------- bounded

def test_the_file_and_its_projections_rotate_and_one_rotated_file_is_kept(tmp_path):
    path = tmp_path / "decision-explanations.jsonl"
    writer = live.LiveDecisionExplanationWriter(path, max_bytes=4096)
    advisory: dict = {}
    for sid in range(9477100, 9477130):
        assert writer.record(core_event(sid=sid), advisory) is not None
    assert path.exists() and path.with_name(path.name + ".1").exists()
    assert not path.with_name(path.name + ".2").exists()
    for p in (path, path.with_name(path.name + ".1")):
        # Rotated before an append: a file passes the bound by one record at most.
        assert p.stat().st_size < 4096 + max(len(x) for x in p.read_bytes().splitlines()) + 1
        assert all(validate_v2_explanation(r) == [] for r in _rows(p))
    for name in (DECISION_PROJECTION_NAME, TRUST_PROJECTION_NAME):
        projection = path.with_name(name)
        if projection.exists():  # only with azazel_fabric installed
            assert not projection.with_name(name + ".2").exists()
            assert projection.stat().st_size < 2 * 4096


def test_the_agent_bounds_its_file():
    assert live.DEFAULT_MAX_BYTES == 8 * 1024 * 1024 and live.DEFAULT_KEEP == 1
    src = (ROOT / "py" / "azazel_edge_ai" / "agent.py").read_text(encoding="utf-8")
    assert "LiveDecisionExplanationWriter(DECISION_EXPLANATIONS_PATH)" in src


def test_the_scenario_replay_explainer_is_unchanged_by_default(tmp_path):
    from azazel_edge.explanations import DecisionExplainer

    explainer = DecisionExplainer(output_path=tmp_path / "demo.jsonl")
    assert explainer.max_bytes is None


# ---------------------------------------------- the readers read it

def test_booth_focus_shows_what_the_agent_wrote(agent, tmp_path, monkeypatch):
    import azazel_edge_web.app as webapp

    agent_mod._handle_event(core_event("redirect"))
    rec = _rows(agent)[0]
    monkeypatch.setattr(webapp, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(webapp, "FALLBACK_STATE_PATH", tmp_path / "fallback.json")
    monkeypatch.setattr(webapp, "DECISION_EXPLANATIONS_PATH", agent)
    monkeypatch.setattr(webapp, "BOOTH_DEMO_EXPLANATIONS_PATH", tmp_path / "no-demo.jsonl")
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
    monkeypatch.setattr(webapp, "cp_read_snapshot_payload", None)
    (tmp_path / "state.json").write_text(json.dumps({"snapshot_epoch": 1}), encoding="utf-8")
    payload = webapp.app.test_client().get("/api/booth-focus").get_json()
    assert payload["available"] is True
    assert payload["mode"]["kind"] == "live_test_input"
    assert payload["decision"]["action"] == "REDIRECT"
    assert payload["decision"]["reason"] == rec["reason"]
    assert payload["decision"]["release_condition"] == rec["release_condition"]
    assert payload["decision"]["evidence_ids"] == rec["evidence_ids"][:4]
    assert payload["audit"] == {
        "trace_id": rec["trace_id"], "policy_profile": rec["policy_profile"],
        "config_hash": rec["config_hash"], "config_hash_basis": "enforcement_settings",
        "format_version": "v2",
    }
    # A dry-run decision never reads as applied on the screen.
    assert "NOT APPLIED - planned only (dry_run)" in payload["decision"]["reason"]
    assert payload["decision"]["release_condition"] == "NOT APPLIED - planned only (dry_run)"
    assert payload["safety"]["dry_run"] is True


def test_audit_review_finds_the_decision_in_the_core_chain(agent, tmp_path, monkeypatch):
    chain = tmp_path / "log-ai" / "core-decision-audit.jsonl"
    recorder = CoreDecisionRecorder(P0AuditLogger(chain), None, None).start()
    monkeypatch.setattr(agent_mod, "CORE_RECORDER", recorder)
    try:
        agent_mod._handle_event(core_event("isolate"))  # a P0 decision: recorded in the chain
    finally:
        recorder.stop()
    rec = _rows(agent)[0]
    assert rec["trace_id"] in {r.get("trace_id") for r in _rows(chain)}
    out = io.StringIO()
    with redirect_stdout(out):
        rc = audit_review.main(["--explanations-path", str(agent), "--audit-path", str(chain),
                                "--trace-id", rec["trace_id"], "--json"])
    assert rc == 0
    result = json.loads(out.getvalue())
    assert result["schema_valid"] is True and result["selected_action"] == "isolate"
    assert result["chain"]["ok"] is True and result["chain"]["entries"] >= 1


# --------------------------------------------------- one path for all

def test_writer_readers_unit_tmpfiles_and_installer_name_the_same_path():
    assert LIVE_DECISION_EXPLANATIONS_PATH == "/var/log/azazel-edge/ai/decision-explanations.jsonl"
    # The agent: beside its audit log (default /var/log/azazel-edge/ai).
    assert str(agent_mod.AGENT_LOG_DIR / "decision-explanations.jsonl") == LIVE_DECISION_EXPLANATIONS_PATH
    src = (ROOT / "py" / "azazel_edge_ai" / "agent.py").read_text(encoding="utf-8")
    assert 'DECISION_EXPLANATIONS_PATH = AI_AUDIT_PATH.parent / "decision-explanations.jsonl"' in src
    assert 'AZAZEL_AI_AUDIT_LOG", str(AGENT_LOG_DIR / "ai-audit.jsonl")' in src
    # The readers' defaults.
    assert audit_review._DEFAULT_EXPLANATIONS_PATH == LIVE_DECISION_EXPLANATIONS_PATH
    app = (ROOT / "azazel_edge_web" / "app.py").read_text(encoding="utf-8")
    assert f'"AZAZEL_DECISION_EXPLANATIONS_PATH", "{LIVE_DECISION_EXPLANATIONS_PATH}"' in app
    # Writable by the agent, readable by the Web UI's group.
    unit = UNIT.read_text(encoding="utf-8")
    rw = re.search(r"^ReadWritePaths=(.*)$", unit, re.M).group(1).split()
    assert "/var/log/azazel-edge/ai" in rw
    assert re.search(r"^ProtectSystem=strict$", unit, re.M) and re.search(r"^UMask=0027$", unit, re.M)
    assert re.search(r"^User=azazel-agent$", unit, re.M)
    assert re.search(r"^d /var/log/azazel-edge/ai\s+2750 azazel-agent azazel-web -$",
                     TMPFILES.read_text(encoding="utf-8"), re.M)
    # An old default in an environment file moves to the new path.
    installer = (ROOT / "installer" / "internal" / "setup_agent_account.sh").read_text(encoding="utf-8")
    assert ("AZAZEL_DECISION_EXPLANATIONS_PATH|/var/log/azazel-edge/decision-explanations\\.jsonl|"
            f"{LIVE_DECISION_EXPLANATIONS_PATH}") in installer


# ------------------------------------------- applied vs planned only

def _applied(event: dict, ledger: str = "active") -> dict:
    """The event as the core reports an action it applied (mode enforced)."""
    enf = event["enforcement"]
    enf.update(mode="enforced", result="applied", executed_count=1, failed_count=0)
    enf["metadata"]["release_ledger_state"] = ledger
    event["enforcement_status"].update(enforce_enabled=True, dry_run=False, enforce_level="full-auto")
    return event


def test_only_an_applied_action_has_a_lease_and_reads_as_applied(agent):
    agent_mod._handle_event(_applied(core_event("redirect")))
    rec = _rows(agent)[0]
    assert rec["machine"]["arbiter"]["applied_state"] == "applied"
    assert rec["release_condition"].startswith("core lease expires at ")
    assert "NOT APPLIED" not in rec["reason"] and "NOT APPLIED" not in rec["operator_wording"]


@pytest.mark.parametrize("ledger", ["prepared", "cancelled", "planned_only", ""])
def test_an_applied_action_without_a_running_lease_shows_no_lease(ledger):
    enf = _applied(core_event("redirect"), ledger)["enforcement"]
    assert live.applied_state(enf) == "applied"
    assert live._release_condition(enf) == ""


@pytest.mark.parametrize("result", ["partial_failure", "failed", "applied", "", "something_new"])
def test_a_failed_apply_is_not_shown_as_applied(agent, result):
    event = _applied(core_event("redirect"), "cancelled")
    event["enforcement"].update(result=result, executed_count=0, failed_count=1)
    enf = event["enforcement"]
    assert live.applied_state(enf) == "apply_failed"
    assert live._release_condition(enf) == "NOT APPLIED - apply failed"
    agent_mod._handle_event(event)
    rec = _rows(agent)[0]
    assert rec["machine"]["arbiter"]["applied_state"] == "apply_failed"
    assert rec["release_condition"] == "NOT APPLIED - apply failed"
    assert rec["reason"].endswith("[NOT APPLIED - apply failed]")
    assert "NOT APPLIED - apply failed" in rec["operator_wording"]


def test_a_partial_failure_that_executed_a_command_is_applied_with_its_lease(agent):
    event = _applied(core_event("isolate"), "uncertain")
    event["enforcement"].update(result="partial_failure", executed_count=1, failed_count=1)
    assert live.applied_state(event["enforcement"]) == "applied"
    agent_mod._handle_event(event)
    rec = _rows(agent)[0]
    assert rec["machine"]["arbiter"]["applied_state"] == "applied"
    assert rec["release_condition"].startswith("core lease expires at ")
    assert "NOT APPLIED" not in rec["reason"]


def _held(event: dict, result: str, held_task: str, due: float) -> dict:
    """A new alert for a flow already held: the core runs no command and
    names the held lease and its (possibly extended) expiry."""
    enf = _applied(event, "merged")["enforcement"]
    enf.update(result=result, executed_count=0, failed_count=0, command_plan=[])
    enf["metadata"].update(release_extended_task_id=held_task, release_due_epoch=due)
    return event


def test_a_held_or_extended_restriction_reads_as_held_with_its_lease_not_as_failed(agent):
    from azazel_edge.explanations import trace
    from azazel_edge.outcome.adapter import from_rust_event

    # New restriction, then the same flow seen again (held, then extended),
    # then its release: the held lease and its expiry follow through.
    first = _applied(core_event("throttle"), "active")
    first["enforcement"]["metadata"]["release_task_id"] = "release-00000000000000a1"
    assert live.applied_state(first["enforcement"]) == "applied"
    for result, due in (("already_held", 1_800_000_300.0), ("extended", 1_800_000_600.0)):
        event = _held(core_event("throttle"), result, "release-00000000000000a1", due)
        enf = event["enforcement"]
        assert live.applied_state(enf) == "held"
        assert live._not_applied_label(enf) == ""
        assert live._release_condition(enf) == (
            "HELD - existing restriction continues: core lease release-00000000000000a1 expires at "
            + __import__("datetime").datetime.fromtimestamp(due, __import__("datetime").timezone.utc).isoformat(timespec="seconds")
        )
        assert trace.applied_label("held", "enforced") == "HELD - existing restriction continues"
        assert "held" in trace.APPLIED_STATES and result in trace.ENFORCEMENT_RESULTS
        receipt = from_rust_event(event).execution
        assert receipt.release_ref == "release-00000000000000a1"
        assert receipt.expires_at == __import__("datetime").datetime.fromtimestamp(due, __import__("datetime").timezone.utc).isoformat()
        agent_mod._handle_event(event)
        rec = _rows(agent)[-1]
        assert rec["machine"]["arbiter"]["applied_state"] == "held"
        assert "NOT APPLIED" not in rec["reason"] and "NOT APPLIED" not in rec["release_condition"]
    # Only an enforced outcome is held; the same result in another mode is not.
    odd = _held(core_event("throttle"), "extended", "release-00000000000000a1", 1.0)
    odd["enforcement"]["mode"] = "dry_run"
    assert live.applied_state(odd["enforcement"]) == "apply_failed"


def test_only_no_disruptive_action_is_none():
    enf = core_event("notify")["enforcement"]
    enf.update(result="no_disruptive_action", executed_count=0, mode="disabled")
    assert live.applied_state(enf) == "none" and live._not_applied_label(enf) == ""


@pytest.mark.parametrize("mode", ["dry_run", "policy_gated", "release_guard_failed"])
def test_a_planned_action_says_not_applied_and_has_no_lease_time(agent, mode, tmp_path, monkeypatch):
    import azazel_edge_web.app as webapp

    event = core_event("isolate")
    event["enforcement"]["mode"] = mode
    if mode == "policy_gated":
        event["enforcement_status"]["dry_run"] = False
    agent_mod._handle_event(event)
    rec = _rows(agent)[0]
    label = f"NOT APPLIED - planned only ({mode})"
    assert rec["release_condition"] == label
    assert rec["reason"].endswith(f"[{label}]") and label in rec["operator_wording"]
    assert "core lease" not in rec["release_condition"]
    monkeypatch.setattr(webapp, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(webapp, "FALLBACK_STATE_PATH", tmp_path / "fallback.json")
    monkeypatch.setattr(webapp, "DECISION_EXPLANATIONS_PATH", agent)
    monkeypatch.setattr(webapp, "BOOTH_DEMO_EXPLANATIONS_PATH", tmp_path / "no-demo.jsonl")
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
    monkeypatch.setattr(webapp, "cp_read_snapshot_payload", None)
    (tmp_path / "state.json").write_text(json.dumps({"snapshot_epoch": 1}), encoding="utf-8")
    payload = webapp.app.test_client().get("/api/booth-focus").get_json()
    assert payload["decision"]["action"] == "ISOLATE"
    assert label in payload["decision"]["reason"]
    assert payload["decision"]["release_condition"] == label


def test_nothing_disruptive_has_no_release_condition(agent):
    event = core_event("observe")
    event["enforcement"].update(mode="disabled", result="no_disruptive_action", command_plan=[], rollback_plan=[])
    event["enforcement"]["metadata"] = {"release_ledger_state": "not_applicable"}
    agent_mod._handle_event(event)
    rec = _rows(agent)[0]
    assert rec["release_condition"] == "" and "NOT APPLIED" not in rec["reason"]
    assert rec["machine"]["arbiter"]["applied_state"] == "none"


def test_audit_review_says_the_config_hash_is_not_a_policy_file_hash(agent):
    agent_mod._handle_event(core_event("redirect"))
    outputs = {}
    for flag in ("full", "--compact", "--json"):
        out = io.StringIO()
        with redirect_stdout(out):
            audit_review.main(["--explanations-path", str(agent), "--audit-path", str(agent.parent / "none.jsonl")]
                              + ([] if flag == "full" else [flag]))
        outputs[flag] = out.getvalue()
    assert "config_hash_basis : enforcement_settings (not a policy file hash)" in outputs["full"]
    assert "hash_basis=enforcement_settings " in outputs["--compact"]
    assert json.loads(outputs["--json"])["config_hash_basis"] == "enforcement_settings"


def test_booth_focus_script_shows_the_hash_basis():
    js = (ROOT / "azazel_edge_web" / "static" / "booth_focus.js").read_text(encoding="utf-8")
    assert "data.audit.config_hash_basis" in js and "not a policy file hash" in js


# ----------------------------------------------- where it is written

def test_the_explanation_is_written_after_the_advisory_and_the_snapshot(agent, monkeypatch):
    order: list = []
    real_write, real_snapshot = agent_mod._write_json, agent_mod._update_ui_snapshot
    monkeypatch.setattr(agent_mod, "_write_json", lambda path, payload: (order.append(("json", Path(path).name)), real_write(path, payload)))
    monkeypatch.setattr(agent_mod, "_update_ui_snapshot", lambda advisory, **kw: (order.append(("snapshot",)), real_snapshot(advisory, **kw)))
    writer = agent_mod.DECISION_EXPLANATIONS
    real_record = writer.record
    monkeypatch.setattr(writer, "record", lambda event, advisory: (order.append(("explanation",)), real_record(event, advisory))[1])
    agent_mod._handle_event(core_event("redirect"))
    names = [o[0] if o[0] != "json" else o[1] for o in order]
    assert names[-1] == "explanation" and names.count("explanation") == 1
    assert names.index(agent_mod.ADVISORY_PATH.name) < names.index("snapshot") < names.index("explanation")
    src = (ROOT / "py" / "azazel_edge_ai" / "agent.py").read_text(encoding="utf-8")
    body = src[src.index("def _handle_event("):src.index("def _handle_line(")]
    assert body.rstrip().endswith("_record_decision_explanation(event, advisory)")
    assert body.index("_update_ui_snapshot(advisory)") < body.index("_record_decision_explanation(")


# ----------------------------------------------- installer, run as bash

def _gnu_sed() -> bool:
    import subprocess
    try:
        return "GNU" in subprocess.run(["sed", "--version"], capture_output=True, text=True).stdout
    except OSError:
        return False


@pytest.mark.skipif(not _gnu_sed(), reason="the installer runs GNU sed (Debian); not on this host")
def test_the_installer_rewrites_the_old_default_and_keeps_the_old_file(tmp_path):
    import subprocess

    src = (ROOT / "installer" / "internal" / "setup_agent_account.sh").read_text(encoding="utf-8")
    start = src.index("rewrite_old_default() {")
    end = src.index('say "done.')
    block = src[start:end]
    sec, web = tmp_path / "azazel-edge-security", tmp_path / "azazel-edge-web"
    old_dir, new_dir = tmp_path / "log", tmp_path / "log" / "ai"
    new_dir.mkdir(parents=True)
    (old_dir / "decision-explanations.jsonl").write_text("{}\n", encoding="utf-8")
    sec.write_text("OTHER=1\n", encoding="utf-8")
    web.write_text(
        'AZAZEL_DECISION_EXPLANATIONS_PATH="/var/log/azazel-edge/decision-explanations.jsonl"\nKEEP=x\n',
        encoding="utf-8",
    )
    script = (
        'set -euo pipefail\nsay() { echo "[agent-account] $*"; }\n'
        f'SECURITY_ENV="{sec}"\nWEB_ENV="{web}"\nOLD_LOG_DIR="{old_dir}"\nNEW_LOG_DIR="{new_dir}"\n'
        + block
    )
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert web.read_text(encoding="utf-8") == (
        f'AZAZEL_DECISION_EXPLANATIONS_PATH="{LIVE_DECISION_EXPLANATIONS_PATH}"\nKEEP=x\n'
    )
    assert sec.read_text(encoding="utf-8") == "OTHER=1\n"
    assert (old_dir / "decision-explanations.jsonl").read_text(encoding="utf-8") == "{}\n"
    assert f"NOTICE: {old_dir}/decision-explanations.jsonl is kept and no longer read" in res.stdout
    # A custom value is kept and reported, never rewritten.
    web.write_text("AZAZEL_DECISION_EXPLANATIONS_PATH=/srv/x.jsonl\n", encoding="utf-8")
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert web.read_text(encoding="utf-8") == "AZAZEL_DECISION_EXPLANATIONS_PATH=/srv/x.jsonl\n"
    assert "keeps AZAZEL_DECISION_EXPLANATIONS_PATH=/srv/x.jsonl" in res.stdout
