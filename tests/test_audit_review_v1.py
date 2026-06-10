from __future__ import annotations

"""test_audit_review_v1.py - Tests for the read-only audit review command.

Run:
    python3.10 -m unittest tests.test_audit_review_v1 -v
"""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.audit import P0AuditLogger
from azazel_edge.explanations import DecisionExplainer

# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _noc_good() -> dict:
    return {
        "availability": {"label": "good", "evidence_ids": ["noc-a"]},
        "path_health": {"label": "good", "evidence_ids": ["noc-p"]},
        "device_health": {"label": "good", "evidence_ids": ["noc-d"]},
        "client_health": {"label": "good", "evidence_ids": ["noc-c"]},
        "capacity_health": {"label": "good", "evidence_ids": []},
        "client_inventory_health": {"label": "good", "evidence_ids": []},
        "config_drift_health": {"label": "good", "evidence_ids": []},
        "summary": {"status": "good", "reasons": []},
        "evidence_ids": ["noc-a", "noc-p", "noc-d", "noc-c"],
    }


def _soc_redirect() -> dict:
    """SOC signal strong enough for a redirect decision."""
    return {
        "suspicion": {"score": 92, "label": "critical", "reasons": [], "evidence_ids": ["soc-s"]},
        "confidence": {"score": 84, "label": "critical", "reasons": [], "evidence_ids": ["soc-c"]},
        "technique_likelihood": {"score": 60, "label": "medium", "reasons": [], "evidence_ids": ["soc-t"]},
        "blast_radius": {"score": 72, "label": "high", "reasons": [], "evidence_ids": ["soc-b"]},
        "summary": {
            "status": "critical",
            "attack_candidates": ["T1071 Application Layer Protocol"],
            "ai_attack_candidates": [],
            "ti_matches": [],
        },
        "evidence_ids": ["soc-s", "soc-c", "soc-t", "soc-b"],
    }


def _build_explanation_record(
    tmp_dir: Path, trace_id: str, explanations_path: Path
) -> dict:
    """Build a real v2 explanation record via the production path and persist it."""
    arbiter = ActionArbiter()
    noc = _noc_good()
    soc = _soc_redirect()
    arbiter_result = arbiter.decide(
        noc, soc, client_impact={"score": 20, "critical_client_count": 0}
    )
    explainer = DecisionExplainer(output_path=explanations_path)
    record = explainer.explain(
        noc=noc,
        soc=soc,
        arbiter=arbiter_result,
        target="azazel-edge",
        trace_id=trace_id,
        persist=True,
    )
    return record


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class AuditReviewV1Tests(unittest.TestCase):

    # ------------------------------------------------------------------
    # Test 1: Happy path
    # ------------------------------------------------------------------
    def test_happy_path_exit_0_and_output_fields(self) -> None:
        """Happy path: real explanation + real audit log -> exit 0, correct output."""
        import azazel_edge.audit_review as audit_review

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            exp_path = tmp_path / "decision-explanations.jsonl"
            audit_path = tmp_path / "triage-audit.jsonl"

            # Write a real v2 explanation
            record = _build_explanation_record(tmp_path, "trace-bheu-05", exp_path)

            # Write a real audit log entry
            logger = P0AuditLogger(audit_path)
            logger.log_action_decision(
                trace_id="trace-bheu-05",
                source="arbiter",
                action="redirect",
            )

            # Capture stdout and run
            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = audit_review.main(
                    argv=[
                        "--explanations-path", str(exp_path),
                        "--audit-path", str(audit_path),
                        "--trace-id", "trace-bheu-05",
                    ]
                )
            output = buf.getvalue()

            self.assertEqual(exit_code, 0, f"Expected exit 0, got {exit_code}\nOutput:\n{output}")

            # Fields that must appear in the output
            self.assertIn("trace-bheu-05", output, "trace_id missing from output")
            self.assertIn(record["selected_action"], output, "selected_action missing from output")
            self.assertIn(record["release_condition"], output, "release_condition missing from output")
            self.assertIn(record["policy_profile"], output, "policy_profile missing from output")
            self.assertIn(record["config_hash"], output, "config_hash missing from output")

            # Audit chain status
            self.assertIn("OK", output, "Chain OK status missing from output")

    # ------------------------------------------------------------------
    # Test 2: Tampered audit log -> exit 3, MISMATCH reported
    # ------------------------------------------------------------------
    def test_tampered_audit_log_exit_3(self) -> None:
        """Tampered log entry causes chain mismatch, command returns exit code 3."""
        import azazel_edge.audit_review as audit_review

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            exp_path = tmp_path / "decision-explanations.jsonl"
            audit_path = tmp_path / "triage-audit.jsonl"

            _build_explanation_record(tmp_path, "trace-bheu-05", exp_path)

            # Write two audit log entries so chain has 2 entries
            logger = P0AuditLogger(audit_path)
            logger.log_action_decision(
                trace_id="trace-bheu-05", source="arbiter", action="redirect"
            )
            logger.log_evaluation(
                trace_id="trace-bheu-05", source="soc_evaluator", result="critical"
            )

            # Corrupt the second record: change a field value so its hash is wrong
            lines = audit_path.read_text(encoding="utf-8").splitlines()
            rows = [json.loads(line) for line in lines]
            rows[1]["action"] = "TAMPERED_VALUE"
            audit_path.write_text(
                "\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n",
                encoding="utf-8",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = audit_review.main(
                    argv=[
                        "--explanations-path", str(exp_path),
                        "--audit-path", str(audit_path),
                    ]
                )
            output = buf.getvalue()

            self.assertEqual(exit_code, 3, f"Expected exit 3, got {exit_code}\nOutput:\n{output}")
            self.assertIn("MISMATCH", output, "MISMATCH keyword missing from output")

    # ------------------------------------------------------------------
    # Test 3: Read-only — file contents are byte-identical after the run
    # ------------------------------------------------------------------
    def test_read_only_no_writes_to_files(self) -> None:
        """Command must not modify the explanations or audit files."""
        import azazel_edge.audit_review as audit_review

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            exp_path = tmp_path / "decision-explanations.jsonl"
            audit_path = tmp_path / "triage-audit.jsonl"

            _build_explanation_record(tmp_path, "trace-bheu-05", exp_path)

            logger = P0AuditLogger(audit_path)
            logger.log_action_decision(
                trace_id="trace-bheu-05", source="arbiter", action="redirect"
            )

            # Snapshot byte contents before running the command
            exp_before = exp_path.read_bytes()
            audit_before = audit_path.read_bytes()

            buf = io.StringIO()
            with redirect_stdout(buf):
                audit_review.main(
                    argv=[
                        "--explanations-path", str(exp_path),
                        "--audit-path", str(audit_path),
                    ]
                )

            # Assert byte-identical after the run
            self.assertEqual(
                exp_path.read_bytes(), exp_before,
                "Explanations file was modified by audit_review.main()",
            )
            self.assertEqual(
                audit_path.read_bytes(), audit_before,
                "Audit log file was modified by audit_review.main()",
            )

    # ------------------------------------------------------------------
    # Test 4: trace-id selection and last-record fallback
    # ------------------------------------------------------------------
    def test_trace_id_selection_and_last_record_fallback(self) -> None:
        """--trace-id selects the right record; omitting it picks the last."""
        import azazel_edge.audit_review as audit_review

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            exp_path = tmp_path / "decision-explanations.jsonl"
            audit_path = tmp_path / "triage-audit.jsonl"

            # Write two explanation records with different trace_ids
            _build_explanation_record(tmp_path, "trace-first", exp_path)
            _build_explanation_record(tmp_path, "trace-last", exp_path)

            logger = P0AuditLogger(audit_path)
            logger.log_action_decision(
                trace_id="trace-last", source="arbiter", action="redirect"
            )

            # --trace-id selects the first record
            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = audit_review.main(
                    argv=[
                        "--explanations-path", str(exp_path),
                        "--audit-path", str(audit_path),
                        "--trace-id", "trace-first",
                    ]
                )
            output = buf.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("trace-first", output)
            self.assertNotIn("trace-last", output.split("trace_id")[1].split("\n")[0]
                             if "trace_id" in output else output,
                             "trace-last appeared in trace_id line when trace-first was requested")

            # Omitting --trace-id picks the last record
            buf2 = io.StringIO()
            with redirect_stdout(buf2):
                exit_code2 = audit_review.main(
                    argv=[
                        "--explanations-path", str(exp_path),
                        "--audit-path", str(audit_path),
                    ]
                )
            output2 = buf2.getvalue()
            self.assertEqual(exit_code2, 0)
            self.assertIn("trace-last", output2)

    # ------------------------------------------------------------------
    # Test 5: duplicate trace-id uses the latest matching record
    # ------------------------------------------------------------------
    def test_trace_id_selection_uses_latest_matching_record(self) -> None:
        """When the same trace_id appears multiple times, the newest one wins."""
        import azazel_edge.audit_review as audit_review

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            exp_path = tmp_path / "decision-explanations.jsonl"
            audit_path = tmp_path / "triage-audit.jsonl"

            first = _build_explanation_record(tmp_path, "trace-dup", exp_path)
            second = _build_explanation_record(tmp_path, "trace-dup", exp_path)

            lines = exp_path.read_text(encoding="utf-8").splitlines()
            rows = [json.loads(line) for line in lines]
            rows[0]["operator_wording"] = "older duplicate record"
            rows[1]["operator_wording"] = "newer duplicate record"
            exp_path.write_text(
                "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
                encoding="utf-8",
            )

            logger = P0AuditLogger(audit_path)
            logger.log_action_decision(
                trace_id="trace-dup", source="arbiter", action=first["selected_action"]
            )
            logger.log_action_decision(
                trace_id="trace-dup", source="arbiter", action=second["selected_action"]
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = audit_review.main(
                    argv=[
                        "--explanations-path", str(exp_path),
                        "--audit-path", str(audit_path),
                        "--trace-id", "trace-dup",
                    ]
                )
            output = buf.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("newer duplicate record", output)
            self.assertNotIn("older duplicate record", output)

    # ------------------------------------------------------------------
    # Test 6: malformed explanations JSONL returns exit 3
    # ------------------------------------------------------------------
    def test_malformed_explanations_jsonl_exit_3(self) -> None:
        """Malformed explanation JSONL must fail closed with exit code 3."""
        import azazel_edge.audit_review as audit_review

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            exp_path = tmp_path / "decision-explanations.jsonl"
            audit_path = tmp_path / "triage-audit.jsonl"

            _build_explanation_record(tmp_path, "trace-bheu-05", exp_path)
            with exp_path.open("a", encoding="utf-8") as handle:
                handle.write('{"broken": \n')

            logger = P0AuditLogger(audit_path)
            logger.log_action_decision(
                trace_id="trace-bheu-05", source="arbiter", action="redirect"
            )

            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            old_stderr = sys.stderr
            try:
                sys.stderr = stderr_buf
                with redirect_stdout(stdout_buf):
                    exit_code = audit_review.main(
                        argv=[
                            "--explanations-path", str(exp_path),
                            "--audit-path", str(audit_path),
                        ]
                    )
            finally:
                sys.stderr = old_stderr

            self.assertEqual(exit_code, 3)
            self.assertIn("invalid explanation JSONL", stderr_buf.getvalue())

    # ------------------------------------------------------------------
    # Bonus: missing explanations file returns exit 2
    # ------------------------------------------------------------------
    def test_missing_explanations_file_exit_2(self) -> None:
        """Missing explanations file must return exit code 2, no traceback."""
        import azazel_edge.audit_review as audit_review

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            exp_path = tmp_path / "nonexistent-explanations.jsonl"
            audit_path = tmp_path / "triage-audit.jsonl"

            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = audit_review.main(
                    argv=[
                        "--explanations-path", str(exp_path),
                        "--audit-path", str(audit_path),
                    ]
                )

            self.assertEqual(exit_code, 2)

    # ------------------------------------------------------------------
    # Bonus: --json output is valid JSON with expected keys
    # ------------------------------------------------------------------
    def test_json_output_flag(self) -> None:
        """--json flag emits a parseable JSON object with expected keys."""
        import azazel_edge.audit_review as audit_review

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            exp_path = tmp_path / "decision-explanations.jsonl"
            audit_path = tmp_path / "triage-audit.jsonl"

            _build_explanation_record(tmp_path, "trace-json-test", exp_path)

            logger = P0AuditLogger(audit_path)
            logger.log_action_decision(
                trace_id="trace-json-test", source="arbiter", action="redirect"
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = audit_review.main(
                    argv=[
                        "--explanations-path", str(exp_path),
                        "--audit-path", str(audit_path),
                        "--json",
                    ]
                )
            output = buf.getvalue()
            self.assertEqual(exit_code, 0)

            parsed = json.loads(output)
            for key in (
                "trace_id", "selected_action", "release_condition",
                "policy_profile", "config_hash", "schema_valid", "chain",
            ):
                self.assertIn(key, parsed, f"Key {key!r} missing from JSON output")

            self.assertTrue(parsed["schema_valid"])
            self.assertTrue(parsed["chain"]["ok"])

    # ------------------------------------------------------------------
    # Bonus: --compact output flag
    # ------------------------------------------------------------------
    def test_compact_output_flag(self) -> None:
        """--compact flag produces a single-line summary."""
        import azazel_edge.audit_review as audit_review

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            exp_path = tmp_path / "decision-explanations.jsonl"
            audit_path = tmp_path / "triage-audit.jsonl"

            _build_explanation_record(tmp_path, "trace-compact-test", exp_path)

            logger = P0AuditLogger(audit_path)
            logger.log_action_decision(
                trace_id="trace-compact-test", source="arbiter", action="redirect"
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = audit_review.main(
                    argv=[
                        "--explanations-path", str(exp_path),
                        "--audit-path", str(audit_path),
                        "--compact",
                    ]
                )
            output = buf.getvalue().strip()
            self.assertEqual(exit_code, 0)
            # compact output is a single line containing key=value tokens
            self.assertEqual(len(output.splitlines()), 1, "compact output should be a single line")
            self.assertIn("trace=", output)
            self.assertIn("action=", output)
            self.assertIn("chain:OK", output)


if __name__ == "__main__":
    unittest.main()
