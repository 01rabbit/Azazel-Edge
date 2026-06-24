from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ISSUES = ROOT / "bin" / "azazel-edge-bhusa-issues"


class BhusaIssueHelperV1Tests(unittest.TestCase):
    def test_create_preview_lists_all_issue_specs(self) -> None:
        result = subprocess.run(
            [str(ISSUES), "create", "--json"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            check=True,
        )
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"], "preview")
        self.assertEqual(payload["parent_issue"], 283)
        self.assertEqual(payload["issue_count"], 8)
        self.assertEqual(len(payload["issues"]), 8)
        self.assertEqual(payload["issues"][0]["title"], "BHUSA 2026: lock demo story and talk track")
        self.assertIn("area:bhusa-2026", payload["issues"][0]["labels"])

    def test_parent_comment_renders_template_with_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            links_path = Path(tmp) / "links.md"
            links_path.write_text(
                "# Created issue links\n\n- [Issue A](https://github.com/01rabbit/Azazel-Edge/issues/1000)\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(ISSUES), "parent-comment", "--links-path", str(links_path), "--json"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertIn("Vegas readiness child issues", payload["body"])
            self.assertIn("Issue A", payload["body"])

    def test_parent_comment_writes_markdown_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            links_path = Path(tmp) / "links.md"
            output_path = Path(tmp) / "72-parent-issue-comment.md"
            links_path.write_text(
                "# Created issue links\n\n- [Issue A](https://github.com/01rabbit/Azazel-Edge/issues/1000)\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    str(ISSUES),
                    "parent-comment",
                    "--links-path",
                    str(links_path),
                    "--output-path",
                    str(output_path),
                    "--write",
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertTrue(payload["written"])
            self.assertEqual(payload["output_path"], str(output_path))
            markdown = output_path.read_text(encoding="utf-8")
            self.assertIn("Vegas readiness child issues", markdown)
            self.assertIn("Issue A", markdown)

    def test_progress_comment_renders_status_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            status_path = Path(tmp) / "status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "overall_state": "planning-complete",
                        "days_until_session": 43,
                        "thresholds": {"min_full_rehearsals": 3, "min_fallback_drills": 1},
                        "full_rehearsal_variant": {"passes": 1},
                        "rehearsal_summary": {"fallback_drill_runs": 1},
                        "github": {
                            "linked_issue_count": 8,
                            "issues": [
                                {"number": 284, "title": "Lock Vegas demo story and talk track", "state": "CLOSED"},
                                {"number": 285, "title": "Stabilize deterministic replay for Arsenal booth demo", "state": "OPEN"},
                            ],
                        },
                        "remaining_work": ["record 2 more successful full rehearsals"],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(ISSUES), "progress-comment", "--status-json-path", str(status_path), "--json"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertIn("Vegas readiness progress update", payload["body"])
            self.assertIn("Closed child issues", payload["body"])
            self.assertIn("#284 Lock Vegas demo story and talk track", payload["body"])
            self.assertIn("#285 Stabilize deterministic replay for Arsenal booth demo", payload["body"])
            self.assertIn("record 2 more successful full rehearsals", payload["body"])

    def test_progress_comment_writes_markdown_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            status_path = Path(tmp) / "status.json"
            output_path = Path(tmp) / "71-parent-progress-comment.md"
            status_path.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "overall_state": "planning-complete",
                        "days_until_session": 43,
                        "thresholds": {"min_full_rehearsals": 3, "min_fallback_drills": 1},
                        "full_rehearsal_variant": {"passes": 1},
                        "rehearsal_summary": {"fallback_drill_runs": 1},
                        "github": {"linked_issue_count": 8, "issues": []},
                        "remaining_work": ["record 2 more successful full rehearsals"],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    str(ISSUES),
                    "progress-comment",
                    "--status-json-path",
                    str(status_path),
                    "--output-path",
                    str(output_path),
                    "--write",
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertTrue(payload["written"])
            self.assertEqual(payload["output_path"], str(output_path))
            markdown = output_path.read_text(encoding="utf-8")
            self.assertIn("## Vegas readiness progress update", markdown)
            self.assertIn("record 2 more successful full rehearsals", markdown)

    def test_sync_links_renders_and_writes_current_issue_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            links_path = Path(tmp) / "links.md"
            gh_path = Path(tmp) / "gh"
            gh_path.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import sys
                    if sys.argv[1:4] != ["issue", "list", "--repo"]:
                        raise SystemExit(2)
                    print(json.dumps([
                        {
                            "number": 284,
                            "title": "[BHUSA 2026] Lock Vegas demo story and talk track",
                            "url": "https://github.com/01rabbit/Azazel-Edge/issues/284",
                            "state": "OPEN",
                        },
                        {
                            "number": 285,
                            "title": "[BHUSA 2026] Stabilize deterministic replay for Arsenal booth demo",
                            "url": "https://github.com/01rabbit/Azazel-Edge/issues/285",
                            "state": "CLOSED",
                        },
                    ]))
                    """
                ),
                encoding="utf-8",
            )
            gh_path.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{tmp}:{env['PATH']}"
            result = subprocess.run(
                [str(ISSUES), "sync-links", "--links-path", str(links_path), "--write", "--json"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                env=env,
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertTrue(payload["written"])
            markdown = links_path.read_text(encoding="utf-8")
            self.assertIn("#284 — Lock Vegas demo story and talk track", markdown)
            self.assertIn("`OPEN`", markdown)
            self.assertIn("`CLOSED`", markdown)


if __name__ == "__main__":
    unittest.main()
