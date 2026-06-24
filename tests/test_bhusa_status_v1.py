from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATUS = ROOT / "bin" / "azazel-edge-bhusa-status"
REHEARSE = ROOT / "bin" / "azazel-edge-bhusa-rehearse"


class BhusaStatusV1Tests(unittest.TestCase):
    def test_status_reports_local_rehearsal_progress_without_github(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "bhusa-rehearsal.jsonl"
            for duration in ("310", "320"):
                subprocess.run(
                    [
                        str(REHEARSE),
                        "record",
                        "--variant",
                        "full",
                        "--duration-sec",
                        duration,
                        "--record-path",
                        str(record_path),
                        "--json",
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                    check=True,
                )
            result = subprocess.run(
                [
                    str(STATUS),
                    "--record-path",
                    str(record_path),
                    "--skip-github",
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["overall_state"], "planning-complete")
            self.assertEqual(payload["rehearsal_summary"]["total_runs"], 2)
            self.assertIn("record 1 more successful full rehearsals", payload["remaining_work"])
            self.assertIn("record 1 more fallback drills", payload["remaining_work"])

    def test_status_queries_github_child_issue_state_with_stubbed_gh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            record_path = tmp_path / "bhusa-rehearsal.jsonl"
            links_path = tmp_path / "links.md"
            gh_path = tmp_path / "gh"

            for duration in ("300", "305", "315"):
                subprocess.run(
                    [
                        str(REHEARSE),
                        "record",
                        "--variant",
                        "full",
                        "--duration-sec",
                        duration,
                        "--record-path",
                        str(record_path),
                        "--json",
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                    check=True,
                )
            subprocess.run(
                [
                    str(REHEARSE),
                    "record",
                    "--variant",
                    "fallback-drill",
                    "--duration-sec",
                    "95",
                    "--record-path",
                    str(record_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )

            links_path.write_text(
                textwrap.dedent(
                    """\
                    # Created issue links

                    - [#284 — Lock Vegas demo story and talk track](https://github.com/01rabbit/Azazel-Edge/issues/284)
                    - [#285 — Stabilize deterministic replay for Arsenal booth demo](https://github.com/01rabbit/Azazel-Edge/issues/285)
                    """
                ),
                encoding="utf-8",
            )
            gh_path.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import sys
                    print(json.dumps([
                        {
                            "number": 284,
                            "title": "Lock Vegas demo story and talk track",
                            "state": "CLOSED",
                            "url": "https://github.com/01rabbit/Azazel-Edge/issues/284",
                        },
                        {
                            "number": 285,
                            "title": "Stabilize deterministic replay for Arsenal booth demo",
                            "state": "OPEN",
                            "url": "https://github.com/01rabbit/Azazel-Edge/issues/285",
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
                [
                    str(STATUS),
                    "--record-path",
                    str(record_path),
                    "--links-path",
                    str(links_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                env=env,
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["github"]["linked_issue_count"], 2)
            self.assertEqual(len(payload["github"]["issues"]), 2)
            self.assertEqual(payload["github"]["issues"][0]["state"], "CLOSED")
            self.assertEqual(payload["github"]["issues"][1]["state"], "OPEN")
            self.assertIn(
                "close child issue #285 (Stabilize deterministic replay for Arsenal booth demo)",
                payload["remaining_work"],
            )

    def test_status_writes_markdown_doc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "bhusa-rehearsal.jsonl"
            status_doc_path = Path(tmp) / "15-status.md"
            for duration in ("310", "320"):
                subprocess.run(
                    [
                        str(REHEARSE),
                        "record",
                        "--variant",
                        "full",
                        "--duration-sec",
                        duration,
                        "--record-path",
                        str(record_path),
                        "--json",
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                    check=True,
                )
            result = subprocess.run(
                [
                    str(STATUS),
                    "--record-path",
                    str(record_path),
                    "--skip-github",
                    "--write-status-doc",
                    "--status-doc-path",
                    str(status_doc_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["status_doc_path"], str(status_doc_path))
            markdown = status_doc_path.read_text(encoding="utf-8")
            self.assertIn("# Status", markdown)
            self.assertIn("## Snapshot", markdown)
            self.assertIn("## Remaining Work", markdown)

    def test_status_include_freeze_check_passes_offline_doc_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            record_path = tmp_path / "bhusa-rehearsal.jsonl"
            status_doc_path = tmp_path / "15-status.md"
            offline_doc_path = tmp_path / "offline-bundle"
            offline_doc_path.mkdir()
            for duration in ("310", "320", "330"):
                subprocess.run(
                    [
                        str(REHEARSE),
                        "record",
                        "--variant",
                        "full",
                        "--duration-sec",
                        duration,
                        "--record-path",
                        str(record_path),
                        "--json",
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                    check=True,
                )
            subprocess.run(
                [
                    str(REHEARSE),
                    "record",
                    "--variant",
                    "fallback-drill",
                    "--duration-sec",
                    "95",
                    "--record-path",
                    str(record_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            result = subprocess.run(
                [
                    str(STATUS),
                    "--record-path",
                    str(record_path),
                    "--skip-github",
                    "--include-freeze-check",
                    "--offline-doc-path",
                    str(offline_doc_path),
                    "--write-status-doc",
                    "--status-doc-path",
                    str(status_doc_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertIsNotNone(payload["freeze_check"])
            self.assertTrue(payload["freeze_check"]["ok"])
            self.assertEqual(len(payload["freeze_check"]["offline_doc_checks"]), 1)
            self.assertTrue(payload["freeze_check"]["offline_doc_checks"][0]["ok"])
            markdown = status_doc_path.read_text(encoding="utf-8")
            self.assertIn("## Freeze Check", markdown)
            self.assertIn("Offline doc paths checked", markdown)


if __name__ == "__main__":
    unittest.main()
