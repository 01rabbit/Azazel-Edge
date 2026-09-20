"""The optional GitHub lookup degrades; it does not stop the report (#420).

An enrichment source that is allowed to be absent has to be absent *visibly*.
Two failures are covered here and they are different:

1. `gh` missing raised `FileNotFoundError` out of `subprocess.run` itself --
   not out of its return value -- so the `except ValueError` around the call
   never saw it and a traceback reached the operator instead of a report.
2. Once caught, the empty issue list read as "no open issues". That is worse
   than the traceback: the report reaches its strongest verdict *because* the
   lookup failed, and nothing on the page says so.

The source is injected rather than arranged on `PATH`. A test that reaches a
branch by removing a binary from the runner stops reaching it the day the
image changes, and reports success while doing so.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from unittest import mock
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge import bhusa_status  # noqa: E402

REHEARSE = ROOT / "bin" / "azazel-edge-bhusa-rehearse"
STATUS = ROOT / "bin" / "azazel-edge-bhusa-status"

LINKS = """\
# Created issue links

- [#284 — Lock Vegas demo story](https://github.com/01rabbit/Azazel-Edge/issues/284)
- [#285 — Stabilize deterministic replay](https://github.com/01rabbit/Azazel-Edge/issues/285)
"""

ANSWERED = {
    284: {"number": 284, "title": "Lock Vegas demo story", "state": "CLOSED", "url": "u284"},
    285: {"number": 285, "title": "Stabilize deterministic replay", "state": "OPEN", "url": "u285"},
}


def _record(record_path: Path, variant: str, duration: str) -> None:
    subprocess.run(
        [
            str(REHEARSE), "record", "--variant", variant,
            "--duration-sec", duration, "--record-path", str(record_path), "--json",
        ],
        capture_output=True, text=True, cwd=str(ROOT), check=True,
    )


class GitHubDegradationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.record_path = tmp / "rehearsal.jsonl"
        for duration in ("300", "305", "315"):
            _record(self.record_path, "full", duration)
        _record(self.record_path, "fallback-drill", "95")
        self.links_path = tmp / "links.md"
        self.links_path.write_text(LINKS, encoding="utf-8")

    def _args(self, **overrides) -> argparse.Namespace:
        args = bhusa_status._build_parser().parse_args(
            [
                "--record-path", str(self.record_path),
                "--links-path", str(self.links_path),
            ]
        )
        for key, value in overrides.items():
            setattr(args, key, value)
        return args

    def _report(self, source, **overrides):
        return bhusa_status._build_report(
            self._args(**overrides),
            issue_source=source,
            now=lambda: "2026-09-20T00:00:00+00:00",
        )

    @staticmethod
    def _raising(reason: str, detail: str = "detail"):
        def source(repo: str):
            raise bhusa_status.GitHubUnavailable(reason, detail)

        return source

    # -- the five cases the issue names ----------------------------------

    def test_a_missing_gh_binary_is_reported_rather_than_raised(self) -> None:
        """Case 1, against the real default source.

        `gh` is genuinely absent in this environment, so this calls the
        shipped source rather than a stub. If `gh` is ever installed on a
        runner the assertion still holds: an authenticated `gh` answers and
        the branch below covers it, an unauthenticated one raises
        `GitHubUnavailable` with a different reason. Either way nothing
        escapes as a traceback, which is the property under test.
        """

        try:
            bhusa_status._load_github_issue_map("01rabbit/Azazel-Edge")
        except bhusa_status.GitHubUnavailable as exc:
            self.assertIn(
                exc.reason,
                {
                    bhusa_status.GH_NOT_INSTALLED,
                    bhusa_status.GH_NOT_AUTHENTICATED,
                    bhusa_status.GH_FAILED,
                    bhusa_status.GH_RATE_LIMITED,
                },
            )
        except Exception as exc:  # noqa: BLE001 - this is the defect
            self.fail(f"the default source raised {type(exc).__name__}: {exc}")

    def test_a_missing_binary_is_classified_as_missing_and_not_merely_caught(self) -> None:
        """The reason, pinned without asking the environment.

        Deleting the `FileNotFoundError` handler outright changes nothing
        observable to a test that only asks "did something get caught":
        `OSError` is its superclass and the handler below it swallows it as a
        generic `gh_failed`. The operator would then be told to investigate a
        CLI failure on a machine that has no CLI.

        This is why the test above is written to accept several reasons and
        this one is not. That one asks whether anything escapes, which is true
        wherever it runs; this one asks which reason, which needs the failure
        arranged rather than found.
        """

        with mock.patch.object(
            bhusa_status, "_run_command", side_effect=FileNotFoundError(2, "No such file", "gh")
        ):
            with self.assertRaises(bhusa_status.GitHubUnavailable) as caught:
                bhusa_status._load_github_issue_map("owner/repo")
        self.assertEqual(caught.exception.reason, bhusa_status.GH_NOT_INSTALLED)

    def test_an_unreadable_binary_is_not_reported_as_a_missing_one(self) -> None:
        """`PermissionError` is also an `OSError`, and means something else.

        A `gh` that is present but not executable is a file mode to fix, not
        an install to perform.
        """

        with mock.patch.object(
            bhusa_status, "_run_command", side_effect=PermissionError(13, "Permission denied", "gh")
        ):
            with self.assertRaises(bhusa_status.GitHubUnavailable) as caught:
                bhusa_status._load_github_issue_map("owner/repo")
        self.assertEqual(caught.exception.reason, bhusa_status.GH_NOT_EXECUTABLE)

    def test_a_start_failure_with_no_better_name_falls_back_to_generic(self) -> None:
        """The fallback the two above must not be reachable through."""

        with mock.patch.object(
            bhusa_status, "_run_command", side_effect=OSError("exec format error")
        ):
            with self.assertRaises(bhusa_status.GitHubUnavailable) as caught:
                bhusa_status._load_github_issue_map("owner/repo")
        self.assertEqual(caught.exception.reason, bhusa_status.GH_FAILED)

    def test_a_hung_lookup_is_given_up_on_rather_than_waited_out(self) -> None:
        """An enrichment source with no timeout is not optional."""

        with mock.patch.object(
            bhusa_status,
            "_run_command",
            side_effect=subprocess.TimeoutExpired(cmd=["gh"], timeout=bhusa_status.GH_TIMEOUT_SEC),
        ):
            with self.assertRaises(bhusa_status.GitHubUnavailable) as caught:
                bhusa_status._load_github_issue_map("owner/repo")
        self.assertEqual(caught.exception.reason, bhusa_status.GH_TIMED_OUT)

    def test_the_lookup_is_actually_given_a_timeout(self) -> None:
        """A `TimeoutExpired` handler on a call that can never time out is decoration."""

        with mock.patch.object(bhusa_status, "_run_command") as run:
            run.return_value = subprocess.CompletedProcess(["gh"], 0, "[]", "")
            bhusa_status._load_github_issue_map("owner/repo")
        self.assertEqual(run.call_args.kwargs.get("timeout"), bhusa_status.GH_TIMEOUT_SEC)

    def test_unparseable_output_is_not_read_as_an_empty_repository(self) -> None:
        """`[]` and "I could not read the answer" must not become the same report."""

        with mock.patch.object(bhusa_status, "_run_command") as run:
            run.return_value = subprocess.CompletedProcess(["gh"], 0, "<html>login</html>", "")
            with self.assertRaises(bhusa_status.GitHubUnavailable) as caught:
                bhusa_status._load_github_issue_map("owner/repo")
        self.assertEqual(caught.exception.reason, bhusa_status.GH_UNPARSEABLE)

    def test_a_nonzero_exit_is_unavailability_not_a_crash(self) -> None:
        report = self._report(self._raising(bhusa_status.GH_FAILED, "exit 1"))
        self.assertTrue(report["ok"])
        self.assertEqual(report["github"]["availability"], "unavailable")
        self.assertEqual(report["github"]["unavailable_reason"], bhusa_status.GH_FAILED)

    def test_a_timeout_is_unavailability_not_a_crash(self) -> None:
        report = self._report(self._raising(bhusa_status.GH_TIMED_OUT, "exceeded 20.0s"))
        self.assertTrue(report["ok"])
        self.assertEqual(report["github"]["unavailable_reason"], bhusa_status.GH_TIMED_OUT)

    def test_an_authentication_failure_is_named_as_itself(self) -> None:
        """Not folded into a generic failure: the operator's next step differs.

        A credential to refresh, a wait for a rate limit and a CLI to install
        are three different actions, and a report that says only "gh failed"
        makes the reader go find out which.
        """

        report = self._report(self._raising(bhusa_status.GH_NOT_AUTHENTICATED, "gh auth login"))
        self.assertEqual(
            report["github"]["unavailable_reason"], bhusa_status.GH_NOT_AUTHENTICATED
        )
        self.assertNotEqual(
            report["github"]["unavailable_reason"], bhusa_status.GH_FAILED
        )

    def test_a_normal_response_still_produces_counts(self) -> None:
        """The case that keeps every assertion above from passing vacuously."""

        report = self._report(lambda repo: dict(ANSWERED))
        self.assertTrue(report["ok"])
        self.assertEqual(report["github"]["availability"], "available")
        self.assertIsNone(report["github"]["unavailable_reason"])
        self.assertEqual(report["github"]["open_issue_count"], 1)
        self.assertEqual(report["github"]["closed_issue_count"], 1)
        self.assertEqual(report["limitations"], [])

    # -- absence must not read as health ---------------------------------

    def test_an_unavailable_lookup_reports_unknown_counts_not_zero(self) -> None:
        report = self._report(self._raising(bhusa_status.GH_NOT_INSTALLED))
        self.assertIsNone(report["github"]["open_issue_count"])
        self.assertIsNone(report["github"]["closed_issue_count"])

        text = bhusa_status._format_text(report)
        self.assertIn("open=unknown", text)
        self.assertNotIn("open=0", text)

        markdown = bhusa_status._format_markdown(report)
        self.assertIn("GitHub open child issues: `unknown`", markdown)
        self.assertNotIn("GitHub open child issues: `0`", markdown)

    def test_an_unavailable_lookup_cannot_reach_the_strongest_verdict(self) -> None:
        """The dangerous half of the defect, stated as a comparison.

        With every other gate satisfied, the *only* difference between these
        two runs is whether the lookup answered. If an outage could produce
        `freeze-ready`, a booth candidate would be selected on the strength of
        a failed subprocess.
        """

        answered = self._report(
            lambda repo: {284: dict(ANSWERED[284])}, include_freeze_check=True
        )
        outage = self._report(
            self._raising(bhusa_status.GH_NOT_INSTALLED), include_freeze_check=True
        )

        self.assertEqual(answered["overall_state"], "freeze-ready")
        self.assertNotEqual(outage["overall_state"], "freeze-ready")

    def test_an_unavailable_lookup_leaves_a_limitation_with_a_reason_and_a_time(self) -> None:
        report = self._report(self._raising(bhusa_status.GH_RATE_LIMITED, "API rate limit"))
        (limitation,) = report["limitations"]
        self.assertEqual(limitation["subject"], "github_child_issue_state")
        self.assertEqual(limitation["state"], "unavailable")
        self.assertEqual(limitation["reason"], bhusa_status.GH_RATE_LIMITED)
        self.assertEqual(limitation["observed_at"], "2026-09-20T00:00:00+00:00")
        self.assertIn("unknown", limitation["effect"])
        self.assertIn("## Limitations", bhusa_status._format_markdown(report))

    def test_remaining_work_says_unknown_rather_than_listing_nothing(self) -> None:
        """An empty "remaining work" section is how a reader concludes there is none."""

        report = self._report(self._raising(bhusa_status.GH_NOT_INSTALLED))
        self.assertTrue(
            any("unavailable" in item for item in report["remaining_work"]),
            report["remaining_work"],
        )

    # -- required vs optional --------------------------------------------

    def test_absence_alone_does_not_make_the_report_not_ok(self) -> None:
        report = self._report(self._raising(bhusa_status.GH_NOT_INSTALLED))
        self.assertTrue(report["ok"], "a local readiness report is not wrong for lacking gh")

    def test_require_github_fails_the_report_when_the_lookup_cannot_run(self) -> None:
        report = self._report(
            self._raising(bhusa_status.GH_NOT_INSTALLED), require_github=True
        )
        self.assertFalse(report["ok"])

    def test_require_github_passes_when_the_lookup_answers(self) -> None:
        report = self._report(lambda repo: dict(ANSWERED), require_github=True)
        self.assertTrue(report["ok"])

    def test_the_two_failure_modes_have_different_exit_codes(self) -> None:
        """Exit 2 is "no report". Exit 3 is "a report you said was not enough".

        A script that cannot tell them apart would treat a workstation without
        `gh` the same as a missing rehearsal record, and retry the wrong thing.
        """

        strict = subprocess.run(
            [
                str(STATUS), "--record-path", str(self.record_path),
                "--links-path", str(self.links_path), "--require-github", "--json",
            ],
            capture_output=True, text=True, cwd=str(ROOT), check=False,
        )
        self.assertEqual(strict.returncode, 3, strict.stderr)
        payload = json.loads(strict.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["github"]["availability"], "unavailable")

        # A *required* local check that genuinely fails: an unreadable
        # rehearsal record. An absent one is not it -- the summary reports
        # zero runs, which is an answer.
        unreadable = Path(self._tmp.name) / "corrupt.jsonl"
        unreadable.write_text("not json at all\n", encoding="utf-8")
        no_evidence = subprocess.run(
            [str(STATUS), "--record-path", str(unreadable), "--json"],
            capture_output=True, text=True, cwd=str(ROOT), check=False,
        )
        self.assertEqual(no_evidence.returncode, 2, no_evidence.stdout)
        self.assertFalse(json.loads(no_evidence.stdout)["ok"])

    def test_the_default_path_produces_a_report_with_gh_absent(self) -> None:
        """End to end, no stub, no `--skip-github`: the defect's own scenario."""

        result = subprocess.run(
            [
                str(STATUS), "--record-path", str(self.record_path),
                "--links-path", str(self.links_path), "--json",
            ],
            capture_output=True, text=True, cwd=str(ROOT), check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["github"]["availability"], "unavailable")
        self.assertIsNone(payload["github"]["open_issue_count"])

    # -- classification ---------------------------------------------------

    def test_gh_stderr_is_classified_into_the_action_it_implies(self) -> None:
        cases = [
            ("gh: To use GitHub CLI in a GitHub Actions workflow, set the GH_TOKEN. "
             "error: requires authentication", bhusa_status.GH_NOT_AUTHENTICATED),
            ("API rate limit exceeded for user ID 1", bhusa_status.GH_RATE_LIMITED),
            ("HTTP 401: Bad credentials", bhusa_status.GH_NOT_AUTHENTICATED),
            ("GraphQL: Could not resolve to a Repository", bhusa_status.GH_FAILED),
        ]
        for stderr, expected in cases:
            with self.subTest(stderr=stderr):
                self.assertEqual(
                    bhusa_status._classify_gh_failure(stderr, "", 1), expected
                )

    def test_classification_reads_stdout_too(self) -> None:
        """`gh` has moved messages between the streams across versions.

        A classifier reading only stderr would report `gh_failed` for a
        credential problem it had the text to name.
        """

        self.assertEqual(
            bhusa_status._classify_gh_failure("", "error: requires authentication", 1),
            bhusa_status.GH_NOT_AUTHENTICATED,
        )


if __name__ == "__main__":
    unittest.main()
