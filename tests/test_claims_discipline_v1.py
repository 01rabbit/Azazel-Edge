"""
test_claims_discipline_v1.py — pytest / unittest for tools/claims_discipline.py

Tests:
  1. run_all() returns [] on the real repo tree (current-state clean check).
  2. Each checker flags a seeded violation written into a temp dir.
  3. An allowlisted path containing a phrase is NOT flagged.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

# Make 'import tools.claims_discipline' work from repo root
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.claims_discipline import (
    ALLOWLIST,
    FORBIDDEN_PHRASES,
    find_arsenal_bheu_files,
    find_arsenal_bheu_references,
    find_hype_violations,
    run_all,
)


class TestCleanTree(unittest.TestCase):
    """Check #0: real repo tree must be violation-free."""

    def test_run_all_clean_on_real_tree(self) -> None:
        violations = run_all(_REPO_ROOT)
        self.assertEqual(
            violations,
            [],
            msg=f"Unexpected violations on real repo tree:\n" + "\n".join(violations),
        )


class TestHypeViolations(unittest.TestCase):
    """Check #1: hype phrase detection."""

    def _make_fake_repo(self, tmp: Path) -> Path:
        """Create a minimal fake repo layout under tmp."""
        (tmp / "docs").mkdir(parents=True, exist_ok=True)
        (tmp / "docs" / "arsenal").mkdir(parents=True, exist_ok=True)
        return tmp

    def test_flags_hype_phrase_in_readme(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            doc = fake_root / "docs" / "intro.md"
            doc.write_text(
                "This product offers military-grade encryption.\n", encoding="utf-8"
            )
            violations = find_hype_violations(fake_root)
            self.assertTrue(
                any("military-grade" in v for v in violations),
                msg=f"Expected 'military-grade' violation, got: {violations}",
            )

    def test_flags_hype_phrase_in_docs_subdir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            doc = fake_root / "docs" / "overview.md"
            doc.write_text(
                "We provide guaranteed protection against all threats.\n",
                encoding="utf-8",
            )
            violations = find_hype_violations(fake_root)
            self.assertTrue(
                any("guaranteed protection" in v for v in violations),
                msg=f"Expected 'guaranteed protection' violation, got: {violations}",
            )

    def test_flags_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            doc = fake_root / "docs" / "caps.md"
            doc.write_text("UNBREAKABLE security guaranteed.\n", encoding="utf-8")
            violations = find_hype_violations(fake_root)
            self.assertTrue(
                any("unbreakable" in v for v in violations),
                msg=f"Expected 'unbreakable' violation (case-insensitive), got: {violations}",
            )

    def test_allowlisted_path_not_flagged(self) -> None:
        """A file whose repo-relative path is in ALLOWLIST must be skipped."""
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            # Pick an allowlisted path that sits under docs/
            allowlisted_rel = "docs/roadmaps/blackhat-europe-auditable-edge-socnoc-roadmap.md"
            allowlisted_path = fake_root / allowlisted_rel
            allowlisted_path.parent.mkdir(parents=True, exist_ok=True)
            allowlisted_path.write_text(
                # Contains a hype phrase inside a grep example
                "grep -r \"military-grade\" docs/\n",
                encoding="utf-8",
            )
            violations = find_hype_violations(fake_root)
            self.assertEqual(
                violations,
                [],
                msg=f"Allowlisted path must not produce violations, got: {violations}",
            )

    def test_no_false_positive_on_clean_docs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            doc = fake_root / "docs" / "clean.md"
            doc.write_text("This product is reliable and well-tested.\n", encoding="utf-8")
            violations = find_hype_violations(fake_root)
            self.assertEqual(violations, [])

    def test_negated_phrase_not_flagged(self) -> None:
        """A forbidden phrase in a negation/disclaimer context must PASS."""
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            doc = fake_root / "docs" / "disclaimer.md"
            doc.write_text(
                "Azazel-Edge is not an autonomous AI defender.\n"
                "It is not military-grade and does not provide "
                "guaranteed protection.\n"
                "This tool isn't unbreakable.\n",
                encoding="utf-8",
            )
            violations = find_hype_violations(fake_root)
            self.assertEqual(
                violations,
                [],
                msg=f"Negated phrases must not be flagged, got: {violations}",
            )

    def test_positive_phrase_still_flagged(self) -> None:
        """A positive (non-negated) hype claim must still be FLAGGED."""
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            doc = fake_root / "docs" / "hype.md"
            doc.write_text(
                "The world's first autonomous AI defender.\n"
                "This is unbreakable.\n",
                encoding="utf-8",
            )
            violations = find_hype_violations(fake_root)
            self.assertTrue(
                any("autonomous ai defender" in v for v in violations),
                msg=f"Expected positive 'autonomous ai defender' flag, got: {violations}",
            )
            self.assertTrue(
                any("unbreakable" in v for v in violations),
                msg=f"Expected positive 'unbreakable' flag, got: {violations}",
            )


class TestArsenalBheuReferences(unittest.TestCase):
    """Check #2: Black Hat Europe content references in docs/arsenal/."""

    def _make_fake_repo(self, tmp: Path) -> Path:
        (tmp / "docs" / "arsenal").mkdir(parents=True, exist_ok=True)
        return tmp

    def test_flags_black_hat_europe_in_arsenal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            arsenal_file = fake_root / "docs" / "arsenal" / "blackhat-usa-2026.md"
            arsenal_file.write_text(
                "# Black Hat Europe submission\nSubmit here.\n", encoding="utf-8"
            )
            violations = find_arsenal_bheu_references(fake_root)
            self.assertTrue(
                any("black hat europe" in v for v in violations),
                msg=f"Expected 'black hat europe' violation, got: {violations}",
            )

    def test_flags_blackhat_europe_variant(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            arsenal_file = fake_root / "docs" / "arsenal" / "demo.md"
            arsenal_file.write_text(
                "Submitted to blackhat-europe track.\n", encoding="utf-8"
            )
            violations = find_arsenal_bheu_references(fake_root)
            self.assertTrue(
                any("blackhat-europe" in v for v in violations),
                msg=f"Expected 'blackhat-europe' violation, got: {violations}",
            )

    def test_no_false_positive_on_clean_arsenal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            arsenal_file = fake_root / "docs" / "arsenal" / "blackhat-usa-2026.md"
            arsenal_file.write_text(
                "# Black Hat USA 2026\nDemo of edge detection.\n", encoding="utf-8"
            )
            violations = find_arsenal_bheu_references(fake_root)
            self.assertEqual(violations, [])

    def test_missing_arsenal_dir_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # No docs/arsenal/ directory at all
            violations = find_arsenal_bheu_references(Path(td))
            self.assertEqual(violations, [])


class TestArsenalBheuFiles(unittest.TestCase):
    """Check #3: docs/arsenal/blackhat-europe-*.md file existence."""

    def _make_fake_repo(self, tmp: Path) -> Path:
        (tmp / "docs" / "arsenal").mkdir(parents=True, exist_ok=True)
        return tmp

    def test_flags_blackhat_europe_filename(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            bheu_file = fake_root / "docs" / "arsenal" / "blackhat-europe-foo.md"
            bheu_file.write_text("# draft\n", encoding="utf-8")
            violations = find_arsenal_bheu_files(fake_root)
            self.assertIn(
                "docs/arsenal/blackhat-europe-foo.md",
                violations,
                msg=f"Expected filename violation, got: {violations}",
            )

    def test_does_not_flag_other_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_root = self._make_fake_repo(Path(td))
            other = fake_root / "docs" / "arsenal" / "blackhat-usa-2026.md"
            other.write_text("# USA submission\n", encoding="utf-8")
            violations = find_arsenal_bheu_files(fake_root)
            self.assertEqual(violations, [])

    def test_missing_arsenal_dir_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            violations = find_arsenal_bheu_files(Path(td))
            self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
