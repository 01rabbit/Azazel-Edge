"""
claims_discipline.py — Automated read-only claims-discipline checker.

Three checks:
  1. Hype phrases in README.md and docs/ (case-insensitive).
  2. "Black Hat Europe" references inside docs/arsenal/ files.
  3. docs/arsenal/blackhat-europe-*.md filename existence.

Allowlisted paths may contain phrase strings without triggering check #1
(they define or quote the phrases).

Hype phrase matches are also skipped when they appear in a negation context
(e.g. "not an autonomous AI defender"), which is good claims discipline.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Union

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FORBIDDEN_PHRASES: list[str] = [
    "world's first",
    "worlds first",
    "military-grade",
    "military grade",
    "unbreakable",
    "guaranteed protection",
    "autonomous ai defender",
]

# Repo-relative paths that are allowed to contain the forbidden phrase strings.
# Paths that don't exist are simply never scanned, so future docs can be
# pre-listed here without causing errors.
ALLOWLIST: set[str] = {
    # This checker file itself
    "tools/claims_discipline.py",
    # The test file
    "tests/test_claims_discipline_v1.py",
    # Docs that define / quote the phrases (phrase-definition files)
    "docs/roadmaps/blackhat-europe-auditable-edge-socnoc-roadmap.md",
    "docs/issues/blackhat-europe/09-claims-discipline-validation.md",
}

# Negation tokens that, when they immediately precede a forbidden phrase on the
# same line, mark the occurrence as a disclaimer (good claims discipline) and
# cause it to be skipped. Matched case-insensitively on word boundaries within a
# short lookbehind window. Includes "not", "never", and any n't contraction.
_NEGATION_RE = re.compile(r"(?:\bnot\b|\bnever\b|n't\b)", re.IGNORECASE)

# Size of the same-line lookbehind window (characters before the match start).
_NEGATION_WINDOW = 20

# File extensions / name patterns considered text documents
_TEXT_SUFFIXES = {".md", ".rst"}
_TEXT_NAME_PREFIXES = {"README"}


def _is_text_doc(path: Path) -> bool:
    return path.suffix.lower() in _TEXT_SUFFIXES or any(
        path.name.upper().startswith(p) for p in _TEXT_NAME_PREFIXES
    )


def _repo_relative(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return str(path)


def _read_text(path: Path) -> str:
    """Read a file as text, ignoring undecodable bytes."""
    return path.read_text(encoding="utf-8", errors="ignore")


def _is_negated(line: str, match_start: int) -> bool:
    """Return True if the text immediately preceding ``match_start`` on ``line``
    contains a negation token within the lookbehind window."""
    window_start = max(0, match_start - _NEGATION_WINDOW)
    preceding = line[window_start:match_start]
    return _NEGATION_RE.search(preceding) is not None


# ---------------------------------------------------------------------------
# Check 1: Hype phrases
# ---------------------------------------------------------------------------

def find_hype_violations(repo_root: Union[str, Path]) -> list[str]:
    """Return 'path:lineno: phrase' strings for forbidden phrases found in
    README.md (repo root) and all text docs under docs/, excluding allowlisted
    paths."""
    repo_root = Path(repo_root).resolve()
    violations: list[str] = []

    candidates: list[Path] = []

    # README.md at repo root
    root_readme = repo_root / "README.md"
    if root_readme.is_file():
        candidates.append(root_readme)

    # All text docs under docs/
    docs_dir = repo_root / "docs"
    if docs_dir.is_dir():
        for p in sorted(docs_dir.rglob("*")):
            if p.is_file() and _is_text_doc(p):
                candidates.append(p)

    for path in candidates:
        rel = _repo_relative(path, repo_root)
        if rel in ALLOWLIST:
            continue
        try:
            text = _read_text(path)
        except (OSError, PermissionError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            lower_line = line.lower()
            for phrase in FORBIDDEN_PHRASES:
                # Scan every occurrence of the phrase on this line so each one
                # can be independently checked for a negation context.
                start = 0
                while True:
                    idx = lower_line.find(phrase, start)
                    if idx == -1:
                        break
                    if not _is_negated(line, idx):
                        violations.append(f"{rel}:{lineno}: {phrase!r}")
                    start = idx + len(phrase)

    return violations


# ---------------------------------------------------------------------------
# Check 2: Black Hat Europe references in docs/arsenal/
# ---------------------------------------------------------------------------

_BHEU_PATTERNS = [
    "black hat europe",
    "blackhat europe",
    "blackhat-europe",
]


def find_arsenal_bheu_references(repo_root: Union[str, Path]) -> list[str]:
    """Return 'path:lineno: pattern' strings for any Black Hat Europe reference
    found inside files under docs/arsenal/.  Not allowlisted."""
    repo_root = Path(repo_root).resolve()
    violations: list[str] = []

    arsenal_dir = repo_root / "docs" / "arsenal"
    if not arsenal_dir.is_dir():
        return violations

    for path in sorted(arsenal_dir.rglob("*")):
        if not path.is_file():
            continue
        if not _is_text_doc(path):
            continue
        try:
            text = _read_text(path)
        except (OSError, PermissionError):
            continue
        lower_text = text.lower()
        for pattern in _BHEU_PATTERNS:
            if pattern in lower_text:
                rel = _repo_relative(path, repo_root)
                for lineno, line in enumerate(text.splitlines(), start=1):
                    if pattern in line.lower():
                        violations.append(f"{rel}:{lineno}: {pattern!r}")

    return violations


# ---------------------------------------------------------------------------
# Check 3: docs/arsenal/blackhat-europe-*.md file existence
# ---------------------------------------------------------------------------

def find_arsenal_bheu_files(repo_root: Union[str, Path]) -> list[str]:
    """Return a list of repo-relative paths for any file matching
    docs/arsenal/blackhat-europe-*.md."""
    repo_root = Path(repo_root).resolve()
    violations: list[str] = []

    arsenal_dir = repo_root / "docs" / "arsenal"
    if not arsenal_dir.is_dir():
        return violations

    for path in sorted(arsenal_dir.glob("blackhat-europe-*.md")):
        violations.append(_repo_relative(path, repo_root))

    return violations


# ---------------------------------------------------------------------------
# Aggregate runner
# ---------------------------------------------------------------------------

def run_all(repo_root: Union[str, Path]) -> list[str]:
    """Run all three checks and return the combined list of violation strings."""
    return (
        find_hype_violations(repo_root)
        + find_arsenal_bheu_references(repo_root)
        + find_arsenal_bheu_files(repo_root)
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    repo_root: Path
    if len(sys.argv) > 1:
        repo_root = Path(sys.argv[1]).resolve()
    else:
        # Default: repo root is the parent directory of this file's directory
        repo_root = Path(__file__).resolve().parent.parent

    violations = run_all(repo_root)
    if violations:
        print("claims-discipline violations found:")
        for v in violations:
            print(f"  {v}")
        return 1
    else:
        print("claims-discipline: OK (no violations)")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
