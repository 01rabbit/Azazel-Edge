"""Edge#390 stage 0: the legacy `mode` inventory stays complete.

`docs/architecture/defensive-state-mode-inventory.md` lists every site that
uses the legacy concept mode (portal / shield / scapegoat). This test is a
completeness check on that page, not a behaviour test:

* every code or test file that carries a legacy-mode marker is named on the
  page, so a new use cannot appear without being inventoried and classified;
* every repository file the page names still exists.

It compares file names only. Line numbers drift with unrelated edits and are
deliberately not checked.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs" / "architecture" / "defensive-state-mode-inventory.md"

#: Where runtime, installer and test code lives.
SCANNED_DIRS = ("py", "azazel_edge_web", "bin", "rust", "installer", "systemd", "tools", "tests")

#: Markers of the legacy concept mode. Captive-portal names and concept
#: branding are out of scope (inventory §5), so a bare "portal" is not one.
MARKERS = (
    re.compile(r"current_mode"),
    re.compile(r"/api/mode\b"),
    re.compile(r"\bmode_(?:portal|shield|scapegoat|set|status|get|apply_default)\b"),
    re.compile(r"\bModeManager\b|\bMODE_MANAGER\b|\bmode_manager\b"),
    re.compile(r"\bmode_state_candidates\b"),
    re.compile(r"\brecent_mode_changes\b|\bmode_last_change\b|\bmode_label\b"),
    re.compile(r"scapegoat", re.IGNORECASE),
    re.compile(r"""["']shield["']"""),
    re.compile(r"(?<![\w-])mode\.json"),
)

#: This file names the markers itself.
SELF = Path(__file__).resolve().relative_to(ROOT).as_posix()


def _tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--", *SCANNED_DIRS],
            check=True,
            capture_output=True,
        ).stdout
        files = [name for name in out.decode("utf-8").split("\0") if name]
        if files:
            return files
    except (OSError, subprocess.CalledProcessError):
        pass
    # No git (e.g. an exported tree): walk the directories instead.
    found = []
    for top in SCANNED_DIRS:
        base = ROOT / top
        if base.is_dir():
            for path in base.rglob("*"):
                if path.is_file() and "__pycache__" not in path.parts and "target" not in path.parts:
                    found.append(path.relative_to(ROOT).as_posix())
    return found


def _files_with_markers() -> set[str]:
    hits = set()
    for name in _tracked_files():
        if name == SELF:
            continue
        try:
            text = (ROOT / name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if any(marker.search(text) for marker in MARKERS):
            hits.add(name)
    return hits


def _page() -> str:
    return INVENTORY.read_text(encoding="utf-8")


def _named_paths(page: str) -> set[str]:
    """Repository paths the page names inside code spans."""

    names = set()
    for span in re.findall(r"`([^`\n]+)`", page):
        candidate = span.split(":", 1)[0].strip()
        if "/" in candidate and re.fullmatch(r"[\w./-]+", candidate) and not candidate.startswith("/"):
            if candidate.split("/", 1)[0] in SCANNED_DIRS + ("docs",) or candidate.endswith(".md"):
                names.add(candidate)
    return names


def test_the_marker_scan_finds_the_known_sites():
    """The scan itself must work, or the completeness check passes vacuously."""

    hits = _files_with_markers()

    for expected in (
        "py/azazel_edge_control/mode_manager.py",
        "azazel_edge_web/app.py",
        "azazel_edge_web/static/sentinel.js",
    ):
        assert expected in hits, f"marker scan missed {expected}"


def test_every_file_with_a_legacy_mode_marker_is_inventoried():
    page = _page()
    missing = sorted(name for name in _files_with_markers() if f"`{name}" not in page)

    assert not missing, (
        "these files use the legacy concept mode but are not in "
        f"{INVENTORY.relative_to(ROOT)}: {missing}. Add a row with its use "
        "class and target term (Edge#390) rather than widening the markers."
    )


def test_every_path_the_inventory_names_exists():
    named = _named_paths(_page())
    gone = sorted(name for name in named if not (ROOT / name).exists())

    assert named, "the inventory names no repository paths; the parser is broken"
    assert not gone, f"the inventory names files that no longer exist: {gone}"
