"""Edge#477: the installer installs every module the installed code needs.

install_migrated_tools.sh installs the Python code into /opt/azazel-edge file
by file (and by package glob). `auth.py`, `io_helpers.py` and `_util.py` were
missing from it, so the installed Web UI and agent could not import them.
These tests read the installer's own `install` lines and check:

- every in-repo module imported (statically, transitively) by an installed
  module, by a module a shipped unit starts with `-m`, or by an installed
  launcher, is installed too;
- every module of the packages is either installed or named below as not
  installed on purpose, so a new module needs a decision;
- verify_runtime_sync.sh compares every installed module and Web UI asset.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "installer" / "internal" / "install_migrated_tools.sh"
SYNC = ROOT / "installer" / "internal" / "verify_runtime_sync.sh"
PACKAGE_ROOTS = ("py", "azazel_edge_web")

# Not installed on purpose: development, measurement and research code that
# no installed module, unit or launcher imports. Keyed by a path prefix.
NOT_INSTALLED = {
    "py/azazel_edge/benchmark/": "benchmark harness (development)",
    "py/azazel_edge/engagement/": "engagement research code, not imported by the installed runtime",
    "py/azazel_edge/mio/": "MIO shadow evaluation (bin/azazel-mio-*), not installed",
    "py/azazel_edge/outcome/": "outcome/postcondition harness (service objectives, CI)",
    "py/azazel_edge/service_objectives/": "service-objective harnesses (CI and lab)",
    "py/azazel_edge/bhusa_": "event preparation tools (bin/azazel-edge-bhusa-*, run from a checkout)",
    "py/azazel_edge/deception_shadow_client.py": "client of an external service, imported by nothing installed",
    "py/azazel_edge/deception_transition.py": "imported by nothing installed",
    "py/azazel_edge/engagement_advisory_client.py": "used by outcome/ (not installed)",
    "py/azazel_edge/soc_policy_dry_run.py": "bin/azazel-soc-policy-dry-run, not installed",
}


def _installer_sources() -> set[str]:
    """Repo-relative files that install_migrated_tools.sh installs."""
    src = TOOLS.read_text(encoding="utf-8")
    loop = re.search(r"^for package in \\\n(.*?)^do\n(.*?)^done\n", src, re.S | re.M)
    assert loop, "the package loop of install_migrated_tools.sh"
    packages = [p.strip(" \\") for p in loop.group(1).splitlines() if p.strip(" \\")]
    assert packages
    found: set[str] = set()
    for line in src.splitlines():
        if not line.lstrip().startswith("install -m "):
            continue
        for quoted, tail in re.findall(r'"\$REPO_ROOT/([^"]+)"(\S*)', line):
            pattern = quoted + tail
            expanded = [pattern.replace("${package}", p) for p in packages] if "${package}" in pattern else [pattern]
            for item in expanded:
                matches = sorted(ROOT.glob(item))
                assert matches, f"installer names a file that is not in the repo: {item}"
                found.update(str(m.relative_to(ROOT)) for m in matches if m.is_file())
    return found


def _module_file(name: str) -> Path | None:
    parts = name.split(".")
    for base in (ROOT / "py", ROOT):
        path = base.joinpath(*parts)
        if (path / "__init__.py").is_file():
            return path / "__init__.py"
        if path.with_suffix(".py").is_file():
            return path.with_suffix(".py")
    return None


def _module_name(path: Path) -> str:
    rel = path.relative_to(ROOT / "py") if path.is_relative_to(ROOT / "py") else path.relative_to(ROOT)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _imports(path: Path) -> set[Path]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    me = _module_name(path)
    package = me if path.name == "__init__.py" else me.rpartition(".")[0]
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                if node.level > 1:
                    parts = parts[: len(parts) - (node.level - 1)]
                base = ".".join(parts + ([node.module] if node.module else []))
            names.add(base)
            names.update(f"{base}.{alias.name}" for alias in node.names)
    out: set[Path] = set()
    for name in names:
        parts = name.split(".")
        for i in range(1, len(parts) + 1):
            found = _module_file(".".join(parts[:i]))
            if found is not None:
                out.add(found)
    return out


def _closure(starts: set[Path]) -> set[Path]:
    seen: set[Path] = set()
    stack = list(starts)
    while stack:
        path = stack.pop()
        if path in seen:
            continue
        seen.add(path)
        stack.extend(_imports(path) - seen)
    return seen


def _unit_and_launcher_entry_points(installed: set[str]) -> set[Path]:
    """Modules started by the shipped units (`-m pkg.mod`, `/opt/azazel-edge/py/x.py`)
    and by the launchers the installer puts in /usr/local/bin."""
    entries: set[Path] = set()
    texts = [p.read_text(encoding="utf-8") for p in sorted((ROOT / "systemd").glob("*.service"))]
    texts += [(ROOT / rel).read_text(encoding="utf-8") for rel in installed if rel.startswith("bin/")]
    for text in texts:
        for name in re.findall(r"\s-m\s+([A-Za-z_][\w.]*)", text):
            found = _module_file(name)
            if found is not None:
                entries.add(found)
        for rel in re.findall(r"(?:/opt/azazel-edge|\$\{ROOT_DIR\})/((?:py|azazel_edge_web)/[\w/]+\.py)", text):
            entries.add(ROOT / rel)
        for name in re.findall(r"^from\s+(azazel_edge[\w.]*)\s+import", text, re.M):
            found = _module_file(name)
            if found is not None:
                entries.add(found)
    return entries


def _repo_modules() -> set[str]:
    out: set[str] = set()
    for top in PACKAGE_ROOTS:
        out.update(str(p.relative_to(ROOT)) for p in (ROOT / top).rglob("*.py"))
    return out


def test_the_three_modules_named_in_the_issue_are_installed():
    installed = _installer_sources()
    for rel in ("azazel_edge_web/auth.py", "azazel_edge_web/io_helpers.py", "py/azazel_edge/_util.py"):
        assert rel in installed, rel


def test_every_module_the_installed_code_imports_is_installed():
    installed = _installer_sources()
    starts = {ROOT / rel for rel in installed if rel.endswith(".py")}
    starts |= _unit_and_launcher_entry_points(installed)
    needed = {str(p.relative_to(ROOT)) for p in _closure(starts)}
    missing = sorted(needed - installed)
    assert not missing, f"imported by installed code but not installed: {missing}"


def test_every_package_module_is_installed_or_excluded_on_purpose():
    installed = _installer_sources()
    unclassified = sorted(
        rel for rel in _repo_modules()
        if rel not in installed and not any(rel.startswith(prefix) for prefix in NOT_INSTALLED)
    )
    assert not unclassified, (
        "modules neither installed by install_migrated_tools.sh nor listed in NOT_INSTALLED: "
        f"{unclassified}"
    )
    # An exclusion must not hide a module that is installed after all.
    for prefix in NOT_INSTALLED:
        assert not [rel for rel in installed if rel.startswith(prefix)], prefix


def test_the_web_ui_templates_and_static_files_are_all_installed():
    installed = _installer_sources()
    for sub in ("static", "templates"):
        for path in (ROOT / "azazel_edge_web" / sub).iterdir():
            assert str(path.relative_to(ROOT)) in installed, path


def test_the_runtime_sync_check_covers_every_installed_module():
    src = SYNC.read_text(encoding="utf-8")
    files = re.search(r"mapfile -t FILES <<'EOF'\n(.*?)\nEOF", src, re.S).group(1).split()
    dirs = re.search(r"mapfile -t DIRS <<'EOF'\n(.*?)\nEOF", src, re.S).group(1).split()
    installed = _installer_sources()
    for rel in sorted(installed):
        if not rel.startswith(PACKAGE_ROOTS):
            continue
        if not rel.endswith((".py", ".js", ".css", ".html")):
            continue
        covered = rel in files or any(rel.startswith(d + "/") and "/" not in rel[len(d) + 1:] for d in dirs)
        assert covered, f"verify_runtime_sync.sh does not compare {rel}"
