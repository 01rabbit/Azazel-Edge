from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _python_files() -> list[Path]:
    files: list[Path] = []
    for rel in ("py", "azazel_edge_web", "tests"):
        files.extend((ROOT / rel).rglob("*.py"))
    return files


def _local_module_names(py_files: list[Path]) -> tuple[set[str], set[str]]:
    module_stems = {p.stem for p in py_files}
    package_names = {p.parent.name for p in py_files if p.stem == "__init__"}
    return module_stems, package_names


def _runtime_requirement_names() -> set[str]:
    req_path = ROOT / "requirements" / "runtime.txt"
    names: set[str] = set()
    for raw in req_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        normalized = line.split(">=")[0].split("==")[0].split("<")[0].strip().lower()
        if normalized:
            names.add(normalized)
    return names


def _third_party_imports() -> set[str]:
    stdlib = set(sys.stdlib_module_names)
    files = _python_files()
    local_mods, local_pkgs = _local_module_names(files)
    imports: set[str] = set()

    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            for module in modules:
                top = module.split(".", 1)[0]
                if not top or top in stdlib:
                    continue
                if top in {"azazel_edge", "azazel_edge_ai", "azazel_edge_control", "azazel_edge_web", "tests"}:
                    continue
                if top in local_mods or top in local_pkgs:
                    continue
                imports.add(top)
    return imports


def test_runtime_dependencies_cover_imports():
    reqs = _runtime_requirement_names()
    module_to_requirement = {
        "PIL": "pillow",
        "yaml": "pyyaml",
    }
    optional_modules = {
        # Hardware-only dependency provided by device-specific setup.
        "waveshare_epd",
    }

    missing: list[tuple[str, str]] = []
    for module in sorted(_third_party_imports()):
        if module in optional_modules:
            continue
        requirement = module_to_requirement.get(module, module.lower())
        if requirement not in reqs:
            missing.append((module, requirement))

    assert not missing, f"Missing runtime requirements for imports: {missing}"

