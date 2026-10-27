"""Edge#388: the M.I.O. cognitive-plane authority matrix, checked against the tree.

docs/architecture/mio-cognitive-plane.md states who may decide, enforce,
advise, display and audit. These tests pin the claims that can be read from
the source: the M.I.O. cognitive core is a library that no running service
imports and that reaches no enforcement, process or socket primitive; the
agent and the Web UI hold no defensive action; the Rust core reads nothing the
agent, the Web UI or M.I.O. writes. They also check that the document's links
and code paths resolve and that the other M.I.O. documents link to it.

Like tests/test_enforcement_boundary_inventory_v1.py, this guards against
accidental drift. It is not a defence against code written to evade it (an
import by computed name, a tool reached through a variable). The checks read
files only.
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "architecture" / "mio-cognitive-plane.md"
MIO_DIR = ROOT / "py" / "azazel_edge" / "mio"
AGENT = ROOT / "py" / "azazel_edge_ai" / "agent.py"
WEB_APP = ROOT / "azazel_edge_web" / "app.py"
CONTROL_DAEMON = ROOT / "py" / "azazel_edge_control" / "daemon.py"
CORE_SRC = ROOT / "rust" / "azazel-edge-core" / "src"

DEFENSIVE_ACTIONS = frozenset({"observe", "notify", "throttle", "redirect", "isolate"})

# The only programs that import azazel_edge.mio outside the package itself.
# Both are offline tools that no unit starts.
MIO_IMPORTERS = frozenset({"bin/azazel-mio-shadow-replay", "bin/azazel-mio-evaluate"})

# What the cognitive core may import from this repository.
MIO_ALLOWED_INTERNAL = frozenset({"azazel_edge.ai_governance"})
# Standard-library modules that start processes, open sockets or load native code.
MIO_FORBIDDEN_MODULES = frozenset(
    {"subprocess", "socket", "ctypes", "multiprocessing", "pty", "asyncio", "http", "ssl", "shlex", "pexpect", "docker"}
)
# Network access is the model adapter's job only.
MIO_URLLIB_ALLOWED = frozenset({"model_adapter.py"})
OS_PROCESS_CALLS = frozenset(
    {"system", "popen", "fork", "forkpty", "kill", "killpg"}
    | {f"exec{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")}
    | {f"spawn{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")}
    | {"posix_spawn", "posix_spawnp"}
)

# Modules that carry decision, enforcement or control authority. Neither the
# cognitive core nor the agent may import them.
AUTHORITY_MODULES = (
    "azazel_edge.arbiter",
    "azazel_edge_control",
    "azazel_edge.control_plane",
    "azazel_edge.deception_transition",
    "azazel_edge.engagement",
    "azazel_edge.outcome",
    "azazel_edge.opencanary_redirect",
)

# Files the agent, the Web UI or the control daemon write. The core must not
# name any of them in its non-test source.
NOT_READ_BY_CORE = (
    "azazel-edge-agent",
    "agent-query",
    "ai_advisory",
    "ai_snapshot",
    "decision-explanations",
    "control.sock",
    "mode.json",
    "azazel-edge-web",
    "azazel_edge.mio",
)

# Documents that must link to the canonical page.
CROSS_LINKED = (
    "docs/INDEX.md",
    "docs/architecture/decision-loop.md",
    "docs/architecture/local-ai-triage.md",
    "docs/MIO_PERSONA_PROFILE.md",
    "docs/MIO_PERSONA_PROFILE_JA.md",
)

_MD_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_BACKTICK = re.compile(r"`([^`\s]+)`")
_PATH_PREFIXES = ("py/", "bin/", "rust/", "tests/", "azazel_edge_web/", "docs/", "systemd/", "installer/")


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _parse(path: Path) -> Optional[ast.Module]:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return None


def _absolute_imports(tree: ast.AST) -> Set[str]:
    """Absolute module names imported; ``from pkg import name`` also yields ``pkg.name``."""
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def _python_programs() -> Iterator[Path]:
    for base in ("py", "azazel_edge_web", "tools"):
        yield from sorted((ROOT / base).rglob("*.py"))
    for path in sorted((ROOT / "bin").iterdir()):
        if path.is_file():
            head = path.read_bytes()[:64]
            if head.startswith(b"#!") and b"python" in head.split(b"\n", 1)[0]:
                yield path


def _imports_module(names: Iterable[str], prefix: str) -> bool:
    return any(n == prefix or n.startswith(prefix + ".") for n in names)


def _enclosing_functions(tree: ast.AST) -> Iterator[Tuple[ast.Call, Optional[str]]]:
    def walk(node: ast.AST, func: Optional[str]) -> Iterator[Tuple[ast.Call, Optional[str]]]:
        for child in ast.iter_child_nodes(node):
            name = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else func
            if isinstance(child, ast.Call):
                yield child, func
            yield from walk(child, name)

    yield from walk(tree, None)


def _call_target(call: ast.Call) -> Optional[Tuple[str, str]]:
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id, func.attr
    return None


def _literal_assignment(tree: ast.Module, name: str):
    """The literal value assigned to a module-level ``name`` (``frozenset({...})`` unwrapped)."""
    for node in tree.body:
        targets: List[ast.expr] = []
        value = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if any(isinstance(t, ast.Name) and t.id == name for t in targets):
            if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in {"frozenset", "set"}:
                value = value.args[0]
            return ast.literal_eval(value)
    raise AssertionError(f"{name} not assigned as a literal")


def _core_non_test_source(path: Path) -> str:
    """The file up to its ``#[cfg(test)] mod ...`` block."""
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines[:-1]):
        if line.strip() == "#[cfg(test)]" and lines[i + 1].lstrip().startswith("mod "):
            return "\n".join(lines[:i])
    return "\n".join(lines)


def _slug(heading: str) -> str:
    text = heading.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(path: Path) -> Set[str]:
    return {
        _slug(line.lstrip("#"))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("#")
    }


class MioCognitiveCoreIsALibrary(unittest.TestCase):
    """Matrix columns "M.I.O. cognitive core": no decide, no enforce, offline only."""

    def _mio_files(self) -> List[Path]:
        files = sorted(MIO_DIR.glob("*.py"))
        self.assertGreaterEqual(len(files), 15)
        return files

    def test_imports_only_stdlib_itself_and_governance(self) -> None:
        for path in self._mio_files():
            tree = _parse(path)
            self.assertIsNotNone(tree, _rel(path))
            for name in sorted(_absolute_imports(tree)):
                top = name.split(".")[0]
                if top.startswith("azazel"):
                    allowed = name.startswith("azazel_edge.mio") or name in MIO_ALLOWED_INTERNAL
                    # ``from azazel_edge.ai_governance import AIGovernance`` also yields the module name.
                    allowed = allowed or any(name.startswith(m + ".") for m in MIO_ALLOWED_INTERNAL)
                    self.assertTrue(allowed, f"{_rel(path)} imports {name}")
                self.assertNotIn(top, MIO_FORBIDDEN_MODULES, f"{_rel(path)} imports {name}")
                if top == "urllib":
                    self.assertIn(path.name, MIO_URLLIB_ALLOWED, f"{_rel(path)} imports {name}")
                for module in AUTHORITY_MODULES:
                    self.assertFalse(_imports_module([name], module), f"{_rel(path)} imports {name}")

    def test_starts_no_process(self) -> None:
        for path in self._mio_files():
            tree = _parse(path)
            for call, _func in _enclosing_functions(tree):
                target = _call_target(call)
                if target and target[0] == "os":
                    self.assertNotIn(target[1], OS_PROCESS_CALLS, f"{_rel(path)} calls os.{target[1]}")

    def test_only_offline_tools_import_it(self) -> None:
        importers: Set[str] = set()
        for path in _python_programs():
            if MIO_DIR in path.parents:
                continue
            tree = _parse(path)
            if tree is None:
                continue
            if _imports_module(_absolute_imports(tree), "azazel_edge.mio"):
                importers.add(_rel(path))
        self.assertEqual(importers, set(MIO_IMPORTERS))

    def test_no_unit_or_installer_starts_it(self) -> None:
        for base in ("systemd", "installer", "packaging"):
            for path in sorted((ROOT / base).rglob("*")):
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                for needle in ("azazel-mio-", "azazel_edge.mio", "azazel_edge/mio"):
                    self.assertFalse(needle in text, f"{_rel(path)} names {needle}")

    def test_recommendation_is_never_executable(self) -> None:
        from azazel_edge.mio.contracts import MioRecommendation

        rec = MioRecommendation.from_mapping(
            {"summary": "s", "recommended_action": "isolate", "rationale": "r", "evidence_refs": ["ev:1"], "executable": True},
            advisory_id="t:e0:c1:advisory",
        )
        self.assertIs(rec.executable, False)
        self.assertIn(rec.recommended_action.lower(), DEFENSIVE_ACTIONS)


class AgentAndWebHoldNoDefensiveAction(unittest.TestCase):
    """Matrix columns "AI agent" and "Web UI": no decide, no enforce."""

    def test_agent_imports_no_authority_module(self) -> None:
        names = _absolute_imports(_parse(AGENT))
        for module in AUTHORITY_MODULES + ("azazel_edge.mio",):
            self.assertFalse(_imports_module(names, module), f"agent imports {module}")

    def test_agent_runs_only_the_default_route_read(self) -> None:
        tree = _parse(AGENT)
        sites = []
        for call, func in _enclosing_functions(tree):
            target = _call_target(call)
            if target is None:
                continue
            if target[0] == "subprocess" or (target[0] == "os" and target[1] in OS_PROCESS_CALLS):
                sites.append((func, call))
        self.assertTrue(sites, "expected the default-route read")
        for func, call in sites:
            self.assertEqual(func, "_default_route_info")
            argv = call.args[0] if call.args else None
            self.assertIsInstance(argv, ast.List)
            words = [e.value for e in argv.elts if isinstance(e, ast.Constant)]
            self.assertEqual(words, ["-4", "route", "show", "default"])

    def test_web_ui_action_table_has_no_defensive_action(self) -> None:
        allowed = set(_literal_assignment(_parse(WEB_APP), "ALLOWED_ACTIONS"))
        self.assertIn("wifi_scan", allowed)
        self.assertEqual(allowed & DEFENSIVE_ACTIONS, set())

    def test_control_daemon_tables_have_no_defensive_action(self) -> None:
        tree = _parse(CONTROL_DAEMON)
        for name in ("WEB_UI_ACTIONS", "ROOT_ONLY_ACTIONS", "NOT_IMPLEMENTED_ACTIONS"):
            table = set(_literal_assignment(tree, name))
            self.assertTrue(table, name)
            self.assertEqual(table & DEFENSIVE_ACTIONS, set(), name)


class CoreReadsNoAdvice(unittest.TestCase):
    """Matrix column "Rust core": it decides from EVE and reads no advisory output."""

    def _sources(self) -> List[Tuple[Path, str]]:
        files = sorted(CORE_SRC.glob("*.rs"))
        self.assertTrue(files)
        return [(p, _core_non_test_source(p)) for p in files]

    def test_names_no_file_written_by_agent_web_or_mio(self) -> None:
        for path, text in self._sources():
            for needle in NOT_READ_BY_CORE:
                self.assertFalse(needle in text, f"{_rel(path)} names {needle}")

    def test_listens_on_nothing_and_only_connects_to_the_agent(self) -> None:
        joined = "\n".join(text for _p, text in self._sources())
        for listener in ("UnixListener", "TcpListener", "UdpSocket"):
            self.assertFalse(listener in joined, f"the core's non-test source uses {listener}")
        self.assertIn("UnixStream::connect", joined)

    def test_decision_happens_before_forwarding(self) -> None:
        text = _core_non_test_source(CORE_SRC / "main.rs")
        body = text[text.index("fn process_value("):]
        body = body[: body.index("\n}\n")]
        self.assertLess(body.index("decide_defense("), body.index("maybe_enforce("))
        self.assertLess(body.index("maybe_enforce("), body.index("send_to_ai_socket("))


class CanonicalDocument(unittest.TestCase):
    def test_matrix_names_every_row_and_column(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        header = next(line for line in text.splitlines() if line.startswith("| | Rust core |"))
        for column in ("Rust core", "Python `ActionArbiter`", "M.I.O. cognitive core", "AI agent", "Web UI", "Operator"):
            self.assertIn(column, header)
        for row in ("**Decide**", "**Enforce**", "**Advise**", "**Display**", "**Audit**"):
            self.assertIn(f"| {row}", text)

    def test_links_resolve(self) -> None:
        docs = [DOC] + [ROOT / p for p in CROSS_LINKED] + sorted(DOC.parent.glob("mio-*.md"))
        for doc in docs:
            for target in _MD_LINK.findall(doc.read_text(encoding="utf-8")):
                if re.match(r"^[a-z]+:", target) or target.startswith("#") or target.startswith("/"):
                    continue
                file_part, _, anchor = target.partition("#")
                resolved = (doc.parent / file_part).resolve()
                self.assertTrue(resolved.exists(), f"{_rel(doc)}: {target}")
                if anchor and resolved.suffix == ".md":
                    self.assertIn(anchor, _anchors(resolved), f"{_rel(doc)}: {target}")

    def test_code_paths_exist(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        paths = {p.rstrip(".,") for p in _BACKTICK.findall(text) if p.startswith(_PATH_PREFIXES)}
        self.assertGreaterEqual(len(paths), 10)
        for rel in sorted(paths):
            self.assertTrue((ROOT / rel).exists(), rel)

    def test_other_documents_link_to_it(self) -> None:
        linked = list(CROSS_LINKED) + [
            _rel(p) for p in sorted(DOC.parent.glob("mio-*.md")) if p != DOC
        ]
        self.assertGreaterEqual(len(linked), 12)
        for rel in linked:
            self.assertTrue("mio-cognitive-plane.md" in (ROOT / rel).read_text(encoding="utf-8"), rel)


if __name__ == "__main__":
    unittest.main()
