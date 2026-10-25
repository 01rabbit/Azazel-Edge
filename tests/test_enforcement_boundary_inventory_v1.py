"""Edge#412: the decision and enforcement boundary, checked from the tree.

docs/X86_64_INTEGRATION_BOUNDARY.md ("Decision and enforcement authority")
names the Rust ``azazel-edge-core`` as the only path that applies a defensive
action with ``nft``/``tc``, and the Python ``ActionArbiter`` as a decision copy
that nothing applies. A consumer checks that statement against the unit
inventory and the Python package; these tests are that check.

The checks read files only. They do not start units or run any tool.
"""

from __future__ import annotations

import ast
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
SYSTEMD_DIR = ROOT / "systemd"
PY_DIR = ROOT / "py"
BOUNDARY_DOC = ROOT / "docs" / "X86_64_INTEGRATION_BOUNDARY.md"

ENFORCER_BINARY = "azazel-edge-core"
ENFORCER_UNIT = "azazel-edge-core.service"
FIREWALL_TOOLS = frozenset(
    {
        "nft",
        "tc",
        "iptables",
        "ip6tables",
        "iptables-nft",
        "iptables-legacy",
        "iptables-restore",
        "ip6tables-restore",
    }
)

# Python modules that run a firewall tool, each reviewed in the boundary doc.
# None of them consumes an ActionArbiter decision or applies a defensive
# action. Adding a module here needs the same review and a doc row.
REVIEWED_FIREWALL_CALLERS: Dict[str, str] = {
    "azazel_edge/outcome/postcondition.py": "read-only postcondition observer",
    "azazel_edge/service_objectives/so04_rollback_completion.py": "SO-04 harness on its own dummy interfaces",
    "azazel_edge_control/wifi_connect.py": "uplink NAT after a Wi-Fi connect",
}

# Direct importers of the Python ActionArbiter: replay, benchmarks, dry run,
# the SO-03 harness and the package itself. None is an enforcement path.
REVIEWED_ARBITER_IMPORTERS: Set[str] = {
    "azazel_edge/arbiter/__init__.py",
    "azazel_edge/scenario_replay.py",
    "azazel_edge/soc_policy_dry_run.py",
    "azazel_edge/benchmark/detection_accuracy.py",
    "azazel_edge/benchmark/pipeline_latency.py",
    "azazel_edge/service_objectives/so03_alert_queue.py",
}

EXEC_DIRECTIVES = (
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
    "ExecCondition",
)
# systemd command-line prefixes (systemd.service(5), "Command lines").
EXEC_PREFIX_CHARS = "-@:+!|"

SUBPROCESS_FUNCS = frozenset(
    {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}
)
OS_FUNCS = frozenset(
    {
        "system",
        "popen",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "posix_spawn",
        "posix_spawnp",
    }
)
ASYNCIO_FUNCS = frozenset({"create_subprocess_exec", "create_subprocess_shell"})
READ_ONLY_VERBS = frozenset({"show", "list"})


# --- systemd unit inventory -------------------------------------------------


def unit_exec_lines(unit_dir: Path) -> Iterable[Tuple[str, str, str]]:
    """Yield (unit name, directive, command line) for every Exec* line."""

    for unit in sorted(unit_dir.iterdir()):
        if not unit.is_file():
            continue
        for raw in unit.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")) or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key in EXEC_DIRECTIVES:
                yield unit.name, key, value.strip()


def _command_basenames(command: str) -> List[str]:
    names = []
    for token in command.replace("'", " ").replace('"', " ").replace(";", " ").split():
        token = token.lstrip(EXEC_PREFIX_CHARS)
        if token:
            names.append(token.rsplit("/", 1)[-1])
    return names


def units_starting(unit_dir: Path, binary: str) -> List[Tuple[str, str]]:
    return [
        (unit, key)
        for unit, key, command in unit_exec_lines(unit_dir)
        if binary in _command_basenames(command)
    ]


def units_naming_firewall_tools(unit_dir: Path) -> List[Tuple[str, str, str]]:
    hits = []
    for unit, key, command in unit_exec_lines(unit_dir):
        for name in _command_basenames(command):
            if name in FIREWALL_TOOLS:
                hits.append((unit, key, name))
    return hits


# --- Python package scan ----------------------------------------------------


def _is_exec_call(node: ast.Call, subprocess_names: Set[str]) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        owner, attr = func.value.id, func.attr
        if owner == "subprocess" and attr in SUBPROCESS_FUNCS:
            return True
        if owner == "os" and attr in OS_FUNCS:
            return True
        if owner == "asyncio" and attr in ASYNCIO_FUNCS:
            return True
    if isinstance(func, ast.Name) and func.id in subprocess_names:
        return True
    return False


def _names_firewall_tool(value: str) -> bool:
    parts = value.split()
    if not parts:
        return False
    return parts[0].rsplit("/", 1)[-1] in FIREWALL_TOOLS


def firewall_callers(py_dir: Path) -> Set[str]:
    """Modules that run a process and name a firewall tool as a command.

    Conservative on purpose: a module counts when it has any process call and
    any string constant whose first word is a firewall tool, because the argv
    is often built from variables (``[self.nft, ...]``, ``[fw_tool, ...]``).
    """

    callers = set()
    for path in sorted(py_dir.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        subprocess_names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in ("subprocess", "os", "asyncio"):
                for alias in node.names:
                    if alias.name in SUBPROCESS_FUNCS | OS_FUNCS | ASYNCIO_FUNCS:
                        subprocess_names.add(alias.asname or alias.name)
        has_exec = any(
            isinstance(node, ast.Call) and _is_exec_call(node, subprocess_names) for node in ast.walk(tree)
        )
        if not has_exec:
            continue
        names_tool = any(
            isinstance(node, ast.Constant) and isinstance(node.value, str) and _names_firewall_tool(node.value)
            for node in ast.walk(tree)
        )
        if names_tool:
            callers.add(path.relative_to(py_dir).as_posix())
    return callers


ARBITER_MODULES = frozenset({"azazel_edge.arbiter", "azazel_edge.arbiter.action"})


def arbiter_importers(py_dir: Path) -> Set[str]:
    """Modules that import the arbiter package or name ``ActionArbiter`` in code."""

    importers = set()
    for path in sorted(py_dir.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        in_arbiter_pkg = path.parent.name == "arbiter"
        for node in ast.walk(tree):
            hit = False
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level == 0:
                    hit = module in ARBITER_MODULES or (
                        module == "azazel_edge" and any(a.name == "arbiter" for a in node.names)
                    )
                else:
                    hit = in_arbiter_pkg or module.split(".")[-1] in ("arbiter", "action")
            elif isinstance(node, ast.Import):
                hit = any(a.name in ARBITER_MODULES for a in node.names)
            elif isinstance(node, ast.Name):
                hit = node.id == "ActionArbiter"
            elif isinstance(node, ast.Attribute):
                hit = node.attr == "ActionArbiter"
            if hit:
                importers.add(path.relative_to(py_dir).as_posix())
                break
    return importers


def postcondition_mutating_argv(path: Path) -> List[Tuple[int, Tuple[str, ...]]]:
    """Literal tc/nft argv passed to a ``.run(...)`` call without a read verb."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bad = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run"):
            continue
        if not node.args or not isinstance(node.args[0], (ast.Tuple, ast.List)):
            continue
        words = tuple(
            elt.value for elt in node.args[0].elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        )
        if words and words[0] in FIREWALL_TOOLS and not (READ_ONLY_VERBS & set(words)):
            bad.append((node.lineno, words))
    return bad


class EnforcerUnitInventoryTest(unittest.TestCase):
    def test_exactly_one_unit_starts_the_enforcer(self) -> None:
        self.assertEqual(units_starting(SYSTEMD_DIR, ENFORCER_BINARY), [(ENFORCER_UNIT, "ExecStart")])

    def test_no_unit_runs_a_firewall_tool_directly(self) -> None:
        self.assertEqual(units_naming_firewall_tools(SYSTEMD_DIR), [])

    def test_enforcer_unit_ships_with_enforcement_off(self) -> None:
        text = (SYSTEMD_DIR / ENFORCER_UNIT).read_text(encoding="utf-8")
        for setting in (
            'Environment="AZAZEL_DEFENSE_ENFORCE=false"',
            'Environment="AZAZEL_DEFENSE_DRY_RUN=true"',
            'Environment="AZAZEL_DEFENSE_ENFORCE_LEVEL=advisory"',
            'Environment="AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO=false"',
        ):
            self.assertIn(setting, text)

    def test_control_daemon_is_not_described_as_an_executor(self) -> None:
        text = (SYSTEMD_DIR / "azazel-edge-control-daemon.service").read_text(encoding="utf-8")
        description = [line for line in text.splitlines() if line.startswith("Description=")]
        self.assertEqual(len(description), 1)
        self.assertNotIn("executor", description[0].lower())

    def test_checker_catches_a_second_unit_starting_the_enforcer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            units = Path(tmp) / "systemd"
            shutil.copytree(SYSTEMD_DIR, units)
            extra = units / "azazel-edge-web.service"
            extra.write_text(
                extra.read_text(encoding="utf-8") + "\n[Service]\nExecStartPost=-/usr/local/bin/azazel-edge-core\n",
                encoding="utf-8",
            )
            self.assertEqual(len(units_starting(units, ENFORCER_BINARY)), 2)

    def test_checker_catches_a_unit_running_nft(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            units = Path(tmp) / "systemd"
            shutil.copytree(SYSTEMD_DIR, units)
            extra = units / "azazel-edge-selftest.service"
            extra.write_text(
                extra.read_text(encoding="utf-8") + "\nExecStartPre=/bin/bash -lc 'exec /usr/sbin/nft -f /x'\n",
                encoding="utf-8",
            )
            self.assertEqual(units_naming_firewall_tools(units), [("azazel-edge-selftest.service", "ExecStartPre", "nft")])


class PythonFirewallCallerTest(unittest.TestCase):
    def test_only_reviewed_modules_run_firewall_tools(self) -> None:
        self.assertEqual(firewall_callers(PY_DIR), set(REVIEWED_FIREWALL_CALLERS))

    def test_postcondition_observer_only_reads(self) -> None:
        self.assertEqual(postcondition_mutating_argv(PY_DIR / "azazel_edge/outcome/postcondition.py"), [])

    def test_action_arbiter_has_no_process_or_firewall_call(self) -> None:
        arbiter_dir = PY_DIR / "azazel_edge" / "arbiter"
        self.assertEqual(firewall_callers(arbiter_dir), set())
        for path in arbiter_dir.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imported.add(node.module.split(".")[0])
            self.assertFalse(imported & {"subprocess", "socket"}, path.name)

    def test_action_arbiter_importers_are_reviewed(self) -> None:
        self.assertEqual(arbiter_importers(PY_DIR), REVIEWED_ARBITER_IMPORTERS)

    def test_reviewed_callers_are_listed_in_the_boundary_doc(self) -> None:
        doc = BOUNDARY_DOC.read_text(encoding="utf-8")
        self.assertIn("## Decision and enforcement authority", doc)
        for module in REVIEWED_FIREWALL_CALLERS:
            self.assertIn(f"`py/{module}`", doc)

    def test_checker_catches_a_new_firewall_caller(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "py"
            (pkg / "azazel_edge").mkdir(parents=True)
            (pkg / "azazel_edge" / "a.py").write_text(
                "import subprocess\nsubprocess.run(['nft', 'add', 'rule'])\n", encoding="utf-8"
            )
            (pkg / "azazel_edge" / "b.py").write_text(
                "from subprocess import check_call as cc\ntool = 'tc'\ncc([tool, 'qdisc', 'replace'])\n",
                encoding="utf-8",
            )
            (pkg / "azazel_edge" / "c.py").write_text(
                "import os\nos.system('/usr/sbin/iptables -A FORWARD -j DROP')\n", encoding="utf-8"
            )
            (pkg / "azazel_edge" / "d.py").write_text("WORDS = ['nft', 'tc']\n", encoding="utf-8")
            self.assertEqual(firewall_callers(pkg), {"azazel_edge/a.py", "azazel_edge/b.py", "azazel_edge/c.py"})

    def test_checker_catches_a_mutating_observer_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "postcondition.py"
            path.write_text("runner.run(('nft', 'flush', 'ruleset'), timeout_seconds=1)\n", encoding="utf-8")
            self.assertEqual(postcondition_mutating_argv(path), [(1, ("nft", "flush", "ruleset"))])


if __name__ == "__main__":
    unittest.main()
