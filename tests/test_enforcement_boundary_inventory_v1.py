"""Edge#412: the decision and enforcement boundary, checked from the tree.

docs/X86_64_INTEGRATION_BOUNDARY.md ("Decision and enforcement authority")
names the Rust ``azazel-edge-core`` as the Edge runtime path that applies a
defensive action, the Python ``ActionArbiter`` as a decision copy that nothing
applies, and lists every other place in the tree that runs a firewall tool.
These tests are the check a consumer runs against that statement.

What this is and is not: a guard against accidental drift (a new unit, a new
module or a new installer line that runs ``nft``/``tc``/``iptables``). It is
not a defence against code written to evade it -- an argv assembled from
variables, an interpreter started with an inline script, a tool reached
through a shell variable, or a library loaded by a computed name all pass. The
boundary doc states the same limit.

The checks read files only. They do not start units or run any tool.
"""

from __future__ import annotations

import ast
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
SYSTEMD_DIR = ROOT / "systemd"
INSTALLER_DIR = ROOT / "installer"
BOUNDARY_DOC = ROOT / "docs" / "X86_64_INTEGRATION_BOUNDARY.md"

ENFORCER_BINARY = "azazel-edge-core"
ENFORCER_UNIT = "azazel-edge-core.service"

# ``ip`` is deliberately absent. "ip" is a common dictionary key and argv word
# (about twenty Python modules contain the string), the file-level heuristic
# below would flag most of them, and the uses that change state (``ip link`` /
# ``ip netns`` in the SO-02 harness) move interfaces, not filtering policy.
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
        "ipset",
        "conntrack",
    }
)
# Python libraries that change filtering or routing state without a process.
FIREWALL_LIBRARIES = frozenset({"pyroute2", "nftables", "iptc"})

# Every Python module in the tree that runs a firewall tool. None consumes an
# ActionArbiter decision. Each has a row in the boundary doc.
REVIEWED_FIREWALL_CALLERS: Dict[str, str] = {
    "py/azazel_edge/outcome/postcondition.py": "read-only observation of the core's enforcement postcondition",
    "py/azazel_edge/service_objectives/so04_rollback_completion.py": "SO-04 harness on dummy interfaces it creates",
    "py/azazel_edge_control/wifi_connect.py": "uplink NAT after a Wi-Fi connect; changes network state, not a defensive action",
    "tools/hil/azazel_hil_remote.py": "HIL tool, read-only tc/nft observation",
}

# Every shell line in the tree that runs a firewall tool, by file. Lines inside
# heredocs count: they are the scripts and units the installer generates.
# Only baseline connectivity setup and read-only checks belong here. No entry
# may be a defensive action: the Rust core is the only defensive path
# (Edge#412; the Wazuh active response exception was removed by owner decision).
REVIEWED_SHELL_INVOCATIONS: Dict[str, Dict[str, str]] = {
    "installer/internal/install_captive_portal.sh": {
        'nft -f "${NFT_FILE}" || true': "baseline firewall: captive portal HTTP redirect",
    },
    "installer/internal/install_internal_network.sh": {
        "if nft list table ip azazel_internal >/dev/null 2>&1; then": "baseline firewall: internal network NAT/forward",
        "nft delete table ip azazel_internal": "baseline firewall: internal network NAT/forward",
        'nft -f "$NFT_RULES_FILE"': "baseline firewall: internal network NAT/forward",
        "nft list table ip azazel_internal >/dev/null 2>&1 && nft delete table ip azazel_internal || true": (
            "baseline firewall: generated azazel-internal-apply runner"
        ),
        "nft -f /etc/nftables.d/azazel-internal.nft || true": "baseline firewall: generated azazel-internal-apply runner",
        "nft list table ip azazel_internal": "installer verify step, read-only",
    },
}

# Units the installer writes with a heredoc instead of copying from systemd/.
REVIEWED_GENERATED_UNITS: Dict[str, str] = {
    "azazel-internal-apply.service": "installer/internal/install_internal_network.sh",
}

# Direct importers of the Python ActionArbiter: replay, benchmarks, dry run
# and the package itself. None is an enforcement path. (The SO-03 harness
# measures the Rust core's decisions and does not import it.)
REVIEWED_ARBITER_IMPORTERS: Set[str] = {
    "py/azazel_edge/arbiter/__init__.py",
    "py/azazel_edge/scenario_replay.py",
    "py/azazel_edge/soc_policy_dry_run.py",
    "py/azazel_edge/benchmark/detection_accuracy.py",
    "py/azazel_edge/benchmark/pipeline_latency.py",
}

EXCLUDED_TOP = frozenset({".git", "tests", "docs", "rust", ".venv", "venv", "node_modules"})
NON_SCRIPT_SUFFIXES = frozenset(
    {
        ".md", ".html", ".json", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".ttf", ".otf",
        ".woff", ".woff2", ".css", ".js", ".yaml", ".yml", ".toml", ".txt", ".rs", ".lock", ".gz", ".csv",
        ".j2", ".tmpl", ".rules", ".xml", ".pyc",
    }
)

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

PROCESS_MODULES: Dict[str, frozenset] = {
    "subprocess": frozenset(
        {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}
    ),
    "os": frozenset(
        {
            "system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
            "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe",
            "posix_spawn", "posix_spawnp",
        }
    ),
    "asyncio": frozenset({"create_subprocess_exec", "create_subprocess_shell"}),
    "pty": frozenset({"spawn"}),
}
READ_ONLY_VERBS = frozenset({"show", "list"})


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _tree_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).parts
        if not rel or rel[0] in EXCLUDED_TOP or "__pycache__" in rel or "target" in rel:
            continue
        if path.is_file():
            yield path


def _is_python(path: Path) -> bool:
    if path.suffix == ".py":
        return True
    if path.suffix:
        return False
    try:
        with path.open("rb") as fh:
            first = fh.readline(200)
    except OSError:
        return False
    return first.startswith(b"#!") and b"python" in first


# --- systemd unit inventory -------------------------------------------------


def _parse_exec_lines(name: str, text: str) -> Iterable[Tuple[str, str, str]]:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in EXEC_DIRECTIVES:
            yield name, key, value.strip()


_HEREDOC_START = re.compile(r"cat\s+>\s*\"?([^\s\"<]+)\"?\s*<<-?\s*['\"]?(\w+)['\"]?")
_ASSIGN = re.compile(r"^\s*(?:readonly\s+|local\s+)?([A-Za-z_]\w*)=\"?([^\"\s]+)\"?\s*$")


def generated_units(installer_dir: Path) -> Dict[str, Tuple[str, str]]:
    """Units an installer writes with a heredoc: name -> (installer, body).

    A heredoc is a unit when its target resolves under ``/etc/systemd/system``
    or its body has a ``[Service]`` section.
    """

    units: Dict[str, Tuple[str, str]] = {}
    for script in sorted(p for p in installer_dir.rglob("*") if p.is_file()):
        try:
            lines = script.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        variables: Dict[str, str] = {}
        i = 0
        while i < len(lines):
            assign = _ASSIGN.match(lines[i])
            if assign:
                variables[assign.group(1)] = assign.group(2)
            start = _HEREDOC_START.search(lines[i])
            if not start:
                i += 1
                continue
            target, tag = start.group(1), start.group(2)
            target = re.sub(r"\$\{?(\w+)\}?", lambda m: variables.get(m.group(1), m.group(0)), target)
            body: List[str] = []
            i += 1
            while i < len(lines) and lines[i].strip() != tag:
                body.append(lines[i])
                i += 1
            text = "\n".join(body)
            if target.startswith("/etc/systemd/system/") or any(l.strip() == "[Service]" for l in body):
                units[target.rsplit("/", 1)[-1]] = (script.relative_to(installer_dir.parent).as_posix(), text)
            i += 1
    return units


def unit_exec_lines(unit_dir: Path, installer_dir: Optional[Path] = None) -> Iterable[Tuple[str, str, str]]:
    """Yield (unit name, directive, command line) for every Exec* line."""

    for unit in sorted(unit_dir.iterdir()):
        if unit.is_file():
            yield from _parse_exec_lines(unit.name, unit.read_text(encoding="utf-8"))
    if installer_dir is not None:
        for name, (_, body) in sorted(generated_units(installer_dir).items()):
            yield from _parse_exec_lines(name, body)


def _command_basenames(command: str) -> List[str]:
    names = []
    for token in re.split(r"[\s'\";&|()`]+", command):
        token = token.lstrip(EXEC_PREFIX_CHARS)
        if token:
            names.append(token.rsplit("/", 1)[-1])
    return names


def units_starting(unit_dir: Path, binary: str, installer_dir: Optional[Path] = None) -> List[Tuple[str, str]]:
    return [
        (unit, key)
        for unit, key, command in unit_exec_lines(unit_dir, installer_dir)
        if binary in _command_basenames(command)
    ]


def units_naming_firewall_tools(unit_dir: Path, installer_dir: Optional[Path] = None) -> List[Tuple[str, str, str]]:
    hits = []
    for unit, key, command in unit_exec_lines(unit_dir, installer_dir):
        for name in _command_basenames(command):
            if name in FIREWALL_TOOLS:
                hits.append((unit, key, name))
    return hits


_INSTALL_UNIT = re.compile(r"\binstall\b[^\n]*?\s\"?(\S*?)/?systemd/([\w.@-]+)\"?\s+\"?/etc/systemd/system/([\w.@-]+)")


def installer_copied_units(installer_dir: Path) -> Set[Tuple[str, str]]:
    """(source unit, installed name) for every ``install .../systemd/X /etc/systemd/system/Y``."""

    copied = set()
    for script in sorted(p for p in installer_dir.rglob("*") if p.is_file()):
        try:
            text = script.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in _INSTALL_UNIT.finditer(text):
            copied.add((match.group(2), match.group(3)))
    return copied


# --- shell invocations ------------------------------------------------------

_SHELL_INVOKE = re.compile(
    r"(?:^|[;&|(`!]|\$\(|\b(?:if|then|do|else|elif|while|until|sudo|exec|env|command|xargs|nohup)\s)\s*"
    r"(?:/[\w./-]*/)?(" + "|".join(sorted((re.escape(t) for t in FIREWALL_TOOLS), key=len, reverse=True)) + r")"
    r"(?=\s|$|[;&|)\"'`])"
)


def shell_firewall_invocations(root: Path) -> Dict[str, Set[str]]:
    """Non-Python, non-comment lines that run a firewall tool, by file."""

    found: Dict[str, Set[str]] = {}
    for path in _tree_files(root):
        if path.suffix in NON_SCRIPT_SUFFIXES or _is_python(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or re.match(r"(?:echo|printf|logger)\b", line):
                continue
            if _SHELL_INVOKE.search(line):
                found.setdefault(path.relative_to(root).as_posix(), set()).add(line)
    return found


# --- Wazuh active response -------------------------------------------------

ACTIVE_RESPONSE_DIR = "/active-response/"
_WRITE_VERBS = frozenset({"tee", "install", "cp", "mv", "ln", "dd", "rsync"})
_VAR_REF = re.compile(r"\$\{?(\w+)(?::\?)?\}?")


def active_response_writers(installer_dir: Path) -> List[Tuple[str, str]]:
    """(installer, path) for every line that writes into a Wazuh active-response directory.

    Conservative: a non-comment line counts when it redirects (``>``) or uses a
    copy/install verb and any word on it, after substituting shell variables
    assigned earlier in the same script, contains ``/active-response/``.
    """

    hits: List[Tuple[str, str]] = []
    for script in sorted(p for p in installer_dir.rglob("*") if p.is_file()):
        try:
            lines = script.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        variables: Dict[str, str] = {}
        for raw in lines:
            assign = _ASSIGN.match(raw)
            if assign:
                variables[assign.group(1)] = assign.group(2)
                continue
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            words = [
                _VAR_REF.sub(lambda m: variables.get(m.group(1), m.group(0)), w)
                for w in re.split(r"[\s'\";&|()`<>]+", line)
                if w
            ]
            writes = ">" in line or bool(_WRITE_VERBS & {w.rsplit("/", 1)[-1] for w in words})
            if writes:
                hits.extend(
                    (script.relative_to(installer_dir.parent).as_posix(), w) for w in words if ACTIVE_RESPONSE_DIR in w
                )
    return hits


# --- Python scan ------------------------------------------------------------


class _ModuleScan:
    """Process calls and firewall references in one Python module."""

    def __init__(self, tree: ast.AST) -> None:
        self.module_aliases: Dict[str, str] = {}
        self.func_aliases: Set[str] = set()
        self.star_modules: Set[str] = set()
        self.firewall_libraries: Set[str] = set()
        self._collect_imports(tree)
        self._collect_assignments(tree)
        self.has_process_call = any(isinstance(n, ast.Call) and self._is_process_call(n) for n in ast.walk(tree))
        self.names_firewall_tool = any(
            isinstance(n, ast.Constant) and isinstance(n.value, str) and _names_firewall_tool(n.value)
            for n in ast.walk(tree)
        )

    def _collect_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in FIREWALL_LIBRARIES:
                        self.firewall_libraries.add(top)
                    if alias.name in PROCESS_MODULES:
                        self.module_aliases[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                top = node.module.split(".")[0]
                if top in FIREWALL_LIBRARIES:
                    self.firewall_libraries.add(top)
                if node.module in PROCESS_MODULES:
                    for alias in node.names:
                        if alias.name == "*":
                            self.star_modules.add(node.module)
                        elif alias.name in PROCESS_MODULES[node.module]:
                            self.func_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.Call):
                # importlib.import_module("nftables") / __import__("pyroute2")
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
                if name in ("import_module", "__import__") and node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        top = arg.value.split(".")[0]
                        if top in FIREWALL_LIBRARIES:
                            self.firewall_libraries.add(top)

    def _collect_assignments(self, tree: ast.AST) -> None:
        # Fixed point over ``r = subprocess.run`` / ``sp = subprocess`` / ``r = getattr(subprocess, "run")``.
        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if self._module_of(node.value) and target.id not in self.module_aliases:
                        self.module_aliases[target.id] = self._module_of(node.value)  # type: ignore[assignment]
                        changed = True
                    elif self._is_process_func(node.value) and target.id not in self.func_aliases:
                        self.func_aliases.add(target.id)
                        changed = True

    def _module_of(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return self.module_aliases.get(node.id)
        if isinstance(node, ast.Call) and node.args:
            # importlib.import_module("subprocess") / __import__("subprocess")
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
            arg = node.args[0]
            if name in ("import_module", "__import__") and isinstance(arg, ast.Constant) and arg.value in PROCESS_MODULES:
                return arg.value
        return None

    def _is_process_func(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            if node.id in self.func_aliases:
                return True
            return any(node.id in PROCESS_MODULES[m] for m in self.star_modules)
        if isinstance(node, ast.Attribute):
            module = self._module_of(node.value)
            return module is not None and node.attr in PROCESS_MODULES[module]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if node.args and self._module_of(node.args[0]):
                # getattr(subprocess, <anything>): counted, the name may be computed.
                return True
        return False

    def _is_process_call(self, node: ast.Call) -> bool:
        return self._is_process_func(node.func)


def _names_firewall_tool(value: str) -> bool:
    parts = value.split()
    if not parts:
        return False
    return parts[0].rsplit("/", 1)[-1] in FIREWALL_TOOLS


def _python_files(root: Path) -> Iterable[Path]:
    for path in _tree_files(root):
        if _is_python(path):
            yield path


def _scan(path: Path) -> _ModuleScan:
    return _ModuleScan(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))


def firewall_callers(root: Path) -> Set[str]:
    """Modules that run a process and name a firewall tool as a command.

    Conservative on purpose: a module counts when it has any process call and
    any string constant whose first word is a firewall tool, because the argv
    is often built from variables (``[self.nft, ...]``, ``[fw_tool, ...]``).
    """

    callers = set()
    for path in _python_files(root):
        scan = _scan(path)
        if scan.has_process_call and scan.names_firewall_tool:
            callers.add(path.relative_to(root).as_posix())
    return callers


def firewall_library_users(root: Path) -> Dict[str, Set[str]]:
    users: Dict[str, Set[str]] = {}
    for path in _python_files(root):
        libraries = _scan(path).firewall_libraries
        if libraries:
            users[path.relative_to(root).as_posix()] = libraries
    return users


ARBITER_MODULES = frozenset({"azazel_edge.arbiter", "azazel_edge.arbiter.action"})


def arbiter_importers(root: Path) -> Set[str]:
    """Modules that import the arbiter package or name ``ActionArbiter`` in code."""

    importers = set()
    for path in _python_files(root):
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
                importers.add(path.relative_to(root).as_posix())
                break
    return importers


def postcondition_mutating_argv(path: Path) -> List[Tuple[int, Tuple[str, ...]]]:
    """Literal tc/nft argv passed to a ``.run(...)`` call without a read verb.

    Only literal argv is seen; an argv held in a variable is not (doc limit).
    """

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


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class EnforcerUnitInventoryTest(unittest.TestCase):
    def test_exactly_one_unit_starts_the_enforcer(self) -> None:
        self.assertEqual(
            units_starting(SYSTEMD_DIR, ENFORCER_BINARY, INSTALLER_DIR), [(ENFORCER_UNIT, "ExecStart")]
        )

    def test_no_unit_runs_a_firewall_tool_directly(self) -> None:
        self.assertEqual(units_naming_firewall_tools(SYSTEMD_DIR, INSTALLER_DIR), [])

    def test_generated_units_are_reviewed(self) -> None:
        found = {name: script for name, (script, _) in generated_units(INSTALLER_DIR).items()}
        self.assertEqual(found, REVIEWED_GENERATED_UNITS)

    def test_installer_copies_units_only_from_systemd_dir(self) -> None:
        copied = installer_copied_units(INSTALLER_DIR)
        self.assertTrue(copied)
        for source, installed in copied:
            self.assertEqual(source, installed)
            self.assertTrue((SYSTEMD_DIR / source).is_file(), source)

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

    def test_checker_catches_a_heredoc_unit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            installer = Path(tmp) / "installer"
            _write(
                installer / "internal" / "x.sh",
                'UNIT="/etc/systemd/system/x.service"\ncat > "$UNIT" <<\'EOS\'\n[Unit]\nDescription=x\n'
                "[Service]\nExecStart=/usr/local/bin/azazel-edge-core\nExecStartPre=/usr/sbin/nft -f /x\nEOS\n",
            )
            self.assertEqual(generated_units(installer)["x.service"][0], "installer/internal/x.sh")
            self.assertEqual(
                units_starting(SYSTEMD_DIR, ENFORCER_BINARY, installer),
                [(ENFORCER_UNIT, "ExecStart"), ("x.service", "ExecStart")],
            )
            self.assertEqual(units_naming_firewall_tools(SYSTEMD_DIR, installer), [("x.service", "ExecStartPre", "nft")])

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


class ShellFirewallInvocationTest(unittest.TestCase):
    def test_only_reviewed_shell_lines_run_firewall_tools(self) -> None:
        expected = {path: set(lines) for path, lines in REVIEWED_SHELL_INVOCATIONS.items()}
        self.assertEqual(shell_firewall_invocations(ROOT), expected)

    def test_checker_catches_new_shell_invocations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "installer" / "a.sh",
                "#!/bin/sh\n# nft -f comment is ignored\necho \"(iptables block)\"\n"
                "sudo /usr/sbin/ipset add bad 1\ncat > /x <<'E'\n  tc qdisc replace dev x root tbf\nE\n"
                "x=$(conntrack -D -s 1)\nif iptables -C INPUT -j DROP; then :; fi\nnftables_ok=1\n",
            )
            self.assertEqual(
                shell_firewall_invocations(root),
                {
                    "installer/a.sh": {
                        "sudo /usr/sbin/ipset add bad 1",
                        "tc qdisc replace dev x root tbf",
                        "x=$(conntrack -D -s 1)",
                        "if iptables -C INPUT -j DROP; then :; fi",
                    }
                },
            )


class WazuhActiveResponseTest(unittest.TestCase):
    """Edge#412 owner decision: Wazuh is observation-only, never an enforcer."""

    WAZUH_INSTALLER = INSTALLER_DIR / "internal" / "install_wazuh_agent.sh"

    def test_no_installer_writes_an_active_response_script(self) -> None:
        self.assertEqual(active_response_writers(INSTALLER_DIR), [])

    def test_wazuh_installer_runs_no_firewall_tool(self) -> None:
        self.assertNotIn(_rel(self.WAZUH_INSTALLER), shell_firewall_invocations(ROOT))

    def test_reviewed_shell_lines_include_no_defensive_action(self) -> None:
        for script, lines in REVIEWED_SHELL_INVOCATIONS.items():
            for line, reason in lines.items():
                self.assertNotIn("defensive", reason.lower(), (script, line))
                self.assertNotIn("active response", reason.lower(), (script, line))

    def test_wazuh_installer_disables_agent_active_response(self) -> None:
        text = self.WAZUH_INSTALLER.read_text(encoding="utf-8")
        self.assertIn("root.findall('active-response')", text)
        self.assertIn("disabled.text = 'yes'", text)
        self.assertNotIn("<command>", text)

    def test_checker_catches_a_reintroduced_active_response_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            installer = Path(tmp) / "installer"
            _write(
                installer / "internal" / "w.sh",
                "#!/usr/bin/env bash\n"
                "# /var/ossec/active-response/bin/old.sh in a comment is ignored\n"
                'AR="/var/ossec/active-response/bin/x-block.sh"\n'
                "cat > /var/ossec/active-response/bin/azazel-block.sh <<'AREOF'\n"
                'nft add rule inet filter input ip saddr "${IP}" drop\n'
                "AREOF\n"
                'install -m 0750 /tmp/x "${AR}"\n'
                "tee /var/ossec/active-response/bin/tc-block.sh </dev/null\n",
            )
            self.assertEqual(
                active_response_writers(installer),
                [
                    ("installer/internal/w.sh", "/var/ossec/active-response/bin/azazel-block.sh"),
                    ("installer/internal/w.sh", "/var/ossec/active-response/bin/x-block.sh"),
                    ("installer/internal/w.sh", "/var/ossec/active-response/bin/tc-block.sh"),
                ],
            )
            self.assertEqual(
                shell_firewall_invocations(Path(tmp)),
                {"installer/internal/w.sh": {'nft add rule inet filter input ip saddr "${IP}" drop'}},
            )


class PythonFirewallCallerTest(unittest.TestCase):
    def test_only_reviewed_modules_run_firewall_tools(self) -> None:
        self.assertEqual(firewall_callers(ROOT), set(REVIEWED_FIREWALL_CALLERS))

    def test_no_module_uses_a_firewall_library(self) -> None:
        self.assertEqual(firewall_library_users(ROOT), {})

    def test_postcondition_observer_only_reads(self) -> None:
        self.assertEqual(postcondition_mutating_argv(ROOT / "py/azazel_edge/outcome/postcondition.py"), [])

    def test_action_arbiter_has_no_process_or_firewall_call(self) -> None:
        arbiter_dir = ROOT / "py" / "azazel_edge" / "arbiter"
        self.assertEqual(firewall_callers(arbiter_dir), set())
        for path in arbiter_dir.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imported.add(node.module.split(".")[0])
            self.assertFalse(imported & ({"socket", "importlib"} | set(PROCESS_MODULES) | FIREWALL_LIBRARIES), path.name)

    def test_action_arbiter_importers_are_reviewed(self) -> None:
        self.assertEqual(arbiter_importers(ROOT), REVIEWED_ARBITER_IMPORTERS)

    def test_reviewed_entries_have_reasons_and_doc_rows(self) -> None:
        doc = BOUNDARY_DOC.read_text(encoding="utf-8")
        self.assertIn("## Decision and enforcement authority", doc)
        for module, reason in REVIEWED_FIREWALL_CALLERS.items():
            self.assertTrue(reason.strip(), module)
            self.assertIn(f"`{module}`", doc)
        for script, lines in REVIEWED_SHELL_INVOCATIONS.items():
            self.assertTrue(lines, script)
            self.assertIn(f"`{script}`", doc)
            for line, reason in lines.items():
                self.assertTrue(reason.strip(), line)
        for unit, script in REVIEWED_GENERATED_UNITS.items():
            self.assertTrue(script.strip(), unit)
            self.assertIn(f"`{unit}`", doc)

    def test_checker_catches_a_new_firewall_caller(self) -> None:
        cases = {
            "a.py": "import subprocess\nsubprocess.run(['nft', 'add', 'rule'])\n",
            "b.py": "from subprocess import check_call as cc\ntool = 'tc'\ncc([tool, 'qdisc', 'replace'])\n",
            "c.py": "import os\nos.system('/usr/sbin/iptables -A FORWARD -j DROP')\n",
            "e.py": "import subprocess as sp\nsp.Popen(['ipset', 'add', 'x', '1'])\n",
            "f.py": "from subprocess import *\nrun(['conntrack', '-D'])\n",
            "g.py": "import subprocess\nr = subprocess.run\nr(['nft', 'flush', 'ruleset'])\n",
            "h.py": "import subprocess\ngetattr(subprocess, 'r' + 'un')(['tc', 'qdisc', 'del'])\n",
            "i.py": "import subprocess\nsp = subprocess\nf = sp.check_output\nf(['iptables', '-F'])\n",
            "j.py": "import importlib\nsp = importlib.import_module('subprocess')\nsp.run(['nft', 'flush', 'ruleset'])\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "py"
            for name, text in cases.items():
                _write(pkg / name, text)
            _write(pkg / "d.py", "WORDS = ['nft', 'tc']\n")
            _write(pkg / "k.py", "import subprocess\nsubprocess.run(['ip', 'route', 'show'])\n")
            self.assertEqual(firewall_callers(pkg), set(cases))

    def test_checker_catches_a_firewall_library(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "py"
            _write(pkg / "a.py", "from pyroute2 import IPRoute\n")
            _write(pkg / "b.py", "import nftables\n")
            _write(pkg / "c.py", "import iptc.easy as e\n")
            _write(pkg / "d.py", "import importlib\nimportlib.import_module('pyroute2')\n")
            _write(pkg / "e.py", "NAME = 'nftables'\n")
            self.assertEqual(
                firewall_library_users(pkg),
                {"a.py": {"pyroute2"}, "b.py": {"nftables"}, "c.py": {"iptc"}, "d.py": {"pyroute2"}},
            )

    def test_checker_catches_a_mutating_observer_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "postcondition.py"
            path.write_text("runner.run(('nft', 'flush', 'ruleset'), timeout_seconds=1)\n", encoding="utf-8")
            self.assertEqual(postcondition_mutating_argv(path), [(1, ("nft", "flush", "ruleset"))])


if __name__ == "__main__":
    unittest.main()
