"""Reviewable single-unit service handoff; no implicit rollback or key rotation."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

from .input_auth import read_regular, open_parent, SourceVerifier
from .input_live import ENV_KEYS, sealed_image
from .input_service import (
    verify,
    require_root,
    _write,
    POLICY,
)
from .journal import OutcomeJournalError, _json, _parse
from .instance import CoreLease

UNIT = "azazel-edge-core.service"
DROPIN = "90-signed-input.conf"
HOOKS = ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost")
PROPERTIES = (
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlGroup",
    "FragmentPath",
    "DropInPaths",
    "ExecStart",
    "User",
    "Group",
    "CapabilityBoundingSet",
    "PrivateUsers",
    "DynamicUser",
    "RootDirectory",
    "RootImage",
    "ProtectSystem",
    "ProtectHome",
    "ReadOnlyPaths",
    "InaccessiblePaths",
    "ReadWritePaths",
    "AmbientCapabilities",
    "SecureBits",
    "Type",
    "ExecStartPre",
    "ExecStartPost",
    "ExecStop",
    "ExecStopPost",
    "AppArmorProfile",
)


def digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


def profile(bundle, python):
    for path in (str(bundle), str(python)):
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", path) or ".." in Path(path).parts:
            raise OutcomeJournalError("literal physical service paths required")
    return (
        "# Azazel registered signed input; explicit operator profile\n[Service]\n"
        "ExecStart=\n"
        f"ExecStart={python} -I -m azazel_edge.outcome.service_entry --bundle {bundle} --boot-ref %b\n"
        "Restart=no\nKillMode=mixed\nTimeoutStopSec=90s\n"
        "UnsetEnvironment=PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT\n"
    ).encode()


class Systemd:
    """Fixed manager and proc roots in production; tests inject a separate adapter."""

    def __init__(self):
        self.directory = Path("/etc/systemd/system") / (UNIT + ".d")
        self.control = Path("/run/azazel-edge-core-switch")

    def command(self, *args):
        result = subprocess.run(
            ["/usr/bin/systemctl", "--system", "--no-pager", *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=100,
            check=False,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C",
                "SYSTEMD_COLORS": "0",
            },
        )
        if result.returncode or len(result.stdout) > 65536:
            raise OutcomeJournalError("service manager operation refused")
        return result.stdout

    def snapshot(self):
        if Path("/proc/1/comm").read_text().strip() != "systemd":
            raise OutcomeJournalError("host systemd PID namespace required")
        # systemctl suppresses empty Exec* arrays even with --all. Read these
        # through typed local D-Bus properties; never infer absent == empty.
        raw = self.command(
            "show",
            UNIT,
            *[
                "--property=" + key
                for key in PROPERTIES
                if key not in (*HOOKS, "AppArmorProfile")
            ],
        )
        state = {}
        for line in raw.decode().splitlines():
            key, sep, value = line.partition("=")
            if not sep or key not in PROPERTIES or key in state:
                raise OutcomeJournalError("ambiguous service manager state")
            state[key] = value
        state.update(self.hooks())
        if (
            set(state) != set(PROPERTIES)
            or state["LoadState"] != "loaded"
            or state["ActiveState"] not in ("active", "inactive", "failed")
        ):
            raise OutcomeJournalError("service state is not safely loaded/stable")
        fragments = [state["FragmentPath"], *state["DropInPaths"].split()]
        state["fragments"] = {}
        for name in fragments:
            path = Path(name).resolve(strict=True)
            raw, _ = read_regular(path, owner=0, max_bytes=65536)
            state["fragments"][str(path)] = hashlib.sha256(raw).hexdigest()
        state["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return state

    def hooks(self):
        result = subprocess.run(
            [
                "/usr/bin/busctl",
                "--system",
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1/unit/azazel_2dedge_2dcore_2eservice",
                "org.freedesktop.systemd1.Service",
                *HOOKS,
                "AppArmorProfile",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        lines = result.stdout.splitlines()
        if (
            result.returncode
            or len(result.stdout) > 65536
            or len(lines) != len(HOOKS) + 1
        ):
            raise OutcomeJournalError("typed service lifecycle properties unavailable")
        values = {}
        for key, line in zip(HOOKS, lines[: len(HOOKS)]):
            value = _parse(line)
            if (
                type(value) is not dict
                or set(value) != {"type", "data"}
                or value["type"] != "a(sasbttttuii)"
                or type(value["data"]) is not list
            ):
                raise OutcomeJournalError(
                    "unrecognized service lifecycle property type"
                )
            values[key] = "" if not value["data"] else _json(value["data"]).decode()
        armor = _parse(lines[-1])
        if (
            type(armor) is not dict
            or set(armor) != {"type", "data"}
            or armor["type"] != "(bs)"
            or type(armor["data"]) is not list
            or len(armor["data"]) != 2
            or type(armor["data"][0]) is not bool
            or type(armor["data"][1]) is not str
        ):
            raise OutcomeJournalError("typed core AppArmor property unavailable")
        values["AppArmorProfile"] = (
            _json(armor["data"]).decode() if any(armor["data"]) else ""
        )
        return values

    def cores(self):
        result = []
        processes = list(Path("/proc").glob("[0-9]*"))
        if len(processes) > 8192:
            raise OutcomeJournalError("process inventory budget exceeded")
        for proc in processes:
            try:
                exe = os.readlink(proc / "exe")
                if (
                    Path(exe.removesuffix(" (deleted)")).name != "azazel-edge-core"
                    and not exe.startswith("/memfd:edge-live-origin")
                    and not exe.startswith("memfd:edge-live-origin")
                ):
                    continue
                arguments = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                if "memfd:edge-live-origin" not in exe and len(arguments) != 1:
                    raise OutcomeJournalError(
                        "existing core command-line overrides need separate review"
                    )
                statline = (proc / "stat").read_text()
                start = statline[statline.rfind(")") + 2 :].split()[19]
                cgroups = (proc / "cgroup").read_text().splitlines()
                cgroup = next(
                    (
                        line.split(":", 2)[2]
                        for line in cgroups
                        if line.startswith("0::")
                    ),
                    None,
                )
                if cgroup is None:
                    raise OutcomeJournalError("unified cgroup identity required")
                raw = (proc / "environ").read_bytes()
                if len(raw) > 65536:
                    raise OutcomeJournalError("core environment inventory bound")
                env = {}
                for item in raw.split(b"\0"):
                    key, _, value = item.partition(b"=")
                    name = key.decode(errors="replace")
                    if name.startswith("AZAZEL_") and name[7:] in ENV_KEYS:
                        env[name] = value.decode()
                status = (proc / "status").read_text()
                uid = int(status.split("Uid:", 1)[1].split()[0])
                caps = int(status.split("CapEff:", 1)[1].split()[0], 16)
                result.append(
                    dict(
                        uid=uid,
                        cap_eff=caps,
                        pid=int(proc.name),
                        start=start,
                        exe=exe,
                        cgroup=cgroup,
                        environment=env,
                    )
                )
            except FileNotFoundError:
                continue
        return result

    def capture_ready(self, bundle, p, main_pid, after_seq):
        from .input_live import registration

        registered = registration(p, bundle / "origin.json")
        expected_armor = registered.get("capture_apparmor_profile")
        raw, _ = read_regular(
            p.data["source_path"],
            owner=p.data["producer_uid"],
            max_bytes=p.data["input_max_bytes"],
        )
        verifier = SourceVerifier(p)
        verifier.verify(raw)
        if (
            verifier.seq < after_seq + 2
            or verifier.live_state.closed
            or verifier.live_state.seq < 1
        ):
            raise OutcomeJournalError("new signed native start not verified")
        children = (
            Path(f"/proc/{main_pid}/task/{main_pid}/children").read_text().split()
        )
        if len(children) > 16:
            raise OutcomeJournalError("service child inventory bound")
        signers = 0
        natives = 0
        for child in children:
            try:
                status = Path(f"/proc/{child}/status").read_text()
                uid = int(status.split("Uid:", 1)[1].split()[0])
                command = Path(f"/proc/{child}/cmdline").read_bytes().split(b"\0")
                if (
                    "native_apparmor_profile" in registered
                    and b"--live-origin-fd" in command
                ):
                    if (
                        uid != 0
                        or Path(f"/proc/{child}/attr/apparmor/current")
                        .read_text()
                        .strip()
                        != registered["native_apparmor_profile"] + " (enforce)"
                    ):
                        raise OutcomeJournalError(
                            "live native AppArmor context unavailable"
                        )
                    natives += 1
                if (
                    uid == p.data["producer_uid"]
                    and b"--receive-fd" in command
                    and str(bundle / POLICY).encode() in command
                ):
                    if (
                        expected_armor is not None
                        and Path(f"/proc/{child}/attr/apparmor/current")
                        .read_text()
                        .strip()
                        != expected_armor + " (enforce)"
                    ):
                        raise OutcomeJournalError(
                            "live signer AppArmor context unavailable"
                        )
                    signers += 1
            except FileNotFoundError:
                continue
        if "native_apparmor_profile" in registered and natives != 1:
            raise OutcomeJournalError("registered confined native process not alive")
        if signers != 1:
            raise OutcomeJournalError("registered signer process not alive")
        self.witness(bundle, p)

    def native(self, r):
        from .input_live import native_arguments

        image = sealed_image(r)
        try:
            result = subprocess.run(
                [f"/proc/self/fd/{image}", "--health", *native_arguments(r)],
                pass_fds=(image,),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=5,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", **r["environment"]},
            )
        finally:
            os.close(image)
        expected = dict(
            schema_version="azazel-edge-core/capture-service/v1",
            lock_file="core-instance.lock",
            lock_scope="release-state-directory",
            private_fd=True,
            live_origin="outcome-live-origin/v1",
        )
        if result.returncode not in (0, 1) or len(result.stdout) > 8192:
            raise OutcomeJournalError("registered native ABI/contract unavailable")
        report = _parse(result.stdout)
        if (
            report.get("contract") != "azazel-edge-core/health/v1"
            or report.get("capture_service") != expected
        ):
            raise OutcomeJournalError(
                "registered native lacks shared instance/capture contract"
            )
        if "native_apparmor_profile" in r and report.get("native_apparmor") != dict(
            schema_version="azazel-edge-core/native-apparmor/v1",
            sealed_memfd=True,
            early_transition=True,
            enforced_profile=r["native_apparmor_profile"],
        ):
            raise OutcomeJournalError("registered native AppArmor gate unavailable")
        return dict(
            version=report["version"],
            capture_service=expected,
            **(
                {"native_apparmor": report["native_apparmor"]}
                if "native_apparmor_profile" in r
                else {}
            ),
        )

    def runtime(self, python, package):
        script = "from pathlib import Path;from azazel_edge.outcome import service_entry;from azazel_edge.outcome.input_auth import crypto;crypto();print(Path(service_entry.__file__).resolve().parent)"
        result = subprocess.run(
            [str(python), "-I", "-c", script],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        if result.returncode or result.stdout != (str(package) + "\n").encode():
            raise OutcomeJournalError("isolated installed service runtime unavailable")

    def capture_runtime(self, python, package, p, expected):
        script = "import sys;from pathlib import Path;from azazel_edge.outcome.confinement import enforce_capture;from azazel_edge.outcome import input_live;input_live.harden_receiver(int(sys.argv[2]));enforce_capture(sys.argv[1]);print(Path(input_live.__file__).resolve().parent)"
        result = subprocess.run(
            [str(python), "-I", "-c", script, expected, str(p.data["producer_uid"])],
            user=p.data["producer_uid"],
            group=p.data["producer_uid"],
            extra_groups=[],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            env={"PATH": "/nonexistent"},
        )
        if result.returncode or result.stdout != (str(package) + "\n").encode():
            raise OutcomeJournalError("registered capture AppArmor runtime unavailable")

    def stop(self):
        self.command("stop", UNIT)

    def reload(self):
        self.command("daemon-reload")

    def start(self):
        self.command("start", UNIT)

    def wait(self, active):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            state = self.snapshot()
            if (
                active
                and state["ActiveState"] == "active"
                and int(state["MainPID"]) > 0
            ):
                return state
            if (
                not active
                and state["ActiveState"] in ("inactive", "failed")
                and int(state["MainPID"]) == 0
            ):
                return state
            time.sleep(0.1)
        raise OutcomeJournalError("service transition not confirmed")

    def witness(self, bundle, p):
        # Read-only fresh proof using the existing authorized observer role;
        # no journal writer, initialization, anchor access or permission grant.
        script = r"""
import sys,hashlib
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy,read_regular,SourceVerifier
from azazel_edge.outcome.input_witness import WitnessClient
from azazel_edge.outcome.journal import _parse
p=TrustPolicy.from_file(Path(sys.argv[1]),role='observer');d=p.data
raw,_=read_regular(Path(d['journal_directory'])/'observations.journal',owner=d['observer_uid'],max_bytes=d['journal_max_bytes'])
if not raw.endswith(b'\n'):raise OSError('uninitialized or partial journal')
last=_parse(raw.splitlines()[-1]);client=WitnessClient(p);client.preflight(last['seq'],last['sha256'],len(raw))
source,_=read_regular(d['source_path'],owner=d['producer_uid'],max_bytes=d['input_max_bytes']);tip=SourceVerifier(p).verify(source)
s=client.state;n=s['source_size']
if len(source)<n or hashlib.sha256(source[:n]).hexdigest()!=s['source_sha256'] or tip['seq']<s['source_seq']:raise OSError('protected source continuity mismatch')
print('verified')
"""
        result = subprocess.run(
            [sys.executable, "-c", script, str(bundle / POLICY)],
            cwd="/",
            user=p.data["observer_uid"],
            group=p.data["observer_uid"],
            extra_groups=[],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            env={
                "PATH": "/nonexistent",
                "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
            },
        )
        if result.returncode or result.stdout != b"verified\n":
            raise OutcomeJournalError(
                "fresh protected witness/journal proof unavailable"
            )


def _security(state):
    if state.get("AppArmorProfile", "") != "":
        raise OutcomeJournalError(
            "confined sealed native exec needs separate commissioning; no debug flag or unconfined fallback"
        )
    if state.get("Type") not in ("simple", "exec") or any(
        state.get(k) != ""
        for k in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost")
    ):
        raise OutcomeJournalError(
            "unit type/lifecycle hooks need separate commissioning"
        )
    if state.get("User") not in ("", "root", "0") or state.get("Group") not in (
        "",
        "root",
        "0",
    ):
        raise OutcomeJournalError("cutover cannot elevate a non-root service")
    if not {"cap_setuid", "cap_setgid"} <= set(
        state.get("CapabilityBoundingSet", "").split()
    ):
        raise OutcomeJournalError(
            "existing unit cannot drop signer UID/GID; no capability grants"
        )
    if not {"cap_dac_override", "cap_dac_read_search"} & set(
        state.get("CapabilityBoundingSet", "").split()
    ):
        raise OutcomeJournalError(
            "existing unit cannot verify private role material; no DAC capability grants"
        )
    if state.get("AmbientCapabilities") != "" or state.get("SecureBits") != "0":
        raise OutcomeJournalError(
            "unexpected inherited capabilities/securebits; no privilege relaxation"
        )
    for key in ("PrivateUsers", "DynamicUser", "ProtectSystem", "ProtectHome"):
        if state.get(key) != "no":
            raise OutcomeJournalError(
                "unverified unit sandbox; no permission relaxation"
            )
    for key in (
        "RootDirectory",
        "RootImage",
        "ReadOnlyPaths",
        "InaccessiblePaths",
        "ReadWritePaths",
    ):
        if state.get(key) != "":
            raise OutcomeJournalError(
                "unit path namespace needs separate commissioning"
            )


def _inventory(system, state):
    cores = system.cores()
    if len(cores) > 1 or any(
        core["cgroup"] != state["ControlGroup"]
        or core.get("uid") != 0
        or core.get("cap_eff", 0) & ((1 << 6) | (1 << 7)) != ((1 << 6) | (1 << 7))
        or not core.get("cap_eff", 0) & ((1 << 1) | (1 << 2))
        for core in cores
    ):
        raise OutcomeJournalError("duplicate or unmanaged core; no transition")
    active = state["ActiveState"] == "active"
    if active != (len(cores) == 1) or active != (int(state["MainPID"]) > 0):
        raise OutcomeJournalError("service/process identity mismatch")
    return cores


def _same_configuration(core, r):
    # Never guess defaults of a possibly older executable or silently change
    # enforcement/forwarding. Missing actual values require operator review.
    actual = core["environment"]

    def canon(value):
        if value.lower() in ("0", "false", "no", "off"):
            return "false"
        if value.lower() in ("1", "true", "yes", "on"):
            return "true"
        return value

    booleans = {
        "AZAZEL_FORWARD_AI",
        "AZAZEL_FORWARD_LOG",
        "AZAZEL_DEFENSE_ENFORCE",
        "AZAZEL_DEFENSE_DRY_RUN",
        "AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO",
        "AZAZEL_EVE_FROM_START",
    }
    desired = r["environment"]
    for key in set(actual) | set(desired):
        if key == "AZAZEL_EVENT_STDOUT":
            continue
        if key not in actual or key not in desired:
            raise OutcomeJournalError(
                "effective core setting omitted; no default inference"
            )
        before, after = actual[key], desired[key]
        if (canon(before) != canon(after)) if key in booleans else (before != after):
            raise OutcomeJournalError(
                "effective core configuration is missing/different; no guessed cutover"
            )


def _trusted_package():
    return Path(__file__).resolve().parent


def ready(bundle, python, system):
    p, r = verify(bundle)
    raw, _ = read_regular(
        p.data["source_path"],
        owner=p.data["producer_uid"],
        max_bytes=p.data["input_max_bytes"],
    )
    v = SourceVerifier(p)
    v.verify(raw)
    if not v.live_state.closed:
        raise OutcomeJournalError("unclosed signed history; no connected restart")
    python = Path(python).absolute()
    parent, name = open_parent(python, trusted_owner=0)
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if info.st_uid != 0:
            raise OutcomeJournalError("untrusted interpreter link")
    finally:
        os.close(parent)
    actual = python.resolve(strict=True)
    code, _ = read_regular(actual, owner=0, max_bytes=64 * 1024 * 1024)
    # Launcher and signer code and their package path must be operator-installed,
    # root-owned and protected. This does not attest all loader/dependencies.
    code_refs = {
        str(python): dict(real=str(actual), sha256=hashlib.sha256(code).hexdigest())
    }
    venv = python.parent.parent / "pyvenv.cfg"
    if venv.exists():
        data, _ = read_regular(venv, owner=0, max_bytes=8192)
        code_refs[str(venv)] = hashlib.sha256(data).hexdigest()
    package = _trusted_package()
    for file in (
        *package.glob("*.py"),
        package.parent / "__init__.py",
        package.parent / "path_schema.py",
    ):
        data, _ = read_regular(file, owner=0, max_bytes=1024 * 1024)
        code_refs[str(file)] = hashlib.sha256(data).hexdigest()
    system.runtime(python, package)
    if "capture_apparmor_profile" in r:
        from .confinement import capture_image

        capture_python, code_refs["capture_confinement"] = capture_image(
            python, r["capture_apparmor_profile"]
        )
        system.capture_runtime(
            capture_python, package, p, r["capture_apparmor_profile"]
        )
    code_refs["native_health"] = system.native(r)
    system.witness(bundle, p)
    return p, r, python, code_refs


def _ensure_dropin_directory(path):
    """Set exact mode only on our newly created directory, through its owned FD.

    Protected root-owned parents exclude other-role replacement. This does not
    claim protection against a hostile root/same-authority directory replacer.
    Existing names are validated unchanged, never repaired or followed.
    """
    from .input_service import check_directory

    parent, name = open_parent(path, trusted_owner=0)
    fd = None
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            check_directory(path, 0, 0o755)
            return
        created = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(created.st_mode)
            or created.st_uid != 0
            or stat.S_IMODE(created.st_mode) & ~0o700
        ):
            raise OutcomeJournalError(
                "new drop-in directory identity/permissions unsafe"
            )
        fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )

        def same(mode):
            opened = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if any(
                not stat.S_ISDIR(value.st_mode)
                or value.st_uid != 0
                or (value.st_dev, value.st_ino) != (created.st_dev, created.st_ino)
                or stat.S_IMODE(value.st_mode) != mode
                for value in (opened, named)
            ):
                raise OutcomeJournalError("new drop-in directory changed; no repair")

        same(stat.S_IMODE(created.st_mode))
        os.fchmod(fd, 0o755)
        os.fsync(fd)
        same(0o755)
        os.fsync(parent)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


class Switch:
    def __init__(self, bundle, python=None, system=None):
        require_root()
        self.bundle = Path(bundle)
        self.python = Path(python or sys.executable)
        self.system = system or Systemd()

    def plan(self):
        p, r, python, code = ready(self.bundle, self.python, self.system)
        state = self.system.snapshot()
        _security(state)
        cores = _inventory(self.system, state)
        if cores:
            _same_configuration(cores[0], r)
        elif r["environment"]["AZAZEL_DEFENSE_ENFORCE"].lower() not in (
            "0",
            "false",
            "no",
            "off",
        ) or r["environment"]["AZAZEL_DEFENSE_DRY_RUN"].lower() not in (
            "1",
            "true",
            "yes",
            "on",
        ):
            raise OutcomeJournalError(
                "inactive service cannot newly enable enforcement"
            )
        target = self.system.directory / DROPIN
        if target.exists() or target.is_symlink():
            raise OutcomeJournalError(
                "managed drop-in already exists; explicit restore/review required"
            )
        body = profile(self.bundle, python)
        return dict(
            schema_version="outcome-service-switch/v1",
            plan_id=secrets.token_hex(16),
            bundle=str(self.bundle),
            python=str(python),
            trust_sha256=p.digest,
            registration_sha256=p.data["origin_registration_sha256"],
            code=code,
            before=state,
            cores=cores,
            dropin=str(target),
            profile_sha256=hashlib.sha256(body).hexdigest(),
        )

    def _directory(self):
        path = self.bundle / "switch"
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        from .input_service import check_directory

        check_directory(path, 0, 0o700)
        return path

    def _operation(self):
        parent, name = open_parent(self.system.control, trusted_owner=0)
        try:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
            os.fsync(parent)
        finally:
            os.close(parent)
        from .input_service import check_directory

        check_directory(self.system.control, 0, 0o700)
        return CoreLease(str(self.system.control / "operation-ledger"))

    def _publish(self, target, body, expected):
        # Publish only fully written/fsynced bytes, with no-replace semantics.
        # A failed/crashed two-link publication is retained for explicit restore.
        temporary = target.with_name("." + DROPIN + "." + expected + ".pending")
        _write(temporary, body, 0, 0o644)
        parent, name = open_parent(target, trusted_owner=0)
        try:
            os.link(
                temporary.name,
                name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
                follow_symlinks=False,
            )
            os.unlink(temporary.name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)

    def apply(self, plan, expected):
        if digest(plan) != expected:
            raise OutcomeJournalError("reviewed plan digest mismatch")
        directory = self._directory()
        with self._operation():
            p, r, python, code = ready(self.bundle, self.python, self.system)
            if (
                plan.get("schema_version") != "outcome-service-switch/v1"
                or plan["bundle"] != str(self.bundle)
                or plan["python"] != str(python)
                or plan["trust_sha256"] != p.digest
                or plan["registration_sha256"] != p.data["origin_registration_sha256"]
                or plan["code"] != code
            ):
                raise OutcomeJournalError("stale service code/enrollment plan")
            source, _ = read_regular(
                p.data["source_path"],
                owner=p.data["producer_uid"],
                max_bytes=p.data["input_max_bytes"],
            )
            before_seq = SourceVerifier(p).verify(source)["seq"]
            state = self.system.snapshot()
            _security(state)
            cores = _inventory(self.system, state)
            if state != plan["before"] or cores != plan["cores"]:
                raise OutcomeJournalError("service changed since review")
            if cores:
                _same_configuration(cores[0], r)
            target = self.system.directory / DROPIN
            body = profile(self.bundle, python)
            if (
                str(target) != plan["dropin"]
                or hashlib.sha256(body).hexdigest() != plan["profile_sha256"]
                or target.exists()
                or target.is_symlink()
            ):
                raise OutcomeJournalError("service profile target changed")
            receipt = directory / (expected + ".jsonl")
            _write(receipt, _json(dict(stage="reviewed", plan=plan)) + b"\n", 0, 0o600)

            def note(stage):
                fd = os.open(
                    receipt, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
                )
                try:
                    data = _json(dict(stage=stage)) + b"\n"
                    if os.write(fd, data) != len(data):
                        raise OutcomeJournalError("switch receipt short write")
                    os.fsync(fd)
                finally:
                    os.close(fd)

            try:
                self.system.stop()
                self.system.wait(False)
                stopped = self.system.snapshot()
                _inventory(self.system, stopped)
                note("old_stopped")
                # Hold the same lifetime lease through the critical stopped
                # profile-write phase. It is released for systemd's new core;
                # the new native guard arbitrates any external start race.
                with CoreLease(r["environment"]["AZAZEL_DEFENSE_RELEASE_LEDGER"]):
                    ready(self.bundle, self.python, self.system)
                    if stopped["fragments"] != plan["before"]["fragments"]:
                        raise OutcomeJournalError(
                            "unit fragments changed while stopping"
                        )
                    _ensure_dropin_directory(self.system.directory)
                    self._publish(target, body, expected)
                    note("profile_written")
                    self.system.reload()
                self.system.start()
                deadline = time.monotonic() + 15
                while True:
                    new = self.system.wait(True)
                    try:
                        _inventory(self.system, new)
                        self.system.capture_ready(
                            self.bundle, p, int(new["MainPID"]), before_seq
                        )
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
                current, _ = read_regular(target, owner=0, max_bytes=8192)
                if (
                    hashlib.sha256(current).hexdigest() != plan["profile_sha256"]
                    or "azazel_edge.outcome.service_entry" not in new["ExecStart"]
                ):
                    raise OutcomeJournalError("new service identity not confirmed")
                note("started")
                return dict(
                    status="started",
                    receipt=str(receipt),
                    observation="separate_verified_recovery_required",
                )
            except BaseException:
                try:
                    note("failed_no_automatic_rollback")
                except OSError:
                    pass
                raise

    def restore(self, receipt):
        directory = self._directory()
        with self._operation():
            raw, _ = read_regular(receipt, owner=0, max_bytes=32768, mode=0o600)
            first = _parse(raw.splitlines()[0])
            plan = first["plan"]
            if (
                Path(receipt).parent != directory
                or Path(receipt).name != digest(plan) + ".jsonl"
                or first["stage"] != "reviewed"
                or plan["bundle"] != str(self.bundle)
            ):
                raise OutcomeJournalError("restore receipt mismatch")
            state = self.system.snapshot()
            if (
                state["ActiveState"] == "active"
                or self.system.cores()
                or int(state["MainPID"])
            ):
                raise OutcomeJournalError(
                    "explicit stop and process proof required before restore"
                )
            target = self.system.directory / DROPIN
            if not target.exists() and not target.is_symlink():
                return dict(
                    status="profile_not_published_service_not_started",
                    receipt=str(receipt),
                )
            # Recover only our exact interrupted hard-link publication, never
            # truncate/overwrite a changed or foreign service configuration.
            pending = target.with_name("." + DROPIN + "." + digest(plan) + ".pending")
            parent, name = open_parent(target, trusted_owner=0)
            try:
                a = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if a.st_nlink == 2:
                    b = os.stat(pending.name, dir_fd=parent, follow_symlinks=False)
                    if (a.st_dev, a.st_ino, a.st_uid, a.st_nlink) != (
                        b.st_dev,
                        b.st_ino,
                        0,
                        2,
                    ):
                        raise OutcomeJournalError("foreign partial profile publication")
                    fd = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
                    )
                    try:
                        data = os.read(fd, 8193)
                    finally:
                        os.close(fd)
                    if hashlib.sha256(data).hexdigest() != plan["profile_sha256"]:
                        raise OutcomeJournalError("partial profile bytes changed")
                    os.unlink(pending.name, dir_fd=parent)
                    os.fsync(parent)
            finally:
                os.close(parent)
            raw, _ = read_regular(target, owner=0, max_bytes=8192)
            if (
                str(target) != plan["dropin"]
                or hashlib.sha256(raw).hexdigest() != plan["profile_sha256"]
            ):
                raise OutcomeJournalError(
                    "modified service profile; no automatic overwrite"
                )
            parent, name = open_parent(target, trusted_owner=0)
            try:
                os.unlink(name, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
            self.system.reload()
            return dict(
                status="profile_restored_service_not_started", receipt=str(receipt)
            )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Explicit root single-unit signed service switch; no default activation"
    )
    parser.add_argument("operation", choices=("plan", "apply", "restore"))
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--expect-sha256")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        switch = Switch(args.bundle)
        if args.operation == "plan":
            plan = switch.plan()
            result = dict(plan=plan, sha256=digest(plan))
        elif args.operation == "apply":
            if args.plan is None or args.expect_sha256 is None:
                raise OutcomeJournalError("concrete reviewed plan and digest required")
            raw, _ = read_regular(args.plan, owner=0, max_bytes=32768)
            result = switch.apply(_parse(raw), args.expect_sha256)
        else:
            if args.receipt is None:
                raise OutcomeJournalError("exact switch receipt required")
            result = switch.restore(args.receipt)
        print(_json(result).decode())
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print(
            "service handoff refused/failed; preserve receipt; no automatic fallback or key reset",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
