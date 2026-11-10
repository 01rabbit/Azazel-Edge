"""Offline root/actual-UID key deployment, native exclusion and modeled manager.

No host systemctl or production paths are mutated. Manager failures are injected;
these tests are not proof of real systemd boot/power-cut acceptance.
"""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import patch
import pytest

pytest.importorskip("cryptography")
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux root needed for service/key UID boundaries",
)
from test_outcome_input_auth_linux import Fixture, Child, ROOT
from test_outcome_live_origin_linux import register_live, Run, events
from azazel_edge.outcome.input_auth import TrustPolicy, _json
from azazel_edge.outcome.input_service import (
    provision,
    verify,
    PRODUCER_KEY,
    WITNESS_KEY,
)
from azazel_edge.outcome.service_switch import Switch, Systemd, digest, DROPIN
from azazel_edge.outcome.instance import CoreLease


def candidate(f):
    register_live(f)
    f.bundle = f.root / "bundle"
    d = dict(f.p.data)
    d.update(
        source_path=str(f.bundle / "input"),
        journal_directory=str(f.bundle / "observer"),
        anchor_directory=str(f.bundle / "witness/anchors"),
        socket_path=str(f.bundle / "socket/witness.sock"),
    )
    f.p = TrustPolicy(d)
    f.candidate = f.root / "candidate.json"
    f.candidate.write_bytes(_json(d))
    f.candidate.chmod(0o644)
    f.incoming = f.root / "private/incoming-producer"
    f.incoming.write_bytes(f.pk.read_bytes())
    f.incoming.chmod(0o600)
    return f


@pytest.fixture
def unprovisioned():
    f = candidate(Fixture())
    try:
        yield f
    finally:
        f.clean()


@pytest.fixture
def bundle(unprovisioned):
    f = unprovisioned
    provision(f.bundle, f.candidate, f.registration, f.incoming, f.wk)
    f.policy_file = f.bundle / "trust.json"
    f.registration = f.bundle / "origin.json"
    f.pk = f.bundle / PRODUCER_KEY
    f.wk = f.bundle / WITNESS_KEY
    return f


def test_key_import_is_idempotent_and_roles_cannot_read_other_private_keys(bundle):
    f = bundle
    p, r = verify(f.bundle)
    before = {x: x.read_bytes() for x in (f.pk, f.wk, f.policy_file, f.source)}
    provision(f.bundle, f.candidate, f.registration, f.incoming, f.wk)
    assert all(x.read_bytes() == data for x, data in before.items())
    for uid, path in ((65534, f.pk), (65534, f.wk), (1000, f.wk)):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                'import sys;open(sys.argv[1],"rb").read()',
                str(path),
            ],
            user=uid,
            group=uid,
            extra_groups=[],
            capture_output=True,
        )
        assert result.returncode != 0
    assert f.pk.stat().st_uid == 1000 and f.pk.stat().st_mode & 0o777 == 0o600
    assert f.wk.stat().st_uid == 0 and f.wk.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_key",
        "incoming_mode",
        "partial",
        "key_mode",
        "policy_changed",
        "source_link",
    ],
)
def test_provision_refuses_inconsistent_or_partial_material_without_reset(
    unprovisioned, fault
):
    f = unprovisioned
    if fault == "wrong_key":
        f.incoming.write_bytes(b"x" * 32)
    elif fault == "incoming_mode":
        f.incoming.chmod(0o644)
    elif fault == "partial":
        f.bundle.mkdir(mode=0o700)
    else:
        provision(f.bundle, f.candidate, f.registration, f.incoming, f.wk)
        if fault == "key_mode":
            (f.bundle / PRODUCER_KEY).chmod(0o644)
        elif fault == "policy_changed":
            (f.bundle / "trust.json").write_bytes(b"{}")
        else:
            source = f.bundle / "input"
            source.rename(f.bundle / "original-input")
            source.symlink_to(f.bundle / "original-input")
    before = f.incoming.read_bytes()
    with pytest.raises(OSError):
        provision(f.bundle, f.candidate, f.registration, f.incoming, f.wk)
    assert f.incoming.read_bytes() == before


def test_failed_sync_quarantines_partial_bundle_without_retry_or_disclosure(
    unprovisioned,
):
    f = unprovisioned
    with patch(
        "azazel_edge.outcome.input_service.os.fsync",
        side_effect=OSError("injected sync failure"),
    ):
        with pytest.raises(OSError):
            provision(f.bundle, f.candidate, f.registration, f.incoming, f.wk)
    assert f.bundle.stat().st_mode & 0o777 == 0o700
    with pytest.raises(OSError):
        verify(f.bundle)
    with pytest.raises(OSError):
        provision(f.bundle, f.candidate, f.registration, f.incoming, f.wk)


class Manager(Systemd):
    def __init__(self, f):
        self.f = f
        self.directory = f.root / "units" / ("azazel-edge-core.service.d")
        self.directory.parent.mkdir(mode=0o755)
        self.control = f.root / "controller-lock"
        self.calls = []
        self.failure = None
        self.active = True
        self.base = dict(
            LoadState="loaded",
            ActiveState="active",
            SubState="running",
            MainPID="101",
            ControlGroup="/system.slice/azazel-edge-core.service",
            FragmentPath="/trusted/core.service",
            DropInPaths="",
            ExecStart="/usr/local/bin/azazel-edge-core",
            fragments={"/trusted/core.service": "a" * 64},
            boot_id="boot-a",
        )
        self.base.update(
            Type="simple",
            ExecStartPre="",
            ExecStartPost="",
            ExecStop="",
            ExecStopPost="",
            User="",
            Group="",
            CapabilityBoundingSet="cap_setuid cap_setgid cap_dac_override",
            PrivateUsers="no",
            DynamicUser="no",
            RootDirectory="",
            RootImage="",
            ProtectSystem="no",
            ProtectHome="no",
            ReadOnlyPaths="",
            InaccessiblePaths="",
            ReadWritePaths="",
            AmbientCapabilities="",
            SecureBits="0",
        )
        self.env = json.loads(f.registration.read_bytes())["environment"]

    def snapshot(self):
        result = copy.deepcopy(self.base)
        if not self.active:
            result.update(ActiveState="inactive", SubState="dead", MainPID="0")
        if (self.directory / DROPIN).exists():
            result["ExecStart"] = "python -I -m azazel_edge.outcome.service_entry"
            result["DropInPaths"] = str(self.directory / DROPIN)
        return result

    def cores(self):
        if not self.active:
            return []
        return [
            dict(
                uid=0,
                cap_eff=(1 << 6) | (1 << 7) | (1 << 1),
                pid=101,
                start="7",
                exe="/usr/local/bin/azazel-edge-core",
                cgroup=self.base["ControlGroup"],
                environment=copy.deepcopy(self.env),
            )
        ]

    def _call(self, op):
        self.calls.append(op)
        if self.failure == op:
            raise OSError("injected " + op)

    def stop(self):
        self._call("stop")
        self.active = False

    def reload(self):
        self._call("reload")

    def start(self):
        self._call("start")
        self.active = True

    def wait(self, active):
        return self.snapshot()

    def native(self, r):
        self._call("native")
        return super().native(r)

    def runtime(self, python, package):
        self._call("runtime")

    def capture_ready(self, bundle, p, main_pid, after_seq):
        self._call("capture_ready")

    def witness(self, bundle, p):
        self._call("witness")


@pytest.fixture
def switched(bundle, monkeypatch):
    f = bundle
    package = f.root / "installed-package"
    package.mkdir(mode=0o755)
    for file in (ROOT / "py/azazel_edge/outcome").glob("*.py"):
        shutil.copyfile(file, package / file.name)
    for name in ("__init__.py", "path_schema.py"):
        shutil.copyfile(ROOT / "py/azazel_edge" / name, f.root / name)
    monkeypatch.setattr(
        "azazel_edge.outcome.service_switch._trusted_package", lambda: package
    )
    manager = Manager(f)
    switch = Switch(f.bundle, Path(sys.executable), manager)
    return f, manager, switch


def test_reviewed_plan_apply_and_explicit_restore_never_start_a_second_unit(switched):
    f, m, s = switched
    plan = s.plan()
    assert m.calls == ["runtime", "native", "witness"]
    result = s.apply(plan, digest(plan))
    assert m.calls.count("stop") == 1 and m.calls.count("start") == 1
    assert m.calls.index("stop") < m.calls.index("reload") < m.calls.index("start")
    body = (m.directory / DROPIN).read_text()
    assert "KillMode=mixed" in body and "Restart=no" in body
    m.active = False
    before = f.pk.read_bytes()
    s.restore(Path(result["receipt"]))
    assert not (m.directory / DROPIN).exists() and f.pk.read_bytes() == before
    assert m.calls.count("start") == 1


@pytest.mark.parametrize(
    "fault",
    [
        "pid",
        "config",
        "code",
        "keys",
        "witness",
        "runtime",
        "native",
        "digest",
        "unmanaged",
    ],
)
def test_stale_or_unverified_plan_never_stops_existing_defense(switched, fault):
    f, m, s = switched
    plan = s.plan()
    if fault == "pid":
        m.base["MainPID"] = "102"
    elif fault == "config":
        m.env["AZAZEL_DEFENSE_DRY_RUN"] = "false"
    elif fault == "code":
        next((f.root / "installed-package").glob("*.py")).write_text("# changed")
    elif fault == "keys":
        f.pk.chmod(0o644)
    elif fault in ("witness", "runtime", "native"):
        m.failure = fault
    elif fault == "unmanaged":
        m.base["ControlGroup"] = "/other"
        m.cores = lambda: [
            dict(pid=200, start="7", exe="core", cgroup="/unmanaged", environment=m.env)
        ]
    with pytest.raises(OSError):
        s.apply(plan, "0" * 64 if fault == "digest" else digest(plan))
    assert "stop" not in m.calls and "start" not in m.calls


@pytest.mark.parametrize("failure", ["stop", "reload", "start"])
def test_manager_failure_preserves_receipt_and_never_implicitly_falls_back(
    switched, failure
):
    f, m, s = switched
    plan = s.plan()
    m.failure = failure
    with pytest.raises(OSError):
        s.apply(plan, digest(plan))
    receipt = f.bundle / "switch" / (digest(plan) + ".jsonl")
    assert b"failed_no_automatic_rollback" in receipt.read_bytes()
    assert m.calls.count("start") == (failure == "start")
    assert (m.directory / DROPIN).exists() == (failure != "stop")
    assert f.pk.stat().st_mode & 0o777 == 0o600


def test_real_witness_preflight_uses_observer_role_without_journal_writes(bundle):
    f = bundle
    f.start(initialize=True)
    c = Child(f, True)
    assert c.initial.get("ready"), c.initial
    c.close()
    before = f.journal.read_bytes()
    anchors = f.anchors.read_bytes()
    Systemd().witness(f.bundle, f.p)
    assert f.journal.read_bytes() == before and f.anchors.read_bytes() == anchors
    f.halt()
    with pytest.raises(OSError):
        Systemd().witness(f.bundle, f.p)


def test_normal_and_signed_daemons_share_lifetime_guard_and_sigkill_releases_only_lock(
    bundle,
):
    f = bundle
    run = Run(f)
    try:
        run.started()
        events(f, 2)
        r = json.loads(f.registration.read_bytes())
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", **r["environment"]}
        duplicate = subprocess.Popen(
            [str(f.binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        duplicate.communicate(timeout=10)
        assert duplicate.returncode == 3
        another = Run(f)
        try:
            stdout, stderr = another.process.communicate(timeout=10)
            assert another.process.returncode != 0 and "core_started" not in stdout
            assert len(f.source.read_bytes().splitlines()) == 2
        finally:
            another.close()
        assert run.stop() == 0
        with CoreLease(r["environment"]["AZAZEL_DEFENSE_RELEASE_LEDGER"]):
            pass
    finally:
        run.close()


def test_operation_lock_is_shared_across_bundle_choices(switched):
    f, m, s = switched
    plan = s.plan()
    lease = s._operation()
    try:
        with pytest.raises(OSError):
            s.apply(plan, digest(plan))
        alternate = Switch(f.root / "other-bundle", Path(sys.executable), m)
        with pytest.raises(OSError):
            alternate._operation()
        assert "stop" not in m.calls
    finally:
        lease.close()


@pytest.mark.parametrize("fault", ["active", "edited"])
def test_restore_refuses_active_core_or_foreign_profile_changes(switched, fault):
    f, m, s = switched
    plan = s.plan()
    result = s.apply(plan, digest(plan))
    if fault == "edited":
        m.active = False
        (m.directory / DROPIN).write_text("# foreign edit\n")
    with pytest.raises(OSError):
        s.restore(Path(result["receipt"]))
    assert (m.directory / DROPIN).exists() and m.calls.count("start") == 1


def test_duplicate_process_inventory_refuses_readonly_plan(switched):
    f, m, s = switched
    real = m.cores
    m.cores = lambda: real() * 2
    with pytest.raises(OSError):
        s.plan()
    assert "stop" not in m.calls and not m.directory.exists()


def test_sigkill_during_key_import_leaves_only_quarantined_private_material(
    unprovisioned,
):
    import select

    f = unprovisioned
    script = r"""
import sys,os,time
from pathlib import Path
from azazel_edge.outcome import input_service
real=input_service.os.write
seen=False
def pause(fd,data):
 global seen
 result=real(fd,data)
 if not seen:
  seen=True;print('paused',flush=True);time.sleep(30)
 return result
input_service.os.write=pause
input_service.provision(*map(Path,sys.argv[1:]))
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(f.bundle),
            str(f.candidate),
            str(f.registration),
            str(f.incoming),
            str(f.wk),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(os.environ, PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py")),
    )
    try:
        assert select.select([process.stdout], [], [], 10)[0]
        assert process.stdout.readline() == b"paused\n"
        process.kill()
        process.wait(timeout=10)
        assert f.bundle.stat().st_mode & 0o777 == 0o700
        assert (f.bundle / PRODUCER_KEY).stat().st_mode & 0o777 == 0o600
        with pytest.raises(OSError):
            verify(f.bundle)
        with pytest.raises(OSError):
            provision(f.bundle, f.candidate, f.registration, f.incoming, f.wk)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()


def test_normal_start_owns_same_guard_before_signed_preparation(bundle):
    import select, signal

    f = bundle
    r = json.loads(f.registration.read_bytes())
    process = subprocess.Popen(
        [str(f.binary)],
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", **r["environment"]},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        pending = b""
        for _ in range(100):
            if select.select([process.stderr], [], [], 0.1)[0]:
                pending += os.read(process.stderr.fileno(), 8192)
            if b"azazel-edge-core started:" in pending:
                break
        else:
            raise AssertionError("normal core did not start")
        run = Run(f)
        try:
            stdout, stderr = run.process.communicate(timeout=10)
            assert run.process.returncode != 0 and "core_started" not in stdout
            assert f.source.read_bytes() == b"" and process.poll() is None
        finally:
            run.close()
        process.kill()
        process.wait(timeout=10)
        with CoreLease(r["environment"]["AZAZEL_DEFENSE_RELEASE_LEDGER"]):
            pass
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=10)
        process.stderr.close()


def test_ai_socket_registration_preserves_private_ai_role_without_key_grants(bundle):
    import socket
    from azazel_edge.outcome.input_live import registration

    f = bundle
    directory = f.root / "private-ai"
    directory.mkdir(mode=0o700)
    os.chown(directory, 65532, 65532)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    path = directory / "ai.sock"
    sock.bind(str(path))
    path.chmod(0o600)
    os.chown(path, 65532, 65532)
    try:
        r = json.loads(f.registration.read_bytes())
        r.update(
            schema_version="outcome-live-origin-registration/v2", ai_socket_uid=65532
        )
        r["environment"]["AZAZEL_AI_SOCKET"] = str(path)
        public = f.root / "new-ai-registration"
        public.write_bytes(_json(r))
        public.chmod(0o644)
        p = TrustPolicy(
            {
                **dict(f.p.data),
                "origin_registration_sha256": __import__("hashlib")
                .sha256(_json(r))
                .hexdigest(),
            }
        )
        assert registration(p, public)["ai_socket_uid"] == 65532
        # A producer cannot traverse the private AI directory and receives no ACL.
        child = subprocess.run(
            [sys.executable, "-c", "import os,sys;os.stat(sys.argv[1])", str(path)],
            user=1000,
            group=1000,
            extra_groups=[],
            capture_output=True,
        )
        assert child.returncode != 0
        assert f.pk.stat().st_uid == 1000 and f.wk.stat().st_uid == 0
    finally:
        sock.close()


def test_generated_service_profile_passes_real_systemd_syntax_verification(bundle):
    from azazel_edge.outcome.service_switch import profile

    tool = shutil.which("systemd-analyze")
    assert (
        tool
    ), "mandatory systemd syntax checker must be preinstalled in test environment"
    f = bundle
    unit = f.root / "azazel-edge-core.service"
    unit.write_bytes(
        b"[Unit]\nDescription=Offline signed input profile syntax test\n[Service]\nType=simple\n"
        + profile(f.bundle, Path(sys.executable))
    )
    result = subprocess.run(
        [tool, "verify", str(unit)], capture_output=True, timeout=10
    )
    assert result.returncode == 0, result.stderr.decode()


def test_preflight_preserves_venv_and_requires_real_isolated_runtime(bundle):
    import venv

    f = bundle
    runtime = f.root / "runtime"
    venv.EnvBuilder(with_pip=False).create(runtime)
    copied = f.root / "installed-py"
    copied.mkdir(mode=0o755)
    shutil.copytree(
        ROOT / "py/azazel_edge",
        copied / "azazel_edge",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    site = next((runtime / "lib").glob("python*/site-packages"))
    paths = [str(copied), *[p for p in sys.path if p.endswith("site-packages")]]
    (site / "operator-installed.pth").write_text("\n".join(paths) + "\n")
    python = runtime / "bin/python"
    Systemd().runtime(python, copied / "azazel_edge/outcome")
    # Isolated startup must not accidentally use caller PYTHONPATH/fallback.
    with pytest.raises(OSError):
        Systemd().runtime(python, f.root / "wrong-package")


def test_real_post_start_proof_requires_live_signer_and_authenticated_native_start(
    bundle,
):
    from test_outcome_live_origin_linux import children

    f = bundle
    f.start(initialize=True)
    observer = Child(f, True)
    assert observer.initial.get("ready"), observer.initial
    observer.close()
    run = Run(f)
    try:
        run.started()
        events(f, 2)
        Systemd().capture_ready(f.bundle, f.p, run.process.pid, 0)
        signer = next(
            pid
            for pid in children(run)
            if Path(f"/proc/{pid}/status").read_text().split("Uid:")[1].split()[0]
            == "1000"
        )
        os.kill(signer, 9)
        for _ in range(100):
            if not Path(f"/proc/{signer}").exists():
                break
            __import__("time").sleep(0.01)
        with pytest.raises(OSError):
            Systemd().capture_ready(f.bundle, f.p, run.process.pid, 0)
    finally:
        run.close()


def test_interrupted_profile_publication_is_explicitly_restorable_without_start(
    switched,
):
    f, m, s = switched
    plan = s.plan()
    real = os.unlink

    def fail_pending(path, *args, **kwargs):
        if str(path).endswith(".pending"):
            raise OSError("injected publication interruption")
        return real(path, *args, **kwargs)

    with patch(
        "azazel_edge.outcome.service_switch.os.unlink", side_effect=fail_pending
    ):
        with pytest.raises(OSError):
            s.apply(plan, digest(plan))
    target = m.directory / DROPIN
    assert target.stat().st_nlink == 2 and "start" not in m.calls
    receipt = f.bundle / "switch" / (digest(plan) + ".jsonl")
    s.restore(receipt)
    assert not target.exists() and "start" not in m.calls


def test_public_bundle_preparation_needs_no_existing_destination_or_private_keys(
    unprovisioned,
):
    from azazel_edge.outcome.input_service import prepare

    f = unprovisioned
    d = dict(f.p.data)
    d.pop("origin_registration_sha256")
    d["schema_version"] = "outcome-input-trust/v1"
    template = f.root / "public-template.json"
    template.write_bytes(_json(d))
    template.chmod(0o644)
    environment = f.root / "environment.json"
    environment.write_bytes(
        _json(json.loads(f.registration.read_bytes())["environment"])
    )
    environment.chmod(0o644)
    with patch(
        "azazel_edge.outcome.input_service.key_bytes",
        side_effect=AssertionError("private key read during public preparation"),
    ):
        result = prepare(f.bundle, template, f.binary, environment)
    assert result["trust_policy"] == dict(f.p.data)
    assert result["registration"] == json.loads(f.registration.read_bytes())
    assert not f.bundle.exists()


@pytest.mark.parametrize(
    "property,value",
    [
        ("User", "1000"),
        ("CapabilityBoundingSet", "cap_net_admin"),
        ("PrivateUsers", "yes"),
        ("RootDirectory", "/srv/chroot"),
        ("Type", "notify"),
        ("ExecStop", "custom-stop-hook"),
    ],
)
def test_cutover_never_elevates_or_relaxes_existing_service_permissions(
    switched, property, value
):
    f, m, s = switched
    m.base[property] = value
    with pytest.raises(OSError):
        s.plan()
    assert "stop" not in m.calls and "start" not in m.calls


def test_deployed_signer_cannot_retain_capabilities_or_regain_privilege(bundle):
    from test_outcome_live_origin_linux import children

    f = bundle
    run = Run(f)
    try:
        run.started()
        events(f, 2)
        signer = next(
            pid
            for pid in children(run)
            if Path(f"/proc/{pid}/status").read_text().split("Uid:")[1].split()[0]
            == "1000"
        )
        status = Path(f"/proc/{signer}/status").read_text()
        assert status.split("NoNewPrivs:")[1].split()[0] == "1"
        for key in ("CapEff", "CapPrm", "CapAmb"):
            assert int(status.split(key + ":")[1].split()[0], 16) == 0
        assert not status.split("Groups:")[1].splitlines()[0].strip()
    finally:
        run.close()


def test_managed_entry_rechecks_witness_on_every_start_and_preserves_source_on_failure(
    bundle,
):
    import venv

    f = bundle
    runtime = f.root / "managed-runtime"
    venv.EnvBuilder(with_pip=False).create(runtime)
    copied = f.root / "managed-py"
    copied.mkdir(mode=0o755)
    shutil.copytree(
        ROOT / "py/azazel_edge",
        copied / "azazel_edge",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    site = next((runtime / "lib").glob("python*/site-packages"))
    (site / "operator-installed.pth").write_text(
        "\n".join([str(copied), *[p for p in sys.path if p.endswith("site-packages")]])
        + "\n"
    )
    f.start(initialize=True)
    observer = Child(f, True)
    assert observer.initial.get("ready"), observer.initial
    observer.close()
    run = Run.__new__(Run)
    run.f = f
    run.process = subprocess.Popen(
        [
            str(runtime / "bin/python"),
            "-I",
            "-m",
            "azazel_edge.outcome.service_entry",
            "--bundle",
            str(f.bundle),
            "--boot-ref",
            "managed-boot",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        run.started()
        events(f, 2)
        assert run.stop() == 0
        events(f, 3)
    finally:
        run.close()
    before = f.source.read_bytes()
    f.halt()
    result = subprocess.run(
        [
            str(runtime / "bin/python"),
            "-I",
            "-m",
            "azazel_edge.outcome.service_entry",
            "--bundle",
            str(f.bundle),
            "--boot-ref",
            "next-boot",
        ],
        capture_output=True,
        timeout=15,
    )
    assert result.returncode != 0 and b"core_started" not in result.stdout
    assert f.source.read_bytes() == before
