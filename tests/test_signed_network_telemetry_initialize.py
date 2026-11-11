"""Synthetic Root/proof/unit fixtures and private client IO, no VM/role proof."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_initialize as call

BOOT = "095d28ff-ca7d-4b08-9e4b-e36a62db4810"
SHA = "a" * 64


def fixture(tmp_path, monkeypatch, fault=None):
    events, sent = [], []
    monkeypatch.setattr(call.material, "SRC", Path("/opt/edge400-src"))
    source_key = str(Path(call.role.SOURCE).relative_to(call.material.SRC))
    material = dict(
        source_sha256={source_key: SHA},
        abi_sha256="b" * 64,
        interpreter_sha256="c" * 64,
        role=call.role.ROLE,
    )
    identity = dict(
        pid=123, tgid=123, uid=61002, apparmor=call.role.PROFILE + " (enforce)"
    )
    verified = dict(
        ready=dict(identity=identity),
        effective=dict(unit="fixed"),
        actor=dict(evidence=dict(before=dict(MainPID="123"))),
        metadata=dict(observed="actual-fixture"),
    )
    monkeypatch.setattr(call.g, "guard", lambda: events.append("guard"))
    monkeypatch.setattr(call.g, "boot", lambda: BOOT)
    snapshots = []

    def public_binding():
        snapshots.append(1)
        if fault in ("badtrust", "badorigin"):
            raise ValueError("synthetic public config parser refusal")
        if (
            fault == "missingbeforego"
            and len(snapshots) == 2
            or fault == "missingafterinit"
            and len(snapshots) == 3
        ):
            raise FileNotFoundError("synthetic missing public config")
        value = dict(
            scope="public_root_config_continuity_only",
            scope_ref="synthetic-auth-scope",
            trust_file_sha256="d" * 64,
            origin_file_sha256="e" * 64,
        )
        for field in ("scope_ref", "trust_file_sha256", "origin_file_sha256"):
            if (
                fault == "pregodrift:" + field
                and len(snapshots) == 2
                or fault == "postdrift:" + field
                and len(snapshots) == 3
            ):
                value[field] = "changed"
        return value

    monkeypatch.setattr(call, "public_auth_binding", public_binding)
    monkeypatch.setattr(
        call, "witness_binding", lambda *args: {"synthetic_stable_witness": True}
    )
    monkeypatch.setattr(
        call.proof.p, "_output", lambda output: events.append("private")
    )
    checks = []

    def current(**pins):
        assert pins == dict(abi_sha256="b" * 64, interpreter_sha256="c" * 64)
        checks.append("read")
        if fault == "material" or fault == "materialdrift" and len(checks) > 1:
            raise AssertionError("synthetic material drift")
        return deepcopy(material)

    monkeypatch.setattr(call.material, "verify_current", current)
    policy_reads = []

    def policy(*args):
        policy_reads.append(1)
        return (
            b'{"public":"changed"}'
            if fault == "policydrift" and len(policy_reads) > 1
            else b'{"public":"policy"}'
        )

    monkeypatch.setattr(call.material, "_read", policy)

    def namespace(fd, expected):
        events.append("namespace")
        assert fd == 99 and expected == [5, 100]
        if fault == "namespace":
            raise AssertionError("synthetic replaced namespace")
        return expected

    monkeypatch.setattr(call, "_namespace", namespace)
    monkeypatch.setattr(
        call,
        "prelaunch_unit_material",
        lambda mode, output: events.append("unit-material"),
    )
    monkeypatch.setattr(call.scope, "_state", lambda unit: {"synthetic": "absent"})
    monkeypatch.setattr(
        call.scope, "_known_collected", lambda value: fault != "existing"
    )
    monkeypatch.setattr(
        call.lab.cg,
        "group_empty",
        lambda group, units: group == "/system.slice/" + call.role.INITIALIZER_UNIT
        and units == (call.role.INITIALIZER_UNIT,),
    )

    class Stream:
        closed = False

        def fileno(self):
            return 12

        def close(self):
            if self.closed:
                return
            self.closed = True
            events.append("pipeclose")
            if fault == "pipeclose":
                raise OSError("synthetic pipeclose failure")

    process = SimpleNamespace(
        stdin=Stream(), stdout=Stream(), stderr=Stream(), returncode=0
    )

    def launch(argv, **kw):
        assert argv == call.observer.role_argv("initialize", telemetry_lab_v2=True)
        assert kw["stdin"] == kw["stdout"] == kw["stderr"] == subprocess.PIPE
        assert kw["close_fds"] is True
        assert kw["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
        events.append("launch")
        if fault == "launch":
            raise OSError("synthetic launch failure")
        return process

    monkeypatch.setattr(call.subprocess, "Popen", launch)

    def collect(mode, child, **kw):
        assert mode == "initialize" and child is process
        assert kw == dict(
            expected_namespace=[5, 100],
            kernel_boot_id=BOOT,
            source_sha256=SHA,
            output=tmp_path,
        )
        events.append("fullproof")
        if fault in ("ready", "effective", "source", "rootproof"):
            raise AssertionError("synthetic actual " + fault + " refusal")
        return {} if fault == "missingbundle" else verified

    monkeypatch.setattr(call.proof, "collect_pre_api", collect)
    monkeypatch.setattr(call.select, "select", lambda *args: ([], args[1], []))

    def write(fd, value):
        assert fd == 12 and value == call.role.GO
        saved = json.loads((tmp_path / "initializer-verified-bundle.json").read_bytes())
        assert saved["proof"] == verified and saved["binding"]["roles"][
            "initialize"
        ] == call.role.observer_spec("initialize")
        assert saved["binding_sha256"] == call.plan.manifest_digest(saved["binding"])
        events.append("GO")
        sent.append(value)
        return len(value) - (fault == "shortwrite")

    monkeypatch.setattr(call.os, "write", write)

    def drain(child, output, deadline, prefix="initialization"):
        assert child is process and 0 < deadline - time.monotonic() <= 20
        events.append("drain:" + prefix)
        if prefix == "initialization" and fault == "timeout":
            raise TimeoutError("synthetic deadline")
        value = dict(
            initialized_empty=True,
            identity=identity,
            kernel_boot_id=BOOT,
            boot_ref=call.plan.n.boot_reference(BOOT),
            policy_sha256=call.plan.manifest_digest({"public": "policy"}),
            policy_file_sha256=__import__("hashlib")
            .sha256(b'{"public":"policy"}')
            .hexdigest(),
        )
        if fault == "resultidentity":
            value["identity"] = dict(identity, uid=0)
        if fault == "emptyfalse":
            value["initialized_empty"] = False
        if fault == "boot":
            value["kernel_boot_id"] = "wrong"
        raw = (
            b'{"partial"' if fault == "partial" else json.dumps(value).encode() + b"\n"
        )
        if fault == "exit":
            process.returncode = 1
        call.lab.save(output / (prefix + ".stdout"), raw)
        call.lab.save(
            output / (prefix + ".stderr"), b"error" if fault == "stderr" else b""
        )
        call.lab.save_json(
            output / (prefix + "-client.json"), dict(returncode=process.returncode)
        )
        return dict(stdout=raw, stderr=b"error" if fault == "stderr" else b"")

    monkeypatch.setattr(call, "_drain", drain)

    def cleanup(units, tracked):
        events.append("stop-proof")
        assert units == (call.role.INITIALIZER_UNIT,) and set(tracked) == set(units)
        return dict(errors=["synthetic unknown CG"] if fault == "cleanup" else [])

    monkeypatch.setattr(call.lab, "cleanup", cleanup)

    def reap(child):
        events.append("reap")
        return dict(reaped=True, forced=fault == "force", errors=[])

    monkeypatch.setattr(call, "_reap_client", reap)
    save = call.lab.save_json

    def saving(path, value):
        if path.name == "initializer-verified-bundle.json" and fault == "persist":
            raise OSError("synthetic full-bundle persistence failure")
        if path.name == "initializer-cleanup.json" and fault == "cleanuppersist":
            raise OSError("synthetic cleanup persistence failure")
        return save(path, value)

    monkeypatch.setattr(call.lab, "save_json", saving)
    args = dict(
        abi_sha256="b" * 64,
        interpreter_sha256="c" * 64,
        source_sha256=SHA,
        expected_sources=material["source_sha256"],
        namespace_fd=99,
        namespace_identity=[5, 100],
    )
    if fault == "externalpins":
        args["expected_sources"] = {source_key: "d" * 64}
    return args, events, sent


def test_fixed_initializer_needs_no_four_manifest_and_persists_full_bundle_before_go(
    tmp_path, monkeypatch
):
    args, events, sent = fixture(tmp_path, monkeypatch)
    result = call.initialize(tmp_path, **args)
    assert sent == [call.role.GO]
    assert (
        events.index("fullproof")
        < events.index("GO")
        < events.index("drain:initialization")
        < events.index("stop-proof")
        < events.index("reap")
    )
    assert result["initialization"]["initialized_empty"] is True
    assert (
        result["authorizes_transition"]
        is result["experiment"]
        is result["production_admission"]
        is False
    )
    assert (tmp_path / "initializer-result.json").exists()


@pytest.mark.parametrize(
    "fault",
    [
        "material",
        "namespace",
        "existing",
        "externalpins",
        "launch",
        "ready",
        "effective",
        "source",
        "rootproof",
        "missingbundle",
        "materialdrift",
        "policydrift",
        "persist",
    ],
)
def test_pre_go_gap_never_authorizes_api_and_cleans_owned_client_independently(
    tmp_path, monkeypatch, fault
):
    args, events, sent = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, OSError, KeyError)):
        call.initialize(tmp_path, **args)
    assert sent == [] and not (tmp_path / "initializer-result.json").exists()
    if "launch" in events:
        assert "stop-proof" in events
        if fault != "launch":
            assert "reap" in events and events.count("pipeclose") == 3
    else:
        assert "stop-proof" not in events


@pytest.mark.parametrize(
    "fault",
    [
        "shortwrite",
        "timeout",
        "partial",
        "emptyfalse",
        "resultidentity",
        "boot",
        "exit",
        "stderr",
        "cleanup",
        "cleanuppersist",
        "force",
        "pipeclose",
    ],
)
def test_post_go_or_cleanup_failure_never_publishes_success_and_still_reaps_closes(
    tmp_path, monkeypatch, fault
):
    args, events, _ = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, OSError, ValueError, TimeoutError)):
        call.initialize(tmp_path, **args)
    assert (
        "stop-proof" in events and "reap" in events and events.count("pipeclose") == 3
    )
    assert not (tmp_path / "initializer-result.json").exists()
    if fault not in ("shortwrite", "timeout", "pipeclose"):
        assert (tmp_path / "initialization.stdout").exists() and (
            tmp_path / "initialization.stderr"
        ).exists()


def test_real_private_stream_drain_is_bounded_retains_original_bytes_before_any_parser(
    tmp_path,
):
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys;sys.stdout.buffer.write(b'x'*70000);sys.stderr.write('private')",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        with pytest.raises(AssertionError, match="reply bound"):
            call._drain(child, tmp_path, time.monotonic() + 2)
        assert len((tmp_path / "initialization.stdout").read_bytes()) == 65537
        assert (tmp_path / "initialization.stderr").exists()
        assert (tmp_path / "initialization-client.json").exists()
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        child.stderr.close()


@pytest.mark.parametrize("fault", [None, "inheritable", "replaced", "mode", "owner"])
def test_namespace_handle_is_parent_only_named_fixed_root_identity(monkeypatch, fault):
    import stat

    values = dict(st_dev=5, st_ino=100, st_mode=stat.S_IFREG | 0o444, st_uid=0)
    named = dict(values)
    if fault == "replaced":
        named["st_ino"] = 101
    if fault == "mode":
        named["st_mode"] = stat.S_IFDIR | 0o755
    if fault == "owner":
        named["st_uid"] = 61002

    def lookup(path, **kw):
        assert path == call.role.NSFS_TARGETS[0] and kw == dict(follow_symlinks=False)
        return SimpleNamespace(**named)

    monkeypatch.setattr(
        call,
        "os",
        SimpleNamespace(
            fstat=lambda fd: SimpleNamespace(**values),
            stat=lookup,
            get_inheritable=lambda fd: fault == "inheritable",
        ),
    )
    if fault is None:
        assert call._namespace(99, [5, 100]) == [5, 100]
    else:
        with pytest.raises(AssertionError):
            call._namespace(99, [5, 100])


def test_controller_itself_forcibly_reaps_a_real_owned_stuck_private_client(
    tmp_path, monkeypatch
):
    spawn, draining, reaping, selecting = (
        subprocess.Popen,
        call._drain,
        call._reap_client,
        call.select.select,
    )
    args, events, _ = fixture(tmp_path, monkeypatch, "rootproof")
    children = []

    def launch(argv, **kw):
        child = spawn(
            [
                sys.executable,
                "-c",
                "import signal,sys,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('private-ready',flush=True);time.sleep(30)",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        marker = child.stdout.readline()
        call.lab.save(tmp_path / "synthetic-owned-client-ready.raw", marker)
        assert marker == b"private-ready\n"
        children.append(child)
        return child

    monkeypatch.setattr(call.subprocess, "Popen", launch)
    monkeypatch.setattr(call, "_drain", draining)
    monkeypatch.setattr(call, "_reap_client", reaping)

    def refuse(*args, **kw):
        raise AssertionError("synthetic rootproof refusal")

    monkeypatch.setattr(call.proof, "collect_pre_api", refuse)
    monkeypatch.setattr(call.select, "select", selecting)
    try:
        with pytest.raises(AssertionError, match="rootproof"):
            call.initialize(tmp_path, **args)
        child = children[0]
        assert child.poll() is not None and child.returncode == -9
        saved = json.loads((tmp_path / "initializer-client-reap.json").read_bytes())
        assert saved["forced"] is True and saved["reaped"] is True and saved["errors"]
        assert all(
            stream.closed for stream in (child.stdin, child.stdout, child.stderr)
        )
        assert (
            "stop-proof" in events
            and not (tmp_path / "initializer-result.json").exists()
        )
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait()
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()


def unit_query_fixture(tmp_path, monkeypatch, raw=None, code=0, stderr=b""):
    first, second = tmp_path / "units-first", tmp_path / "units-second"
    first.mkdir()
    second.mkdir()
    stdout = (
        raw if raw is not None else (str(first) + "\n" + str(second) + "\n").encode()
    )
    monkeypatch.setattr(call.proof.p, "_output", lambda output: None)
    reading = call.material._read

    def read(path, limit=1024 * 1024, mode=None):
        if str(path).endswith("launch-unit-paths.stderr"):
            assert limit == 4096
            return stderr
        return reading(path, limit, mode)

    monkeypatch.setattr(call.material, "_read", read)

    def query(argv, prefix, output):
        assert argv == ["systemd-analyze", "unit-paths"]
        assert prefix in ("initialize-launch-unit-paths", "live-launch-unit-paths")
        call.lab.save(output / (prefix + ".stdout"), stdout)
        call.lab.save(output / (prefix + ".stderr"), stderr)
        call.lab.save_json(output / (prefix + ".argv.json"), argv)
        call.lab.save_json(output / (prefix + ".result.json"), dict(returncode=code))
        return code, stdout

    monkeypatch.setattr(call.proof.p.old, "_retained_query", query)
    return first, second, stdout


@pytest.mark.parametrize("mode", ["initialize", "live"])
def test_actual_search_paths_are_checked_for_closed_modes_and_raw_query_retained(
    tmp_path, monkeypatch, mode
):
    first, second, raw = unit_query_fixture(tmp_path, monkeypatch)
    assert call.prelaunch_unit_material(mode, tmp_path) == [str(first), str(second)]
    assert (tmp_path / (mode + "-launch-unit-paths.stdout")).read_bytes() == raw


@pytest.mark.parametrize(
    "name",
    [
        call.role.INITIALIZER_UNIT,
        call.role.INITIALIZER_UNIT + ".d",
        call.role.INITIALIZER_UNIT + ".wants",
        call.role.INITIALIZER_UNIT + ".requires",
        call.role.INITIALIZER_UNIT + ".upholds",
        "service.d",
        "edge400-.service.d",
        "edge400-signed-.service.d",
        "edge400-signed-network-.service.d",
        "edge400-signed-network-telemetry-.service.d",
    ],
)
@pytest.mark.parametrize("kind", ["existing", "dangling"])
def test_inherited_material_any_actual_path_refuses_before_any_launch_or_go(
    tmp_path, monkeypatch, name, kind
):
    guard = call.prelaunch_unit_material
    args, events, sent = fixture(tmp_path, monkeypatch)
    _, second, raw = unit_query_fixture(tmp_path, monkeypatch)
    node = second / name  # Ensure the second path is checked too.
    if kind == "dangling":
        node.symlink_to(second / "absent-target")
    elif name.endswith((".d", ".wants", ".requires", ".upholds")):
        node.mkdir()
    else:
        node.write_text("[Service]\nExecStartPre=/usr/bin/true\n")
    monkeypatch.setattr(call, "prelaunch_unit_material", guard)
    with pytest.raises(AssertionError, match="inherited"):
        call.initialize(tmp_path, **args)
    assert "launch" not in events and sent == [] and "stop-proof" not in events
    assert (tmp_path / "initialize-launch-unit-paths.stdout").read_bytes() == raw
    assert node.is_symlink() if kind == "dangling" else node.exists()


@pytest.mark.parametrize(
    "fault",
    [
        "nonzero",
        "timeout",
        "stderr",
        "empty",
        "duplicate",
        "relative",
        "parent",
        "double",
        "space",
        "escaped",
        "blank",
        "cr",
        "unterminated",
        "oversize",
    ],
)
def test_bad_unit_query_refuses_with_originals_and_never_launches(
    tmp_path, monkeypatch, fault
):
    guard = call.prelaunch_unit_material
    args, events, sent = fixture(tmp_path, monkeypatch)
    rows = {
        "empty": b"",
        "duplicate": b"/etc/systemd/system\n/etc/systemd/system\n",
        "relative": b"etc/systemd/system\n",
        "parent": b"/etc/systemd/../system\n",
        "double": b"/etc//systemd/system\n",
        "space": b"/etc/systemd/unit path\n",
        "escaped": b"/etc/systemd/unit\\040path\n",
        "blank": b"/etc/systemd/system\n\n",
        "cr": b"/etc/systemd/system\r\n",
        "unterminated": b"/etc/systemd/system",
        "oversize": b"/" + b"a" * 16384 + b"\n",
    }
    _, _, raw = unit_query_fixture(
        tmp_path,
        monkeypatch,
        raw=rows.get(fault),
        code=None if fault == "timeout" else 1 if fault == "nonzero" else 0,
        stderr=b"query diagnostic" if fault == "stderr" else b"",
    )
    monkeypatch.setattr(call, "prelaunch_unit_material", guard)
    with pytest.raises((AssertionError, ValueError)):
        call.initialize(tmp_path, **args)
    assert "launch" not in events and sent == []
    assert (tmp_path / "initialize-launch-unit-paths.stdout").read_bytes() == raw
    assert (tmp_path / "initialize-launch-unit-paths.result.json").exists()


def test_valid_actual_lookup_guard_composes_before_launch_and_go(tmp_path, monkeypatch):
    guard = call.prelaunch_unit_material
    args, events, sent = fixture(tmp_path, monkeypatch)
    unit_query_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(call, "prelaunch_unit_material", guard)
    result = call.initialize(tmp_path, **args)
    assert result["initialization"]["initialized_empty"] is True
    assert sent == [call.role.GO] and "launch" in events
    assert (tmp_path / "initialize-launch-unit-paths.result.json").exists()


@pytest.mark.parametrize("mode", [True, None, "initialize.service", "../../initialize"])
def test_prelaunch_guard_never_accepts_arbitrary_unit_or_mode(tmp_path, mode):
    with pytest.raises(ValueError):
        call.prelaunch_unit_material(mode, tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "fault",
    [
        "badtrust",
        "badorigin",
        "missingbeforego",
        "pregodrift:scope_ref",
        "pregodrift:trust_file_sha256",
        "pregodrift:origin_file_sha256",
    ],
)
def test_public_auth_missing_invalid_or_drift_before_go_never_opens_api(
    tmp_path, monkeypatch, fault
):
    args, events, sent = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((ValueError, AssertionError, FileNotFoundError)):
        call.initialize(tmp_path, **args)
    assert sent == [] and not (tmp_path / "initializer-result.json").exists()
    if "launch" in events:
        assert "stop-proof" in events and "reap" in events
    else:
        assert fault in ("badtrust", "badorigin")
    if fault.startswith("pregodrift"):
        retained = json.loads(
            (tmp_path / "initializer-public-auth-before-go.json").read_bytes()
        )
        assert retained[fault.split(":", 1)[1]] == "changed"


@pytest.mark.parametrize(
    "fault",
    [
        "missingafterinit",
        "postdrift:scope_ref",
        "postdrift:trust_file_sha256",
        "postdrift:origin_file_sha256",
    ],
)
def test_public_auth_drift_after_init_retains_raws_and_refuses_success(
    tmp_path, monkeypatch, fault
):
    args, events, sent = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, FileNotFoundError)):
        call.initialize(tmp_path, **args)
    assert sent == [call.role.GO] and "stop-proof" in events and "reap" in events
    assert (tmp_path / "initialization.stdout").exists()
    assert not (tmp_path / "initializer-result.json").exists()
    if fault.startswith("postdrift"):
        retained = json.loads(
            (tmp_path / "initializer-public-auth-after-init.json").read_bytes()
        )
        assert retained[fault.split(":", 1)[1]] == "changed"


def test_full_verified_binding_retains_same_public_auth_snapshot_without_crypto_claim(
    tmp_path, monkeypatch
):
    args, _, _ = fixture(tmp_path, monkeypatch)
    result = call.initialize(tmp_path, **args)
    initial = result["binding"]["public_auth"]
    before_go = json.loads(
        (tmp_path / "initializer-public-auth-before-go.json").read_bytes()
    )
    after_init = json.loads(
        (tmp_path / "initializer-public-auth-after-init.json").read_bytes()
    )
    verified = json.loads((tmp_path / "initializer-verified-bundle.json").read_bytes())
    assert initial == before_go == after_init == verified["binding"]["public_auth"]
    assert initial["scope"] == "public_root_config_continuity_only"
    assert result["authorizes_transition"] is False


def test_full_bundle_directory_is_fsynced_and_closed_before_go(tmp_path, monkeypatch):
    import os
    import stat

    args, events, sent = fixture(tmp_path, monkeypatch)
    original_open, original_sync, original_close = os.open, os.fsync, os.close
    directory_fds = []

    def opening(path, flags, *a, **k):
        fd = original_open(path, flags, *a, **k)
        if path == tmp_path:
            assert flags == os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory_fds.append(fd)
        return fd

    def syncing(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            assert fd in directory_fds
            saved = json.loads(
                (tmp_path / "initializer-verified-bundle.json").read_bytes()
            )
            assert set(saved["proof"]) == {"ready", "effective", "actor", "metadata"}
            assert saved["binding_sha256"] == call.plan.manifest_digest(
                saved["binding"]
            )
            events.append("directory-fsync")
        return original_sync(fd)

    def closing(fd):
        if fd in directory_fds:
            events.append("directory-close")
        return original_close(fd)

    monkeypatch.setattr(call.os, "open", opening)
    monkeypatch.setattr(call.os, "fsync", syncing)
    monkeypatch.setattr(call.os, "close", closing)
    call.initialize(tmp_path, **args)
    assert sent == [call.role.GO]
    assert (
        events.index("directory-fsync")
        < events.index("directory-close")
        < events.index("GO")
    )


def test_directory_fsync_failure_no_go_and_original_error_survives_cleanup(
    tmp_path, monkeypatch
):
    import os
    import stat

    args, events, sent = fixture(tmp_path, monkeypatch, "cleanup")
    original_sync, original_close = os.fsync, os.close
    failure = OSError("synthetic directory persistence failure")
    directory_fds = []
    closed = []

    def syncing(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fds.append(fd)
            raise failure
        return original_sync(fd)

    def closing(fd):
        if fd in directory_fds:
            closed.append(fd)
        return original_close(fd)

    monkeypatch.setattr(call.os, "fsync", syncing)
    monkeypatch.setattr(call.os, "close", closing)
    with pytest.raises(OSError) as caught:
        call.initialize(tmp_path, **args)
    assert caught.value is failure and failure.__notes__
    assert directory_fds and closed == directory_fds
    assert sent == [] and not (tmp_path / "initializer-result.json").exists()
    assert (
        "stop-proof" in events and "reap" in events and events.count("pipeclose") == 3
    )
    assert (tmp_path / "initializer-verified-bundle.json").exists()
    assert (tmp_path / "initializer-cleanup.json").exists()
    assert (tmp_path / "initializer-client-reap.json").exists()
