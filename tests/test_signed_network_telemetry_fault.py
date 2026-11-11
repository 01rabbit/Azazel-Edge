"""Real private files/FD append and real crypto; Root/roles/init facts synthetic."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace

import pytest
from azazel_edge.outcome.input_auth import (
    TrustPolicy,
    SourceVerifier,
    read_regular,
    open_parent,
)
from azazel_edge.outcome.journal import OutcomeJournalError, _json, ZERO_HASH
from auth_input_helpers import make_policy

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_fault as f
from test_signed_network_telemetry_proof import identity, BOOT


@pytest.fixture
def tmp_path():
    # Actual Unix socket layout metadata must fit the unchanged 100-byte contract.
    with tempfile.TemporaryDirectory(prefix="edge-fault-", dir="/tmp") as directory:
        yield Path(directory).resolve()


def fixture(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    for name in ("observer", "witness/anchors"):
        (root / name).mkdir(parents=True)
    output = tmp_path / "fault"
    output.mkdir(mode=0o700)
    live_output = tmp_path / "live"
    live_output.mkdir(mode=0o700)
    trust, *_ = make_policy(root, producer=61001, observer=61002, witness=0)
    trust = TrustPolicy(
        dict(
            trust.data,
            schema_version="outcome-input-trust/v3",
            origin_registration_sha256="f" * 64,
            source_path=str(root / "input"),
            journal_directory=str(root / "observer"),
            anchor_directory=str(root / "witness/anchors"),
            socket_path=str(root / "socket/witness.sock"),
        )
    )
    (root / "input").touch(mode=0o644)
    journal = b""
    head = ZERO_HASH
    for seq, (kind, data) in enumerate(
        [
            ("header", {}),
            ("session_open", dict(boot_id=f.init.plan.n.boot_reference(BOOT))),
            ("input_ready", dict(offset=0, sha256=hashlib.sha256(b"").hexdigest())),
            ("session_close", dict(boot_id=f.init.plan.n.boot_reference(BOOT))),
        ],
        1,
    ):
        body = dict(seq=seq, prev=head, kind=kind, data=data)
        head = hashlib.sha256(_json(body)).hexdigest()
        journal += _json(dict(body, sha256=head)) + b"\n"
    (root / "observer/observations.journal").write_bytes(journal)
    (root / "observer/observations.journal").chmod(0o600)
    (root / "witness/anchors/anchors.journal").write_bytes(
        b"SYNTHETIC untouched witness baseline\n"
    )
    (root / "witness/anchors/anchors.journal").chmod(0o600)
    current = dict(
        abi_sha256="a" * 64,
        interpreter_sha256="b" * 64,
        source_sha256={"synthetic-reviewed": "c" * 64},
    )
    public = dict(trust_sha256=trust.digest, scope_ref=trust.data["scope_ref"])
    binding = dict(
        material=current,
        public_auth=public,
        kernel_boot_id=BOOT,
        policy_sha256="d" * 64,
        policy_file_sha256="e" * 64,
    )
    initialized = dict(
        binding=binding,
        initialization=dict(
            initialized_empty=True,
            identity=identity(),
            kernel_boot_id=BOOT,
            boot_ref=f.init.plan.n.boot_reference(BOOT),
            policy_sha256="d" * 64,
            policy_file_sha256="e" * 64,
        ),
        proof=dict(
            ready=dict(mode="initialize", role=f.init.role.ROLE, identity=identity())
        ),
        authorizes_transition=False,
        experiment=False,
        production_admission=False,
    )
    monkeypatch.setattr(f.g, "BUNDLE", root)
    monkeypatch.setattr(f.g, "guard", lambda: None)
    monkeypatch.setattr(f.g, "boot", lambda: BOOT)
    monkeypatch.setattr(f.g, "Systemd", lambda: SimpleNamespace(cores=lambda: []))
    monkeypatch.setattr(f.init.proof.p, "_output", lambda path: None)
    monkeypatch.setattr(f, "public_auth_binding", lambda: deepcopy(public))
    monkeypatch.setattr(f.material, "verify_current", lambda **k: deepcopy(current))
    monkeypatch.setenv("EDGE_SIGNED_NETWORK_TELEMETRY", "1")
    owner = os.geteuid()
    source_fds = set()

    def typed(info, uid):
        return SimpleNamespace(
            **{
                name: getattr(info, name)
                for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size")
            },
            st_uid=uid,
        )

    def reading(path, **kwargs):
        raw, info = read_regular(
            path, owner=owner, mode=kwargs.get("mode"), max_bytes=kwargs["max_bytes"]
        )
        return raw, typed(info, kwargs["owner"])

    def opening(path, flags, *args, **kwargs):
        fd = os.open(path, flags, *args, **kwargs)
        if path == "input" and flags & os.O_WRONLY:
            source_fds.add(fd)
        return fd

    def fstating(fd):
        return typed(os.fstat(fd), 61001) if fd in source_fds else os.fstat(fd)

    def stating(path, **kwargs):
        info = os.stat(path, **kwargs)
        return typed(info, 61001) if path == "input" else info

    real_os = {
        key: getattr(os, key)
        for key in (
            "O_RDONLY",
            "O_DIRECTORY",
            "O_NOFOLLOW",
            "O_WRONLY",
            "O_APPEND",
            "O_CLOEXEC",
            "O_NONBLOCK",
            "close",
            "write",
            "fsync",
            "environ",
            "path",
        )
    }
    monkeypatch.setattr(
        f,
        "os",
        SimpleNamespace(
            **real_os, open=opening, fstat=fstating, stat=stating, geteuid=lambda: 0
        ),
    )
    monkeypatch.setattr(f, "read_regular", reading)
    monkeypatch.setattr(
        f, "open_parent", lambda path, **kwargs: open_parent(path, trusted_owner=owner)
    )
    return root, output, live_output, trust, initialized


def prepare(tmp_path, monkeypatch):
    root, output, live_output, trust, initialized = fixture(tmp_path, monkeypatch)
    snapshot = f.capture_init(output, trust=trust, initialization=initialized)
    poisoned = f.inject(output, snapshot=snapshot, session_ref="1" * 32)
    return root, output, live_output, poisoned


def retained_live(live_output, snapshot):
    values = {
        "live-terminal.stdout": b"",
        "live-terminal.stderr": b"Traceback (most recent call last):\n"
        + b"azazel_edge.outcome.journal.OutcomeJournalError: authentication signature invalid\n",
        "live-terminal-client.json": dict(returncode=1, error=None),
        "live-cleanup.json": dict(errors=[]),
        "live-client-reap.json": dict(errors=[], reaped=True, forced=False),
        "live-verified-bundle.json": dict(
            binding=snapshot.initialization["binding"],
            binding_sha256=f.init.plan.manifest_digest(
                snapshot.initialization["binding"]
            ),
            proof=dict(
                ready=dict(mode="live"),
                effective={"synthetic": True},
                actor={"synthetic": True},
                metadata={"synthetic": True},
            ),
        ),
    }
    for name, value in values.items():
        (live_output / name).write_bytes(
            value if type(value) is bytes else _json(value)
        )
    return values


def test_real_owned_fd_single_append_exact_crypto_refusal_and_unchanged_baseline(
    tmp_path, monkeypatch
):
    root, output, live_output, snapshot = prepare(tmp_path, monkeypatch)
    assert (root / "input").read_bytes() == snapshot.wire
    with pytest.raises(OutcomeJournalError, match="^authentication signature invalid$"):
        SourceVerifier(snapshot.trust).verify(snapshot.wire)
    retained_live(live_output, snapshot)
    result = f.classify_refusal(
        output,
        snapshot=snapshot,
        live_output=live_output,
        failure=AssertionError("actual live worker failed"),
    )
    assert (
        result["status"] == "expected_signature_refusal_observed"
        and "outer_cleanup_pending" in result["scope"]
    )
    assert (
        result["authorizes_transition"]
        is result["experiment"]
        is result["production_admission"]
        is False
    )
    assert (output / "fault-init-journal.raw").read_bytes() == (
        output / "fault-after-refusal-journal.raw"
    ).read_bytes()
    assert (output / "fault-init-anchors.raw").read_bytes() == (
        output / "fault-after-refusal-anchors.raw"
    ).read_bytes()


@pytest.mark.parametrize(
    "fault",
    [
        "source",
        "journal",
        "anchors",
        "unexpected",
        "generic",
        "cleanupnote",
        "stderr",
        "stdout",
        "rc",
        "forced",
        "binding",
    ],
)
def test_any_missing_drift_or_generic_failure_stays_blocked(
    tmp_path, monkeypatch, fault
):
    root, output, live_output, snapshot = prepare(tmp_path, monkeypatch)
    values = retained_live(live_output, snapshot)
    failure = AssertionError("actual live worker failed")
    if fault in ("source", "journal", "anchors"):
        path = {
            "source": root / "input",
            "journal": root / "observer/observations.journal",
            "anchors": root / "witness/anchors/anchors.journal",
        }[fault]
        with path.open("ab") as stream:
            stream.write(b"changed")
    if fault == "unexpected":
        (root / "observer/outcomes.jsonl").touch()
    if fault == "generic":
        failure = AssertionError("some unrelated failure")
    if fault == "cleanupnote":
        failure.add_note("cleanup failed")
    if fault == "stderr":
        (live_output / "live-terminal.stderr").write_bytes(b"PermissionError: denied\n")
    if fault == "stdout":
        (live_output / "live-terminal.stdout").write_bytes(b'{"success":true}\n')
    if fault == "rc":
        (live_output / "live-terminal-client.json").write_bytes(
            _json(dict(returncode=0, error=None))
        )
    if fault == "forced":
        (live_output / "live-client-reap.json").write_bytes(
            _json(dict(errors=[], reaped=True, forced=True))
        )
    if fault == "binding":
        values["live-verified-bundle.json"]["binding"] = dict(
            snapshot.initialization["binding"], kernel_boot_id="other"
        )
        (live_output / "live-verified-bundle.json").write_bytes(
            _json(values["live-verified-bundle.json"])
        )
    with pytest.raises((AssertionError, ValueError, OSError)):
        f.classify_refusal(
            output, snapshot=snapshot, live_output=live_output, failure=failure
        )
    assert not (output / "fault-refusal.json").exists()


@pytest.mark.parametrize("fault", ["short", "fd-sync", "parent-sync"])
def test_partial_or_persistence_failure_keeps_source_raw_and_never_repairs(
    tmp_path, monkeypatch, fault
):
    root, output, _, trust, initialized = fixture(tmp_path, monkeypatch)
    baseline = f.capture_init(output, trust=trust, initialization=initialized)
    write, sync = f.os.write, f.os.fsync

    def writing(fd, raw):
        return write(fd, raw[:17] if fault == "short" else raw)

    def syncing(fd):
        mode = os.fstat(fd).st_mode
        if (
            fault == "fd-sync"
            and stat.S_ISREG(mode)
            or fault == "parent-sync"
            and stat.S_ISDIR(mode)
            and os.fstat(fd).st_ino == root.stat().st_ino
        ):
            raise OSError("synthetic persistence failure")
        return sync(fd)

    monkeypatch.setattr(f.os, "write", writing)
    monkeypatch.setattr(f.os, "fsync", syncing)
    with pytest.raises((AssertionError, OSError)):
        f.inject(output, snapshot=baseline, session_ref="1" * 32)
    actual = (root / "input").read_bytes()
    assert actual and (len(actual) == 17 if fault == "short" else len(actual) > 17)
    assert (output / "fault-after-append-source.raw").read_bytes() == actual
    assert (root / "observer/observations.journal").read_bytes() == baseline.records[
        "journal"
    ]["raw"]
    assert not (output / "fault-refusal.json").exists()


@pytest.mark.parametrize("fault", ["not-empty", "symlink", "hardlink", "flag", "core"])
def test_unowned_used_or_unmarked_source_never_written(tmp_path, monkeypatch, fault):
    root, output, _, trust, initialized = fixture(tmp_path, monkeypatch)
    if fault == "not-empty":
        (root / "input").write_bytes(b"USED")
    if fault == "symlink":
        (root / "input").unlink()
        (root / "foreign").write_bytes(b"FOREIGN")
        (root / "input").symlink_to(root / "foreign")
    if fault == "hardlink":
        os.link(root / "input", root / "other")
    if fault == "flag":
        monkeypatch.delenv("EDGE_SIGNED_NETWORK_TELEMETRY")
    if fault == "core":
        monkeypatch.setattr(
            f.g, "Systemd", lambda: SimpleNamespace(cores=lambda: [123])
        )
    with pytest.raises((AssertionError, ValueError, OSError)):
        f.capture_init(output, trust=trust, initialization=initialized)
    assert not (output / "fault-append-intent.json").exists()
    if fault == "not-empty":
        assert (root / "input").read_bytes() == b"USED"
    if fault == "symlink":
        assert (root / "foreign").read_bytes() == b"FOREIGN"
