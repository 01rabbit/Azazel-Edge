"""Synthetic custody observations; never a native/capture or service trial."""

import importlib.util
import ctypes
from copy import deepcopy
import errno
import json
import os
from pathlib import Path
import runpy
import stat
import sys

import pytest

REAL_SYSTEMD = Path(__file__).parent / "real_systemd"
sys.path.insert(0, str(REAL_SYSTEMD))
SPEC = importlib.util.spec_from_file_location(
    "native_close_lab_under_test", REAL_SYSTEMD / "native_close_receipts.py"
)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


def inventories():
    def entry(fd, inode, mode, owner=0):
        return dict(
            fd=fd, device=1, inode=inode, owner_uid=owner, mode=mode, nlink=1, flags=0
        )

    root = entry(1, 100, stat.S_IFREG | 0o600)
    native = entry(1, 200, stat.S_IFIFO | 0o600)
    receiver = entry(1, 300, stat.S_IFIFO | 0o600, 61001)
    diagnostic = entry(2, 400, stat.S_IFSOCK | 0o600)
    return root, dict(
        launcher=dict(
            pid=10,
            start_ticks=20,
            complete=True,
            entries=[root, diagnostic, dict(native, fd=5), dict(receiver, fd=6)],
            errors=[],
        ),
        native=dict(
            pid=11,
            start_ticks=21,
            complete=True,
            entries=[native, diagnostic],
            errors=[],
        ),
        receiver=dict(
            pid=12,
            start_ticks=22,
            complete=True,
            entries=[receiver, diagnostic],
            errors=[],
        ),
        sampled_ns=30,
    )


def test_distinct_child_private_pipes_and_exclusive_root_object():
    root, observed = inventories()
    assert lab.check_fd_custody(observed, root) == root


@pytest.mark.parametrize(
    "fault",
    [
        "native_sink_fd",
        "receiver_sink_fd",
        "shared_pipe",
        "child_stderr_sink",
        "root_wrong_object",
        "incomplete",
        "missing_parent_pipe",
    ],
)
def test_no_root_authority_from_child_fd_or_missing_observation(fault):
    root, observed = inventories()
    if fault == "native_sink_fd":
        observed["native"]["entries"].append(dict(root, fd=9))
    elif fault == "receiver_sink_fd":
        observed["receiver"]["entries"].append(dict(root, fd=9))
    elif fault == "shared_pipe":
        observed["receiver"]["entries"][0] = dict(observed["native"]["entries"][0])
    elif fault == "child_stderr_sink":
        observed["native"]["entries"][1] = dict(root, fd=2)
    elif fault == "root_wrong_object":
        observed["launcher"]["entries"][0] = dict(root, inode=999)
    elif fault == "incomplete":
        observed["native"]["complete"] = False
    elif fault == "missing_parent_pipe":
        observed["launcher"]["entries"].pop()
    with pytest.raises(AssertionError):
        lab.check_fd_custody(observed, root)


def test_original_read_brackets_return_exact_bytes_and_full_mode(tmp_path):
    path = tmp_path / "public-fixture.raw"
    path.write_bytes(b"original public fixture\n")
    raw, receipt = lab.stable_read(path, 100)
    assert raw == b"original public fixture\n"
    assert receipt["object"]["mode"] == path.stat().st_mode
    assert receipt["sha256"] == lab.accounting.sha256(raw)


@pytest.mark.parametrize("fault", ["hardlink", "oversize", "replacement"])
def test_original_read_rejects_changed_or_unbounded_object(
    tmp_path, monkeypatch, fault
):
    path = tmp_path / "public-fixture.raw"
    path.write_bytes(b"original\n")
    if fault == "hardlink":
        os.link(path, tmp_path / "alias")
    elif fault == "replacement":
        real_read = os.read
        replaced = False

        def replace_during_read(fd, size):
            nonlocal replaced
            raw = real_read(fd, size)
            if not replaced:
                replaced = True
                other = tmp_path / "replacement"
                other.write_bytes(b"original\n")
                other.replace(path)
            return raw

        monkeypatch.setattr(lab.os, "read", replace_during_read)
    with pytest.raises(AssertionError):
        lab.stable_read(path, 2 if fault == "oversize" else 100)


def test_begin_never_redirects_output_of_a_running_core():
    from types import SimpleNamespace

    instance = object.__new__(lab.CloseReceiptLab)
    instance.contexts = {}
    instance.g = SimpleNamespace(
        Systemd=lambda: SimpleNamespace(cores=lambda: [dict(pid=42)])
    )
    with pytest.raises(AssertionError, match="no running core"):
        instance.begin("normal-four")


def test_root_original_is_retained_before_manager_property_failure(monkeypatch):
    instance = object.__new__(lab.CloseReceiptLab)
    raw = b"original malformed custody remains evidence\n"
    metadata = dict(
        device=1,
        inode=10,
        owner_uid=0,
        mode=stat.S_IFREG | 0o600,
        nlink=1,
        size=len(raw),
        mtime_ns=2,
        ctime_ns=3,
    )
    context = dict(
        path=Path("/fixed/root-sink"),
        controller=dict(
            root_custody=dict(
                prepared=dict(metadata, size=0), after=None, bytes=None, sha256=None
            )
        ),
        files={},
    )
    instance.contexts = {"normal-four": context}
    monkeypatch.setattr(lab, "stable_read", lambda *args: (raw, dict(object=metadata)))

    def unavailable_manager(context):
        raise ValueError("typed manager property unavailable")

    monkeypatch.setattr(instance, "invocation", unavailable_manager)
    with pytest.raises(ValueError, match="manager property"):
        instance.stopped("normal-four")
    assert context["files"]["root-custody.raw"] == raw
    assert context["controller"]["root_custody"]["sha256"] == lab.accounting.sha256(raw)


def test_over_budget_descriptor_inventory_is_unknown_not_complete(monkeypatch):
    monkeypatch.setattr(
        Path, "iterdir", lambda path: [Path(str(n)) for n in range(257)]
    )
    result = lab.descriptor_inventory(dict(pid=10, start_ticks=20))
    assert result["complete"] is False and result["entries"] == []
    assert result["errors"] == [
        dict(fd=None, error="descriptor inventory exceeds bound")
    ]


def test_annex_rejection_appends_failure_without_overwriting_originals(tmp_path):
    from types import SimpleNamespace

    instance = object.__new__(lab.CloseReceiptLab)

    def write(path, raw):
        with path.open("xb") as stream:
            stream.write(raw)

    instance.g = SimpleNamespace(BASE=tmp_path, write=write)
    instance.contexts = {}
    for case, accepted in (("normal-four", True), ("restart-one", False)):
        directory = tmp_path / "native-close-receipts-public" / case
        directory.mkdir(parents=True)
        write(directory / "evaluation.json", b"original evaluation\n")
        write(directory / "source-after.raw", b"original public fixture\n")
        instance.contexts[case] = dict(
            exported=True, analysis_accepted=accepted, files={}
        )
    instance.retain_failures(AssertionError("annex predicate rejected"))
    accepted = tmp_path / "native-close-receipts-public/normal-four"
    rejected = tmp_path / "native-close-receipts-public/restart-one"
    assert not (accepted / "failure.json").exists()
    assert (
        json.loads((rejected / "failure.json").read_bytes())["message"]
        == "annex predicate rejected"
    )
    assert (rejected / "evaluation.json").read_bytes() == b"original evaluation\n"
    assert (rejected / "source-after.raw").read_bytes() == b"original public fixture\n"


def test_journal_record_limit_is_explicit_instead_of_silent_tail_selection(monkeypatch):
    from types import SimpleNamespace

    instance = object.__new__(lab.CloseReceiptLab)
    metadata = dict(
        device=1,
        inode=10,
        owner_uid=0,
        mode=stat.S_IFREG | 0o600,
        nlink=1,
        size=0,
        mtime_ns=2,
        ctime_ns=3,
    )
    context = dict(
        path=Path("/fixed/root-sink"),
        controller=dict(
            root_custody=dict(prepared=metadata),
            invocation=dict(active_state="inactive", invocation_id="a" * 32),
            error=None,
        ),
        files={},
    )
    instance.contexts = {"normal-four": context}
    commands = []

    def command(*args):
        commands.append(args)
        return SimpleNamespace(stdout="{}\n" * 161)

    instance.g = SimpleNamespace(command=command)
    monkeypatch.setattr(lab, "stable_read", lambda *args: (b"", dict(object=metadata)))
    monkeypatch.setattr(instance, "invocation", lambda context: None)
    instance.stopped("normal-four")
    assert "--lines=161" in commands[0]
    assert context["files"]["launcher-journal.raw"] == b"{}\n" * 160
    assert context["controller"]["error"]["type"] == "DiagnosticTruncated"
    assert "record_limit160=True" in context["controller"]["error"]["message"]


def preparation(monkeypatch, *, refusal=False, fault=None):
    from types import SimpleNamespace
    from azazel_edge.outcome import input_auth

    calls = []
    mode = "managed_prelaunch_refusal" if refusal else "live_parent_and_children"
    instance = object.__new__(lab.CloseReceiptLab)
    instance.cases = {"case": dict(custody_mode=mode)}
    files = {
        "root-custody.raw": b"raw",
        "launcher-systemd.json": b"wait",
        **{
            name + "-" + phase + ".raw": b"raw"
            for name in ("source", "anchors", "journal")
            for phase in ("before", "after")
        },
    }
    instance.contexts = {
        "previous": dict(
            exported=True,
            analysis_accepted=True,
            files=files,
            controller=dict(invocation=dict(exec_main_exit_monotonic_us=10)),
        )
    }
    if fault == "unarchived":
        instance.contexts["previous"]["exported"] = False
    elif fault == "unaccepted":
        instance.contexts["previous"]["analysis_accepted"] = False
    elif fault == "missing_snapshot":
        del files["journal-after.raw"]
    elif fault == "missing_wait":
        instance.contexts["previous"]["controller"]["invocation"][
            "exec_main_exit_monotonic_us"
        ] = 0
    saved = deepcopy(instance.contexts)

    def cores():
        calls.append("cores")
        return [dict(pid=99)] if fault == "running_core" else []

    def snapshot():
        calls.append("manager")
        return dict(ActiveState="active" if fault == "active" else "failed")

    def systemctl(*args):
        calls.append(args)

    def record(*args, **kwargs):
        calls.append(("record", args, kwargs))

    instance.g = SimpleNamespace(
        Systemd=lambda: SimpleNamespace(cores=cores, snapshot=snapshot),
        fixture=lambda: SimpleNamespace(p="public-policy"),
        source=lambda: b"signed fixture",
        systemctl=systemctl,
        record=record,
        UNIT="fixed-owned-lab.service",
    )

    class Verifier:
        def __init__(self, policy):
            assert policy == "public-policy"
            self.live_state = SimpleNamespace(
                closed=(refusal if fault == "wrong_closure" else not refusal),
                session="b" * 32 if fault == "wrong_session" else "a" * 32,
            )

        def verify(self, raw):
            calls.append("verify_source")
            assert raw == b"signed fixture"
            return dict(seq=3, head="f" * 64, size=14, sha256="e" * 64)

    monkeypatch.setattr(input_auth, "SourceVerifier", Verifier)
    return instance, calls, saved


@pytest.mark.parametrize("refusal", [False, True])
def test_case_preparation_guards_then_resets_counter_exactly_once(monkeypatch, refusal):
    instance, calls, saved = preparation(monkeypatch, refusal=refusal)
    instance.prepare_case_start("case", previous_session="a" * 32 if refusal else None)
    assert calls[:3] == ["cores", "manager", "verify_source"]
    assert calls[3] == ("reset-failed", "fixed-owned-lab.service")
    assert calls[4][0] == "record" and len(calls) == 5
    assert calls[4][2]["expected_source_closed"] is (not refusal)
    assert instance.contexts == saved


@pytest.mark.parametrize(
    "fault,refusal",
    [
        ("running_core", False),
        ("active", False),
        ("unarchived", False),
        ("unaccepted", False),
        ("missing_snapshot", False),
        ("missing_wait", False),
        ("wrong_closure", False),
        ("wrong_closure", True),
        ("wrong_session", True),
    ],
)
def test_failed_preparation_guard_never_resets_or_records_success(
    monkeypatch, fault, refusal
):
    instance, calls, saved = preparation(monkeypatch, refusal=refusal, fault=fault)
    with pytest.raises(AssertionError):
        instance.prepare_case_start(
            "case", previous_session="a" * 32 if refusal else None
        )
    assert not any(isinstance(call, tuple) for call in calls)
    assert instance.contexts == saved


@pytest.mark.parametrize("write_allowed", [False, True])
def test_fixed_native_policy_helper_probes_read_and_write_without_writing(
    monkeypatch, capsys, write_allowed
):
    from types import SimpleNamespace

    sink = "normal-four-" + "a" * 32 + ".raw"
    monkeypatch.setattr(sys, "argv", ["native_probe.py", "--close-sink-name", sink])
    monkeypatch.setattr(
        ctypes,
        "CDLL",
        lambda *args, **kwargs: SimpleNamespace(aa_change_profile=lambda profile: 0),
    )
    original_read_text = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *args, **kwargs: "edge400-native (enforce)\n"
        if str(path) == "/proc/self/attr/apparmor/current"
        else original_read_text(path, *args, **kwargs),
    )
    opened, closed = [], []

    def open_sink(path, flags):
        assert path == Path("/var/lib/edge400-systemd-lab/close-custody") / sink
        opened.append(flags)
        if flags == os.O_WRONLY | os.O_APPEND and write_allowed:
            return 123
        raise PermissionError(errno.EACCES, "mock policy denial")

    monkeypatch.setattr(os, "open", open_sink)
    monkeypatch.setattr(os, "close", lambda fd: closed.append(fd))
    if write_allowed:
        with pytest.raises(AssertionError, match="write unexpectedly allowed"):
            runpy.run_path(str(REAL_SYSTEMD / "native_probe.py"), run_name="__main__")
        assert closed == [123]
    else:
        with pytest.raises(SystemExit) as stopped:
            runpy.run_path(str(REAL_SYSTEMD / "native_probe.py"), run_name="__main__")
        assert stopped.value.code == 0
        assert (
            "root-exclusive-sink-write" in json.loads(capsys.readouterr().out)["denied"]
        )
    assert opened == [os.O_RDONLY, os.O_WRONLY | os.O_APPEND]
