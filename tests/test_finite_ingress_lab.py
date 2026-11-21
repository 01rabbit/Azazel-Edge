"""Recipe/mocked readiness and local FD helpers; no native capture trial."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
from types import SimpleNamespace

import pytest

REAL_SYSTEMD = Path(__file__).parent / "real_systemd"
sys.path.insert(0, str(REAL_SYSTEMD))
SPEC = importlib.util.spec_from_file_location(
    "finite_ingress_lab_under_test", REAL_SYSTEMD / "finite_ingress.py"
)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)
PROTOCOL = json.loads((REAL_SYSTEMD / lab.PROTOCOL_NAME).read_bytes())


@pytest.mark.parametrize("case", PROTOCOL["cases"], ids=lambda case: case["case_id"])
def test_frozen_recipes_match_intended_pins_without_claiming_actual_population(case):
    raw = lab.materialize(case["recipe"], PROTOCOL["alert_template"])
    pin = case["recipe_intended_pin"]
    assert len(raw) == pin["bytes"] and lab.accounting.sha256(raw) == pin["sha256"]
    assert raw.count(b"\n") == pin["lf_records"]
    assert len(raw.rsplit(b"\n", 1)[-1]) == pin["tail_bytes"]
    assert PROTOCOL["intended_pins_are_measured_denominator"] is False


def test_same_length_overwrite_recipe_differs_and_truncation_is_strictly_shorter():
    cases = {case["case_id"]: case for case in PROTOCOL["cases"]}
    for name, same_length in (
        ("ingress-same-inode-overwrite", True),
        ("ingress-truncate", False),
    ):
        case = cases[name]
        before = lab.materialize(case["recipe"], PROTOCOL["alert_template"])
        after = lab.materialize(
            case["mutation"]["replacement_recipe"], PROTOCOL["alert_template"]
        )
        assert before != after
        assert (len(before) == len(after)) is same_length
        if not same_length:
            assert len(after) < len(before)


def test_readonly_held_snapshot_uses_original_fd_without_changing_offset(tmp_path):
    path = tmp_path / "raw-fixture"
    path.write_bytes(b"actual raw fixture\n")
    fd = os.open(path, os.O_RDONLY)
    try:
        os.lseek(fd, 3, os.SEEK_SET)
        raw, snapshot = lab.snapshot_fd(fd, 100)
        assert raw == path.read_bytes()
        assert os.lseek(fd, 0, os.SEEK_CUR) == 3
        assert snapshot["fd"] == fd and snapshot["flags"] & os.O_ACCMODE == os.O_RDONLY
        assert snapshot["before"] == snapshot["after"]
        assert snapshot["sha256"] == lab.accounting.sha256(raw)
    finally:
        os.close(fd)


def test_snapshot_rejects_writable_descriptor_and_oversize_input(tmp_path):
    path = tmp_path / "raw-fixture"
    path.write_bytes(b"too large\n")
    fd = os.open(path, os.O_RDWR)
    try:
        with pytest.raises(AssertionError):
            lab.snapshot_fd(fd, 100)
    finally:
        os.close(fd)
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(AssertionError):
            lab.snapshot_fd(fd, 2)
    finally:
        os.close(fd)


def test_writer_records_actual_append_join_and_readback(tmp_path):
    path = tmp_path / "raw-fixture"
    path.write_bytes(b"")
    fd = os.open(path, os.O_RDONLY)
    instance = object.__new__(lab.FiniteIngressLab)
    instance.g = SimpleNamespace(ENV={"AZAZEL_EVE_PATH": str(path)})
    context = dict(
        eve_fd=fd,
        files={},
        ingress=dict(
            held_fd=dict(
                object=lab.accounting.source_metadata(os.fstat(fd), detailed=True)
            ),
            writer=[],
            snapshots=dict.fromkeys(lab.RAW_NAMES),
            errors=[],
        ),
    )
    try:
        raw = b"actual finite append\n"
        receipt = instance.append(context, raw, "initial")
        assert receipt["joined"] is True and receipt["fsync_completed"] is True
        assert receipt["written_bytes"] == len(raw) == receipt["requested_bytes"]
        assert receipt["offset_after"] - receipt["offset_before"] == len(raw)
        assert (
            receipt["flags"] & os.O_APPEND
            and receipt["flags"] & os.O_ACCMODE == os.O_WRONLY
        )
        assert context["files"]["eve-after-writer.raw"] == raw
    finally:
        os.close(fd)


@pytest.mark.parametrize("poll_fd_open", [False, True])
def test_pressure_pause_checks_existing_fd_once_without_retry(
    monkeypatch, poll_fd_open
):
    instance = object.__new__(lab.FiniteIngressLab)
    calls = []

    def signal_owned(context, signum, stopped):
        calls.append((signum, stopped))
        return dict(signal=signum)

    monkeypatch.setattr(instance, "signal_owned", signal_owned)
    monkeypatch.setattr(
        lab,
        "descriptor_inventory",
        lambda actor: dict(
            complete=True, entries=[dict(device=1, inode=2)] if poll_fd_open else []
        ),
    )
    context = dict(
        controller=dict(actors=dict(native=dict(pid=10))),
        ingress=dict(held_fd=dict(object=dict(device=1, inode=2))),
    )
    if poll_fd_open:
        with pytest.raises(AssertionError, match="no re-pause/retry"):
            instance.prepare_pressure(context)
    else:
        assert instance.prepare_pressure(context) == dict(signal=signal.SIGSTOP)
    assert calls == [(signal.SIGSTOP, True)]


def test_duplicate_sid_readiness_requires_second_signed_actual_span(monkeypatch):
    from azazel_edge.outcome import input_auth

    session = "a" * 32

    def wire(start, end):
        return dict(
            event=dict(
                capture_origin=dict(session_ref=session),
                normalized=dict(sid=90231301),
                ingress_origin=dict(
                    range_ref=session, start_offset=start, end_offset=end
                ),
            )
        )

    one = json.dumps(wire(0, 232)).encode() + b"\n"
    two = one + json.dumps(wire(232, 464)).encode() + b"\n"
    reads = iter((one, two))
    monkeypatch.setattr(lab, "stable_read", lambda *args: (next(reads), {}))

    class Verifier:
        def __init__(self, policy):
            pass

        def verify(self, raw):
            return dict(
                seq=len(raw.splitlines()),
                head="f" * 64,
                size=len(raw),
                sha256=lab.accounting.sha256(raw),
            )

    monkeypatch.setattr(input_auth, "SourceVerifier", Verifier)
    attempts = []

    def wait_for(operation):
        attempts.append(operation())
        assert attempts[-1] is False
        attempts.append(operation())
        assert attempts[-1] is True

    instance = object.__new__(lab.FiniteIngressLab)
    instance.g = SimpleNamespace(
        BUNDLE=Path("/synthetic"),
        fixture=lambda: SimpleNamespace(p="synthetic-policy"),
        wait_for=wait_for,
    )
    context = dict(
        controller=dict(session_ref=session), ingress=dict(range_ref=None, markers=[])
    )
    instance.source_marker(context, dict(sid=90231301, occurrence=2), 464)
    assert attempts == [False, True]
    assert context["ingress"]["markers"][0]["ingress_origin"]["start_offset"] == 232


def test_input_reset_refuses_unclosed_source_before_open(monkeypatch):
    instance = object.__new__(lab.FiniteIngressLab)
    instance.g = SimpleNamespace(
        Systemd=lambda: SimpleNamespace(
            cores=lambda: [], snapshot=lambda: dict(ActiveState="failed")
        ),
        source_closed=lambda: False,
    )
    monkeypatch.setattr(
        os, "open", lambda *args: pytest.fail("must not open/reset input")
    )
    with pytest.raises(AssertionError, match="unclosed Source"):
        instance.reset_input()


def test_failed_proc_lookup_and_stop_still_retain_original_failure(monkeypatch):
    instance = object.__new__(lab.FiniteIngressLab)
    instance.contexts = {
        "case": dict(
            exported=False,
            controller=dict(actors=dict(native=dict(pid=10, start_ticks=20))),
            ingress=dict(errors=[]),
        )
    }
    calls = []

    def unavailable_actor(pid):
        raise FileNotFoundError("process already exited")

    def manager(*args, **kwargs):
        calls.append(args)
        raise OSError("manager unavailable")

    monkeypatch.setattr(lab.accounting, "actor", unavailable_actor)
    instance.g = SimpleNamespace(
        UNIT="owned-core", WITNESS="owned-witness", systemctl=manager
    )
    retained = []
    monkeypatch.setattr(
        instance, "retain_failures", lambda original: retained.append(original)
    )
    original = AssertionError("original experiment failure")
    instance.teardown_failure(original)
    assert retained == [original]
    assert calls == [("disable", "owned-core"), ("stop", "owned-core", "owned-witness")]
    assert [
        entry["stage"] for entry in instance.contexts["case"]["ingress"]["errors"]
    ] == ["teardown-resume", "teardown-manager", "teardown-manager"]
