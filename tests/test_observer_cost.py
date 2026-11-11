"""Unit coverage for minimized process metrics and strict decision comparison."""

import copy

import pytest
from observer_cost_helpers import (
    process_sample,
    process_summary,
    semantics,
    store_bytes,
    NORMALIZED,
    DEFENSE,
    ENFORCEMENT,
    STATUS,
)


def row(sid=1):
    value = dict(pipeline="rust_event_engine_v1", source="suricata_eve")
    for name, keys in [
        ("normalized", NORMALIZED),
        ("defense", DEFENSE),
        ("enforcement", ENFORCEMENT),
        ("enforcement_status", STATUS),
    ]:
        value[name] = dict.fromkeys(keys, "fixed")
    value["normalized"]["sid"] = sid
    value["enforcement_status"].update(enforce_enabled=False, dry_run=True)
    return value


@pytest.mark.parametrize("rows", [[], [row(), row()], [row(2), row(1)]])
def test_exact_coverage_cannot_be_replaced_by_nonempty_transcript(rows):
    with pytest.raises(ValueError):
        semantics(rows, [1])


@pytest.mark.parametrize(
    "field",
    [
        "failed_count",
        "errors",
        "result",
        "selected_action",
        "command_plan",
        "rollback_plan",
    ],
)
def test_parity_keeps_failed_action_semantics(field):
    before = row()
    after = copy.deepcopy(before)
    after["enforcement"][field] = "changed"
    assert semantics([before], [1]) != semantics([after], [1])


def test_only_declared_variable_fields_are_excluded():
    a = row()
    b = copy.deepcopy(a)
    a["normalized"]["ts"] = "before"
    b["normalized"]["ts"] = "after"
    a["enforcement"]["trace_id"] = "one"
    b["enforcement"]["trace_id"] = "two"
    assert semantics([a], [1]) == semantics([b], [1])
    b["enforcement_status"]["enforce_enabled"] = True
    with pytest.raises(ValueError):
        semantics([b], [1])


def proc(tmp_path, *, start=987, ticks=12):
    folder = tmp_path / "123"
    folder.mkdir(exist_ok=True)
    fields = ["0"] * 30
    fields[0] = "S"
    fields[11] = str(ticks)
    fields[12] = "4"
    fields[19] = str(start)
    (folder / "stat").write_text("123 (name with ) parenthesis) " + " ".join(fields))
    (folder / "status").write_text("VmRSS:\t12 kB\nVmHWM:\t20 kB\n")
    (folder / "io").write_text("read_bytes: 100\nwrite_bytes: 200\n")
    return folder


def test_ticks_rss_hwm_io_and_missing_or_reused_pid(tmp_path):
    folder = proc(tmp_path)
    a = process_sample(123, proc_root=tmp_path)
    assert (
        a["available"]
        and a["cpu_ticks"] == 16
        and a["rss_kib"] == 12
        and a["kernel_hwm_kib"] == 20
    )
    proc(tmp_path, ticks=32)
    b = process_sample(123, expected_start=a["start_ticks"], proc_root=tmp_path)
    summary = process_summary([a, b], 100)
    assert summary["cpu_seconds"] == 0.2
    assert summary["sampled_peak_rss_kib"] == 12 and summary["kernel_hwm_kib"] == 20
    proc(tmp_path, start=988)
    absent = process_sample(123, expected_start=987, proc_root=tmp_path)
    assert not absent["available"] and absent["rss_kib"] is None
    assert absent["start_ticks"] == 987
    assert process_summary([a, absent], 100)["cpu_seconds"] is None
    (folder / "stat").unlink()
    assert (
        process_sample(123, expected_start=987, proc_root=tmp_path)["cpu_ticks"] is None
    )


def test_store_size_is_logical_and_unsafe_entries_are_unavailable(tmp_path):
    (tmp_path / "data").write_bytes(b"123")
    assert store_bytes(tmp_path) == 3
    (tmp_path / "link").symlink_to(tmp_path / "data")
    assert store_bytes(tmp_path) is None


@pytest.mark.parametrize("code", [0, 1, -9, -15])
def test_unexpected_observer_death_cannot_pass_full_cursor_gate(monkeypatch, code):
    from types import SimpleNamespace
    import run_observer_cost as lab

    monkeypatch.setattr(lab, "cursors", lambda f: [{}] * 5)
    dead = SimpleNamespace(poll=lambda: code)
    with pytest.raises(RuntimeError, match="observer exited"):
        lab.wait_observer(dead, object(), 5)
    with pytest.raises(RuntimeError, match="process state"):
        lab.require_observer(dead, object(), 5)


@pytest.mark.parametrize("code,count", [(-15, 3), (0, 3), (None, 3), (-9, 2), (-9, 4)])
def test_fault_arm_requires_exact_kill_and_exact_prefix(monkeypatch, code, count):
    from types import SimpleNamespace
    import run_observer_cost as lab

    monkeypatch.setattr(lab, "cursors", lambda f: [{}] * count)
    with pytest.raises(RuntimeError):
        lab.require_observer(
            SimpleNamespace(poll=lambda: code), object(), 3, exit_code=-9
        )


def test_death_between_readiness_and_acceptance_cannot_pass(monkeypatch):
    from types import SimpleNamespace
    import run_observer_cost as lab

    states = iter([None, 0])
    monkeypatch.setattr(lab, "cursors", lambda f: [{}] * 5)
    with pytest.raises(RuntimeError, match="process state"):
        lab.wait_observer(SimpleNamespace(poll=lambda: next(states)), object(), 5)


def test_cleanup_reaches_launcher_reap_pipes_logs_and_witness_after_failures(
    monkeypatch,
):
    from types import SimpleNamespace
    import run_observer_cost as lab

    calls = []

    def fail(name):
        calls.append(name)
        raise TimeoutError(name)

    observer = SimpleNamespace(
        poll=lambda: None,
        kill=lambda: calls.append("observer-kill"),
        wait=lambda **k: fail("observer-wait"),
    )
    pipe = SimpleNamespace(close=lambda: calls.append("launcher-pipe-close"))
    process = SimpleNamespace(
        poll=lambda: None,
        kill=lambda: calls.append("launcher-kill"),
        wait=lambda **k: calls.append("launcher-reap"),
        stdout=pipe,
    )
    launcher = SimpleNamespace(process=process, close=lambda: fail("launcher-close"))
    log = SimpleNamespace(close=lambda: fail("log-close"))
    witness = SimpleNamespace(halt=lambda: calls.append("witness-halt"))
    monkeypatch.setattr(lab, "children", lambda run: [])
    errors = lab._cleanup(witness, launcher, observer, [log])
    assert len(errors) == 3
    assert calls == [
        "observer-kill",
        "observer-wait",
        "launcher-close",
        "launcher-kill",
        "launcher-reap",
        "launcher-reap",
        "launcher-pipe-close",
        "log-close",
        "witness-halt",
    ]


@pytest.mark.parametrize("mismatch", ["input_sha256", "semantic_sha256"])
def test_cross_arm_failure_retains_all_original_fixtures(
    tmp_path, monkeypatch, mismatch
):
    from types import SimpleNamespace
    import run_observer_cost as lab

    original = []
    cleaned = []

    def fake_arm(mode, *, fixtures):
        path = tmp_path / mode
        path.write_bytes(mode.encode())
        original.append(path)
        fixtures.append(SimpleNamespace(clean=lambda: cleaned.append(mode)))
        row = dict(input_sha256="same", semantic_sha256="same")
        if mode == "faulted":
            row[mismatch] = "changed"
        return row

    monkeypatch.setattr(lab.sys, "platform", "linux")
    monkeypatch.setattr(lab.os, "geteuid", lambda: 0)
    monkeypatch.setattr(lab, "arm", fake_arm)
    with pytest.raises(RuntimeError, match="changed exact"):
        lab.run(keep=False)
    assert cleaned == [] and len(original) == 3
    assert all(path.read_bytes() == path.name.encode() for path in original)


def test_success_defers_fixture_cleanup_until_all_arms_verified(monkeypatch):
    from types import SimpleNamespace
    import run_observer_cost as lab

    calls = []

    def fake_arm(mode, *, fixtures):
        calls.append(mode)
        fixtures.append(SimpleNamespace(clean=lambda: calls.append("clean-" + mode)))
        return dict(input_sha256="same", semantic_sha256="same")

    monkeypatch.setattr(lab.sys, "platform", "linux")
    monkeypatch.setattr(lab.os, "geteuid", lambda: 0)
    monkeypatch.setattr(lab, "arm", fake_arm)
    lab.run(keep=False)
    assert calls == ["off", "on", "faulted", "clean-off", "clean-on", "clean-faulted"]
