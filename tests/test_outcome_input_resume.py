"""Observable byte continuity, durable position and honest restart losses."""

from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from azazel_edge.outcome.input_cursor import BoundedInput, EMPTY_SHA, MAX_LINE_BYTES
from azazel_edge.outcome.input_resume import recover_input, observe_input, miss_record
from azazel_edge.outcome.journal import ObservationJournal, OutcomeJournalError, NAME
from azazel_edge.outcome.telemetry import OutcomeTelemetryCollector, persistence_context
from test_outcome_telemetry_g3 import FakeSource, policy, rust_event

ROOT = Path(__file__).resolve().parents[1]
META = dict(decision_id="new", execution_id="new", objective_id="new")
ZERO = dict(offset=0, sha256=EMPTY_SHA)


def setup(tmp_path):
    folder = (tmp_path / "journal").resolve()
    folder.mkdir(mode=0o700)
    path = (tmp_path / "input").resolve()
    path.touch(mode=0o600)
    return folder, path


def open_j(folder, source, create=False, boot="boot-a", **extra):
    return ObservationJournal(
        folder,
        scope_ref="scope-a",
        policy_ref=persistence_context(policy(), "br0"),
        boot_id=boot,
        create=create,
        input_source=source,
        **extra
    )


def event(trace="a", epoch=110):
    return rust_event(
        ts=datetime.fromtimestamp(epoch, timezone.utc).isoformat(), trace=trace
    )


def append(path, value):
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    with path.open("ab") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return raw


def line_for(source, j):
    return next(source.lines(j.input_position(), source.snapshot(j.input_position())))


def collector(j):
    return OutcomeTelemetryCollector(
        source=FakeSource(), policy=policy(), interface="br0", persistence=j
    )


def test_cursor_synced_after_durable_begin_before_emission(tmp_path):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        assert not j.begin_window(**META)
        recover_input(j, policy())
        c = collector(j)
        raw = append(path, event())
        line = line_for(source, j)
        kinds = []
        real = os.fsync

        def synced(fd):
            real(fd)
            kinds.append(
                json.loads((folder / NAME).read_bytes().splitlines()[-1])["kind"]
            )

        with patch("os.fsync", synced):
            observe_input(line, j, c, live_floor=100, now=110)
        assert kinds == ["begin", "cursor"] and len(c.pending) == 1
        assert j.input_position() == dict(
            offset=len(raw), sha256=hashlib.sha256(raw).hexdigest()
        )
        result = c.finalize_due(epoch=114)
        assert len(result) == 1 and j.status()["committed"] == 1
    with BoundedInput(path) as source, open_j(folder, source, boot="boot-b") as j:
        recover_input(j, policy())
        assert (
            len(j.retained_outcomes()) == 1 and not j.status()["new_admission_closed"]
        )
        assert (
            j.status()["input_records"] == 1 and j.status()["missed_input_records"] == 0
        )


def test_clean_restart_backlog_is_loss_not_baseline_and_duplicate_cannot_reopen(
    tmp_path,
):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
    append(path, event("missed", 110))
    with BoundedInput(path) as source, open_j(folder, source, boot="boot-b") as j:
        assert j.status()["input_recovery_pending"]
        recover_input(j, policy())
        c = collector(j)
        assert j.status()["lost"] == 1 and j.status()["missed_input_records"] == 1
        assert not c.samples and not c.activity and not c.pending
        # Even a newly dated copy cannot reopen the missed execution identity.
        append(path, event("missed", 210))
        observe_input(line_for(source, j), j, c, live_floor=200, now=210)
        assert not c.pending and c.finalize_due(epoch=214) == ()
        assert not c.activity  # Re-dated loss cannot contaminate a new baseline.
        append(path, event("new", 211))
        observe_input(line_for(source, j), j, c, live_floor=200, now=211)
        assert len(c.finalize_due(epoch=215)) == 1
        assert j.status()["lost"] == 1 and j.status()["committed"] == 1


CHILD = """
import sys,json,os
from pathlib import Path
from test_outcome_input_resume import open_j,event,append,collector,line_for
from test_outcome_telemetry_g3 import policy
from azazel_edge.outcome.input_cursor import BoundedInput
from azazel_edge.outcome.input_resume import recover_input,observe_input,miss_record
folder=Path(sys.argv[1]);path=Path(sys.argv[2]);phase=sys.argv[3]
source=BoundedInput(path);j=open_j(folder,source,True);recover_input(j,policy());c=collector(j)
append(path,event('killed',110))
if phase=='begun':c.observe_event(event('killed',110),observed_epoch=110)
if phase in ('position','committed'):observe_input(line_for(source,j),j,c,live_floor=100,now=110)
if phase=='committed':c.finalize_due(epoch=114)
if phase=='recovery':
 j.close();append(path,event('second',111));j=open_j(folder,source);miss_record(line_for(source,j),j,policy())
print('durable',flush=True);sys.stdin.read()
"""


@pytest.mark.parametrize(
    "phase", ["unclaimed", "begun", "position", "committed", "recovery"]
)
def test_real_sigkill_resumes_only_verified_input_never_missing_windows(
    tmp_path, phase
):
    folder, path = setup(tmp_path)
    env = dict(
        os.environ,
        PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py") + ":" + str(ROOT / "tests"),
    )
    with subprocess.Popen(
        [sys.executable, "-c", CHILD, str(folder), str(path), phase],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as child:
        assert child.stdout.readline().strip() == "durable"
        with BoundedInput(path) as source:
            with pytest.raises(OSError):
                open_j(folder, source)
        child.kill()
        child.wait(timeout=10)
    with BoundedInput(path) as source, open_j(folder, source, boot="boot-b") as j:
        assert j.status()["unclean_recovery"] and j.status()["input_recovery_pending"]
        assert not j.begin_window(**META)
        recover_input(j, policy())
        assert not j.status()["new_admission_closed"]
        assert not j.status()["input_recovery_pending"]
        assert j.status()["lost"] == (
            0 if phase == "committed" else 2 if phase == "recovery" else 1
        )
        assert len(j.retained_outcomes()) == (phase == "committed")
        assert j.input_position()["offset"] == path.stat().st_size
        append(path, event("after-restart", 210))
        c = collector(j)
        observe_input(line_for(source, j), j, c, live_floor=200, now=210)
        assert len(c.finalize_due(epoch=214)) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "rewrite",
        "truncate",
        "replace",
        "partial",
        "missing",
        "mode",
        "symlink",
        "hardlink",
        "fifo",
        "budget",
        "path",
    ],
)
def test_bad_continuity_refuses_recovery_without_mutating_journal(tmp_path, fault):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
        append(path, event())
        observe_input(line_for(source, j), j, collector(j), live_floor=100, now=110)
    before = (folder / NAME).read_bytes()
    kwargs = {}
    if fault == "rewrite":
        path.write_bytes(path.read_bytes().replace(b"10.0.0.8", b"10.0.0.9"))
    elif fault == "truncate":
        path.write_bytes(b"")
    elif fault == "replace":
        raw = path.read_bytes()
        path.rename(tmp_path / "old")
        path.write_bytes(raw)
    elif fault == "partial":
        with path.open("ab") as stream:
            stream.write(b'{"incomplete":')
    elif fault == "missing":
        path.unlink()
    elif fault == "mode":
        path.chmod(0o666)
    elif fault == "symlink":
        path.rename(tmp_path / "old")
        path.symlink_to(tmp_path / "old")
    elif fault == "hardlink":
        os.link(path, tmp_path / "link")
    elif fault == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    elif fault == "budget":
        kwargs["max_records"] = 1
    else:
        changed = (tmp_path / "moved").resolve()
        path.rename(changed)
        path = changed
    with pytest.raises(OSError):
        with BoundedInput(path, **kwargs) as source:
            open_j(folder, source)
    assert (folder / NAME).read_bytes() == before


def test_nonempty_initialization_and_v1_migration_are_refused(tmp_path):
    folder, path = setup(tmp_path)
    append(path, event())
    with BoundedInput(path) as source:
        with pytest.raises(OSError):
            open_j(folder, source, True)
    assert list(folder.iterdir()) == []
    path.write_bytes(b"")
    with ObservationJournal(
        folder,
        scope_ref="scope-a",
        policy_ref=persistence_context(policy(), "br0"),
        boot_id="boot-a",
        create=True,
    ):
        pass
    before = (folder / NAME).read_bytes()
    with BoundedInput(path) as source:
        with pytest.raises(OSError):
            open_j(folder, source)
    assert (folder / NAME).read_bytes() == before


@pytest.mark.parametrize("failure", ["write", "sync", "torn"])
def test_cursor_failure_never_advances_volatile_position_or_refills_window(
    tmp_path, failure
):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
        c = collector(j)
        append(path, event())
        line = line_for(source, j)
        real_write = os.write
        real_sync = os.fsync

        def write(fd, data):
            if json.loads(bytes(data))["kind"] == "cursor":
                if failure == "torn":
                    real_write(fd, data[:9])
                if failure != "sync":
                    raise OSError(errno.ENOSPC, "injected cursor write failure")
            return real_write(fd, data)

        def sync(fd):
            if (
                failure == "sync"
                and json.loads((folder / NAME).read_bytes().splitlines()[-1])["kind"]
                == "cursor"
            ):
                raise OSError(errno.EIO, "cursor sync failure")
            real_sync(fd)

        with patch("os.write", write), patch("os.fsync", sync):
            with pytest.raises(OSError):
                observe_input(line, j, c, live_floor=100, now=110)
        assert j.status()["input_position"] == ZERO
        assert not j.status()["continuity_available"]
        with pytest.raises(OSError):
            j.retained_outcomes()
        with patch("os.write", side_effect=AssertionError("no retries")):
            with pytest.raises(OSError):
                j.advance_input(line.position, missed=False)
    before = (folder / NAME).read_bytes()
    with BoundedInput(path) as source:
        if failure == "torn":
            with pytest.raises(OSError):
                open_j(folder, source)
            assert (folder / NAME).read_bytes() == before
        else:
            with open_j(folder, source) as j:
                recover_input(j, policy())
                assert j.status()["lost"] == 1 and not j.retained_outcomes()
                assert j.input_position()["offset"] == path.stat().st_size
                assert not j.status()["new_admission_closed"]


@pytest.mark.parametrize("stamp", [99, 100, 102, 108, 111, "unparseable", "naive"])
def test_stale_future_unclocked_or_unwarmed_input_is_loss(tmp_path, stamp):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
        c = collector(j)
        value = event()
        value["normalized"]["ts"] = (
            "unparseable"
            if stamp == "unparseable"
            else (
                "1970-01-01T00:01:50"
                if stamp == "naive"
                else datetime.fromtimestamp(stamp, timezone.utc).isoformat()
            )
        )
        append(path, value)
        observe_input(line_for(source, j), j, c, live_floor=100, now=110)
        assert j.status()["lost"] == 1 and j.status()["missed_input_records"] == 1
        assert not c.pending and not c.activity and not c.samples
        assert c.finalize_due(epoch=120) == ()


def test_position_cannot_skip_records_or_accept_fabricated_snapshot(tmp_path):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
        append(path, event("one"))
        append(path, event("two"))
        with pytest.raises(OSError):
            next(source.lines(ZERO, b"fake\n"))
        lines = source.lines(ZERO, source.snapshot(ZERO))
        next(lines)
        second = next(lines)
        with pytest.raises(OSError):
            j.advance_input(second.position, missed=True)
        assert j.input_position() == ZERO


def test_partial_live_line_waits_but_oversized_input_and_record_refused(tmp_path):
    folder, path = setup(tmp_path)
    with BoundedInput(path, max_bytes=MAX_LINE_BYTES) as source, open_j(
        folder, source, True
    ) as j:
        recover_input(j, policy())
        path.write_bytes(b"{")
        assert source.snapshot(j.input_position()) == b""
        with pytest.raises(OSError):
            source.snapshot(j.input_position(), require_complete=True)
        path.write_bytes(b"x" * (MAX_LINE_BYTES + 1))
        with pytest.raises(OSError):
            source.snapshot(j.input_position())


def test_input_record_budget_seals_without_eviction(tmp_path):
    folder, path = setup(tmp_path)
    with BoundedInput(path, max_records=1) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
        append(path, event("one"))
        miss_record(line_for(source, j), j, policy())
        assert j.status()["new_admission_closed"]
        assert j.status()["input_records"] == 1 and j.status()["lost"] == 1
    with BoundedInput(path, max_records=1) as source, open_j(folder, source) as j:
        with pytest.raises(OSError):
            recover_input(j, policy())
        assert j.status()["seal_reason"] == "input_capacity"
        assert j.status()["lost"] == 1
    append(path, event("two"))
    with BoundedInput(path, max_records=1) as source:
        with pytest.raises(OSError, match="record budget"):
            source.snapshot(ZERO)


@pytest.mark.parametrize(
    "raw", [b"{}\n", b'{"a":1,"a":2}\n', b"NaN\n", b"[]\n", b"\xff\n"]
)
def test_malformed_unknown_input_never_advances_position(tmp_path, raw):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
        path.write_bytes(raw)
        with pytest.raises(OSError):
            miss_record(line_for(source, j), j, policy())
        assert j.input_position() == ZERO and j.status()["committed"] == 0


def test_foreground_opt_in_samples_only_fresh_segment_and_cleanly_reopens(tmp_path):
    from azazel_edge.outcome import input_resume as driver
    from azazel_edge.outcome import telemetry

    folder, path = setup(tmp_path)
    output = tmp_path / "output"
    clock = {"wall": 100.0, "mono": 0.0}
    polls = []

    def sleep(_):
        polls.append(True)
        clock["wall"] += 1
        clock["mono"] += 1
        if len(polls) == 1:
            append(path, event("stale", 1))
        if len(polls) == 4:
            append(path, event("fresh", 104))
        if len(polls) == 8:
            raise KeyboardInterrupt

    with patch.object(
        driver.OutcomeTelemetryPolicy, "from_file", return_value=policy()
    ), patch.object(driver, "LinuxProcTelemetrySource", FakeSource), patch.object(
        driver.time, "time", lambda: clock["wall"]
    ), patch.object(
        driver.time, "monotonic", lambda: clock["mono"]
    ), patch.object(
        driver.time, "sleep", sleep
    ):
        with pytest.raises(KeyboardInterrupt):
            telemetry.run_live(
                input_path=path,
                output_path=output,
                policy_path=Path("unused"),
                interface="br0",
                journal_directory=folder,
                journal_scope="scope-a",
                journal_boot_id="boot-a",
                initialize_journal=True,
                resume_input=True,
            )
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(rows) == 1 and rows[0]["outcome"]["decision_id"] == "fresh"
    assert rows[0]["outcome"]["causal_support"] == "inconclusive"
    with BoundedInput(path) as source, open_j(folder, source, boot="boot-b") as j:
        assert not j.status()["unclean_recovery"]
        recover_input(j, policy())
        assert j.status()["lost"] == 1 and j.status()["committed"] == 1
        assert (
            j.status()["input_records"] == 2 and j.status()["missed_input_records"] == 1
        )


def test_foreground_clock_jump_withholds_pending_results_and_no_shifted_windows(
    tmp_path,
):
    from azazel_edge.outcome import input_resume as driver
    from azazel_edge.outcome import telemetry

    folder, path = setup(tmp_path)
    output = tmp_path / "output"
    clock = {"wall": 100.0, "mono": 0.0}
    polls = []

    def sleep(_):
        polls.append(True)
        clock["wall"] += 1
        clock["mono"] += 1
        if len(polls) == 4:
            append(path, event("before-jump", 104))
        if len(polls) == 5:
            clock["wall"] += 100
        assert len(polls) < 7

    with patch.object(
        driver.OutcomeTelemetryPolicy, "from_file", return_value=policy()
    ), patch.object(driver, "LinuxProcTelemetrySource", FakeSource), patch.object(
        driver.time, "time", lambda: clock["wall"]
    ), patch.object(
        driver.time, "monotonic", lambda: clock["mono"]
    ), patch.object(
        driver.time, "sleep", sleep
    ):
        with pytest.raises(OSError, match="clock continuity"):
            telemetry.run_live(
                input_path=path,
                output_path=output,
                policy_path=Path("unused"),
                interface="br0",
                journal_directory=folder,
                journal_scope="scope-a",
                journal_boot_id="boot-a",
                initialize_journal=True,
                resume_input=True,
            )
    assert not output.exists()
    with BoundedInput(path) as source, open_j(folder, source) as j:
        recover_input(j, policy())
        assert j.status()["lost"] == 1 and not j.retained_outcomes()


def test_runtime_prefix_change_prevents_result_commit(tmp_path):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
        c = collector(j)
        append(path, event("pending", 110))
        observe_input(line_for(source, j), j, c, live_floor=100, now=110)
        path.write_bytes(path.read_bytes().replace(b"pending", b"changed"))
        with pytest.raises(OSError):
            source.snapshot(j.input_position())
        c.invalidate_pending_windows()
        assert not c.finalize_due(epoch=114) and j.status()["lost"] == 1


def test_cursor_and_loss_operations_have_no_command_or_network_dependency(tmp_path):
    folder, path = setup(tmp_path)
    with patch("socket.socket", side_effect=AssertionError("network forbidden")), patch(
        "subprocess.Popen", side_effect=AssertionError("commands forbidden")
    ):
        with BoundedInput(path) as source, open_j(folder, source, True) as j:
            recover_input(j, policy())
            append(path, event())
            miss_record(line_for(source, j), j, policy())
        with BoundedInput(path) as source, open_j(folder, source) as j:
            recover_input(j, policy())
            assert j.status()["lost"] == 1 and not j.retained_outcomes()


def test_cli_resume_requires_explicit_journal_and_does_not_change_defaults():
    from azazel_edge.outcome import telemetry

    with patch.object(telemetry, "run_live") as live:
        with pytest.raises(SystemExit):
            telemetry.main(["--policy", "unused", "--journal-resume-input"])
        assert not live.called
        telemetry.main(["--policy", "unused"])
        assert live.call_args.kwargs["resume_input"] is False
        telemetry.main(
            [
                "--policy",
                "unused",
                "--journal-directory",
                "/unused",
                "--journal-scope",
                "scope-a",
                "--journal-boot-id",
                "boot-a",
                "--journal-resume-input",
            ]
        )
        assert live.call_args.kwargs["resume_input"] is True


def test_source_symlink_parent_and_relative_path_refused(tmp_path):
    folder, path = setup(tmp_path)
    link = tmp_path / "parent-link"
    link.symlink_to(path.parent, target_is_directory=True)
    with pytest.raises(OSError):
        BoundedInput(link / path.name)
    with pytest.raises(OSError):
        BoundedInput(Path("relative.jsonl"))


def test_foreground_detects_rewritten_prefix_before_due_outcome_commit(tmp_path):
    from azazel_edge.outcome import input_resume as driver
    from azazel_edge.outcome import telemetry

    folder, path = setup(tmp_path)
    output = tmp_path / "output"
    clock = {"wall": 100.0, "mono": 0.0}
    polls = []

    def sleep(_):
        polls.append(True)
        clock["wall"] += 1
        clock["mono"] += 1
        if len(polls) == 4:
            append(path, event("pending", 104))
        if len(polls) == 7:
            path.write_bytes(path.read_bytes().replace(b"pending", b"changed"))
        assert len(polls) < 9

    with patch.object(
        driver.OutcomeTelemetryPolicy, "from_file", return_value=policy()
    ), patch.object(driver, "LinuxProcTelemetrySource", FakeSource), patch.object(
        driver.time, "time", lambda: clock["wall"]
    ), patch.object(
        driver.time, "monotonic", lambda: clock["mono"]
    ), patch.object(
        driver.time, "sleep", sleep
    ):
        with pytest.raises(OSError, match="prefix continuity"):
            telemetry.run_live(
                input_path=path,
                output_path=output,
                policy_path=Path("unused"),
                interface="br0",
                journal_directory=folder,
                journal_scope="scope-a",
                journal_boot_id="boot-a",
                initialize_journal=True,
                resume_input=True,
            )
    frames = [json.loads(line) for line in (folder / NAME).read_bytes().splitlines()]
    assert not output.exists() and not any(f["kind"] == "commit" for f in frames)
    assert sum(f["kind"] == "lost" for f in frames) == 1
    with BoundedInput(path) as source:
        with pytest.raises(OSError):
            open_j(folder, source)


def test_bytes_arriving_during_recovery_are_also_lost_before_fence(tmp_path):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
    append(path, event("first"))
    with BoundedInput(path) as source, open_j(folder, source) as j:
        real = j.advance_input

        def advance(position, *, missed):
            real(position, missed=missed)
            if j.status()["input_records"] == 1:
                append(path, event("arrived-during-recovery"))

        with patch.object(j, "advance_input", advance):
            recover_input(j, policy())
        assert j.status()["lost"] == 2 and j.status()["missed_input_records"] == 2
        assert j.input_position()["offset"] == path.stat().st_size
        assert not j.status()["input_recovery_pending"] and not j.retained_outcomes()


def test_recovery_catchup_is_bounded_and_never_opens_admission_if_busy(tmp_path):
    from azazel_edge.outcome.input_resume import MAX_RECOVERY_PASSES

    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
    append(path, event("first"))
    with BoundedInput(path) as source, open_j(folder, source) as j:
        real = j.advance_input

        def advance(position, *, missed):
            real(position, missed=missed)
            append(path, event("extra-" + str(j.status()["input_records"])))

        with patch.object(j, "advance_input", advance):
            with pytest.raises(OSError, match="bounded startup"):
                recover_input(j, policy())
        assert j.status()["input_records"] == MAX_RECOVERY_PASSES
        assert j.status()["input_recovery_pending"] and not j.begin_window(**META)
        assert not j.retained_outcomes()


def test_superseded_snapshot_iterator_cannot_move_cursor(tmp_path):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
        append(path, event("one"))
        append(path, event("two"))
        lines = source.lines(ZERO, source.snapshot(ZERO))
        miss_record(next(lines), j, policy())
        saved = j.input_position()
        source.snapshot(saved)
        with pytest.raises(OSError, match="superseded"):
            next(lines)
        assert j.input_position() == saved


def test_overflowed_number_in_unused_input_field_still_refuses_cursor(tmp_path):
    folder, path = setup(tmp_path)
    with BoundedInput(path) as source, open_j(folder, source, True) as j:
        recover_input(j, policy())
        raw = json.dumps(event()).replace("{", '{"unused":1e400,', 1).encode() + b"\n"
        path.write_bytes(raw)
        with pytest.raises(OSError):
            miss_record(line_for(source, j), j, policy())
        assert j.input_position() == ZERO and not j.retained_outcomes()
