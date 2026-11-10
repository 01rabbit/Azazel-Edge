"""Durable observation ordering, real process loss and conservative recovery."""

from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from azazel_edge.outcome.journal import (
    ObservationJournal,
    OutcomeJournalError,
    NAME,
    MAX_RECORD_BYTES,
)
from azazel_edge.outcome.telemetry import OutcomeTelemetryCollector, persistence_context
from azazel_edge.outcome.contracts import CausalSupport
from test_outcome_golden_replay_g5 import _outcome
from test_outcome_telemetry_g3 import FakeSource, policy, rust_event

ROOT = Path(__file__).resolve().parents[1]
META = dict(
    decision_id="decision-a", execution_id="execution-a", objective_id="objective-a"
)


def directory(tmp_path, name="scope"):
    p = (tmp_path / name).resolve()
    p.mkdir(mode=0o700)
    p.chmod(0o700)
    return p


def journal(path, create=False, **overrides):
    args = dict(
        scope_ref="scope-a", policy_ref="policy-a", boot_id="boot-a", create=create
    )
    args.update(overrides)
    return ObservationJournal(path, **args)


def test_begin_sync_precedes_collection_commit_sync_precedes_emission(tmp_path):
    p = directory(tmp_path)
    pol = policy()
    ctx = persistence_context(pol, "br0")
    with journal(p, True, policy_ref=ctx) as j:
        c = OutcomeTelemetryCollector(
            source=FakeSource(), policy=pol, interface="br0", persistence=j
        )
        real = os.fsync
        observed = []

        def synced(fd):
            real(fd)
            last = json.loads((p / NAME).read_bytes().splitlines()[-1])
            observed.append(last["kind"])
            if last["kind"] == "begin":
                assert not c.pending

        with patch("os.fsync", synced):
            assert c.observe_event(
                rust_event(ts="2026-01-01T00:00:00Z", trace="journal-a"),
                observed_epoch=100,
            )
            assert observed == ["begin"] and j.status()["pending"] == 1
            records = c.finalize_due(epoch=104)
            assert len(records) == 1 and observed == ["begin", "commit"]
            assert records[0].causal_support is CausalSupport.INCONCLUSIVE
        assert j.retained_outcomes()[0].to_dict() == records[0].to_dict()
    with journal(p, policy_ref=ctx, boot_id="boot-b") as restored:
        c = OutcomeTelemetryCollector(
            source=FakeSource(), policy=pol, interface="br0", persistence=restored
        )
        assert not c.observe_event(
            rust_event(ts="2026-01-01T00:00:00Z", trace="journal-a"), observed_epoch=200
        )
        assert c.finalize_due(epoch=204) == ()
        assert (
            restored.status()["committed"] == 1
            and not restored.status()["new_admission_closed"]
        )


def test_clean_close_loses_pending_never_rebuilds_window(tmp_path):
    p = directory(tmp_path)
    with journal(p, True) as j:
        assert j.begin_window(**META)
    with journal(p, boot_id="boot-b") as j:
        assert j.status()["lost"] == 1 and not j.status()["unclean_recovery"]
        assert not j.begin_window(**META) and not j.commit_outcome(_outcome())
        assert j.retained_outcomes() == ()
        assert j.begin_window(
            decision_id="decision-b",
            execution_id="execution-b",
            objective_id="objective-b",
        )


CHILD = """
import sys
from azazel_edge.outcome.journal import ObservationJournal
from test_outcome_golden_replay_g5 import _outcome
j=ObservationJournal(sys.argv[1],scope_ref='scope-a',policy_ref='policy-a',boot_id='boot-a',create=True)
if sys.argv[2]!='empty':
 j.begin_window(decision_id='decision-a',execution_id='execution-a',objective_id='objective-a')
if sys.argv[2]=='committed':j.commit_outcome(_outcome())
print('durable',flush=True)
sys.stdin.read()
"""


@pytest.mark.parametrize("phase", ["empty", "pending", "committed"])
def test_sigkill_real_process_recovery_preserves_results_and_seals_unknown_tail(
    tmp_path, phase
):
    p = directory(tmp_path)
    env = dict(
        os.environ,
        PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py") + ":" + str(ROOT / "tests"),
    )
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(p), phase],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "durable"
        with pytest.raises(OSError):
            journal(p)  # A separate OS process owns the writer lock.
        child.kill()
        child.wait(timeout=10)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
    with journal(p, boot_id="boot-b") as j:
        assert j.status()["unclean_recovery"] and j.status()["new_admission_closed"]
        assert j.status()["seal_reason"] == "unclean_restart"
        assert j.status()["lost"] == (phase == "pending")
        assert len(j.retained_outcomes()) == (phase == "committed")
        assert not j.begin_window(
            decision_id="decision-new",
            execution_id="execution-new",
            objective_id="objective-new",
        )
        if phase == "committed":
            assert j.retained_outcomes()[0].outcome_id == "outcome-a"
    size = (p / NAME).stat().st_size
    with journal(p, boot_id="boot-c") as j:
        assert j.status()["new_admission_closed"]
    assert (p / NAME).stat().st_size == size


@pytest.mark.parametrize("failure", [errno.ENOSPC, errno.EIO, errno.EINVAL])
def test_failed_sync_poisoning_has_no_volatile_fallback_and_survives_restart(
    tmp_path, failure
):
    p = directory(tmp_path)
    j = journal(p, True)
    try:
        with patch("os.fsync", side_effect=OSError(failure, "injected sync failure")):
            with pytest.raises(OSError):
                j.begin_window(**META)
        assert not j.status()["continuity_available"]
        with patch("os.write", side_effect=AssertionError("must not retry disk I/O")):
            with pytest.raises(OutcomeJournalError):
                j.begin_window(**META)
    finally:
        j.close()
    with journal(p) as recovered:
        assert (
            recovered.status()["new_admission_closed"]
            and recovered.status()["lost"] == 1
        )
        assert not recovered.begin_window(**META)


def test_failure_before_begin_bytes_are_written_still_seals_unknown_event_on_restart(
    tmp_path,
):
    p = directory(tmp_path)
    j = journal(p, True)
    with patch("os.write", side_effect=OSError(errno.ENOSPC, "disk full")):
        with pytest.raises(OSError):
            j.begin_window(**META)
    j.close()
    with journal(p) as recovered:
        assert recovered.status()["identities"] == 0
        assert recovered.status()["seal_reason"] == "unclean_restart"
        assert not recovered.begin_window(**META)


def test_short_write_and_torn_tail_are_not_automatically_repaired(tmp_path):
    p = directory(tmp_path)
    j = journal(p, True)
    real = os.write
    calls = []

    def torn(fd, data):
        if not calls:
            calls.append(True)
            return real(fd, data[:12])
        raise OSError(errno.EIO, "injected torn append")

    with patch("os.write", torn):
        with pytest.raises(OSError):
            j.begin_window(**META)
    j.close()
    before = (p / NAME).read_bytes()
    with pytest.raises(OutcomeJournalError):
        journal(p)
    assert (p / NAME).read_bytes() == before


def test_partial_writes_are_completed_before_fsync(tmp_path):
    p = directory(tmp_path)
    with journal(p, True) as j:
        real = os.write
        with patch("os.write", side_effect=lambda fd, data: real(fd, data[:7])):
            assert j.begin_window(**META)
        assert j.commit_outcome(_outcome())
    with journal(p) as j:
        assert j.status()["committed"] == 1


@pytest.mark.parametrize(
    "fault", ["hash", "tail", "policy", "scope", "budget", "mode", "missing"]
)
def test_corruption_context_and_permission_changes_refuse_startup_without_mutation(
    tmp_path, fault
):
    p = directory(tmp_path)
    with journal(p, True) as j:
        j.begin_window(**META)
        j.commit_outcome(_outcome())
    args = {}
    if fault == "hash":
        (p / NAME).write_bytes(
            (p / NAME).read_bytes().replace(b"outcome-a", b"outcome-b")
        )
    elif fault == "tail":
        (p / NAME).write_bytes((p / NAME).read_bytes()[:-3])
    elif fault == "policy":
        args["policy_ref"] = "policy-b"
    elif fault == "scope":
        args["scope_ref"] = "scope-b"
    elif fault == "budget":
        args["max_identities"] = 2
    elif fault == "mode":
        (p / NAME).chmod(0o640)
    else:
        (p / NAME).unlink()
    before = (p / NAME).read_bytes() if (p / NAME).exists() else None
    with pytest.raises(OSError):
        journal(p, **args)
    assert ((p / NAME).read_bytes() if (p / NAME).exists() else None) == before


def test_links_fifo_directory_and_reinitialization_are_refused(tmp_path):
    target = directory(tmp_path, "target")
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError):
        journal(link, True)
    with journal(target, True):
        pass
    with pytest.raises(OSError):
        journal(target, True)
    other = directory(tmp_path, "other")
    (other / NAME).symlink_to(target / NAME)
    with pytest.raises(OSError):
        journal(other)
    (other / NAME).unlink()
    os.link(target / NAME, other / NAME)
    with pytest.raises(OSError):
        journal(other)
    (other / NAME).unlink()
    os.mkfifo(other / NAME, 0o600)
    with pytest.raises(OSError):
        journal(other)
    (other / NAME).unlink()
    (other / NAME).mkdir()
    with pytest.raises(OSError):
        journal(other)


def test_exclusive_writer_lock_and_path_identity_drift(tmp_path):
    p = directory(tmp_path)
    with journal(p, True) as j:
        with pytest.raises(OSError):
            journal(p)
        os.rename(p / NAME, p / "moved")
        (p / NAME).write_bytes((p / "moved").read_bytes())
        (p / NAME).chmod(0o600)
        with pytest.raises(OutcomeJournalError):
            j.begin_window(**META)
        assert not j.status()["continuity_available"]


def test_capacity_is_persistent_no_rotation_and_pending_commit_has_reserved_space(
    tmp_path,
):
    p = directory(tmp_path)
    with journal(p, True, max_identities=1) as j:
        assert j.begin_window(**META)
        assert j.commit_outcome(_outcome())
        assert not j.begin_window(
            decision_id="decision-b",
            execution_id="execution-b",
            objective_id="objective-b",
        )
        assert j.status()["seal_reason"] == "identity_capacity"
    with journal(p, max_identities=1) as j:
        assert j.status()["new_admission_closed"] and j.status()["committed"] == 1
    assert sorted(v.name for v in p.iterdir()) == [NAME]
    q = directory(tmp_path, "byte-cap")
    with journal(q, True, max_bytes=2 * MAX_RECORD_BYTES) as j:
        assert j.begin_window(**META)
        assert not j.begin_window(
            decision_id="decision-b",
            execution_id="execution-b",
            objective_id="objective-b",
        )
        assert j.status()["seal_reason"] == "byte_capacity"
        assert j.commit_outcome(_outcome())
        assert j.status()["bytes"] <= 2 * MAX_RECORD_BYTES


def test_collector_failure_drops_outcome_without_changing_input_or_decision(tmp_path):
    p = directory(tmp_path)
    pol = policy()
    event = rust_event(ts="2026-01-01T00:00:00Z", trace="journal-fail")
    before = json.dumps(event, sort_keys=True)
    with journal(p, True, policy_ref=persistence_context(pol, "br0")) as j:
        c = OutcomeTelemetryCollector(
            source=FakeSource(), policy=pol, interface="br0", persistence=j
        )
        assert c.observe_event(event, observed_epoch=100)
        with patch("os.fsync", side_effect=OSError(errno.EIO, "sync failed")):
            assert c.finalize_due(epoch=104) == ()
        assert c.persistence_errors == 1 and json.dumps(event, sort_keys=True) == before
    with journal(p, policy_ref=persistence_context(pol, "br0")) as recovered:
        assert recovered.status()["new_admission_closed"]
        # Complete commit bytes may have reached storage before fsync failed;
        # if present they are retained once, never re-created with later samples.
        assert recovered.status()["committed"] == 1


def test_policy_sampling_context_and_unbegun_or_supported_outcome_are_refused(tmp_path):
    p = directory(tmp_path)
    with journal(p, True) as j:
        with pytest.raises(OutcomeJournalError):
            j.commit_outcome(_outcome())
        with pytest.raises(OutcomeJournalError):
            OutcomeTelemetryCollector(
                source=FakeSource(), policy=policy(), interface="br0", persistence=j
            )
        assert j.begin_window(**META)
        with pytest.raises(OutcomeJournalError):
            j.commit_outcome(
                replace(_outcome(), causal_support=CausalSupport.SUPPORTED)
            )
        assert j.status()["committed"] == 0


def test_parent_directory_sync_failure_is_fatal_and_does_not_reinitialize(tmp_path):
    p = directory(tmp_path)
    real = os.fsync
    calls = []

    def sync(fd):
        import stat

        calls.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        if calls[-1] == "directory":
            raise OSError(errno.EINVAL, "directory sync unsupported")
        return real(fd)

    with patch("os.fsync", sync):
        with pytest.raises(OSError):
            journal(p, True)
    assert calls == ["file", "directory"]
    before = (p / NAME).read_bytes()
    with pytest.raises(OSError):
        journal(p, True)
    assert (p / NAME).read_bytes() == before


def test_session_budget_is_persistent_and_never_rotates(tmp_path):
    from azazel_edge.outcome.journal import MAX_SESSIONS

    p = directory(tmp_path)
    for n in range(MAX_SESSIONS):
        with journal(p, create=n == 0) as j:
            assert not j.status()["new_admission_closed"]
    with journal(p) as j:
        assert j.status()["seal_reason"] == "session_capacity"
        assert j.status()["sessions"] == MAX_SESSIONS
    size = (p / NAME).stat().st_size
    with journal(p) as j:
        assert j.status()["new_admission_closed"]
    assert (p / NAME).stat().st_size == size


def test_collector_capacity_loss_is_durable_and_cannot_use_later_samples(tmp_path):
    p = directory(tmp_path)
    pol = policy()
    ctx = persistence_context(pol, "br0", max_pending=1)
    a = rust_event(ts="2026-01-01T00:00:00Z", trace="capacity-a")
    b = rust_event(ts="2026-01-01T00:00:00Z", trace="capacity-b")
    with journal(p, True, policy_ref=ctx) as j:
        c = OutcomeTelemetryCollector(
            source=FakeSource(),
            policy=pol,
            interface="br0",
            max_pending=1,
            persistence=j,
        )
        assert c.observe_event(a, observed_epoch=100)
        assert not c.observe_event(b, observed_epoch=100)
        assert j.status()["lost"] == 1
    with journal(p, policy_ref=ctx) as j:
        c = OutcomeTelemetryCollector(
            source=FakeSource(),
            policy=pol,
            interface="br0",
            max_pending=1,
            persistence=j,
        )
        for t in range(200, 210):
            c.record_sample(epoch=t)
        assert not c.observe_event(a, observed_epoch=210)
        assert not c.observe_event(b, observed_epoch=210)
        assert c.finalize_due(epoch=220) == () and j.status()["lost"] == 2


def test_journal_has_no_network_or_child_process_dependency(tmp_path):
    p = directory(tmp_path)
    with patch("socket.socket", side_effect=AssertionError("network forbidden")), patch(
        "subprocess.Popen", side_effect=AssertionError("commands forbidden")
    ):
        with journal(p, True) as j:
            assert j.begin_window(**META) and j.commit_outcome(_outcome())
        with journal(p) as j:
            assert j.status()["committed"] == 1


def test_live_opt_in_wiring_and_clean_shutdown(tmp_path):
    from azazel_edge.outcome import telemetry

    p = directory(tmp_path)
    source = tmp_path / "input.jsonl"
    source.write_text("{}\n")
    pol = policy()
    output = tmp_path / "unused.jsonl"
    # No historical replay; interrupt at the first idle poll. The finally block
    # writes a clean close even on KeyboardInterrupt, before releasing the lock.
    with patch.object(
        telemetry.OutcomeTelemetryPolicy, "from_file", return_value=pol
    ), patch.object(telemetry, "LinuxProcTelemetrySource", FakeSource), patch.object(
        telemetry.time, "sleep", side_effect=KeyboardInterrupt
    ):
        with pytest.raises(KeyboardInterrupt):
            telemetry.run_live(
                input_path=source,
                output_path=output,
                policy_path=Path("unused"),
                interface="br0",
                journal_directory=p,
                journal_scope="scope-a",
                journal_boot_id="boot-a",
                initialize_journal=True,
            )
    with journal(p, policy_ref=persistence_context(pol, "br0")) as j:
        assert j.status()["identities"] == 0 and not j.status()["unclean_recovery"]
    assert not output.exists()


def test_live_refuses_closed_journal_before_reading_procfs_or_input(tmp_path):
    from azazel_edge.outcome import telemetry

    p = directory(tmp_path)
    pol = policy()
    ctx = persistence_context(pol, "br0")
    with journal(p, True, policy_ref=ctx, max_identities=1) as j:
        j.begin_window(**META)
        j.commit_outcome(_outcome())
    with patch.object(
        telemetry.OutcomeTelemetryPolicy, "from_file", return_value=pol
    ), patch.object(
        telemetry,
        "LinuxProcTelemetrySource",
        side_effect=AssertionError("must refuse before source construction"),
    ):
        with pytest.raises(OSError, match="admission closed"):
            telemetry.run_live(
                input_path=tmp_path / "missing",
                output_path=tmp_path / "unused",
                policy_path=Path("unused"),
                interface="br0",
                journal_directory=p,
                journal_scope="scope-a",
                journal_boot_id="boot-a",
                journal_max_identities=1,
            )


def test_cli_defaults_remain_volatile_and_incomplete_opt_in_refused():
    from azazel_edge.outcome import telemetry

    with patch.object(telemetry, "run_live") as live:
        assert telemetry.main(["--policy", "unused.json"]) == 0
        assert live.call_args.kwargs["journal_directory"] is None
        assert not live.call_args.kwargs["initialize_journal"]
        for args in (
            ["--journal-directory", "/unused"],
            ["--journal-scope", "scope-a"],
            ["--journal-initialize"],
        ):
            with pytest.raises(SystemExit):
                telemetry.main(["--policy", "unused.json", *args])
        assert live.call_count == 1


def test_live_io_failure_stops_without_volatile_projection(tmp_path):
    from azazel_edge.outcome import telemetry

    p = directory(tmp_path)
    pol = policy()
    source = tmp_path / "input"
    source.write_text("")
    output = tmp_path / "output"
    real = os.fsync
    polls = []

    def sync(fd):
        last = json.loads((p / NAME).read_bytes().splitlines()[-1])
        if last["kind"] == "begin":
            raise OSError(errno.EIO, "injected begin sync failure")
        real(fd)

    def poll(_):
        assert not polls, "collector must stop instead of polling forever after failure"
        polls.append(True)
        source.write_text(
            json.dumps(rust_event(ts="2026-01-01T00:00:00Z", trace="live-failure"))
            + "\n{}\n"
        )

    with patch.object(
        telemetry.OutcomeTelemetryPolicy, "from_file", return_value=pol
    ), patch.object(telemetry, "LinuxProcTelemetrySource", FakeSource), patch.object(
        telemetry.time, "sleep", poll
    ), patch(
        "os.fsync", sync
    ), patch.object(
        telemetry, "_decode_event", wraps=telemetry._decode_event
    ) as decode:
        with pytest.raises(OSError, match="continuity unavailable"):
            telemetry.run_live(
                input_path=source,
                output_path=output,
                policy_path=Path("unused"),
                interface="br0",
                journal_directory=p,
                journal_scope="scope-a",
                journal_boot_id="boot-a",
                initialize_journal=True,
            )
        assert decode.call_count == 1  # Do not drain further input after a failed sync.
    assert not output.exists()
    with journal(p, policy_ref=persistence_context(pol, "br0")) as j:
        assert (
            j.status()["lost"] == 1 and j.status()["seal_reason"] == "unclean_restart"
        )


def test_live_rejects_journal_input_or_projection_alias(tmp_path):
    from azazel_edge.outcome import telemetry

    p = directory(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(p / NAME)
    with patch.object(
        telemetry.OutcomeTelemetryPolicy, "from_file", return_value=policy()
    ):
        for source, output in ((p / NAME, tmp_path / "out"), (tmp_path / "in", alias)):
            with pytest.raises(ValueError, match="separate"):
                telemetry.run_live(
                    input_path=source,
                    output_path=output,
                    policy_path=Path("unused"),
                    interface="br0",
                    journal_directory=p,
                    journal_scope="scope-a",
                    journal_boot_id="boot-a",
                    initialize_journal=True,
                )
    assert list(p.iterdir()) == []


def test_oversized_result_cannot_consume_reserved_loss_space(tmp_path):
    p = directory(tmp_path)
    with journal(p, True, max_bytes=2 * MAX_RECORD_BYTES) as j:
        assert j.begin_window(**META)
        before = (p / NAME).read_bytes()
        with pytest.raises(OutcomeJournalError):
            j.commit_outcome(
                replace(_outcome(), evidence_refs=("x" * MAX_RECORD_BYTES,))
            )
        assert (p / NAME).read_bytes() == before and j.status()["committed"] == 0
        j.lose_window(**META)
        assert j.status()["lost"] == 1 and not j.commit_outcome(_outcome())


def test_exported_nested_values_cannot_mutate_retained_result(tmp_path):
    p = directory(tmp_path)
    original = replace(
        _outcome(),
        baseline_metrics={"sample": {"value": 1}},
        evidence_refs=["original"],
    )
    with journal(p, True) as j:
        j.begin_window(**META)
        j.commit_outcome(original)
        result = j.retained_outcomes()[0]
        result.baseline_metrics["sample"]["value"] = 999
        result.evidence_refs.append("fabricated")
        assert j.retained_outcomes()[0].to_dict() == original.to_dict()
    with journal(p) as j:
        assert j.retained_outcomes()[0].to_dict() == original.to_dict()


@pytest.mark.parametrize("fail_directory", [False, True])
def test_sealed_reopen_must_resync_before_exposing_recovered_results(
    tmp_path, fail_directory
):
    import stat

    p = directory(tmp_path)
    with journal(p, True, max_identities=1) as j:
        assert j.begin_window(**META) and j.commit_outcome(_outcome())
        assert not j.begin_window(
            decision_id="new", execution_id="new", objective_id="new"
        )
    before = (p / NAME).read_bytes()
    real = os.fsync
    calls = []

    def sync(fd):
        is_directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        calls.append(is_directory)
        if is_directory == fail_directory:
            raise OSError(errno.EIO, "recovery sync failed")
        real(fd)

    with patch("os.fsync", sync):
        with pytest.raises(OSError, match="recovery sync failed"):
            journal(p, max_identities=1)
    assert calls == ([False, True] if fail_directory else [False])
    assert (p / NAME).read_bytes() == before
    with journal(p, max_identities=1) as j:
        assert j.retained_outcomes()[0].outcome_id == "outcome-a"
