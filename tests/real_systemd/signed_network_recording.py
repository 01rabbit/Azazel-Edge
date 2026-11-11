"""Test-only recording of unchanged G3 calls; no probe or execution authority."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import stat
import time

from azazel_edge.benchmark.benefit import BenefitInputError, manifest_digest
from azazel_edge.outcome import input_resume
from azazel_edge.outcome.golden_replay import run_golden_replay
from azazel_edge.outcome.telemetry import (
    OutcomeTelemetryCollector,
    OutcomeTelemetryPolicy,
)

MAX_BYTES = 4 * 1024 * 1024
MAX_ROWS = 900


def need(value, message):
    if not value:
        raise BenefitInputError(message)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


class CallRecording:
    """Exclusive bounded sidecar under the existing observer/** grant.

    Failure interrupts the trial; an unfinished file is retained, never repaired.
    Hashes detect accidental changes, not malicious operator/own-UID rewriting.
    """

    def __init__(self, path, *, metadata):
        self.fd = os.open(
            path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        self.size = self.count = 0
        self.previous = "0" * 64
        self.closed = False
        try:
            self.append("begin", metadata)
        except BaseException:
            os.close(self.fd)
            self.closed = True
            raise

    def append(self, kind, data):
        need(not self.closed, "recording already closed")
        unsigned = dict(seq=self.count, prev=self.previous, kind=kind, data=data)
        row = dict(unsigned, sha256=manifest_digest(unsigned))
        raw = canonical(row) + b"\n"
        need(
            self.count < MAX_ROWS and self.size + len(raw) <= MAX_BYTES,
            "recording bound exceeded",
        )
        remaining = memoryview(raw)
        while remaining:
            count = os.write(self.fd, remaining)
            need(count > 0, "recording write stopped")
            remaining = remaining[count:]
        os.fsync(self.fd)
        self.previous = row["sha256"]
        self.count += 1
        self.size += len(raw)

    def close(self, *, complete):
        if not self.closed:
            try:
                if complete:
                    self.append("end", {})
            finally:
                os.close(self.fd)
                self.closed = True


@contextmanager
def record_collector(path, *, policy, policy_source_ref):
    """Only this single-threaded test observer replaces the constructor binding.

    Every super call/return is unchanged; no additional sample/finalize is made.
    A SIGTERM handler in the driver may exit normally to close the sidecar.
    An exception retains an incomplete recording and withholds a replay join.
    """
    need(
        input_resume.OutcomeTelemetryCollector is OutcomeTelemetryCollector,
        "collector already replaced",
    )
    expected_ref = OutcomeTelemetryPolicy.from_mapping(
        policy, source_ref=policy_source_ref
    ).policy_ref
    sink = CallRecording(
        path,
        metadata=dict(
            policy_sha256=manifest_digest(policy),
            policy_source_ref=policy_source_ref,
            policy_ref=expected_ref,
        ),
    )

    class RecordedCollector(OutcomeTelemetryCollector):
        def __init__(self, **kwargs):
            need(
                kwargs["policy"].policy_ref == expected_ref,
                "actual collector policy differs",
            )
            super().__init__(**kwargs)

        def record_sample(self, *, epoch=None):
            need(epoch is not None, "explicit real loop epoch required")
            start = time.monotonic_ns()
            result = super().record_sample(epoch=epoch)
            sink.append(
                "sample",
                dict(
                    epoch=epoch,
                    start_ns=start,
                    end_ns=time.monotonic_ns(),
                    sample=asdict(result) if result else None,
                ),
            )
            return result

        def observe_event(self, event, *, observed_epoch=None):
            need(observed_epoch is not None, "explicit intake epoch required")
            start = time.monotonic_ns()
            result = super().observe_event(event, observed_epoch=observed_epoch)
            sink.append(
                "event",
                dict(
                    epoch=observed_epoch,
                    start_ns=start,
                    end_ns=time.monotonic_ns(),
                    event=event,
                    accepted=result,
                ),
            )
            return result

        def finalize_due(self, *, epoch=None):
            need(epoch is not None, "explicit finalization epoch required")
            start = time.monotonic_ns()
            result = super().finalize_due(epoch=epoch)
            sink.append(
                "finalize",
                dict(
                    epoch=epoch,
                    start_ns=start,
                    end_ns=time.monotonic_ns(),
                    outcomes=[r.to_dict() for r in result],
                ),
            )
            return result

    input_resume.OutcomeTelemetryCollector = RecordedCollector
    complete = False
    try:
        yield
        complete = True
    finally:
        input_resume.OutcomeTelemetryCollector = OutcomeTelemetryCollector
        sink.close(complete=complete)


def read_calls(path):
    fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == os.geteuid()
            and not info.st_mode & 0o022,
            "unsafe call recording",
        )
        need(info.st_size <= MAX_BYTES, "recording byte bound")
        raw = os.read(fd, MAX_BYTES + 1)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        need(
            (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            == (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
            and (named.st_dev, named.st_ino) == (info.st_dev, info.st_ino)
            and len(raw) == info.st_size,
            "recording changed during read",
        )
    finally:
        os.close(fd)
    return decode_calls(raw)


def decode_calls(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate recording key")
            result[key] = value
        return result

    need(
        type(raw) is bytes and len(raw) <= MAX_BYTES and raw.endswith(b"\n"),
        "bounded complete recording required",
    )
    lines = raw.splitlines()
    need(len(lines) <= MAX_ROWS, "recording row bound")
    need(len(lines) >= 2, "unfinished recording")
    rows = []
    previous = "0" * 64
    for seq, line in enumerate(lines):
        row = json.loads(
            line,
            object_pairs_hook=pairs,
            parse_constant=lambda _: need(False, "nonfinite recording"),
        )
        need(
            type(row) is dict and set(row) == {"seq", "prev", "kind", "data", "sha256"},
            "recording envelope",
        )
        need(
            canonical(row) == line
            and type(row["seq"]) is int
            and row["seq"] == seq
            and row["prev"] == previous,
            "recording sequence",
        )
        need(
            row["sha256"]
            == manifest_digest({k: row[k] for k in ("seq", "prev", "kind", "data")}),
            "recording digest",
        )
        rows.append(row)
        previous = row["sha256"]
    need(
        rows[0]["kind"] == "begin"
        and rows[-1]["kind"] == "end"
        and rows[-1]["data"] == {},
        "unfinished recording",
    )
    metadata = rows[0]["data"]
    need(
        type(metadata) is dict
        and set(metadata) == {"policy_sha256", "policy_source_ref", "policy_ref"},
        "recorded policy context missing",
    )
    last_epoch = last_end = -1
    for row in rows[1:-1]:
        data = row["data"]
        extra = (
            {"sample"}
            if row["kind"] == "sample"
            else {"event", "accepted"}
            if row["kind"] == "event"
            else {"outcomes"}
            if row["kind"] == "finalize"
            else set()
        )
        need(
            extra
            and type(data) is dict
            and set(data) == {"epoch", "start_ns", "end_ns"} | extra,
            "unknown recorded call",
        )
        need(
            type(data["epoch"]) in (int, float)
            and math.isfinite(data["epoch"])
            and data["epoch"] >= last_epoch,
            "recorded epoch moved backwards",
        )
        need(
            type(data["start_ns"]) is int
            and type(data["end_ns"]) is int
            and last_end <= data["start_ns"] <= data["end_ns"],
            "recorded monotonic overlap",
        )
        last_epoch, last_end = data["epoch"], data["end_ns"]
    return dict(context=metadata, calls=rows[1:-1])


def replay_calls(
    recorded,
    *,
    policy,
    boot,
    interface="es",
    interval=0.25,
    root_probe=None,
):
    """Readonly G5 projection; compare live outputs before optional lab augmentation.

    Caller must separately verify signed event coverage, journal, root probe
    provenance/namespace/clock bindings, and controller service facts.
    This function never authenticates any caller-supplied recording.
    """
    context, rows = recorded["context"], recorded["calls"]
    need(
        context["policy_sha256"] == manifest_digest(policy),
        "canonical policy SHA differs",
    )
    live_policy_source_ref = context["policy_source_ref"]
    need(
        type(live_policy_source_ref) is str and 0 < len(live_policy_source_ref) <= 4096,
        "invalid policy source_ref",
    )
    expected = OutcomeTelemetryPolicy.from_mapping(
        policy, source_ref=live_policy_source_ref
    ).policy_ref
    need(context["policy_ref"] == expected, "recorded live policy_ref differs")
    steps, actual = [], []
    for row in rows:
        kind, data = row["kind"], row["data"]
        step = dict(op=kind, epoch=data["epoch"])
        if kind == "sample":
            sample = data["sample"]
            need(
                type(sample) is dict
                and sample["epoch"] == data["epoch"]
                and sample["interface"] == interface,
                "sample unavailable or binding differs",
            )
            need(
                sample["observed_at"]
                == datetime.fromtimestamp(data["epoch"], timezone.utc).isoformat(),
                "G5 cannot preserve sample timestamp",
            )
            need(
                sample["coverage"]
                and all(v is True for v in sample["coverage"].values()),
                "sample coverage incomplete",
            )
            step.update(
                {
                    k: sample[k]
                    for k in ("network", "system", "coverage", "evidence_ref")
                }
            )
        elif kind == "event":
            need(type(data["accepted"]) is bool, "invalid event acceptance")
            step["event"] = data["event"]
        else:
            need(
                kind == "finalize" and type(data["outcomes"]) is list,
                "invalid finalization",
            )
            actual.extend(data["outcomes"])
        steps.append(step)
    fixture = dict(
        schema_version="outcome-golden-replay-input/v1",
        fixture_id="signed-network-actual-calls",
        policy=policy,
        interface=interface,
        sample_interval_seconds=interval,
        boots=[dict(boot=boot, steps=steps)],
    )
    plain = run_golden_replay(fixture)
    projected = [
        t["stages"]["outcome"] for t in plain["decisions"] if t["stages"].get("outcome")
    ]
    live_ref = OutcomeTelemetryPolicy.from_mapping(
        policy, source_ref=live_policy_source_ref
    ).policy_ref
    replay_ref = OutcomeTelemetryPolicy.from_mapping(
        policy, source_ref="golden-replay"
    ).policy_ref
    compared = json.loads(canonical(actual))
    for outcome in compared:
        need(
            outcome["telemetry_coverage"]["policy_ref"] == live_ref
            and outcome["evidence_refs"].count(live_ref) == 1,
            "live policy provenance binding differs",
        )
        outcome["telemetry_coverage"]["policy_ref"] = replay_ref
        outcome["evidence_refs"] = [
            replay_ref if ref == live_ref else ref for ref in outcome["evidence_refs"]
        ]
    need(
        sorted(compared, key=canonical) == sorted(projected, key=canonical),
        "actual live Outcome differs beyond explicit policy source_ref",
    )
    augmented = None
    if root_probe is not None:
        need(
            root_probe.get("op") == "probe"
            and type(root_probe.get("epoch")) in (float, int)
            and math.isfinite(root_probe["epoch"]),
            "explicit actual root probe required",
        )
        # Only a new projection gets the external ROOT lab record. Never replace
        # the original live calls, journal, outcome, or plain replay.
        extra = json.loads(canonical(fixture))
        extra["boots"][0]["steps"].append(root_probe)
        extra["boots"][0]["steps"].sort(key=lambda s: s["epoch"])
        augmented = run_golden_replay(extra)
        fixture = extra
    return dict(
        scope="read_only_g5_projection_not_live_observer_verification",
        recording=fixture,
        live_outcomes=actual,
        live_policy_ref=live_ref,
        replay_policy_ref=replay_ref,
        comparison="equal_except_explicit_policy_source_ref",
        canonical_policy_sha256=manifest_digest(policy),
        live_outcomes_sha256=manifest_digest(actual),
        plain_replay_sha256=manifest_digest(plain),
        exact_differences=[
            dict(
                outcome_id=o["outcome_id"],
                path="telemetry_coverage.policy_ref",
                live=live_ref,
                replay=replay_ref,
            )
            for o in actual
            if live_ref != replay_ref
        ]
        + [
            dict(
                outcome_id=o["outcome_id"],
                path="evidence_refs[" + str(o["evidence_refs"].index(live_ref)) + "]",
                live=live_ref,
                replay=replay_ref,
            )
            for o in actual
            if live_ref != replay_ref
        ],
        plain_replay=plain,
        root_augmented_replay=augmented,
        original_calls_sha256=manifest_digest(rows),
        production_origin_admitted=False,
    )
