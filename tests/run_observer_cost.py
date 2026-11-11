"""Opt-in isolated Linux-root downstream observer cost/parity lab, not G6."""
# ruff: noqa: E402

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

SRC = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(SRC / "py"), str(SRC / "tests")]
from observer_cost_helpers import (
    digest,
    semantics,
    process_sample,
    process_summary,
    store_bytes,
)
from test_outcome_input_auth_linux import Fixture
from test_outcome_live_origin_linux import register_live, Run, events, children
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier, _json
from azazel_edge.outcome.telemetry import POLICY_SCHEMA_VERSION

SIDS = (42001, 42002, 42003)
TRANSCRIPT = [
    dict(
        timestamp="2026-01-01T00:00:00Z",
        event_type="alert",
        src_ip="10.77.0.8",
        dest_ip="10.77.0.1",
        src_port=45123,
        dest_port=22,
        proto="TCP",
        alert=dict(
            signature_id=sid,
            severity=2,
            signature="observer-cost-fixed",
            category="lab",
            action="allowed",
        ),
    )
    for sid in SIDS
]
INITIALIZE = r"""
import sys
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_cursor import BoundedInput
from azazel_edge.outcome.input_witness import InputAuthentication
from azazel_edge.outcome.journal import ObservationJournal
from azazel_edge.outcome.input_resume import recover_input
from azazel_edge.outcome.telemetry import OutcomeTelemetryPolicy,persistence_context
p=TrustPolicy.from_file(Path(sys.argv[1]),role='observer');d=p.data
policy=OutcomeTelemetryPolicy.from_file(Path(sys.argv[2]))
with BoundedInput(Path(d['source_path']),max_bytes=d['input_max_bytes'],max_records=d['input_max_records'],authentication=InputAuthentication(p)) as source:
 with ObservationJournal(Path(d['journal_directory']),scope_ref=d['scope_ref'],policy_ref=persistence_context(policy,'lo',0.05),boot_id=sys.argv[3],create=True,max_bytes=d['journal_max_bytes'],input_source=source) as journal:
  recover_input(journal,policy)
"""


def wait(check):
    end = time.monotonic() + 12
    while time.monotonic() < end:
        result = check()
        if result:
            return result
        time.sleep(0.02)
    raise RuntimeError("bounded observer-cost deadline")


def cursors(f):
    try:
        raw = f.journal.read_bytes()
        if len(raw) > f.p.data["journal_max_bytes"] or not raw.endswith(b"\n"):
            return []
        return [
            row["data"]
            for row in map(json.loads, raw.splitlines())
            if row["kind"] == "cursor"
        ]
    except FileNotFoundError:
        return []


def decisions(f):
    path = f.root / "native-log"
    if not path.exists():
        return []
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("native transcript bound")
    if not raw.endswith(b"\n"):
        return []
    return [
        r
        for r in map(json.loads, raw.splitlines())
        if r.get("pipeline") == "rust_event_engine_v1"
    ]


def arm(mode, *, keep=False):
    if mode not in ("off", "on", "faulted"):
        raise ValueError("unknown observer arm")
    f = Fixture()
    run = observer = None
    logs = []
    passed = False
    try:
        register_live(f)
        r = json.loads(f.registration.read_bytes())
        r["environment"]["AZAZEL_FORWARD_LOG"] = "1"
        r["environment"]["AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO"] = "0"
        f.registration.write_bytes(_json(r))
        f.p = TrustPolicy(
            {
                **f.p.data,
                "origin_registration_sha256": hashlib.sha256(_json(r)).hexdigest(),
            }
        )
        f.policy_file.write_bytes(_json(dict(f.p.data)))
        policy = f.root / "telemetry-policy.json"
        policy.write_bytes(
            _json(
                dict(
                    schema_version=POLICY_SCHEMA_VERSION,
                    policy_version="observer-cost-disabled-v1",
                    actions={},
                )
            )
        )
        f.start(initialize=True)
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        env = dict(os.environ, PYTHONPATH=str(SRC / "py") + ":" + str(SRC / "tests"))
        uid = f.p.data["observer_uid"]
        if mode != "off":
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    INITIALIZE,
                    str(f.policy_file),
                    str(policy),
                    boot,
                ],
                env=env,
                user=uid,
                group=uid,
                extra_groups=[],
                capture_output=True,
                check=True,
                timeout=15,
            )
        run = Run(f)
        run.started()
        events(f, 2)
        if mode != "off":
            output = Path(f.p.data["journal_directory"]) / "outcomes.jsonl"
            err = (f.root / "observer.stderr").open("wb")
            logs.append(err)
            observer = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "azazel_edge.outcome.telemetry",
                    "--input",
                    str(f.source),
                    "--output",
                    str(output),
                    "--policy",
                    str(policy),
                    "--interface",
                    "lo",
                    "--poll-seconds",
                    "0.05",
                    "--sample-interval-seconds",
                    "0.05",
                    "--journal-directory",
                    f.p.data["journal_directory"],
                    "--journal-scope",
                    f.p.data["scope_ref"],
                    "--journal-boot-id",
                    boot,
                    "--journal-max-bytes",
                    str(f.p.data["journal_max_bytes"]),
                    "--journal-resume-input",
                    "--input-auth-policy",
                    str(f.policy_file),
                ],
                env=env,
                user=uid,
                group=uid,
                extra_groups=[],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=err,
            )
            wait(lambda: observer.poll() is None and len(cursors(f)) == 2)
        kids = children(run)
        native = [
            pid
            for pid in kids
            if int(
                Path(f"/proc/{pid}/status").read_text().split("Uid:", 1)[1].split()[0]
            )
            == 0
        ]
        signer = [pid for pid in kids if pid not in native]
        if len(native) != 1 or len(signer) != 1:
            raise RuntimeError("native/signer identity unavailable")
        pids = dict(native=native[0], signer=signer[0])
        if observer:
            pids["observer"] = observer.pid
        samples = {role: [process_sample(pid)] for role, pid in pids.items()}
        if any(points[0]["start_ticks"] is None for points in samples.values()):
            raise RuntimeError("initial process identity unavailable")
        start = time.monotonic()
        size_before = store_bytes(f.root)
        for index, row in enumerate(TRANSCRIPT):
            with f.raw.open("ab") as stream:
                stream.write(_json(row) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            wait(lambda: len(decisions(f)) == index + 1)
            events(f, index + 3)
            if observer and observer.poll() is None:
                wait(lambda: len(cursors(f)) == index + 3)
            for role, pid in pids.items():
                samples[role].append(
                    process_sample(pid, expected_start=samples[role][0]["start_ticks"])
                )
            if mode == "faulted" and index == 0:
                observer.kill()
                observer.wait(timeout=5)
        for role, pid in pids.items():
            samples[role].append(
                process_sample(pid, expected_start=samples[role][0]["start_ticks"])
            )
        elapsed = time.monotonic() - start
        logical_after = store_bytes(f.root)
        projected = semantics(decisions(f), SIDS)
        if observer and observer.poll() is None:
            # Stop before session_end: live lifecycle correctly closes the intake boundary.
            observer.terminate()
            observer.wait(timeout=5)
        if run.stop() != 0:
            raise RuntimeError("signed core did not close cleanly")
        data = f.source.read_bytes()
        verifier = SourceVerifier(f.p)
        verifier.verify(data)
        signed = [
            json.loads(line)["event"]
            for line in data.splitlines()
            if json.loads(line)["event"].get("pipeline") == "rust_event_engine_v1"
        ]
        if not verifier.live_state.closed or semantics(signed, SIDS) != projected:
            raise RuntimeError("signed capture coverage or semantic mismatch")
        cursor = cursors(f)
        ticks = os.sysconf("SC_CLK_TCK")
        result = dict(
            mode=mode,
            fixture=str(f.root),
            elapsed_seconds=elapsed,
            input_sha256=digest(TRANSCRIPT),
            expected_decisions=len(SIDS),
            native_decisions=len(projected),
            signed_decisions=len(signed),
            semantic_sha256=digest(projected),
            signed_source_sha256=hashlib.sha256(data).hexdigest(),
            ticks_per_second=ticks,
            processes={
                role: process_summary(points, ticks) for role, points in samples.items()
            },
            store_coverage="complete"
            if size_before is not None and logical_after is not None
            else "incomplete",
            store_bytes_before=size_before,
            store_bytes_after=logical_after,
            store_growth_bytes=logical_after - size_before
            if logical_after is not None and size_before is not None
            else None,
            observer_input_records=len(cursor) if mode != "off" else None,
            observer_missed_records=sum(c["missed"] for c in cursor)
            if mode != "off"
            else None,
            observer_unprocessed_decisions=len(SIDS) - max(0, len(cursor) - 2)
            if mode != "off"
            else None,
            observer_exit=observer.returncode if observer else None,
        )
        passed = True
        return result
    finally:
        if observer and observer.poll() is None:
            observer.kill()
            observer.wait(timeout=5)
        if run:
            run.close()
        for stream in logs:
            stream.close()
        if passed and not keep:
            f.clean()
        else:
            f.halt()  # Preserve every original file on failure or explicit retention.


def run(*, keep=False):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("isolated Linux root required")
    arms = [arm(mode, keep=keep) for mode in ("off", "on", "faulted")]
    if (
        len({a["input_sha256"] for a in arms}) != 1
        or len({a["semantic_sha256"] for a in arms}) != 1
    ):
        raise RuntimeError("observer changed exact covered decision semantics")
    return dict(
        schema_version="edge-observer-cost-lab/v1",
        decision_parity="exact_for_fixed_disabled_input",
        arms=arms,
        limitations=[
            "downstream observer increment only; signer active in all arms",
            "fixed timestamps are intentionally stale; missed input remains missed; no applied windows or effects",
            "sampled RSS is not kernel HWM; unavailable metrics are not zero",
            "logical byte growth/kernel IO are not storage durability or physical wear",
            "fresh sequential software arms are not efficacy, hostile-load thresholds, production admission or G6",
        ],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-isolated-linux-root", action="store_true", required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(keep=True)
    with args.output.open("x") as stream:
        json.dump(result, stream, sort_keys=True)
        stream.write("\n")
    print(
        json.dumps(
            dict(decision_parity=result["decision_parity"], report=str(args.output))
        )
    )


if __name__ == "__main__":
    main()
