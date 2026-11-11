"""One manually started frozen lab assignment; no admission or VM orchestration."""

# ruff: noqa: E402
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(SRC / "py"),
    str(SRC / "tests"),
    str(Path(__file__).resolve().parent),
]
import signed_network_phase as phase
import signed_network_observer as observer
import signed_network_recording as recording
import signed_network_service as service
from azazel_edge.outcome import from_rust_event
from azazel_edge.outcome import nft_flow_evidence as flow
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier, read_regular
from azazel_edge.outcome.input_live import registration
from azazel_edge.outcome.postcondition import SubprocessReadOnlyRunner
from azazel_edge.outcome.release_evidence import from_rust_release_event

p, g, n, plan, scope, lab = (
    phase.p,
    phase.g,
    phase.n,
    phase.plan,
    phase.scope,
    phase.lab,
)


def _json(path, owner=0, maximum=8 * 1024 * 1024):
    return plan.strict(read_regular(path, owner=owner, max_bytes=maximum)[0])


def _source_identity():
    return dict(
        source_revision=phase._read(SRC / "SOURCE_REVISION", 41).decode().strip(),
        helper_sha256=hashlib.sha256(
            phase._read(Path(__file__), 1024 * 1024)
        ).hexdigest(),
        network_driver_sha256=hashlib.sha256(
            phase._read(Path(n.__file__), 1024 * 1024)
        ).hexdigest(),
    )


class SignedSource:
    def __init__(self, trust, kernel, candidate):
        self.trust, self.kernel, self.candidate = trust, kernel, candidate
        self.verifier = SourceVerifier(trust)
        self.identity = None
        self.raw = b""
        self.events = []

    def poll(self, *, terminal=False):
        d = self.trust.data
        self.raw, info = read_regular(
            Path(d["source_path"]),
            owner=d["producer_uid"],
            max_bytes=d["input_max_bytes"],
        )
        identity = (info.st_dev, info.st_ino)
        plan.need(self.identity in (None, identity), "signed source identity replaced")
        self.identity = identity
        complete = self.raw[: self.raw.rfind(b"\n") + 1]
        self.verifier.verify(complete)  # Complete bad frames ALWAYS fail, never retry.
        wires = [plan.strict(line) for line in complete.splitlines()]
        plan.need(
            all(wire["boot_ref"] == self.kernel.replace("-", "") for wire in wires),
            "signed source kernel boot differs",
        )
        kinds = [wire["event"]["capture_origin"]["kind"] for wire in wires]
        plan.need(
            kinds[:2] == ["session_prepare", "session_start"],
            "signed source start differs",
        )
        tail = kinds[2:]
        if terminal:
            plan.need(
                len(complete) == len(self.raw)
                and tail
                and tail[-1] == "session_end"
                and self.verifier.live_state.closed,
                "actual complete signed terminal unavailable",
            )
            tail = tail[:-1]
        plan.need(
            not tail or tail[0] == "decision_execution",
            "unexpected complete lifecycle boundary",
        )
        plan.need(
            all(kind == "release" for kind in tail[1:])
            and (self.candidate or len(tail) <= 1),
            "unexpected complete decision/release coverage",
        )
        self.events = [wire["event"] for wire in wires]
        event = _decision(self.events, self.candidate)
        if event is not None and self.candidate:
            _released(
                self.events, event
            )  # Validate complete task bindings immediately.
        return self.events


def _decision(events, candidate):
    decisions = [
        event for event in events if event.get("pipeline") == "rust_event_engine_v1"
    ]
    plan.need(len(decisions) <= 1, "duplicate decision")
    if not decisions:
        return None
    event = decisions[0]
    normal = event["normalized"]
    execution = event["enforcement"]
    plan.need(
        normal["sid"] == 393001
        and normal["src_ip"] == n.ATK
        and normal["dst_ip"] == n.SERVER
        and normal["target_port"] == n.PORT
        and normal["protocol"].lower() == "tcp",
        "fixed EVE flow differs",
    )
    plan.need(
        execution["selected_action"] == "throttle"
        and execution["failed_count"] == 0
        and execution["executed_count"] == (1 if candidate else 0),
        "actual arm execution differs",
    )
    if not candidate:
        plan.need(
            execution["mode"] in ("disabled", "dry_run", "policy_gated"),
            "unknown baseline provider mode",
        )
    bundle = from_rust_event(event)
    status = event["enforcement_status"]
    plan.need(
        status["enforce_enabled"] is candidate and status["dry_run"] is False,
        "signed arm posture differs",
    )
    plan.need(
        bundle.execution.status.value == "applied"
        if candidate
        else bundle.execution.status.value not in ("applied", "partial"),
        "unexpected native execution status",
    )
    return event


def _released(events, event):
    bundle = from_rust_event(event)
    metadata = event["enforcement"]["metadata"]
    found = None
    for raw in events:
        if raw.get("pipeline") != "rust_release_engine_v1":
            continue
        release = from_rust_release_event(raw)
        plan.need(
            release.decision_id == bundle.execution.decision_id
            and release.action_kind == bundle.execution.action_kind.lower()
            and release.release_task_id == bundle.execution.release_ref
            and release.resource_key == metadata["release_resource_key"]
            and release.owner_token == metadata["release_owner_token"],
            "signed release task/resource/owner differs",
        )
        if release.status.value == "released":
            plan.need(
                release.result == "rollback_applied_and_absence_verified"
                and release.failed_count == 0,
                "signed release result does not verify owned rollback absence",
            )
            found = raw
    return found


def _query_worker(manifest_sha, head):
    g.guard()
    phase.validated_inputs(manifest_sha, head)
    prepared = _json(phase.WORK / "prepared.json")
    plan.need(
        prepared["kernel_boot_id"] == g.boot() and os.geteuid() == 0,
        "explicit current root lab query required",
    )
    records = [
        scope.load(path)
        for path in sorted(phase.WORK.glob("namespace-confirmed-*.json"))
    ]
    matched = [
        r for r in records if r["name"] == p.EDGE and r["state"] == "confirmed_created"
    ]
    network = os.stat("/proc/self/ns/net")
    plan.need(
        len(matched) == 1
        and matched[0]["identity"] == dict(device=network.st_dev, inode=network.st_ino),
        "root query outside owned edge namespace",
    )
    binary = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
    plan.need(binary is not None, "trusted nft unavailable")
    started = datetime.now(timezone.utc).isoformat()
    result = SubprocessReadOnlyRunner().run(flow.QUERY, timeout_seconds=2)
    ended = datetime.now(timezone.utc).isoformat()
    print(
        json.dumps(
            dict(
                argv=list(result.argv),
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                query_started_at=started,
                query_ended_at=ended,
                root_uid=os.geteuid(),
                root_pid=os.getpid(),
                kernel_boot_id=g.boot(),
                netns_inode=network.st_ino,
                source_identity=_source_identity(),
                nft_binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                capture_boundary="actual_root_SubprocessReadOnlyRunner_inside_owned_netns",
                source="live_root_query_recorded_once_for_pure_projection",
            )
        ),
        flush=True,
    )


def root_query(assets, label, manifest_sha, head):
    child = assets.spawn(
        "edge",
        [g.PYTHON, "-I", Path(__file__).resolve(), "--root-query", manifest_sha, head],
    )
    raw = bytearray()
    deadline = time.monotonic() + 3
    n.write_new(
        phase.WORK / (label + "-query-launch.json"),
        dict(
            actual_child_argv=list(map(str, child.args)),
            pid=child.pid,
            namespace_identity=dict(
                device=assets.created[p.EDGE][1], inode=assets.created[p.EDGE][2]
            ),
        ),
    )
    try:
        while not raw.endswith(b"\n"):
            remaining = deadline - time.monotonic()
            plan.need(remaining > 0, "root query absolute deadline")
            ready, _, _ = select.select([child.stdout], [], [], remaining)
            plan.need(ready, "root query absolute deadline")
            chunk = os.read(
                child.stdout.fileno(), min(65536, 2 * 1024 * 1024 + 1 - len(raw))
            )
            plan.need(chunk, "root query incomplete envelope")
            raw.extend(chunk)
            plan.need(len(raw) <= 2 * 1024 * 1024, "root query envelope too large")
        child.wait(timeout=max(0.01, deadline - time.monotonic()))
    finally:
        lab.save(phase.WORK / (label + "-query.raw"), bytes(raw))
    receipt = plan.strict(raw)
    plan.need(
        child.returncode == 0
        and receipt["root_pid"] == child.pid
        and receipt["argv"] == list(flow.QUERY)
        and type(receipt["returncode"]) is int
        and receipt["returncode"] == 0
        and receipt["source_identity"] == _source_identity()
        and receipt["kernel_boot_id"] == g.boot()
        and receipt["netns_inode"] == assets.created[p.EDGE][2]
        and type(receipt["root_uid"]) is int
        and receipt["root_uid"] == 0,
        "root query result/identity differs",
    )
    n.write_new(phase.WORK / (label + "-query.json"), receipt)
    return receipt, flow.parse_readback(receipt["stdout"])


def _without_owner(payload, owner):
    return dict(
        nftables=[
            row
            for row in payload["nftables"]
            if not (
                type(row) is dict
                and type(row.get("rule")) is dict
                and row["rule"].get("comment") == owner
            )
        ]
    )


def _closed_callback(rows, event):
    matches = [
        row["data"]
        for row in rows["calls"]
        if row["kind"] == "event"
        and recording.canonical(row["data"]["event"]) == recording.canonical(event)
    ]
    return matches[0] if len(matches) == 1 else None


def run_assignment(manifest_sha, head):
    g.guard()
    inputs = phase.validated_inputs(manifest_sha, head)
    prepared = _json(phase.WORK / "prepared.json")
    kernel = g.boot()
    plan.need(
        prepared["inputs"] == inputs and prepared["kernel_boot_id"] == kernel,
        "prepared assignment/source/boot differs",
    )
    trust = TrustPolicy.from_file(g.BUNDLE / "trust.json", role="witness")
    registered = registration(trust, g.BUNDLE / "origin.json")
    plan.need(
        dict(trust.data) == prepared["trust_policy"]
        and registered == prepared["registration"]
        and p.identity() == prepared["native_pid"],
        "prepared public enrollment/native identity differs",
    )
    candidate = inputs["assignment"]["arm"] == "flow_throttle"
    reader = SignedSource(trust, kernel, candidate)
    reader.poll()
    plan.need(
        len(reader.events) == 2 and len(reader.raw) == len(reader.verifier.raw),
        "unused signed start prefix required",
    )
    n.write_new(
        phase.WORK / "run-intent.json",
        dict(
            inputs=inputs,
            kernel_boot_id=kernel,
            observer_runtime_seconds=observer.RUNTIME_SECONDS,
        ),
    )  # Exclusive; a second caller may NOT clean up another run.
    assets = None
    observer_process = None
    logs = []
    result = None
    error = None
    record = {}
    try:
        assets, proof = scope.reopen_assets(phase.WORK)
        record.update(
            kernel_boot_id=kernel, source_identity=_source_identity(), inputs=inputs
        )
        baseline_receipt, baseline = root_query(assets, "baseline", manifest_sha, head)
        foreign = [
            row["rule"]
            for row in baseline["nftables"]
            if type(row) is dict and "rule" in row
        ]
        plan.need(
            len(foreign) == 1 and foreign[0].get("comment") == assets.foreign,
            "initial independent foreign canary missing/ambiguous",
        )
        peer = assets.spawn(
            "service",
            [g.PYTHON, "-I", "-u", n.PEER, "service", inputs["ticket"]["run_id"]],
            stdin=True,
        )
        plan.need(
            n.receive(peer) == dict(kind="ready", nonce=inputs["ticket"]["run_id"]),
            "service peer readiness differs",
        )
        for name in ("observer.stdout", "observer.stderr"):
            log = (phase.WORK / name).open("xb")
            os.fchmod(log.fileno(), 0o600)
            logs.append(log)
        observer_process = subprocess.Popen(
            observer.role_argv("live"), stdout=logs[0], stderr=logs[1]
        )
        start = time.monotonic()
        before = dict(
            offset=len(reader.raw), sha256=hashlib.sha256(reader.raw).hexdigest()
        )
        journal_path = Path(trust.data["journal_directory"]) / "observations.journal"
        while True:
            plan.need(
                observer_process.poll() is None and time.monotonic() - start < 2,
                "observer readiness missing/dead",
            )
            raw = read_regular(
                journal_path, owner=61002, max_bytes=trust.data["journal_max_bytes"]
            )[0]
            if raw.endswith(b"\n") and lab.ready_for(raw, before):
                break
            time.sleep(0.01)
        context = _json(
            Path(trust.data["journal_directory"]) / "observer-start-context.json", 61002
        )
        plan.need(
            context["source_start_position"] == before
            and context["kernel_boot_id"] == kernel
            and context["scope_ref"] == trust.data["scope_ref"]
            and context["registration_sha256"]
            == trust.data["origin_registration_sha256"],
            "actual observer startup origin differs",
        )
        effective = observer.effective_observer(
            dict(device=assets.created[p.EDGE][1], inode=assets.created[p.EDGE][2])
        )
        n.write_new(phase.WORK / "effective-observer.json", effective)
        record["controller_start_anchor"] = service.record_clock_anchor()
        origin = time.monotonic_ns()
        deadline = origin + 5_000_000_000
        client_origin = origin + 1_250_000_000
        record.update(
            origin_ns=origin, deadline_ns=deadline, client_origin_ns=client_origin
        )
        peer.stdin.write(
            (
                json.dumps(
                    dict(
                        nonce=inputs["ticket"]["run_id"],
                        origin_ns=origin,
                        deadline_ns=deadline,
                    )
                )
                + "\n"
            ).encode()
        )
        peer.stdin.flush()
        client_before = time.monotonic_ns()
        client = assets.spawn(
            "client",
            [
                g.PYTHON,
                "-I",
                "-u",
                n.PEER,
                "client",
                inputs["ticket"]["run_id"],
                client_origin,
                deadline,
            ],
        )
        record.update(
            client_argv=list(map(str, client.args)),
            client_spawn_before_ns=client_before,
            client_spawn_after_ns=time.monotonic_ns(),
        )
        plan.need(
            time.monotonic_ns() < client_origin + 200_000_000,
            "client launch missed first fixed request",
        )
        alert = None
        event = None
        applied_receipt = None
        release = None
        while time.monotonic_ns() < deadline:
            plan.need(
                observer_process.poll() is None,
                "observer exited before service horizon",
            )
            if peer.poll() is not None or client.poll() is not None:
                plan.need(
                    time.monotonic_ns() >= deadline,
                    "peer exited before service horizon",
                )
                break
            now = time.monotonic_ns()
            if alert is None and now >= client_origin:
                raw = phase._read(g.BASE / "eve.json", 65536)
                plan.need(raw == b"", "EVE was not fresh")
                alert = (
                    n._alert(n.ATK, 1, 393001, port=n.PORT, dst=n.SERVER) + "\n"
                ).encode()
                record["alert_append_before_ns"] = time.monotonic_ns()
                fd = os.open(
                    g.BASE / "eve.json", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
                )
                try:
                    plan.need(
                        os.write(fd, alert) == len(alert), "short fixed EVE append"
                    )
                    os.fsync(fd)
                finally:
                    os.close(fd)
                record["alert_append_after_ns"] = time.monotonic_ns()
                lab.save(phase.WORK / "eve-transcript.raw", alert)
            events = reader.poll()
            event = _decision(events, candidate) or event
            plan.need(
                event is None or alert is not None,
                "signed decision preceded actual fixed input",
            )
            if event is not None and applied_receipt is None:
                applied_receipt, active = root_query(
                    assets, "active", manifest_sha, head
                )
                if candidate:
                    plan.need(
                        flow.readback_matches(
                            active, from_rust_event(event).execution.scope
                        ),
                        "full owned flow rule not observed",
                    )
                owner = event["enforcement"]["metadata"].get("release_owner_token", "")
                plan.need(
                    _without_owner(active, owner) == baseline,
                    "foreign chain context changed",
                )
                if not candidate:
                    plan.need(active == baseline, "baseline kernel changed")
            time.sleep(0.01)
        record["controller_end_anchor"] = service.record_clock_anchor()
        service_audit = n.receive(peer)
        client_audit = n.receive(client)
        plan.need(
            peer.wait(timeout=2) == 0 and client.wait(timeout=2) == 0,
            "peer process failed after horizon",
        )
        record.update(service_audit=service_audit, client_audit=client_audit)
        plan.need(
            event is not None
            and applied_receipt is not None
            and phase._read(g.BASE / "eve.json", 65536) == alert,
            "exact fixed decision/input coverage missing",
        )
        record["capture"], record["service_receipt"], record["service_binding"] = (
            service.service_capture(
                inputs["manifest"],
                inputs["assignment"],
                inputs["ticket"]["run_id"],
                inputs["safety"],
                origin_ns=origin,
                deadline_ns=deadline,
                client_origin_ns=client_origin,
                service=service_audit,
                client=client_audit,
                kernel_boot_id=kernel,
            )
        )
        if candidate:
            while release is None:
                plan.need(
                    time.monotonic_ns()
                    < record["alert_append_after_ns"] + 32_000_000_000
                    and observer_process.poll() is None,
                    "signed release/drain budget unavailable",
                )
                release = _released(reader.poll(), event)
                time.sleep(0.01)
        absent_receipt, absent = root_query(assets, "absence", manifest_sha, head)
        plan.need(absent == baseline, "owned rule remains or foreign chain changed")
        record.update(
            event=event,
            release=release,
            baseline_probe=baseline_receipt,
            active_probe=applied_receipt,
            absence_probe=absent_receipt,
        )
        n.command("systemctl", "stop", g.UNIT, timeout=2)  # Witness/observer stay live.
        observer_process.wait(timeout=2)  # Only natural terminal API drain, no signal.
        plan.need(observer_process.returncode == 0, "observer terminal drain failed")
        reader.poll(terminal=True)
        terminal_result = _json(
            Path(trust.data["journal_directory"]) / "observer-terminal-result.json",
            61002,
        )
        terminal = terminal_result["terminal"]
        final_position = dict(
            offset=len(reader.raw), sha256=hashlib.sha256(reader.raw).hexdigest()
        )
        plan.need(
            terminal_result["context"]["kernel_boot_id"] == kernel
            and terminal_result["context"]["scope_ref"] == trust.data["scope_ref"]
            and terminal_result["context"]["registration_sha256"]
            == trust.data["origin_registration_sha256"]
            and terminal["disposition"] == "verified_terminal_control_stop"
            and terminal["source_position_after"] == final_position
            and terminal["cursor_missed"] is True
            and terminal["measurement_completed"] is False
            and terminal["resume_authorized"] is False,
            "actual terminal control origin/cursor differs",
        )
        final_journal = read_regular(
            journal_path, owner=61002, max_bytes=trust.data["journal_max_bytes"]
        )[0]
        frames = lab.journal_frames(final_journal)
        cursors = [frame["data"] for frame in frames if frame["kind"] == "cursor"]
        plan.need(
            frames[-1]["kind"] == "session_close"
            and cursors[-1] == dict(position=final_position, missed=True)
            and terminal_result["witness_state"]["journal_head"] == frames[-1]["sha256"]
            and terminal_result["witness_state"]["source_sha256"]
            == final_position["sha256"],
            "actual terminal journal/witness close differs",
        )
        raw_calls = read_regular(
            Path(trust.data["journal_directory"]) / "actual-collector-calls.jsonl",
            owner=61002,
            max_bytes=recording.MAX_BYTES,
        )[0]
        calls = recording.decode_calls(raw_calls)
        reasons = (
            ["pending_window_lost_at_terminal"]
            if terminal["pending_windows_lost"]
            else []
        )
        decision_callback = _closed_callback(calls, event)
        release_callback = _closed_callback(calls, release) if candidate else None
        if decision_callback is None:
            reasons.append("actual_decision_callback_missing")
        if candidate and release_callback is None:
            reasons.append("actual_release_callback_missing")
        record["decision_callback_receipt_epoch"] = (
            decision_callback["epoch"] if decision_callback is not None else None
        )
        record["release_callback_receipt_epoch"] = (
            release_callback["epoch"] if release_callback is not None else None
        )
        record.update(
            observer_terminal=terminal_result,
            source_sha256=hashlib.sha256(reader.raw).hexdigest(),
            source_bytes=len(reader.raw),
            closed_call_chain_sha256=hashlib.sha256(raw_calls).hexdigest(),
            withheld_reasons=reasons,
        )
        lab.save(phase.WORK / "source-final.raw", reader.raw)
        result = dict(
            status="withheld" if reasons else "run_facts_complete",
            record=record,
            measurement_completed=False,
            production_admission=False,
        )
    except BaseException as exc:
        error = exc
    finally:
        # Persistence/close failure must never suppress the remaining actor stops,
        # child reap or log closes. All failures remain sticky; no result on gaps.
        if error is not None:
            try:
                lab.save(phase.WORK / "failure-source-observation.raw", reader.raw)
                n.write_new(
                    phase.WORK / "run-failure.json",
                    dict(
                        error=type(error).__name__,
                        partial_facts=record,
                        status="withheld",
                    ),
                )
            except BaseException as saved:
                error.add_note(
                    "Failure artifact persistence gap: " + type(saved).__name__
                )
        try:
            if assets is None:
                phase._failure_cleanup(error or RuntimeError("namespace reopen failed"))
            else:
                scope.close_namespaces_after_actors(assets, proof)
        except BaseException as cleanup:
            if error is None:
                error = cleanup
            else:
                error.add_note(
                    "Actor/namespace cleanup failure: " + type(cleanup).__name__
                )
        if observer_process is not None:
            try:
                observer_process.wait(timeout=2)
            except BaseException as reap:
                if error is None:
                    error = reap
                else:
                    error.add_note(
                        "Observer client reap failure: " + type(reap).__name__
                    )
                try:
                    observer_process.kill()
                    observer_process.wait(timeout=2)
                except BaseException as killed:
                    error.add_note(
                        "Owned observer client final reap failure: "
                        + type(killed).__name__
                    )
        for log in logs:
            try:
                log.close()
            except BaseException as closed:
                if error is None:
                    error = closed
                else:
                    error.add_note("Log close failure: " + type(closed).__name__)
    if error is not None:
        raise error
    n.write_new(phase.WORK / "run-facts.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root-query",
        nargs=2,
        required=True,
        metavar=("MANIFEST_SHA256", "START_HEAD"),
    )
    _query_worker(*parser.parse_args().root_query)
