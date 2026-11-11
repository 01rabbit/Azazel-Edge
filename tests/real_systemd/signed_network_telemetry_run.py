"""Explicit v2 assignment runtime; original signed facts, no admission/default hook."""

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
import sys
import time

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(SRC / "py"), str(SRC / "tests"), str(Path(__file__).parent)]
import signed_network_run as old
import signed_network_recording as recording
import signed_network_service as service
import signed_network_telemetry_live as observer
from azazel_edge.outcome.input_auth import TrustPolicy, read_regular
from azazel_edge.outcome.input_live import registration
from azazel_edge.outcome.postcondition import SubprocessReadOnlyRunner

phase, p, g, n, plan, lab, flow = (
    old.phase,
    old.p,
    old.g,
    old.n,
    old.plan,
    old.lab,
    old.flow,
)


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


def _callback(event, label, *, session, deadline_ns):
    """Retain every actual read FIRST; never synthesize END or discard a bad row."""
    plan.need(label in ("active", "absence"), "closed callback artifact kind required")
    path = g.BUNDLE / "observer/actual-collector-calls.jsonl"
    for index in range(512):
        plan.need(
            session.poll() is None and time.monotonic_ns() < deadline_ns,
            "actual callback wait budget unavailable",
        )
        before = time.monotonic_ns()
        raw, info = read_regular(path, owner=61002, max_bytes=recording.MAX_BYTES)
        after = time.monotonic_ns()
        lab.save(
            phase.WORK / (label + "-callback-observation-" + str(index) + ".raw"), raw
        )
        decoded = recording.decode_calls_prefix(raw)
        plan.need(
            not decoded["closed"],
            "observer recorder closed before required callback/query",
        )
        matches = [
            row
            for row in decoded["calls"]
            if row["kind"] == "event"
            and recording.canonical(row["data"]["event"]) == recording.canonical(event)
        ]
        plan.need(len(matches) <= 1, "duplicate actual matching callback")
        if matches:
            row = matches[0]
            plan.need(
                row["data"]["clock_after"]["monotonic_after_ns"] <= after < deadline_ns,
                "actual callback clock outside query budget",
            )
            receipt = dict(
                row=row,
                recording_identity=dict(
                    device=info.st_dev, inode=info.st_ino, uid=info.st_uid
                ),
                raw_sha256=hashlib.sha256(raw).hexdigest(),
                complete_sha256=hashlib.sha256(decoded["complete_prefix"]).hexdigest(),
                partial_tail_bytes=len(decoded["partial_tail"]),
                observed_before_ns=before,
                observed_after_ns=after,
            )
            lab.save(phase.WORK / (label + "-callback-prefix.raw"), raw)
            lab.save(
                phase.WORK / (label + "-callback-complete.raw"),
                decoded["complete_prefix"],
            )
            n.write_new(phase.WORK / (label + "-callback-ready.json"), receipt)
            return receipt
        time.sleep(0.01)
    plan.need(False, "callback observation bound exceeded")


def _query_worker(pins):
    from signed_network_telemetry_phase import validated_telemetry_inputs

    g.guard()
    plan.need(
        os.environ.get("EDGE_SIGNED_NETWORK_TELEMETRY") == "1" and os.geteuid() == 0,
        "explicit v2 Root query required",
    )
    inputs = validated_telemetry_inputs(**pins)
    prepared = old._json(phase.WORK / "prepared.json")
    records = [
        old.scope.load(path)
        for path in sorted(
            (phase.WORK / "namespace-evidence").glob("namespace-confirmed-*.json")
        )
    ]
    matched = [
        row
        for row in records
        if row["name"] == p.EDGE and row["state"] == "confirmed_created"
    ]
    namespace = os.stat("/proc/self/ns/net")
    plan.need(
        prepared["inputs"] == inputs
        and prepared["kernel_boot_id"] == g.boot()
        and len(matched) == 1
        and matched[0]["identity"]
        == dict(device=namespace.st_dev, inode=namespace.st_ino),
        "v2 Root query outside current owned namespace",
    )
    binary = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
    plan.need(binary is not None, "trusted nft unavailable")
    before = service.record_clock_anchor()
    result = SubprocessReadOnlyRunner().run(flow.QUERY, timeout_seconds=2)
    after = service.record_clock_anchor()
    print(
        json.dumps(
            dict(
                argv=list(result.argv),
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                query_started_at=datetime.fromtimestamp(
                    before["epoch_ns"] / 1e9, timezone.utc
                ).isoformat(),
                query_ended_at=datetime.fromtimestamp(
                    after["epoch_ns"] / 1e9, timezone.utc
                ).isoformat(),
                query_start_clock_anchor=before,
                query_end_clock_anchor=after,
                root_uid=os.geteuid(),
                root_pid=os.getpid(),
                kernel_boot_id=g.boot(),
                netns_inode=namespace.st_ino,
                source_identity=_source_identity(),
                nft_binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                capture_boundary="actual_root_SubprocessReadOnlyRunner_inside_owned_netns",
                source="live_root_query_recorded_once_for_pure_projection",
            )
        ),
        flush=True,
    )


def root_query(assets, label, pins, *, deadline_ns, callback=None, horizon_ns=None):
    plan.need(
        label in ("baseline", "active", "absence"), "closed v2 query kind required"
    )
    before = time.monotonic_ns()
    if callback is not None:
        plan.need(
            callback["observed_after_ns"] <= before,
            "Root query precedes retained actual callback",
        )
    child = assets.spawn(
        "edge",
        [
            g.PYTHON,
            "-I",
            "-B",
            Path(__file__).resolve(),
            "--telemetry-root-query",
            json.dumps(pins, sort_keys=True),
        ],
    )
    after = time.monotonic_ns()
    n.write_new(
        phase.WORK / (label + "-query-launch.json"),
        dict(
            actual_child_argv=list(map(str, child.args)),
            pid=child.pid,
            namespace_identity=dict(
                device=assets.created[p.EDGE][1], inode=assets.created[p.EDGE][2]
            ),
            launch_before_ns=before,
            launch_after_ns=after,
        ),
    )
    raw = bytearray()
    limit = min(before + 3_000_000_000, deadline_ns)
    try:
        while not raw.endswith(b"\n"):
            remaining = (limit - time.monotonic_ns()) / 1e9
            plan.need(
                remaining > 0 and select.select([child.stdout], [], [], remaining)[0],
                "v2 Root query absolute deadline",
            )
            chunk = os.read(
                child.stdout.fileno(), min(65536, 2 * 1024 * 1024 + 1 - len(raw))
            )
            raw.extend(chunk)
            plan.need(
                chunk and len(raw) <= 2 * 1024 * 1024, "Root query incomplete/oversized"
            )
        plan.need(time.monotonic_ns() < limit, "Root query capture deadline")
        child.wait(timeout=(limit - time.monotonic_ns()) / 1e9)
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
        "v2 Root query identity differs",
    )
    if callback is not None:
        data = callback["row"]["data"]
        plan.need(
            receipt["query_start_clock_anchor"]["monotonic_before_ns"]
            >= callback["observed_after_ns"],
            "query clock precedes actual callback",
        )
        start, end = (
            datetime.fromisoformat(receipt[k]).timestamp()
            for k in ("query_started_at", "query_ended_at")
        )
        plan.need(data["epoch"] <= start <= end, "query epoch precedes callback")
        if label == "active":
            plan.need(
                end <= data["epoch"] + 2
                and receipt["query_end_clock_anchor"]["monotonic_after_ns"]
                <= horizon_ns,
                "active Root query missed fixed post/H window",
            )
    n.write_new(phase.WORK / (label + "-query.json"), receipt)
    return receipt, flow.parse_readback(receipt["stdout"])


def run_telemetry_assignment(
    output,
    *,
    manifest_sha256,
    start_head,
    source_commit,
    archive_sha256,
    core_sha256,
    abi_sha256,
    interpreter_sha256,
):
    """One fixed v2 direct context; no JSON ownership, retry or v1 fallback."""
    from signed_network_telemetry_phase import prepare_telemetry_assignment

    pins = dict(
        manifest_sha256=manifest_sha256,
        start_head=start_head,
        source_commit=source_commit,
        archive_sha256=archive_sha256,
        core_sha256=core_sha256,
        abi_sha256=abi_sha256,
        interpreter_sha256=interpreter_sha256,
    )
    ctx = prepare_telemetry_assignment(output, **pins)
    error, result, signed = None, None, None
    record = {}
    try:
        record.update(
            kernel_boot_id=g.boot(),
            source_identity=_source_identity(),
            inputs=ctx.inputs,
        )
        n.write_new(
            phase.WORK / "run-intent.json",
            dict(
                inputs=ctx.inputs,
                kernel_boot_id=record["kernel_boot_id"],
                observer_runtime_seconds=40,
            ),
        )
        assets, inputs = ctx.namespaces.assets, ctx.inputs
        candidate = inputs["assignment"]["arm"] == "flow_throttle"
        trust = TrustPolicy.from_file(g.BUNDLE / "trust.json", role="witness")
        registered = registration(trust, g.BUNDLE / "origin.json")
        plan.need(
            registered["environment"]
            == plan.native_environment(inputs["assignment"]["arm"]),
            "registered v2 arm differs",
        )
        record["controller_start_anchor"] = service.record_clock_anchor()
        baseline_receipt, baseline = root_query(
            assets, "baseline", pins, deadline_ns=time.monotonic_ns() + 3_000_000_000
        )
        rules = [
            row["rule"]
            for row in baseline["nftables"]
            if type(row) is dict and "rule" in row
        ]
        plan.need(
            len(rules) == 1 and rules[0].get("comment") == assets.foreign,
            "independent initial foreign canary differs",
        )
        peer = assets.spawn(
            "service",
            [g.PYTHON, "-I", "-B", "-u", n.PEER, "service", inputs["ticket"]["run_id"]],
            stdin=True,
        )
        plan.need(
            n.receive(peer) == dict(kind="ready", nonce=inputs["ticket"]["run_id"]),
            "service peer readiness differs",
        )
        ctx.namespaces.edge()
        g.systemctl("start", g.UNIT)
        g.wait_for(lambda: len(g.Systemd().cores()) == 1)
        ctx.tracked[g.UNIT] = [lab.unit_snapshot(g.UNIT)]
        switch = g.Switch(g.BUNDLE)
        switch_plan = switch.plan()
        n.write_new(phase.WORK / "switch-plan.json", switch_plan)
        plan.need(
            switch.apply(switch_plan, g.digest(switch_plan))["status"] == "started",
            "sealed native start failed",
        )
        g.live()
        ctx.tracked[g.UNIT].append(lab.unit_snapshot(g.UNIT))
        signed = old.SignedSource(trust, record["kernel_boot_id"], candidate)
        signed.poll()
        plan.need(
            len(signed.events) == 2 and len(signed.raw) == len(signed.verifier.raw),
            "unused exact signed prefix required",
        )
        with observer.live(
            phase.WORK / "live", initialization=ctx.initialization, **ctx.args
        ) as session:
            ctx.owned.add(observer.role.OBSERVER_UNIT)
            runtime_end = session.client_launch_before_ns + 40_000_000_000
            record["live_client_launch"] = old._json(
                phase.WORK / "live/live-launch.json"
            )
            before = dict(
                offset=len(signed.raw), sha256=hashlib.sha256(signed.raw).hexdigest()
            )
            journal_path = (
                Path(trust.data["journal_directory"]) / "observations.journal"
            )
            ready_until = min(time.monotonic_ns() + 2_000_000_000, runtime_end)
            while True:
                plan.need(
                    session.poll() is None and time.monotonic_ns() < ready_until,
                    "actual observer input_ready missing/dead",
                )
                raw = read_regular(
                    journal_path, owner=61002, max_bytes=trust.data["journal_max_bytes"]
                )[0]
                if raw.endswith(b"\n") and lab.ready_for(raw, before):
                    break
                time.sleep(0.01)
            lab.save(phase.WORK / "input-ready-journal.raw", raw)
            context = old._json(
                Path(trust.data["journal_directory"]) / "observer-start-context.json",
                61002,
            )
            plan.need(
                context["source_start_position"] == before
                and context["kernel_boot_id"] == record["kernel_boot_id"]
                and context["scope_ref"] == trust.data["scope_ref"]
                and context["registration_sha256"]
                == trust.data["origin_registration_sha256"],
                "actual observer startup origin differs",
            )
            origin = time.monotonic_ns()
            deadline, client_origin = origin + 5_000_000_000, origin + 1_250_000_000
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
                    "-B",
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
                "client missed first fixed request",
            )
            alert, event, applied_receipt, release = None, None, None, None
            decision_callback, release_callback = None, None
            while time.monotonic_ns() < deadline:
                plan.need(
                    session.poll() is None and time.monotonic_ns() < runtime_end,
                    "observer/client runtime budget unavailable",
                )
                plan.need(
                    (peer.poll() is None and client.poll() is None)
                    or time.monotonic_ns() >= deadline,
                    "peer ended before H",
                )
                if alert is None and time.monotonic_ns() >= client_origin:
                    plan.need(
                        phase._read(g.BASE / "eve.json", 65536) == b"",
                        "EVE was not fresh",
                    )
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
                event = old._decision(signed.poll(), candidate) or event
                plan.need(
                    event is None or alert is not None,
                    "signed decision preceded actual fixed input",
                )
                if event is not None and applied_receipt is None:
                    decision_callback = _callback(
                        event,
                        "active",
                        session=session,
                        deadline_ns=min(deadline, runtime_end),
                    )
                    call = decision_callback["row"]["data"]
                    plan.need(
                        call["clock_before"]["monotonic_before_ns"]
                        >= origin + 1_000_000_000
                        and call["clock_after"]["monotonic_after_ns"] + 2_000_000_000
                        <= deadline,
                        "callback pre/post windows outside actual H",
                    )
                    applied_receipt, active = root_query(
                        assets,
                        "active",
                        pins,
                        deadline_ns=min(deadline, runtime_end),
                        callback=decision_callback,
                        horizon_ns=deadline,
                    )
                    if candidate:
                        plan.need(
                            flow.readback_matches(
                                active, old.from_rust_event(event).execution.scope
                            ),
                            "full owned flow rule not observed",
                        )
                    owner = event["enforcement"]["metadata"].get(
                        "release_owner_token", ""
                    )
                    plan.need(
                        old._without_owner(active, owner) == baseline
                        and (candidate or active == baseline),
                        "foreign chain/baseline changed",
                    )
                time.sleep(0.01)
            record["controller_horizon_end_anchor"] = service.record_clock_anchor()
            service_audit = n.receive(peer)
            old._persist_peer_audit(record, "service_audit", service_audit)
            client_audit = n.receive(client)
            old._persist_peer_audit(record, "client_audit", client_audit)
            plan.need(
                peer.wait(timeout=2) == 0 and client.wait(timeout=2) == 0,
                "peer terminal audit/process incomplete",
            )
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
                    kernel_boot_id=record["kernel_boot_id"],
                )
            )
            if candidate:
                while release is None:
                    plan.need(
                        time.monotonic_ns()
                        < min(
                            runtime_end,
                            record["alert_append_after_ns"] + 32_000_000_000,
                        )
                        and session.poll() is None,
                        "signed TTL release/runtime budget unavailable",
                    )
                    release = old._released(signed.poll(), event)
                    time.sleep(0.01)
                release_callback = _callback(
                    release,
                    "absence",
                    session=session,
                    deadline_ns=min(
                        runtime_end, record["alert_append_after_ns"] + 32_000_000_000
                    ),
                )
            absent_receipt, absent = root_query(
                assets,
                "absence",
                pins,
                deadline_ns=runtime_end,
                callback=release_callback,
            )
            plan.need(absent == baseline, "owned rule remains or foreign chain changed")
            record["controller_end_anchor"] = service.record_clock_anchor()
            record.update(
                event=event,
                release=release,
                baseline_probe=baseline_receipt,
                active_probe=applied_receipt,
                absence_probe=absent_receipt,
                decision_callback_receipt_epoch=decision_callback["row"]["data"][
                    "epoch"
                ],
                release_callback_receipt_epoch=release_callback["row"]["data"]["epoch"]
                if release_callback
                else None,
            )
            plan.need(
                time.monotonic_ns() < runtime_end,
                "no remaining conservative observer-client budget",
            )
            n.command(
                "systemctl",
                "stop",
                g.UNIT,
                timeout=min(2, (runtime_end - time.monotonic_ns()) / 1e9),
            )
        record["observer_helper_return_ns"] = time.monotonic_ns()
        plan.need(
            record["observer_helper_return_ns"] <= runtime_end,
            "natural observer cleanup exceeded conservative client budget",
        )
        plan.need(
            session.result is not None, "natural terminal/live cleanup incomplete"
        )
        signed.poll(terminal=True)
        terminal_result = session.result["terminal"]
        raw_calls = read_regular(
            g.BUNDLE / "observer/actual-collector-calls.jsonl",
            owner=61002,
            max_bytes=recording.MAX_BYTES,
        )[0]
        calls = recording.decode_calls(raw_calls)
        reasons = (
            ["pending_window_lost_at_terminal"]
            if terminal_result["terminal"]["pending_windows_lost"]
            else []
        )
        plan.need(
            old._closed_callback(calls, event) is not None
            and (not candidate or old._closed_callback(calls, release) is not None),
            "final actual callback disappeared",
        )
        record.update(
            observer_terminal=terminal_result,
            source_sha256=hashlib.sha256(signed.raw).hexdigest(),
            source_bytes=len(signed.raw),
            closed_call_chain_sha256=hashlib.sha256(raw_calls).hexdigest(),
            withheld_reasons=reasons,
        )
        lab.save(phase.WORK / "source-final.raw", signed.raw)
        result = dict(
            status="withheld" if reasons else "run_facts_complete",
            record=record,
            measurement_completed=False,
            production_admission=False,
        )
    except BaseException as exc:
        error = exc
    finally:
        if error is not None:
            try:
                if signed is not None:
                    lab.save(phase.WORK / "failure-source-observation.raw", signed.raw)
                n.write_new(
                    phase.WORK / "run-failure.json",
                    dict(
                        error=type(error).__name__,
                        partial_facts=record,
                        status="withheld",
                    ),
                )
            except BaseException as saved:
                error.add_note("Failure evidence: " + type(saved).__name__)
        try:
            ctx.close()
        except BaseException as cleanup:
            if error is None:
                error = cleanup
            else:
                error.add_note("Owned context cleanup: " + type(cleanup).__name__)
    if error is not None:
        raise error
    n.write_new(phase.WORK / "run-facts.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--telemetry-root-query", required=True)
    _query_worker(plan.strict(parser.parse_args().telemetry_root_query))
