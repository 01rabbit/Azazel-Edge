"""Read-only fixed-layout signed-lab import; never measurement/admission authority."""

import hashlib
from pathlib import Path

import signed_network_phase as phase
import signed_network_run as run
import signed_network_recording as recording
import signed_network_service as service
from signed_network_clock import qualify_clock
from azazel_edge.outcome.input_auth import (
    TrustPolicy,
    SourceVerifier,
    read_regular,
    verify_signature,
)
from azazel_edge.outcome.input_live import registration
from azazel_edge.outcome.input_service import layout
from azazel_edge.outcome.input_terminal import TerminalControlStop
from azazel_edge.outcome.input_witness import (
    ANCHOR_DOMAIN,
    MESSAGE_BYTES,
    digest,
    validate_state,
)
from azazel_edge.outcome.journal import ZERO_HASH, META, _json, _outcome
from azazel_edge.outcome.telemetry import persistence_context

need, strict, lab, n, g = (
    phase.plan.need,
    phase.plan.strict,
    phase.lab,
    phase.n,
    phase.g,
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def witnessed_prefixes(trust, source, journal, anchors, journal_info):
    """Verify original signed anchor chain against every actual byte prefix.

    Pure byte validation using the existing public signature verifier. No key
    material, WitnessStore/client, journal reopen, socket or filesystem writes.
    The explicit smaller import limits bound full-prefix hashing cost.
    """
    need(
        0 < len(source) <= 4 * 1024 * 1024 and source.count(b"\n") <= 512,
        "readonly source import bound",
    )
    need(
        0 < len(journal) <= 8 * 1024 * 1024 and journal.count(b"\n") <= 4096,
        "readonly journal import bound",
    )
    need(
        0 < len(anchors) <= min(trust.data["anchor_max_bytes"], 8 * 1024 * 1024)
        and anchors.endswith(b"\n")
        and anchors.count(b"\n") <= min(trust.data["anchor_max_records"], 4097),
        "readonly anchor import bound",
    )
    verifier = SourceVerifier(trust)
    verifier.verify(source)  # Signature/native lifecycle verification ONCE.
    tips = {0: dict(seq=0, head=ZERO_HASH, size=0, sha256=sha(b""))}
    offset, prefix_hash = 0, hashlib.sha256()
    for line in source.splitlines(keepends=True):
        offset += len(line)
        prefix_hash.update(line)
        wire = strict(line)  # Already authenticated by the complete verifier.
        tips[offset] = dict(
            seq=wire["seq"],
            head=digest(wire),
            size=offset,
            sha256=prefix_hash.hexdigest(),
        )
    frames = lab.journal_frames(journal)
    prefixes = {0: (0, ZERO_HASH, sha(b""))}
    offset, prefix_hash = 0, hashlib.sha256()
    for frame, line in zip(frames, journal.splitlines(keepends=True)):
        need(
            type(frame["seq"]) is int
            and len(line) <= 65536
            and _json(frame) + b"\n" == line,
            "canonical bounded journal frame",
        )
        offset += len(line)
        prefix_hash.update(line)
        prefixes[offset] = (frame["seq"], frame["sha256"], prefix_hash.hexdigest())
    head, previous = ZERO_HASH, None
    for counter, line in enumerate(anchors.splitlines(keepends=True), 1):
        need(len(line) <= MESSAGE_BYTES, "anchor frame bound")
        wire = strict(line)
        need(
            type(wire) is dict
            and set(wire)
            == {
                "schema_version",
                "counter",
                "prev",
                "trust_sha256",
                "state",
                "signature",
            },
            "anchor fields",
        )
        core = {k: v for k, v in wire.items() if k != "signature"}
        need(
            _json(wire) + b"\n" == line
            and wire["schema_version"] == "outcome-input-anchor/v1"
            and type(wire["counter"]) is int
            and wire["counter"] == counter
            and wire["prev"] == head
            and wire["trust_sha256"] == trust.digest,
            "anchor chain/context",
        )
        verify_signature(
            trust.data["witness_public_key"], wire["signature"], ANCHOR_DOMAIN, core
        )
        state = validate_state(wire["state"])
        j, s = prefixes.get(state["journal_size"]), tips.get(state["source_size"])
        need(
            j is not None
            and s is not None
            and j
            == (state["journal_seq"], state["journal_head"], state["journal_sha256"])
            and all(
                s[k] == state["source_" + k] for k in ("seq", "head", "size", "sha256")
            ),
            "anchor exact prefixes differ",
        )
        if previous is None:
            need(state["journal_seq"] == state["source_seq"] == 0, "anchor genesis")
        else:
            need(
                state["journal_seq"] == previous["journal_seq"] + 1
                and state["source_seq"] >= previous["source_seq"],
                "anchor progression",
            )
        if state["journal_seq"]:
            need(
                (state["journal_device"], state["journal_inode"])
                == (journal_info.st_dev, journal_info.st_ino),
                "anchor journal identity",
            )
        previous, head = state, digest(wire)
    need(
        previous["journal_size"] == len(journal)
        and previous["source_size"] == len(source),
        "anchor final prefix incomplete",
    )
    return frames, verifier, previous


def terminal_chain(trust, source, frames, verifier, result, wire, decoded):
    """Bind original terminal bytes and every durable cursor without observing it."""
    d, context = trust.data, result["context"]
    events = [strict(line)["event"] for line in source.splitlines()]
    kernel = context["kernel_boot_id"]
    need(
        context["boot_ref"] == n.boot_reference(kernel)
        and context["signed_boot_ref"] == kernel.replace("-", "")
        and all(
            strict(line)["boot_ref"] == context["signed_boot_ref"]
            for line in source.splitlines()
        )
        and context["scope_ref"] == d["scope_ref"]
        and context["registration_sha256"] == d["origin_registration_sha256"],
        "terminal context",
    )
    need(
        verifier.live_state.closed
        and source.endswith(wire)
        and wire.count(b"\n") == 1
        and SourceVerifier.unwrap(wire) == decoded,
        "terminal original wire",
    )
    event = strict(decoded)
    need(
        event == events[-1]
        and event["pipeline"] == "rust_live_origin_v1"
        and event["source"] == "rust_core"
        and event["capture_lifecycle"] == {"state": "end"}
        and event["capture_origin"]["kind"] == "session_end",
        "normal terminal required",
    )
    before = dict(offset=len(source) - len(wire), sha256=sha(source[: -len(wire)]))
    after = dict(offset=len(source), sha256=sha(source))
    lost = [f for f in frames if f["kind"] == "lost"]
    expected = TerminalControlStop(
        d["origin_registration_sha256"],
        verifier.live_state.session,
        verifier.live_state.seq,
        before,
        after,
        wire,
        decoded,
        len(lost),
    ).to_dict()
    need(
        recording.canonical(result["terminal"]) == recording.canonical(expected),
        "terminal receipt differs",
    )
    cursors = [f["data"] for f in frames if f["kind"] == "cursor"]
    need(
        frames[-1]["kind"] == "session_close"
        and cursors[-1] == dict(position=after, missed=True),
        "terminal durable cursor/close",
    )
    for frame in frames:
        if frame["kind"] in ("cursor", "input_ready"):
            pos = (
                frame["data"]["position"]
                if frame["kind"] == "cursor"
                else frame["data"]
            )
            size = pos["offset"]
            need(
                type(size) is int
                and 0 <= size <= len(source)
                and (size == 0 or source[size - 1 : size] == b"\n")
                and pos["sha256"] == sha(source[:size]),
                "journal cursor prefix",
            )
    positions, offset = [], 0
    for line in source.splitlines(keepends=True):
        offset += len(line)
        positions.append(dict(offset=offset, sha256=sha(source[:offset])))
    need(
        [row["position"] for row in cursors] == positions,
        "exact ordered full source cursor coverage",
    )
    for row, original in zip(cursors, events):
        need(
            type(row["missed"]) is bool
            and row["missed"] is (original.get("pipeline") == "rust_live_origin_v1"),
            "activity missed or control observed",
        )
    start = positions[1]
    need(
        context["source_start_position"] == start
        and [f["data"] for f in frames if f["kind"] == "input_ready"]
        == [dict(offset=0, sha256=sha(b"")), start]
        and [f["data"] for f in frames if f["kind"] == "session_open"]
        == [dict(boot_id=n.boot_reference(kernel))] * 2
        and sum(f["kind"] == "session_close" for f in frames) == 2
        and frames[0]["kind"] == "header"
        and sum(f["kind"] == "header" for f in frames) == 1
        and all(
            f["kind"]
            in {
                "header",
                "session_open",
                "session_close",
                "cursor",
                "input_ready",
                "begin",
                "commit",
                "lost",
            }
            for f in frames
        ),
        "fresh initialization/live journal lifecycle differs",
    )
    need(
        [
            e["capture_origin"]["kind"]
            for e in events
            if e.get("pipeline") == "rust_live_origin_v1"
        ]
        == ["session_prepare", "session_start", "session_end"],
        "exact single signed session",
    )
    pending, committed = {}, set()
    active, recovering = False, False
    position = dict(offset=0, sha256=sha(b""))
    for frame in frames:
        kind, data = frame["kind"], frame["data"]
        if kind == "header":
            continue  # Unique first header is checked above and fully bound by caller.
        if kind == "session_open":
            need(
                not active and data == {"boot_id": n.boot_reference(kernel)},
                "invalid journal session open",
            )
            active, recovering = True, True
            continue
        need(active, "journal transition outside active session")
        if kind == "session_close":
            need(
                data == {"boot_id": n.boot_reference(kernel)} and not pending,
                "invalid journal clean close",
            )
            active = False
            continue
        if kind == "cursor":
            need(not recovering or data["missed"] is True, "observed recovery cursor")
            position = data["position"]
        elif kind == "input_ready":
            need(recovering and data == position, "invalid journal recovery fence")
            recovering = False
        elif kind == "begin":
            need(
                not recovering and data["boot_id"] == n.boot_reference(kernel),
                "begin outside ready boot-bound session",
            )
        if kind in ("begin", "commit"):
            data = frame["data"]
            key = (data["execution_id"], data["objective_id"])
            meta = {name: data[name] for name in META}
            if frame["kind"] == "begin":
                need(
                    key not in pending and key not in committed,
                    "duplicate pending identity",
                )
                pending[key] = meta
            else:
                need(
                    pending.pop(key, None) == meta and key not in committed,
                    "commit without exact original begin",
                )
                _outcome(data["outcome"])
                committed.add(key)
    need(
        not active and not pending and not lost,
        "pending/lost windows remain unavailable",
    )
    return events


class _Snapshot:
    def __init__(self, result):
        self.result, self.files = result, {}

    def raw(self, path, owner=0, maximum=8 * 1024 * 1024):
        path = Path(path)
        raw, info = read_regular(path, owner=owner, max_bytes=maximum)
        self.result["raw_sha256"][str(path)] = dict(sha256=sha(raw), bytes=len(raw))
        if path in self.files:
            old = self.files[path]
            need(
                raw == old[2]
                and (info.st_dev, info.st_ino) == (old[3].st_dev, old[3].st_ino),
                "artifact changed between readonly reads",
            )
        self.files[path] = (owner, maximum, raw, info)
        return raw, info

    def json(self, path, owner=0, maximum=8 * 1024 * 1024):
        return strict(self.raw(path, owner, maximum)[0])

    def unchanged(self):
        for path, (owner, maximum, raw, before) in self.files.items():
            current, after = read_regular(path, owner=owner, max_bytes=maximum)
            need(
                current == raw
                and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                "artifact changed during readonly import",
            )


def _root_probes(snap, record, inputs, event, candidate):
    proof = snap.json(phase.WORK / "namespace-boot.json", maximum=8192)
    need(
        proof["kernel_boot_id"] == record["kernel_boot_id"]
        and proof["names"] == phase.scope.names(),
        "original namespace boot",
    )
    confirmed = []
    for index in (1, 2, 3):
        row = snap.json(phase.WORK / f"namespace-confirmed-{index}.json", maximum=8192)
        intent = snap.json(phase.WORK / f"namespace-intent-{index}.json", maximum=8192)
        need(
            row["state"] == "confirmed_created"
            and intent == dict(name=row["name"], state="creation_intent"),
            "namespace original intent",
        )
        confirmed.append(row)
    need(
        {row["name"] for row in confirmed} == set(phase.scope.names().values())
        and len(
            {(row["identity"]["device"], row["identity"]["inode"]) for row in confirmed}
        )
        == 3,
        "namespace identities incomplete/duplicate",
    )
    edge = next(row["identity"] for row in confirmed if row["name"] == phase.p.EDGE)
    parsed, probes = {}, {}
    for label, key in (
        ("baseline", "baseline_probe"),
        ("active", "active_probe"),
        ("absence", "absence_probe"),
    ):
        receipt = snap.json(phase.WORK / (label + "-query.json"))
        launch = snap.json(phase.WORK / (label + "-query-launch.json"), maximum=8192)
        need(
            recording.canonical(receipt) == recording.canonical(record[key])
            and launch["namespace_identity"] == edge
            and launch["pid"] == receipt["root_pid"]
            and record["source_identity"] == run._source_identity(),
            "root raw launch/pin binding",
        )
        probes[label] = service.recorded_root_probe(
            receipt,
            event=event,
            kernel_boot_id=record["kernel_boot_id"],
            namespace_inode=edge["inode"],
            source_identity=record["source_identity"],
        )
        parsed[label] = run.flow.parse_readback(receipt["stdout"])
    baseline, active, absent = (parsed[k] for k in ("baseline", "active", "absence"))
    rules = [row["rule"] for row in baseline["nftables"] if "rule" in row]
    need(
        len(rules) == 1
        and rules[0].get("comment") == proof["foreign"]
        and absent == baseline,
        "foreign context/release absence differs",
    )
    owner = event["enforcement"]["metadata"].get("release_owner_token", "")
    if candidate:
        need(
            run.flow.readback_matches(
                active, run.from_rust_event(event).execution.scope
            )
            and run._without_owner(active, owner) == baseline,
            "full owned flow mismatch",
        )
    else:
        need(active == baseline, "baseline kernel changed")
    return probes["active"]


def _require_ordered_callbacks(calls, events):
    # Compare ALL original signed activities, including intermediate release
    # attempts. Python numeric equality would admit bool/int/float substitutions.
    actual = [row["data"]["event"] for row in calls["calls"] if row["kind"] == "event"]
    signed = [
        event
        for event in events
        if event.get("pipeline") in ("rust_event_engine_v1", "rust_release_engine_v1")
    ]
    need(
        recording.canonical(actual) == recording.canonical(signed),
        "exact ordered signed callback coverage",
    )


def read_assignment_artifacts(expected_manifest_sha256, expected_start_head):
    """Read only the protected original guest layout; never run a four-run analysis.

    External Root archive verification remains mandatory. This importer is not
    resistance to a malicious root producing fabricated unsigned lab receipts.
    Original service/live facts survive later authentication/calculation failure.
    """
    result = dict(
        status="withheld",
        reasons=[],
        raw_sha256={},
        independent_service_facts={},
        live_outcomes=[],
        live_outcomes_authentication="unverified_retained_facts",
        root_projection=None,
        measurement_record=None,
        measurement_completed=False,
        production_admission=False,
        resume_authorized=False,
    )
    snap = _Snapshot(result)
    for name in ("service", "client"):
        try:
            result["independent_service_facts"][name] = snap.json(
                phase.WORK / (name + "-audit.json")
            )
        except Exception as exc:
            result["reasons"].append(name + "_audit:" + type(exc).__name__)
    # Retain bounded original live facts even if run-facts is missing/withheld.
    # Fixed layout only: do not use an unverified trust JSON as a path importer.
    try:
        live_raw = snap.raw(g.BUNDLE / "observer/observations.journal", 61002)[0]
        result["live_outcomes"] = [
            f["data"]["outcome"]
            for f in lab.journal_frames(live_raw)
            if f["kind"] == "commit"
        ]
    except Exception as exc:
        result["reasons"].append("live_journal:" + type(exc).__name__)
    try:
        raw = snap.raw(
            g.BUNDLE / "observer/actual-collector-calls.jsonl",
            61002,
            recording.MAX_BYTES,
        )[0]
        result["actual_recorded_calls"] = recording.decode_calls(raw)
    except Exception as exc:
        result["reasons"].append("actual_calls:" + type(exc).__name__)
    try:
        inputs = phase.validated_inputs(expected_manifest_sha256, expected_start_head)
        prepared = snap.json(phase.WORK / "prepared.json")
        facts = snap.json(phase.WORK / "run-facts.json")
        record = facts["record"]
        need(
            prepared["inputs"] == record["inputs"] == inputs
            and prepared["kernel_boot_id"] == record["kernel_boot_id"]
            and facts["status"] == "run_facts_complete"
            and facts["measurement_completed"] is False
            and facts["production_admission"] is False
            and record["withheld_reasons"] == [],
            "successful frozen run facts missing",
        )
        trust = TrustPolicy(snap.json(g.BUNDLE / "trust.json", maximum=16384))
        snap.raw(g.BUNDLE / "origin.json", maximum=16384)
        layout(g.BUNDLE, trust)  # Public paths only; never service.verify/key reads.
        enrolled = registration(trust, g.BUNDLE / "origin.json")
        need(
            enrolled["schema_version"] == "outcome-live-origin-registration/v4"
            and enrolled["mode"] == "live-core"
            and dict(trust.data) == prepared["trust_policy"]
            and enrolled == prepared["registration"]
            and enrolled["environment"]
            == phase.plan.native_environment(inputs["assignment"]["arm"])
            and enrolled["binary_sha256"] == inputs["core_sha256"],
            "registered public origin differs",
        )
        d, directory = trust.data, Path(trust.data["journal_directory"])
        need(
            d["producer_uid"] == 61001
            and d["observer_uid"] == 61002
            and d["witness_uid"] == 0,
            "fixed role identities required",
        )
        source, source_info = snap.raw(d["source_path"], 61001, 4 * 1024 * 1024)
        need(
            snap.raw(phase.WORK / "source-final.raw", maximum=4 * 1024 * 1024)[0]
            == source,
            "original source snapshot differs",
        )
        journal, journal_info = snap.raw(directory / "observations.journal", 61002)
        # Retain unchanged live Outcome facts even if later authenticity fails.
        frames = lab.journal_frames(journal)
        result["live_outcomes"] = [
            f["data"]["outcome"] for f in frames if f["kind"] == "commit"
        ]
        for value in result["live_outcomes"]:
            _outcome(value)
        if result["live_outcomes"]:
            exported = snap.raw(directory / "outcomes.jsonl", 61002, 1024 * 1024)[0]
            need(exported.endswith(b"\n"), "incomplete original live output")
            rows = [strict(line) for line in exported.splitlines()]
            need(
                all(
                    row["collector_mode"] == "passive_g3"
                    and row["effect_assessment"] is None
                    for row in rows
                )
                and recording.canonical([row["outcome"] for row in rows])
                == recording.canonical(result["live_outcomes"]),
                "live output/journal differs",
            )
        terminal = snap.json(directory / "observer-terminal-result.json", 61002)
        anchors = snap.raw(Path(d["anchor_directory"]) / "anchors.journal")[0]
        frames, verifier, state = witnessed_prefixes(
            trust, source, journal, anchors, journal_info
        )
        need(
            state == terminal["witness_state"]
            and terminal == record["observer_terminal"],
            "signed witness acknowledgement differs",
        )
        result["live_outcomes_authentication"] = (
            "original_signed_witness_prefix_verified"
        )
        events = terminal_chain(
            trust,
            source,
            frames,
            verifier,
            terminal,
            snap.raw(directory / "terminal.wire", 61002)[0],
            snap.raw(directory / "terminal.decoded", 61002)[0],
        )
        context = terminal["context"]
        result["authenticated_origin"] = dict(
            assignment_id=inputs["assignment"]["id"],
            kernel_boot_id=record["kernel_boot_id"],
            session_ref=verifier.live_state.session,
            scope_ref=d["scope_ref"],
            registration_sha256=d["origin_registration_sha256"],
            producer_public_key=d["producer_public_key"],
            witness_public_key=d["witness_public_key"],
        )
        payload, policy, policy_file_sha = phase.observer.policy_material()
        config = frames[0]["data"]
        need(
            config
            == dict(
                schema_version="outcome-observation-journal/v3",
                scope_ref=d["scope_ref"],
                policy_sha256=sha(persistence_context(policy, "es", 0.25).encode()),
                max_identities=4096,
                max_bytes=d["journal_max_bytes"],
                input_config=dict(
                    path_sha256=sha(d["source_path"].encode()),
                    device=source_info.st_dev,
                    inode=source_info.st_ino,
                    uid=61001,
                    max_bytes=d["input_max_bytes"],
                    max_records=d["input_max_records"],
                    authentication=trust.binding(),
                ),
            )
            and context["policy_sha256"] == recording.manifest_digest(payload)
            and context["policy_file_sha256"] == policy_file_sha
            and context["kernel_boot_id"] == record["kernel_boot_id"],
            "journal policy/source binding",
        )
        candidate = inputs["assignment"]["arm"] == "flow_throttle"
        event = run._decision(events, candidate)
        release = run._released(events, event) if candidate else None
        need(
            event == record["event"] and release == record["release"],
            "signed provider facts differ",
        )
        raw_calls = snap.raw(
            directory / "actual-collector-calls.jsonl", 61002, recording.MAX_BYTES
        )[0]
        calls = recording.decode_calls(raw_calls)
        need(
            sha(raw_calls) == record["closed_call_chain_sha256"]
            and sha(source) == record["source_sha256"]
            and len(source) == record["source_bytes"],
            "original byte hashes differ",
        )
        for original, key in ((event, "decision"), (release, "release")):
            if original is not None:
                callback = run._closed_callback(calls, original)
                need(
                    callback is not None
                    and callback["epoch"] == record[key + "_callback_receipt_epoch"],
                    "actual signed callback/epoch missing",
                )
        _require_ordered_callbacks(calls, events)
        clock = qualify_clock(
            kernel_boot_id=record["kernel_boot_id"],
            observer_boot_id=context["kernel_boot_id"],
            controller_boot_id=record["kernel_boot_id"],
            observer_start=context["clock_anchor"],
            observer_end=terminal["end_clock_anchor"],
            controller_start=record["controller_start_anchor"],
            controller_end=record["controller_end_anchor"],
            recorded=calls,
        )
        result["clock_qualification"] = clock
        need(
            clock["status"] == "qualified"
            and record["controller_start_anchor"]["monotonic_after_ns"]
            <= record["origin_ns"]
            and record["controller_end_anchor"]["monotonic_before_ns"]
            >= record["deadline_ns"],
            "actual clock/horizon qualification withheld",
        )
        capture, receipt, binding = service.service_capture(
            inputs["manifest"],
            inputs["assignment"],
            inputs["ticket"]["run_id"],
            inputs["safety"],
            origin_ns=record["origin_ns"],
            deadline_ns=record["deadline_ns"],
            client_origin_ns=record["client_origin_ns"],
            service=result["independent_service_facts"]["service"],
            client=result["independent_service_facts"]["client"],
            kernel_boot_id=record["kernel_boot_id"],
        )
        need(
            (capture, receipt, binding)
            == (
                record["capture"],
                record["service_receipt"],
                record["service_binding"],
            ),
            "independent service capture differs",
        )
        stop = snap.json(phase.WORK / "systemd-stop-receipt.json")
        need(
            stop["status"] == "verified_stopped"
            and stop["failures"] == []
            and [a["unit"] for a in stop["actors"]] == list(phase.scope.ACTOR_UNITS),
            "actor cleanup receipt gap",
        )
        for actor in stop["actors"]:
            after = actor["after"]
            need(
                after["ActiveState"] in ("inactive", "failed")
                and after["MainPID"] == after["ControlPID"] == "0"
                and type(actor["stop_returncode"]) is int,
                "actor stop facts inconsistent",
            )
            if actor["stop_returncode"]:
                need(
                    phase.scope._known_collected(actor["before"])
                    and phase.scope._known_collected(after),
                    "collected actor exception differs",
                )
        probe = _root_probes(snap, record, inputs, event, candidate)
        need(
            probe["epoch"] >= record["decision_callback_receipt_epoch"],
            "root probe precedes actual callback",
        )
        projection = recording.replay_calls(
            calls,
            policy=payload,
            boot=n.boot_reference(record["kernel_boot_id"]),
            root_probe=probe if candidate else None,
        )
        result["root_projection"] = projection
        need(
            recording.canonical(projection["live_outcomes"])
            == recording.canonical(result["live_outcomes"]),
            "original journal/collector Outcomes differ",
        )
        result["measurement_record"] = service.measurement_record(
            inputs["manifest"],
            inputs["assignment"],
            capture=capture,
            projection=projection,
            event=event,
            kernel_boot_id=record["kernel_boot_id"],
            session_ref=service.native_session_reference(verifier.live_state.session),
            clock=service.clock_binding(
                context["clock_anchor"],
                record["controller_start_anchor"],
                record["origin_ns"],
            ),
            confounders=[],
        )
        snap.unchanged()
        need(not result["reasons"], "partial independent service facts")
        result["status"] = "calculation_available"
    except Exception as exc:
        result["reasons"].append(type(exc).__name__ + ":" + str(exc)[:160])
        result["measurement_record"] = None
    return result
