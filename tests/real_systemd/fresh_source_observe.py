"""Prospective fresh signed Source experiment; unchanged enforcing lab roles."""

import copy
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import secrets
import sys
import threading
import time

import native_accounting as accounting
import finite_load_cost as old
from finite_ingress import FiniteIngressLab
from native_close_receipts import stable_read
from signed_network_recording import _clock_anchor, decode_calls_prefix

PROTOCOL_NAME = "fresh-source-observe-protocol-v1.json"
PROTOCOL_SHA256 = "f12b5d79b277856251ee674994e5a3527cb07c7ae2c161ebf9241a73c3488bf2"
RECIPE_SHA256 = "46d83e1ea8551a5010f37a45a76044d81ce15d3e8a8e1196ed4d3114fa7da1ea"
CASES = ("fresh-controls", "fresh-interrupted")
SIDE_FILES = dict(old.SIDE_FILES, input_calls="observer-input-calls.raw")
POLICY_PATH = old.POLICY_PATH
HELPER = Path(__file__).with_name("fresh_source_observer.py")
RECORDING_HELPER = Path(__file__).with_name("fresh_source_recording.py")


class FreshObserverProcess(old.ObserverProcess):
    role_mode = "fresh-source"
    bootstrap_schema = "edge-fresh-source-observer-bootstrap/v1"
    go_schema = "edge-fresh-source-observer-go/v1"
    side_files = SIDE_FILES


class FreshObserverProcessV2(FreshObserverProcess):
    role_mode = "fresh-source-v2"
    bootstrap_schema = "edge-fresh-source-observer-bootstrap/v2"
    go_schema = "edge-fresh-source-observer-go/v2"
    side_files = dict(SIDE_FILES, publication="observer-publication.raw")


def audit_role(g, role_command, create=False, *, version=1):
    assert type(version) is int and version in (1, 2)
    actor, failure = None, None
    try:
        process_type = FreshObserverProcess if version == 1 else FreshObserverProcessV2
        actor = process_type(g, role_command, create=create)
        out = actor.wait()
        assert (
            actor.process.returncode == 0
            and actor.receipt["exit"]["ExecMainCode"] == "1"
            and actor.receipt["exit"]["ExecMainStatus"] == "0"
        )
        status = json.loads(out)["status"]
        assert status["committed"] == 0
        return status, actor.receipt
    except BaseException as error:
        failure = error
        actor = actor or getattr(error, "observer_process", None)
        if actor is not None:
            try:
                actor.terminate_and_wait()
            except BaseException as cleanup:
                g.record(
                    "fresh-source-audit-stop-failure", error=old.error_value(cleanup)
                )
            actor.retain_drains()
            g.record(
                "fresh-source-audit-failure",
                receipt=actor.receipt,
                stdout=actor.stdout.decode(errors="replace"),
                stderr=actor.stderr.decode(errors="replace"),
            )
        raise
    finally:
        if actor is not None:
            actor.close(failure)


def input_prefix(raw, *, version=1):
    """Verify complete original context rows; never repair an interrupted tail."""
    rows, tail = old._rows(
        raw,
        f"edge-fresh-input-record/v{version}",
        limit=4 * 1024 * 1024,
        max_rows=256,
        allow_partial=True,
    )
    return rows, tail


class FreshSourceObserveLab(old.FiniteLoadCostLab):
    version = 1
    protocol_name = PROTOCOL_NAME
    protocol_digest = PROTOCOL_SHA256
    public_name = "fresh-source-observe-public"
    core_module = "azazel_edge.benchmark.fresh_source_observe"
    process_type = FreshObserverProcess
    side_files = SIDE_FILES

    def __init__(self, g, role_command):
        core = importlib.import_module(self.core_module)

        self.core = core
        self.g, self.role_command, self.variant = g, role_command, "main"
        self.protocol_raw = Path(__file__).with_name(self.protocol_name).read_bytes()
        assert accounting.sha256(self.protocol_raw) == self.protocol_digest
        self.protocol = json.loads(self.protocol_raw)
        assert (
            accounting.sha256(accounting.canonical(self.protocol["input_recipe"]))
            == RECIPE_SHA256
        )
        self.protocol_sha256 = self.protocol_digest
        self.allowed_case_ids = frozenset(CASES)
        self.public_directory = self.public_name
        self.custody_schema = "outcome-live-close-custody/v3"
        self.cases = {
            case: dict(action="normal_stop", custody_mode="live_parent_and_children")
            for case in CASES
        }
        self.contexts, self._case_manager_clients, self.results = {}, {}, []
        self.active_observer, self.pre_audits = None, []
        self.nonalerts = core.nonalert_lines()

    def begin(self, case_id, *, previous_session=None):
        FiniteIngressLab.begin(self, case_id, previous_session=previous_session)
        context = self.contexts[case_id]
        context["ingress"]["protocol_sha256"] = self.protocol_sha256
        anchor = _clock_anchor()
        started = time.monotonic_ns()
        context["load"] = dict(
            schema_version=f"edge-fresh-load-controller/v{self.version}",
            case_id=case_id,
            protocol_sha256=self.protocol_sha256,
            input_recipe_sha256=RECIPE_SHA256,
            corpus_sha256=None,
            session_ref=None,
            started_ns=started,
            finished_ns=None,
            controller_identity=old.root_identity(os.getpid()),
            controller_anchors=dict(before=anchor, after=None),
            writer=None,
            observer=None,
            resources=dict.fromkeys(
                (
                    "native_before",
                    "native_after",
                    "receiver_before",
                    "receiver_after",
                    "observer_before",
                    "observer_after",
                )
            ),
            audits=copy.deepcopy(self.pre_audits),
            errors=[],
        )
        context["fresh"] = dict(
            schema_version=f"edge-fresh-source-controller/v{self.version}",
            case_id=case_id,
            protocol_sha256=self.protocol_sha256,
            input_recipe_sha256=RECIPE_SHA256,
            session_ref=None,
            started_ns=started,
            finished_ns=None,
            timestamp_receipts_sha256=None,
            input_manifest_sha256=None,
            input_calls_sha256=None,
            readiness=None,
            observations=[],
            interrupt_boundary=None,
            errors=[],
        )
        context["timestamps"] = dict(
            schema_version=f"edge-fresh-timestamp-receipts/v{self.version}",
            case_id=case_id,
            protocol_sha256=self.protocol_sha256,
            input_recipe_sha256=RECIPE_SHA256,
            rows=[],
            errors=[],
        )
        context["materialized_rows"] = {}
        context["writer_failure"] = None

    def configure_observer(self, context):
        directory = self.g.BUNDLE / "observer"
        nonce = context["controller"]["attempt_ref"]
        paths = dict(
            registration=str(self.g.BUNDLE / "origin.json"),
            trust=str(self.g.BUNDLE / "trust.json"),
            policy=str(POLICY_PATH),
        )
        paths.update(
            {
                key: str(directory / ("fresh-" + nonce + "-" + key))
                for key in self.side_files
                if key != "journal"
            }
        )
        paths["journal"] = str(directory / "observations.journal")
        helper_raw, recorder_raw = HELPER.read_bytes(), RECORDING_HELPER.read_bytes()
        metadata = dict(
            run_id=nonce,
            arm=context["controller"]["case_id"],
            role="observer",
            input_recipe_sha256=RECIPE_SHA256,
            code_sha256=accounting.sha256(
                helper_raw
                + b"\0"
                + recorder_raw
                + (
                    b"\0"
                    + Path(__file__).with_name("fresh_publication.py").read_bytes()
                    if self.version == 2
                    else b""
                )
            ),
            core_sha256=context["controller"]["core_image_sha256"],
            interpreter_sha256=accounting.sha256(self.g.PYTHON.resolve().read_bytes()),
        )
        config = dict(
            schema_version=f"edge-fresh-source-observer-config/v{self.version}",
            case_id=metadata["arm"],
            protocol_sha256=self.protocol_sha256,
            input_recipe_sha256=RECIPE_SHA256,
            registration_sha256=context["controller"]["registration_sha256"],
            trust_sha256=context["controller"]["trust_sha256"],
            helper_sha256=accounting.sha256(helper_raw),
            paths=paths,
            metadata=metadata,
        )
        raw = accounting.canonical(config)
        path = old.stage_observer_config(self.g, nonce, raw, prefix="fresh")
        context["files"].update(
            {
                "observer-config.json": raw,
                "observer-policy.json": POLICY_PATH.read_bytes(),
            }
        )
        try:
            observer = self.process_type(
                self.g,
                self.role_command,
                config=path,
                config_sha256=accounting.sha256(raw),
            )
        except BaseException as error:
            observer = getattr(error, "observer_process", None)
            if observer is not None:
                context["observer_process"] = self.active_observer = observer
                context["load"]["observer"] = observer.receipt
            raise
        context["observer_process"] = self.active_observer = observer
        context["load"]["observer"] = observer.receipt
        context["load"]["resources"]["observer_before"] = old.resource(
            observer.receipt["actor"]
        )
        self.ready(context, paths)
        return observer

    def ready(self, context, paths):
        def available():
            try:
                observer = context["observer_process"]
                assert observer.process.poll() is None, (
                    "observer exited before original readiness"
                )
                assert (
                    accounting.actor(observer.receipt["actor"]["pid"])["start_ticks"]
                    == observer.receipt["actor"]["start_ticks"]
                ), "observer incarnation changed before readiness"
                calls_raw, _ = stable_read(Path(paths["calls"]), 4 * 1024 * 1024)
                calls = decode_calls_prefix(calls_raw)
                if not calls["calls"]:
                    return False
                first = calls["calls"][0]
                assert first["kind"] == "sample", (
                    "first original callback must be initial sample"
                )
                journal, _ = stable_read(
                    self.g.BUNDLE / "observer/observations.journal", 8 * 1024 * 1024
                )
                rows = [json.loads(line) for line in journal.splitlines()]
                fence = next(
                    (row for row in reversed(rows) if row["kind"] == "input_ready"),
                    None,
                )
                if fence is None:
                    return False
                anchors, _ = stable_read(
                    self.g.BUNDLE / "witness/anchors/anchors.journal", 8 * 1024 * 1024
                )
                boundary = accounting.witness_boundary(anchors)
                state = json.loads(anchors.splitlines()[-1])["state"]
                if state["journal_seq"] < fence["seq"]:
                    return False
                context["fresh"]["readiness"] = dict(
                    observed_ns=time.monotonic_ns(),
                    first_sample_seq=first["seq"],
                    clock_calls_checkpoint=dict(
                        size=len(calls["complete_prefix"]),
                        sha256=accounting.sha256(calls["complete_prefix"]),
                    ),
                    input_ready_position=fence["data"],
                    journal_checkpoint=dict(
                        size=len(journal), sha256=accounting.sha256(journal)
                    ),
                    witness_boundary=boundary,
                )
                return True
            except (OSError, ValueError, KeyError, AssertionError):
                return False

        self.g.wait_for(available)

    def paced_writer(self, context):
        from datetime import datetime, timezone

        case_id = context["controller"]["case_id"]
        specs = self.core.event_specs(case_id)
        by_index = {}
        for spec in specs:
            by_index.setdefault(spec["after_nonalert"], []).append(spec)
        receipt = dict(
            pid=os.getpid(),
            tid=None,
            fd=None,
            flags=None,
            before=None,
            after=None,
            started_ns=None,
            first_write_before_ns=None,
            marker_one_before_ns=None,
            final_nonalert_after_ns=None,
            finished_ns=None,
            joined_ns=None,
            written_bytes=0,
            nonalert_records=0,
            per_class=dict.fromkeys(("flow", "dns", "stats", "http"), 0),
            write_calls=0,
            fsync_completed=False,
            joined=False,
            sha256=None,
            error=None,
        )
        context["load"]["writer"] = receipt
        ingress = dict(
            stage="initial",
            pid=os.getpid(),
            tid=None,
            fd=None,
            flags=None,
            before=None,
            after=None,
            started_ns=None,
            finished_ns=None,
            offset_before=None,
            offset_after=None,
            requested_bytes=None,
            written_bytes=0,
            write_calls=0,
            fsync_completed=False,
            joined=False,
            joined_ns=None,
            pause=None,
            resume=None,
            error=None,
        )
        context["ingress"]["writer"].append(ingress)

        def writer():
            fd = None
            digest = hashlib.sha256()
            occurrence = {}
            receipt.update(
                tid=threading.get_native_id(), started_ns=time.monotonic_ns()
            )

            def write(raw):
                view = memoryview(raw)
                while view:
                    amount = os.write(fd, view)
                    assert amount > 0
                    digest.update(view[:amount])
                    receipt["written_bytes"] += amount
                    receipt["write_calls"] += 1
                    view = view[amount:]

            try:
                fd = os.open(
                    self.eve_path(),
                    os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
                receipt.update(
                    fd=fd,
                    flags=fcntl.fcntl(fd, fcntl.F_GETFL),
                    before=accounting.source_metadata(os.fstat(fd), detailed=True),
                )
                ingress["offset_before"] = os.lseek(fd, 0, os.SEEK_END)
                assert ingress["offset_before"] == 0
                assert all(
                    receipt["before"][key]
                    == context["ingress"]["held_fd"]["object"][key]
                    for key in ("device", "inode", "owner_uid", "mode", "nlink")
                )
                receipt["first_write_before_ns"] = time.monotonic_ns()
                origin = receipt["first_write_before_ns"]
                for index, line in enumerate(self.nonalerts, 1):
                    assert len(line) == 600
                    deadline = origin + int(index * 1e9 / 3000)
                    delay = (deadline - time.monotonic_ns()) / 1e9
                    if delay > 0:
                        time.sleep(delay)
                    write(line)
                    receipt["nonalert_records"] += 1
                    receipt["per_class"][
                        ("flow", "dns", "stats", "http")[(index - 1) % 4]
                    ] += 1
                    if index == 27004:
                        receipt["final_nonalert_after_ns"] = time.monotonic_ns()
                    for spec in by_index.get(index, []):
                        started = time.monotonic_ns()
                        anchor = None
                        if spec["kind"] == "duplicate":
                            raw = context["materialized_rows"][spec["duplicate_of"]]
                        else:
                            anchor = _clock_anchor()
                            raw = self.core.materialize_alert(spec, anchor["epoch_ns"])
                        after = time.monotonic_ns()
                        event = json.loads(raw)
                        stamp = event["timestamp"]
                        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                        delta = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
                        epoch_ns = (
                            delta.days * 86400 + delta.seconds
                        ) * 1_000_000_000 + delta.microseconds * 1000
                        occurrence[spec["sid"]] = occurrence.get(spec["sid"], 0) + 1
                        record = dict(
                            event_ref=spec["event_ref"],
                            kind=spec["kind"],
                            sid=spec["sid"],
                            occurrence=occurrence[spec["sid"]],
                            after_nonalert=index,
                            duplicate_of=spec.get("duplicate_of"),
                            generation_anchor=anchor,
                            timestamp_epoch_ns=epoch_ns,
                            timestamp=stamp,
                            start_offset=receipt["written_bytes"],
                            end_offset=None,
                            raw_sha256=accounting.sha256(raw),
                            materialization_before_ns=started,
                            materialization_after_ns=after,
                            write_before_ns=time.monotonic_ns(),
                            write_after_ns=None,
                            error=None,
                        )
                        context["timestamps"]["rows"].append(record)
                        if receipt["marker_one_before_ns"] is None:
                            receipt["marker_one_before_ns"] = record["write_before_ns"]
                        try:
                            write(raw)
                            record["end_offset"] = receipt["written_bytes"]
                            record["write_after_ns"] = time.monotonic_ns()
                            context["materialized_rows"][spec["event_ref"]] = raw
                        except BaseException as error:
                            record["error"] = old.error_value(error)
                            raise
                os.fsync(fd)
                receipt["fsync_completed"] = True
                ingress["offset_after"] = os.lseek(fd, 0, os.SEEK_CUR)
                receipt["after"] = accounting.source_metadata(
                    os.fstat(fd), detailed=True
                )
            except BaseException as error:
                receipt["error"] = old.error_value(error)
            finally:
                if fd is not None:
                    os.close(fd)
                receipt.update(
                    sha256=digest.hexdigest(), finished_ns=time.monotonic_ns()
                )

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        return thread, receipt, ingress

    def source_observation(self, context, spec, receipt):
        from azazel_edge.outcome.input_auth import SourceVerifier

        found = None

        def available():
            nonlocal found
            try:
                raw, _ = stable_read(self.g.BUNDLE / "input", 8 * 1024 * 1024)
                if not raw.endswith(b"\n"):
                    return False
                policy = self.g.fixture().p
                SourceVerifier(policy).verify(raw)
                offset = 0
                for line in raw.splitlines(keepends=True):
                    offset += len(line)
                    event = json.loads(line)["event"]
                    origin = event.get("ingress_origin")
                    if (
                        event.get("capture_origin", {}).get("session_ref")
                        != context["controller"]["session_ref"]
                        or type(origin) is not dict
                    ):
                        continue
                    if (
                        origin["start_offset"] != receipt["start_offset"]
                        or origin["end_offset"] != receipt["end_offset"]
                    ):
                        continue
                    assert (
                        event["normalized"]["sid"] == spec["sid"]
                        and event["normalized"]["ts"] == receipt["timestamp"]
                    )
                    assert origin["raw_sha256"] == receipt["raw_sha256"]
                    tip = SourceVerifier(policy).verify(raw[:offset])
                    found = dict(
                        event_ref=spec["event_ref"],
                        observed_ns=time.monotonic_ns(),
                        session_ref=context["controller"]["session_ref"],
                        source_position=dict(offset=offset, sha256=tip["sha256"]),
                        source_checkpoint=tip,
                        ingress_origin=origin,
                    )
                    return True
            except (OSError, AssertionError, ValueError):
                return False
            return False

        self.g.wait_for(available)
        if not any(
            row["event_ref"] == found["event_ref"]
            for row in context["fresh"]["observations"]
        ):
            context["fresh"]["observations"].append(found)
        context["ingress"]["range_ref"] = context["controller"]["session_ref"]
        return found

    def interrupted_barrier(self, context, observation):
        paths = json.loads(context["files"]["observer-config.json"])["paths"]
        result = None

        def available():
            nonlocal result
            try:
                raw, _ = stable_read(Path(paths["input_calls"]), 4 * 1024 * 1024)
                rows, tail = input_prefix(raw, version=self.version)
                candidates = [
                    row
                    for row in rows
                    if row["kind"] == "input_return"
                    and row["data"]["cursor_after"] == observation["source_position"]
                ]
                if not candidates:
                    return False
                row = candidates[-1]
                callbacks = row["data"]["callbacks"]
                assert len(callbacks) == 1 and callbacks[0]["return_value"] is False
                calls_raw, _ = stable_read(Path(paths["calls"]), 4 * 1024 * 1024)
                calls = decode_calls_prefix(calls_raw)
                call = next(
                    (
                        call
                        for call in calls["calls"]
                        if call["seq"] == callbacks[0]["call_seq"]
                    ),
                    None,
                )
                if call is None:
                    return False
                assert call["kind"] == "event" and call["data"]["accepted"] is False
                assert (
                    accounting.sha256(accounting.canonical(call["data"]["event"]))
                    == callbacks[0]["event_sha256"]
                )
                journal, _ = stable_read(
                    self.g.BUNDLE / "observer/observations.journal", 8 * 1024 * 1024
                )
                jr = [json.loads(line) for line in journal.splitlines()]
                if not any(
                    r["kind"] == "cursor"
                    and r["data"]["position"] == observation["source_position"]
                    for r in jr
                ):
                    return False
                anchors, _ = stable_read(
                    self.g.BUNDLE / "witness/anchors/anchors.journal", 8 * 1024 * 1024
                )
                boundary = accounting.witness_boundary(anchors)
                state = json.loads(anchors.splitlines()[-1])["state"]
                cursor_seq = next(
                    r["seq"]
                    for r in jr
                    if r["kind"] == "cursor"
                    and r["data"]["position"] == observation["source_position"]
                )
                if (
                    state["journal_seq"] < cursor_seq
                    or boundary["source_checkpoint"]["size"]
                    < observation["source_position"]["offset"]
                ):
                    return False
                complete = b"".join(raw.splitlines(keepends=True)[: row["seq"]])
                now = time.monotonic_ns()
                context["files"]["observer-fault-anchors.raw"] = anchors
                context["load"]["observer"]["fault_boundary"] = dict(
                    observed_ns=now,
                    source_checkpoint=observation["source_checkpoint"],
                    cursor_position=observation["source_position"],
                    journal_checkpoint=dict(
                        size=len(journal), sha256=accounting.sha256(journal)
                    ),
                    witness_sha256=accounting.sha256(anchors),
                    witness_boundary=boundary,
                )
                result = dict(
                    observed_ns=now,
                    event_ref=observation["event_ref"],
                    input_calls_checkpoint=dict(
                        size=len(complete), sha256=accounting.sha256(complete)
                    ),
                    handler_id=row["data"]["input_id"],
                    event_call_id=callbacks[0]["call_seq"],
                    source_position=observation["source_position"],
                )
                return True
            except (OSError, ValueError, KeyError, StopIteration, AssertionError):
                return False

        self.g.wait_for(available)
        context["fresh"]["interrupt_boundary"] = result

    def collect_observer(self, context):
        observer = context.get("observer_process")
        if observer is None:
            return
        observer.retain_drains()
        context["files"].update(
            {
                "observer-stdout.raw": observer.stdout,
                "observer-stderr.raw": observer.stderr,
            }
        )
        paths = json.loads(context["files"]["observer-config.json"])["paths"]
        for key, name in self.side_files.items():
            try:
                raw, meta = stable_read(
                    Path(paths[key]), 16384 if key == "context" else 4 * 1024 * 1024
                )
                context["files"][name] = raw
                observer.receipt["sidecars"][key] = dict(
                    before=meta["object"],
                    after=meta["object"],
                    sha256=meta["sha256"],
                    size=len(raw),
                )
            except FileNotFoundError:
                pass
        context["load"]["resources"]["observer_after"] = old.resource(
            observer.receipt["actor"]
        )

    def run_audit(self, context, stage):
        started = time.monotonic_ns()
        status, receipt = audit_role(self.g, self.role_command, version=self.version)
        context["load"]["audits"].append(
            dict(
                stage=stage,
                unit=receipt["unit"],
                actor=receipt["actor"],
                started_ns=started,
                finished_ns=time.monotonic_ns(),
                exit=receipt["exit"],
                error=receipt["error"],
            )
        )
        return status

    def manifest(self, context, raw):
        markers = [
            {
                k: row[k]
                for k in (
                    "event_ref",
                    "kind",
                    "sid",
                    "occurrence",
                    "after_nonalert",
                    "start_offset",
                    "end_offset",
                    "raw_sha256",
                    "timestamp",
                )
            }
            for row in context["timestamps"]["rows"]
            if row["end_offset"] is not None and row["error"] is None
        ]
        receipts_raw = accounting.canonical(context["timestamps"])
        context["files"]["fresh-timestamp-receipts.json"] = receipts_raw
        result = dict(
            schema_version=f"edge-fresh-input-manifest/v{self.version}",
            case_id=context["controller"]["case_id"],
            protocol_sha256=self.protocol_sha256,
            input_recipe_sha256=RECIPE_SHA256,
            sha256=accounting.sha256(raw),
            bytes=len(raw),
            lf_records=raw.count(b"\n"),
            nonalert_records=context["load"]["writer"]["nonalert_records"],
            per_class=context["load"]["writer"]["per_class"],
            markers=markers,
            timestamp_receipts_sha256=accounting.sha256(receipts_raw),
        )
        context["files"]["corpus-manifest.json"] = accounting.canonical(result)
        context["fresh"].update(
            timestamp_receipts_sha256=accounting.sha256(receipts_raw),
            input_manifest_sha256=accounting.sha256(
                context["files"]["corpus-manifest.json"]
            ),
        )
        context["load"]["corpus_sha256"] = result["sha256"]
        return result

    def case(self, case_id):
        self.begin(case_id)
        context = self.contexts[case_id]
        g = self.g
        thread, writer, ingress = None, None, None
        try:
            g.systemctl("start", g.UNIT)
            pid = g.live()
            self.started(case_id, pid, g.events()[-1]["capture_origin"]["session_ref"])
            session = context["controller"]["session_ref"]
            context["load"]["session_ref"] = context["fresh"]["session_ref"] = session
            accounting.await_input_start(g)
            for role in ("native", "receiver"):
                context["load"]["resources"][role + "_before"] = old.resource(
                    context["controller"]["actors"][role]
                )
            observer = self.configure_observer(context)
            thread, writer, ingress = self.paced_writer(context)
            specs = self.core.event_specs(case_id)
            if case_id == "fresh-interrupted":

                def first_written():
                    return (
                        context["timestamps"]["rows"]
                        and context["timestamps"]["rows"][0]["end_offset"] is not None
                    )

                g.wait_for(first_written)
                receipt = context["timestamps"]["rows"][0]
                observation = self.source_observation(context, specs[0], receipt)
                self.interrupted_barrier(context, observation)
                assert (
                    time.monotonic_ns()
                    < writer["first_write_before_ns"] + 6_000_000_000
                ), "first callback kill missed fixed second marker deadline"
                observer.signal(signal.SIGKILL)
                observer.wait()
                assert (
                    observer.receipt["exit"]["ExecMainCode"] == "2"
                    and observer.receipt["exit"]["ExecMainStatus"] == "9"
                )
                self.collect_observer(context)
            thread.join(110)
            writer.update(joined=not thread.is_alive(), joined_ns=time.monotonic_ns())
            for key in ingress.keys() & writer.keys():
                ingress[key] = copy.deepcopy(writer[key])
            assert writer["joined"] and writer["error"] is None, writer
            raw = self.snapshot(context, "eve-after-writer.raw")
            assert (
                accounting.sha256(raw) == writer["sha256"]
                and len(raw) == writer["written_bytes"]
            )
            ingress["requested_bytes"] = len(
                raw
            )  # completed actual dynamic write, not prospective raw bytes
            self.manifest(context, raw)
            for spec, receipt in zip(specs, context["timestamps"]["rows"]):
                self.source_observation(context, spec, receipt)
            last = context["fresh"]["observations"][-1]
            context["ingress"]["markers"].append(
                dict(
                    kind="source",
                    sid=specs[-1]["sid"],
                    occurrence=specs[-1]["occurrence"],
                    observed_ns=last["observed_ns"],
                    session_ref=session,
                    range_ref=session,
                    source_checkpoint=last["source_checkpoint"],
                    ingress_origin=last["ingress_origin"],
                    normalized_log_checkpoint=None,
                )
            )
            if case_id == "fresh-controls":

                def last_cursor():
                    try:
                        journal, _ = stable_read(
                            g.BUNDLE / "observer/observations.journal", 8 * 1024 * 1024
                        )
                        return any(
                            row["kind"] == "cursor"
                            and row["data"]["position"] == last["source_position"]
                            for row in map(json.loads, journal.splitlines())
                        )
                    except (OSError, ValueError, AssertionError):
                        return False

                g.wait_for(last_cursor)
                observer.signal(signal.SIGTERM)
                observer.wait()
                assert (
                    observer.process.returncode == 0
                    and observer.receipt["exit"]["ExecMainCode"] == "1"
                    and observer.receipt["exit"]["ExecMainStatus"] == "0"
                )
                self.collect_observer(context)
            for role in ("native", "receiver"):
                context["load"]["resources"][role + "_after"] = old.resource(
                    context["controller"]["actors"][role]
                )
            g.stop()
            self.stopped(case_id)
            self.run_audit(context, "post_window")
            self.finalized(case_id)
        except BaseException as error:
            context["load"]["errors"].append(
                dict(stage="case", **old.error_value(error))
            )
            context["fresh"]["errors"].append(
                dict(stage="case", **old.error_value(error))
            )
            raise
        finally:
            if thread is not None and thread.is_alive():
                thread.join(110)
            if thread is not None and writer is not None:
                writer.update(
                    joined=not thread.is_alive(),
                    joined_ns=writer["joined_ns"] or time.monotonic_ns(),
                )
                for key in ingress.keys() & writer.keys():
                    ingress[key] = copy.deepcopy(writer[key])
            if context.get("observer_process") and context["exported"]:
                try:
                    context["observer_process"].close(
                        original=sys.exc_info()[1] if self.version == 2 else None
                    )
                except BaseException as error:
                    hook = getattr(self, "post_snapshot_error", None)
                    if hook is not None:
                        hook(case_id, error, stage="observer-close")
                    raise
                self.active_observer = None

    def export(self, case_id):
        context = self.contexts[case_id]
        assert not context["exported"]
        for name, held in (("eve-held-final.raw", True), ("eve-path-final.raw", False)):
            try:
                self.snapshot(context, name, held=held)
            except (OSError, AssertionError):
                pass
        ingress, control, load, fresh, files = (
            context[k] for k in ("ingress", "controller", "load", "fresh", "files")
        )
        if "fresh-timestamp-receipts.json" not in files:
            files["fresh-timestamp-receipts.json"] = accounting.canonical(
                context["timestamps"]
            )
            fresh["timestamp_receipts_sha256"] = accounting.sha256(
                files["fresh-timestamp-receipts.json"]
            )
        if files.get("observer-input-calls.raw") is not None:
            fresh["input_calls_sha256"] = accounting.sha256(
                files["observer-input-calls.raw"]
            )
        ingress["finished_ns"] = time.monotonic_ns()
        if context["eve_fd"] is not None:
            os.close(context["eve_fd"])
            context["eve_fd"] = None
            ingress["held_fd"]["closed_ns"] = time.monotonic_ns()
        files["ingress-controller.json"] = accounting.canonical(ingress)
        load["finished_ns"] = time.monotonic_ns()
        load["controller_anchors"]["after"] = _clock_anchor()
        files["load-controller.json"] = accounting.canonical(load)
        fresh["finished_ns"] = time.monotonic_ns()
        files["fresh-controller.json"] = accounting.canonical(fresh)
        control["finished_ns"] = time.monotonic_ns()
        files["close-controller.json"] = accounting.canonical(control)
        files["actor-fd-custody.json"] = accounting.canonical(control["fd_custody"])
        files["code-pins.json"] = accounting.canonical(
            dict(
                source_revision=control["source_revision"],
                protocol_sha256=self.protocol_sha256,
                core_image_sha256=control["core_image_sha256"],
            )
        )
        if files.get("anchors-after.raw"):
            files["witness-boundary.json"] = accounting.canonical(
                accounting.witness_boundary(files["anchors-after.raw"])
            )
        result = self.publish_case(case_id)
        self.assert_case_result(case_id, result)

    def publish_case(self, case_id):
        context = self.contexts[case_id]
        files = context["files"]
        directory = self.g.BASE / self.public_directory / case_id
        directory.mkdir(parents=True, exist_ok=False)
        assert set(files) <= self.core.FILES
        for name, body in files.items():
            if body is not None:
                self.g.write(directory / name, body)
        context["exported"] = True
        artifacts = {name: files.get(name) for name in self.core.FILES}
        pins = {
            name: accounting.sha256(raw) if raw is not None else None
            for name, raw in artifacts.items()
        }
        result = self.core.evaluate_fresh_source_case(artifacts, expected=pins)
        result["observer"] = evaluate_fresh_observer_originals(
            artifacts, pins, version=self.version
        )
        self.g.write(directory / "evaluation.json", accounting.canonical(result))
        self.results.append(result)
        return result

    def assert_case_result(self, case_id, result):
        context = self.contexts[case_id]
        control = context["controller"]
        if control["outcome"] == "failure":
            return
        assert result["finite"]["whole_input_complete"] is True, result
        assert result["load"]["status"] == result["intake"]["status"] == "qualified", (
            result
        )
        expected = (
            "bound_fresh_controls"
            if case_id == "fresh-controls"
            else "bound_interrupted_prefix"
        )
        assert result["status"] == expected, result
        if case_id == "fresh-controls":
            assert (
                result["observer"]["normal_completion"] is True
                and result["observer"]["clock"] is not None
                and result["observer"]["clock"]["status"] == "qualified"
            ), result
        else:
            assert (
                result["observer"]["fault_verified"] is True
                and result["observer"]["clock"] is None
            ), result
        context["analysis_accepted"] = True

    def exercise(self):
        g = self.g
        directory = g.BASE / self.public_directory
        directory.mkdir(mode=0o755, exist_ok=False)
        declaration = accounting.canonical(
            dict(
                protocol_sha256=self.protocol_sha256,
                input_recipe_sha256=RECIPE_SHA256,
                actual_input_hash_known=False,
            )
        )
        with (directory / "recipe-declaration.json").open("xb") as target:
            target.write(declaration)
            target.flush()
            os.fsync(target.fileno())
        try:
            g.systemctl("start", g.UNIT)
            g.wait_for(lambda: len(g.Systemd().cores()) == 1)
            switch = g.Switch(g.BUNDLE)
            plan = switch.plan()
            assert switch.apply(plan, g.digest(plan))["status"] == "started"
            g.live()
            g.stop()
            started = time.monotonic_ns()
            _, receipt = audit_role(g, self.role_command, version=self.version)
            self.pre_audits.append(
                dict(
                    stage="warmup_before",
                    unit=receipt["unit"],
                    actor=receipt["actor"],
                    started_ns=started,
                    finished_ns=time.monotonic_ns(),
                    exit=receipt["exit"],
                    error=receipt["error"],
                )
            )
            for case_id in CASES:
                self.case(case_id)
                self.release_case_reference(case_id)
        except BaseException as error:
            if self.active_observer is not None:
                try:
                    self.active_observer.terminate_and_wait()
                    for context in self.contexts.values():
                        if context.get("observer_process") is self.active_observer:
                            self.collect_observer(context)
                except BaseException as cleanup:
                    g.record(
                        "fresh-observer-failure-cleanup", **old.error_value(cleanup)
                    )
            try:
                self.teardown_failure(error)
            finally:
                if self.active_observer is not None:
                    self.active_observer.close(error)
                    self.active_observer = None
            raise


def finish(g):
    old.finish(g)
    g.record(
        "fresh-source-observation-finished-retained-clean-history",
        source_sha256=accounting.sha256(g.source()),
    )


def _fresh_phase_facts(raw, *, metadata, identity, complete, version=1):
    rows, tail = old._rows(
        raw,
        f"edge-fresh-phase-timing-record/v{version}",
        limit=4 * 1024 * 1024,
        max_rows=4096,
        allow_partial=True,
    )
    assert rows[0]["kind"] == "header"
    header = rows[0]["data"]
    assert all(header[k] == v for k, v in metadata.items())
    assert all(header[k] == v for k, v in identity.items())
    footer = rows[-1]["kind"] == "end"
    closed = (
        footer
        and not tail
        and rows[-1]["data"].get("normal_return") is True
        and rows[-1]["data"].get("incomplete") is False
    )
    if complete:
        assert (
            closed
            and rows[-1]["data"]["normal_return"] is True
            and rows[-1]["data"]["incomplete"] is False
        )
    intents, facts = {}, {}
    for row in rows[1:-1] if footer else rows[1:]:
        data = row["data"]
        if row["kind"] == "intent":
            assert data["span_id"] not in intents
            intents[data["span_id"]] = data
        else:
            assert row["kind"] == "span" and data["span_id"] in intents
            intent = intents.pop(data["span_id"])
            assert all(
                data[k] == intent[k]
                for k in (
                    "span_id",
                    "parent_id",
                    "phase",
                    "event_kind",
                    "event_seq",
                    "operation",
                )
            )
            assert (
                data["outcome"] in ("returned", "raised")
                and data["native_tid"] == identity["native_tid"]
            )
            timing = {}
            for name, start, end in (
                ("wall_ns", "start_ns", "end_ns"),
                ("process_cpu_ns", "process_cpu_start_ns", "process_cpu_end_ns"),
                ("thread_cpu_ns", "thread_cpu_start_ns", "thread_cpu_end_ns"),
            ):
                assert (
                    type(data[start]) is int
                    and type(data[end]) is int
                    and 0 <= data[start] <= data[end]
                )
                timing[name] = data[end] - data[start]
            group = facts.setdefault(
                data["phase"],
                dict(
                    count=0, wall_ns=0, process_cpu_ns=0, thread_cpu_ns=0, max_wall_ns=0
                ),
            )
            group["count"] += 1
            for name in timing:
                group[name] += timing[name]
            group["max_wall_ns"] = max(group["max_wall_ns"], timing["wall_ns"])
    if complete:
        assert not intents
    return dict(
        scope="inclusive_actual_spans_not_additive",
        complete=closed and not intents,
        phases=facts,
        unfinished_spans=len(intents),
        partial_tail_bytes=len(tail),
        partial_tail_sha256=accounting.sha256(tail) if tail else None,
    )


def evaluate_fresh_observer_originals(artifacts, expected, *, version=1):
    """Re-decode original pinned bytes; stored evaluation never supplies authority."""
    from dataclasses import fields
    from azazel_edge.outcome.input_control_stop import ObserverControlStop
    from signed_network_recording import decode_calls
    from signed_network_clock import qualify_clock

    assert version in (1, 2)
    profile = importlib.import_module(
        "azazel_edge.benchmark.fresh_source_observe" + ("_v2" if version == 2 else "")
    )
    self_files = profile.FILES
    side_files = (
        dict(SIDE_FILES, publication="observer-publication.raw")
        if version == 2
        else SIDE_FILES
    )

    result = dict(
        status="withheld",
        normal_completion=None,
        fault_verified=None,
        clock=None,
        phase=None,
        error=None,
    )

    def original(name):
        raw = artifacts[name]
        assert type(raw) is bytes and accounting.sha256(raw) == expected[name], (
            name + ": original pin missing/differs"
        )
        return raw

    def data(name):
        raw = original(name)
        value = json.loads(raw)
        assert accounting.canonical(value) == raw
        return value

    try:
        assert set(artifacts) == set(expected) == self_files
        controller = data("load-controller.json")
        arm, observer = controller["case_id"], controller["observer"]
        assert (
            arm in ("fresh-controls", "fresh-interrupted")
            and type(observer) is dict
            and observer["error"] is None
        )
        assert controller["schema_version"] == f"edge-fresh-load-controller/v{version}"
        config = data("observer-config.json")
        assert (
            config["schema_version"] == f"edge-fresh-source-observer-config/v{version}"
        )
        assert set(config) == {
            "schema_version",
            "case_id",
            "protocol_sha256",
            "input_recipe_sha256",
            "registration_sha256",
            "trust_sha256",
            "helper_sha256",
            "paths",
            "metadata",
        }
        assert set(config["metadata"]) == {
            "run_id",
            "arm",
            "role",
            "input_recipe_sha256",
            "code_sha256",
            "core_sha256",
            "interpreter_sha256",
        }
        assert (
            config["metadata"]["arm"] == arm
            and config["metadata"]["role"] == "observer"
            and config["metadata"]["input_recipe_sha256"] == RECIPE_SHA256
        )
        assert (
            config["case_id"] == arm
            and config["protocol_sha256"]
            == controller["protocol_sha256"]
            == profile.PROTOCOL_SHA256
        )
        assert (
            config["input_recipe_sha256"]
            == controller["input_recipe_sha256"]
            == RECIPE_SHA256
            and config["registration_sha256"]
            == accounting.sha256(original("registration.json"))
            and config["trust_sha256"] == accounting.sha256(original("trust.json"))
        )
        identity, actor = observer["identity"], observer["actor"]
        assert (
            observer["bootstrap"]["schema_version"]
            == f"edge-fresh-source-observer-bootstrap/v{version}"
        )
        assert observer["command_verified"] is True and observer["bootstrap"][
            "pid"
        ] == identity["pid"] == actor["pid"] == int(
            observer["unit_properties"]["MainPID"]
        )
        assert (
            observer["bootstrap"]["challenge"] == observer["challenge"]
            and observer["bootstrap"]["invocation_id"]
            == observer["unit_properties"]["InvocationID"]
        )
        assert (
            actor["uid"] == actor["gid"] == 61002
            and actor["no_new_privs"] is True
            and actor["apparmor_label"] == "edge400-observer (enforce)"
        )
        assert (
            actor["cap_eff"]
            == actor["cap_prm"]
            == actor["cap_bnd"]
            == actor["cap_amb"]
            == 0
        )
        assert identity["start_ticks"] == actor["start_ticks"] > 0
        for key, filename in side_files.items():
            meta = observer["sidecars"][key]
            if artifacts[filename] is None:
                assert expected[filename] is None and meta is None
                continue
            raw = original(filename)
            assert (
                meta["before"] == meta["after"]
                and meta["size"] == len(raw) == meta["before"]["size"]
                and meta["sha256"] == accounting.sha256(raw)
            )
            assert meta["before"]["owner_uid"] == 61002
        original("observer-stdout.raw")
        original("observer-stderr.raw")
        assert not observer["stdout_truncated"] and not observer["stderr_truncated"]
        assert (
            observer["stdout_eof"] is True
            and observer["stderr_eof"] is True
            and observer["drain_errors"] == []
        )
        assert observer["stdout_bytes"] == len(
            artifacts["observer-stdout.raw"]
        ) and observer["stderr_bytes"] == len(artifacts["observer-stderr.raw"])
        assert observer["signal_target"] == actor
        assert (
            observer["started_ns"]
            <= observer["ready_ns"]
            <= observer["stop_requested_ns"]
            <= observer["finished_ns"]
        )
        assert int(observer["exit"]["ExecMainPID"]) == actor["pid"]
        result["phase"] = _fresh_phase_facts(
            original("observer-phase.raw"),
            metadata=config["metadata"],
            identity=identity,
            complete=arm == "fresh-controls",
            version=version,
        )
        if arm == "fresh-interrupted":
            assert (
                observer["signal"] == 9
                and observer["exit"]["ExecMainCode"] == "2"
                and observer["exit"]["ExecMainStatus"] == "9"
            )
            assert artifacts["observer-completion.json"] is None
            result["normal_completion"] = False
            result["fault_verified"] = False
            _verify_fresh_fault_boundary(
                controller, observer, original, version=version
            )
            if version == 2:
                assert (
                    profile.evaluate_publication(artifacts, expected=expected)["status"]
                    == "qualified"
                )
            result["fault_verified"] = True
            return result
        assert (
            observer["signal"] == 15
            and observer["runner_returncode"] == 0
            and observer["exit"]["ExecMainCode"] == "1"
            and observer["exit"]["ExecMainStatus"] == "0"
        )
        completion = data("observer-completion.json")
        assert (
            completion["schema_version"] == f"edge-fresh-observer-completion/v{version}"
            and completion["identity"] == identity
            and completion["metadata"] == config["metadata"]
        )
        control = completion["control_stop"]
        genuine = ObserverControlStop(
            **{f.name: control[f.name] for f in fields(ObserverControlStop)}
        )
        assert genuine.to_dict() == control
        trust = json.loads(original("trust.json"))
        assert (
            control["scope_ref"] == trust["scope_ref"]
            and control["trust_sha256"] == config["trust_sha256"]
            and control["journal_boot_id"] == identity["boot_id"]
        )
        journal = original("observer-journal.raw")
        assert len(journal) == control["journal_bytes_after"]
        last = json.loads(journal.splitlines()[-1])
        assert last["seq"] == control["journal_sequence_after"]
        assert (
            last["sha256"] == control["journal_head_after"]
            and last["kind"] == "session_close"
        )
        previous = "0" * 64
        journal_rows = []
        for seq, line in enumerate(journal.splitlines(keepends=True), 1):
            row = json.loads(line)
            assert (
                set(row) == {"seq", "prev", "kind", "data", "sha256"}
                and accounting.canonical(row) == line
            )
            assert row["seq"] == seq and row["prev"] == previous
            unsigned = {k: v for k, v in row.items() if k != "sha256"}
            assert row["sha256"] == accounting.sha256(
                accounting.canonical(unsigned).rstrip(b"\n")
            )
            previous = row["sha256"]
            journal_rows.append(row)
        assert journal_rows[0]["kind"] == "header"
        positions = [
            row["data"]["position"] for row in journal_rows if row["kind"] == "cursor"
        ]
        assert positions and positions[-1] == control["input_position_after"]
        source = original("source-after.raw")
        assert (
            control["input_offset"] <= len(source)
            and accounting.sha256(source[: control["input_offset"]])
            == control["input_sha256"]
        )
        from azazel_edge.outcome.telemetry import (
            OutcomeTelemetryPolicy,
            persistence_context,
        )

        policy_value = json.loads(original("observer-policy.json"))
        policy = OutcomeTelemetryPolicy.from_mapping(
            policy_value, source_ref=config["paths"]["policy"]
        )
        assert completion["policy_context"] == dict(
            policy_sha256=accounting.sha256(
                accounting.canonical(policy_value).rstrip(b"\n")
            ),
            policy_source_ref=config["paths"]["policy"],
            policy_ref=policy.policy_ref,
        )
        assert control["journal_policy_sha256"] == accounting.sha256(
            persistence_context(policy, "lo", 0.1).encode()
        )
        for key in (
            ("phase", "calls", "context", "input_calls", "publication")
            if version == 2
            else ("phase", "calls", "context", "input_calls")
        ):
            raw = original(side_files[key])
            assert completion["sidecars"][key] == dict(
                bytes=len(raw), sha256=accounting.sha256(raw)
            )
        calls = decode_calls(original("observer-calls.raw"))
        contexts = old._rows(
            original("observer-context.raw"),
            f"edge-fresh-clock-context/v{version}",
            limit=16384,
            max_rows=2,
        )
        assert (
            len(contexts) == 2
            and contexts[0]["kind"] == "begin"
            and contexts[1]["kind"] == "end"
            and contexts[1]["data"]["normal_return"] is True
        )
        assert (
            contexts[0]["data"]["identity"] == identity
            and contexts[0]["data"]["metadata"] == config["metadata"]
        )
        result["normal_completion"] = True
        root = controller["controller_identity"]
        assert (
            identity["clock_domain"]["established"] is True
            and root["clock_domain"]["established"] is True
            and identity["clock_domain"] == root["clock_domain"]
        )
        anchors = controller["controller_anchors"]
        result["clock"] = qualify_clock(
            kernel_boot_id=json.loads(original("close-controller.json"))["boot_id"],
            observer_boot_id=identity["boot_id"],
            controller_boot_id=root["boot_id"],
            observer_start=contexts[0]["data"]["anchor"],
            observer_end=contexts[1]["data"]["anchor"],
            controller_start=anchors["before"],
            controller_end=anchors["after"],
            recorded=calls,
        )
        if version == 2:
            closed = completion["publication"]
            assert set(closed) == {
                "joined",
                "complete",
                "incomplete",
                "error",
                "owner_close",
            }
            assert all(
                closed[k] == v
                for k, v in dict(
                    joined=True, complete=True, incomplete=False, error=None
                ).items()
            )
            owner = closed["owner_close"]
            assert set(owner) == {
                "start_ns",
                "end_ns",
                "process_cpu_start_ns",
                "process_cpu_end_ns",
                "thread_cpu_start_ns",
                "thread_cpu_end_ns",
            }
            assert (
                0 <= owner["start_ns"] <= owner["end_ns"]
                and owner["end_ns"] - owner["start_ns"] <= 5_000_000_000
            )
            assert (
                profile.evaluate_publication(artifacts, expected=expected)["status"]
                == "qualified"
            )
        if result["clock"]["status"] == "qualified":
            result["status"] = "qualified"
    except (
        AssertionError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        OverflowError,
        StopIteration,
    ) as error:
        result["error"] = old.error_value(error)
    return result


def _verify_fresh_fault_boundary(controller, observer, original, *, version=1):
    from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
    from azazel_edge.benchmark.source_witness import _source_tips, _verify_anchors

    boundary = observer["fault_boundary"]
    assert set(boundary) == {
        "observed_ns",
        "source_checkpoint",
        "cursor_position",
        "journal_checkpoint",
        "witness_sha256",
        "witness_boundary",
    }
    writer = controller["writer"]
    assert (
        writer["marker_one_before_ns"]
        <= boundary["observed_ns"]
        <= observer["stop_requested_ns"]
        < writer["first_write_before_ns"] + 6_000_000_000
    )
    policy = TrustPolicy(json.loads(original("trust.json")))
    source = original("source-after.raw")
    SourceVerifier(policy).verify(source)
    tip = boundary["source_checkpoint"]
    assert SourceVerifier(policy).verify(source[: tip["size"]]) == tip
    selected = [
        json.loads(line)["event"]
        for line in source[: tip["size"]].splitlines()
        if json.loads(line)["event"].get("capture_origin", {}).get("session_ref")
        == controller["session_ref"]
        and "normalized" in json.loads(line)["event"]
    ]
    assert [e["normalized"]["sid"] for e in selected] == [90233101]
    marker = json.loads(original("corpus-manifest.json"))["markers"][0]
    origin = selected[0]["ingress_origin"]
    assert origin["range_ref"] == controller["session_ref"] and all(
        origin[k] == marker[k] for k in ("start_offset", "end_offset", "raw_sha256")
    )
    position = boundary["cursor_position"]
    assert position == dict(offset=tip["size"], sha256=tip["sha256"])
    journal = original("observer-journal.raw")
    checkpoint = boundary["journal_checkpoint"]
    assert 0 < checkpoint["size"] <= len(journal)
    prefix = journal[: checkpoint["size"]]
    assert prefix.endswith(b"\n") and accounting.sha256(prefix) == checkpoint["sha256"]
    previous = "0" * 64
    rows = []
    for seq, line in enumerate(prefix.splitlines(keepends=True), 1):
        row = json.loads(line)
        assert (
            accounting.canonical(row) == line
            and row["seq"] == seq
            and row["prev"] == previous
        )
        assert row["sha256"] == accounting.sha256(
            accounting.canonical(
                {k: v for k, v in row.items() if k != "sha256"}
            ).rstrip(b"\n")
        )
        previous = row["sha256"]
        rows.append(row)
    assert rows[0]["kind"] == "header"
    assert any(
        r["kind"] == "cursor" and r["data"]["position"] == position for r in rows
    )
    anchors = original("observer-fault-anchors.raw")
    assert (
        len(anchors) <= 8 * 1024 * 1024
        and accounting.sha256(anchors) == boundary["witness_sha256"]
    )
    witness = boundary["witness_boundary"]
    st, at = witness["source_checkpoint"], witness["anchor_checkpoint"]
    assert accounting.witness_boundary(anchors) == witness and st["size"] >= tip["size"]
    assert _verify_anchors(policy, anchors, _source_tips(source), st) == at
    state = json.loads(anchors.splitlines()[-1])["state"]
    assert (
        state["journal_size"] <= len(prefix)
        and accounting.sha256(prefix[: state["journal_size"]])
        == state["journal_sha256"]
    )
    assert state["journal_seq"] >= next(
        r["seq"]
        for r in rows
        if r["kind"] == "cursor" and r["data"]["position"] == position
    )

    fresh = json.loads(original("fresh-controller.json"))
    recorded = fresh["interrupt_boundary"]
    assert (
        recorded["observed_ns"] == boundary["observed_ns"]
        and recorded["source_position"] == position
    )
    context = original("observer-input-calls.raw")
    checkpoint = recorded["input_calls_checkpoint"]
    prefix = context[: checkpoint["size"]]
    assert (
        len(prefix) == checkpoint["size"]
        and accounting.sha256(prefix) == checkpoint["sha256"]
    )
    rows, tail = input_prefix(prefix, version=version)
    assert not tail
    handler = next(
        r["data"]
        for r in rows
        if r["kind"] == "input_return"
        and r["data"]["input_id"] == recorded["handler_id"]
    )
    assert handler["cursor_after"] == position and len(handler["callbacks"]) == 1
    callback = handler["callbacks"][0]
    assert (
        callback["call_seq"] == recorded["event_call_id"]
        and callback["return_value"] is False
    )
    calls = decode_calls_prefix(original("observer-calls.raw"))
    event_call = next(
        r for r in calls["calls"] if r["seq"] == recorded["event_call_id"]
    )
    assert (
        event_call["kind"] == "event"
        and event_call["data"]["event"] == selected[0]
        and event_call["data"]["accepted"] is False
    )
    assert (
        accounting.sha256(accounting.canonical(event_call["data"]["event"]))
        == callback["event_sha256"]
    )


PROTOCOL_V2_SHA256 = "107595f5c7d85d410d65517a7f50bdb6e3dd3b31bdb4cffcd3936be98b65ea59"


def exclusive_public(path, raw):
    """One immutable Root artifact; no replace or post-seal update."""
    with path.open("xb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def publication_commits(context, needs):
    """Root read-only checks of pinned helper fsynced prefix reports."""
    paths = json.loads(context["files"]["observer-config.json"])["paths"]
    publication, _ = stable_read(Path(paths["publication"]), 1024 * 1024)
    rows, tail = old._rows(
        publication,
        "edge-observer-publication/v1",
        limit=1024 * 1024,
        max_rows=4096,
        allow_partial=True,
    )
    config = json.loads(context["files"]["observer-config.json"])
    assert (
        rows[0]["kind"] == "header"
        and rows[0]["data"]["metadata"] == config["metadata"]
        and rows[0]["data"]["identity"] == context["load"]["observer"]["identity"]
    )
    selected = {}
    for stream, seq in needs.items():
        raw, meta = stable_read(Path(paths[stream]), 4 * 1024 * 1024)
        commits = [
            row
            for row in rows
            if row["kind"] == "commit"
            and row["data"]["stream"] == stream
            and row["data"]["last_seq"] >= seq
        ]
        if not commits:
            return None
        commit = commits[-1]["data"]
        assert (
            commit["bytes"] <= len(raw)
            and accounting.sha256(raw[: commit["bytes"]]) == commit["sha256"]
        )
        obj = meta["object"]
        assert commit["object"] == dict(
            device=obj["device"],
            inode=obj["inode"],
            owner_uid=obj["owner_uid"],
            mode=obj["mode"],
            link_count=obj["nlink"],
        )
        assert obj["owner_uid"] == 61002 and obj["nlink"] == 1
        assert (
            commit["write"]["start_ns"]
            <= commit["write"]["end_ns"]
            <= commit["fsync"]["start_ns"]
            <= commit["fsync"]["end_ns"]
            <= time.monotonic_ns()
        )
        assert (
            type(commit["worker_native_tid"]) is int and commit["worker_native_tid"] > 0
        )
        selected[stream] = dict(size=commit["bytes"], sha256=commit["sha256"])
    prefix = publication[: publication.rfind(b"\n") + 1]
    return selected, dict(size=len(prefix), sha256=accounting.sha256(prefix))


class FreshSourceObserveV2Lab(FreshSourceObserveLab):
    version = 2
    protocol_name = "fresh-source-observe-protocol-v2.json"
    protocol_digest = PROTOCOL_V2_SHA256
    public_name = "fresh-source-observe-v2-public"
    core_module = "azazel_edge.benchmark.fresh_source_observe_v2"
    process_type = FreshObserverProcessV2
    side_files = FreshObserverProcessV2.side_files

    def __init__(self, g, role_command):
        super().__init__(g, role_command)
        self.run_ref = secrets.token_hex(16)
        self.run_started_ns = time.monotonic_ns()
        self.source_revision = (g.SRC / "SOURCE_REVISION").read_text().strip()
        self.outer_errors = []
        self.case_dispositions = {
            case: dict(
                case_id=case,
                state="not_run",
                snapshot_manifest_sha256=None,
                evaluation_sha256=None,
                error=None,
                cleanup_errors=[],
            )
            for case in CASES
        }

    def ready(self, context, paths):
        super().ready(context, paths)

        def committed():
            try:
                result = publication_commits(
                    context,
                    {"calls": context["fresh"]["readiness"]["first_sample_seq"]},
                )
                if result is None:
                    return False
                streams, checkpoint = result
                context["fresh"]["readiness"].update(
                    clock_calls_checkpoint=streams["calls"],
                    publication_checkpoint=checkpoint,
                    observed_ns=time.monotonic_ns(),
                )
                return True
            except (OSError, ValueError, KeyError, AssertionError):
                return False

        self.g.wait_for(committed)

    def interrupted_barrier(self, context, observation):
        super().interrupted_barrier(context, observation)
        paths = json.loads(context["files"]["observer-config.json"])["paths"]
        selected = context["fresh"]["interrupt_boundary"]

        def committed():
            try:
                raw, _ = stable_read(Path(paths["input_calls"]), 4 * 1024 * 1024)
                rows, _ = input_prefix(raw, version=2)
                ret = next(
                    row
                    for row in rows
                    if row["kind"] == "input_return"
                    and row["data"]["input_id"] == selected["handler_id"]
                )
                result = publication_commits(
                    context,
                    {"calls": selected["event_call_id"], "input_calls": ret["seq"]},
                )
                if result is None:
                    return False
                streams, checkpoint = result
                now = time.monotonic_ns()
                selected.update(
                    input_calls_checkpoint=streams["input_calls"],
                    publication_checkpoint=checkpoint,
                    observed_ns=now,
                )
                context["load"]["observer"]["fault_boundary"]["observed_ns"] = now
                return True
            except (OSError, ValueError, KeyError, AssertionError, StopIteration):
                return False

        self.g.wait_for(committed)

    def collect_observer(self, context):
        observer = context.get("observer_process")
        if observer is None:
            return
        observer.retain_drains()
        context["files"].update(
            {
                "observer-stdout.raw": observer.stdout,
                "observer-stderr.raw": observer.stderr,
            }
        )
        paths = json.loads(context["files"]["observer-config.json"])["paths"]
        for key, name in self.side_files.items():
            try:
                raw, meta = stable_read(Path(paths[key]), self.core.file_limit(name))
                context["files"][name] = raw
                observer.receipt["sidecars"][key] = dict(
                    before=meta["object"],
                    after=meta["object"],
                    sha256=meta["sha256"],
                    size=len(raw),
                )
            except FileNotFoundError:
                pass
        context["load"]["resources"]["observer_after"] = old.resource(
            observer.receipt["actor"]
        )

    def publish_case(self, case_id):
        context = self.contexts[case_id]
        files = context["files"]
        directory = self.g.BASE / self.public_directory / case_id
        directory.mkdir(parents=True, exist_ok=False)
        assert set(files) <= self.core.FILES
        for name, raw in files.items():
            if raw is not None:
                exclusive_public(directory / name, raw)
        context["exported"] = True
        artifacts = {name: files.get(name) for name in self.core.FILES}
        pins = {
            name: accounting.sha256(raw) if raw is not None else None
            for name, raw in artifacts.items()
        }
        try:
            result = self.core.evaluate_fresh_source_case(artifacts, expected=pins)
            result["observer"] = evaluate_fresh_observer_originals(
                artifacts, pins, version=2
            )
            evaluation = accounting.canonical(result)
            exclusive_public(directory / "evaluation.json", evaluation)
            files["evaluation.json"] = evaluation
            pins["evaluation.json"] = accounting.sha256(evaluation)
            snapshot = dict(
                schema_version="edge-fresh-snapshot/v1",
                case_id=case_id,
                run_ref=self.run_ref,
                protocol_sha256=self.protocol_sha256,
                source_revision=self.source_revision,
                files=pins,
            )
            snapshot_raw = accounting.canonical(snapshot)
            exclusive_public(
                directory.parent / (case_id + "-snapshot.json"), snapshot_raw
            )
            context.update(
                snapshot_published=True, snapshot=snapshot, snapshot_raw=snapshot_raw
            )
            self.case_dispositions[case_id].update(
                snapshot_manifest_sha256=accounting.sha256(snapshot_raw),
                evaluation_sha256=pins["evaluation.json"],
            )
            self.results.append(result)
            return result
        except BaseException as error:
            self.post_snapshot_error(case_id, error, stage="snapshot-publication")
            raise

    def assert_case_result(self, case_id, result):
        try:
            super().assert_case_result(case_id, result)
            state = (
                "accepted"
                if self.contexts[case_id]["controller"]["outcome"] == "collected"
                else "collection_failed"
            )
            self.case_dispositions[case_id]["state"] = state
            if state == "collection_failed":
                actual = self.contexts[case_id]["controller"].get("error")
                if actual is not None:
                    self.case_dispositions[case_id]["error"] = {
                        "type": actual["type"],
                        "message": actual["message"][:4096],
                    }
        except BaseException as error:
            self.post_snapshot_error(case_id, error, stage="qualification")
            raise

    def post_snapshot_error(self, case_id, error, *, stage, cleanup_errors=None):
        entry = self.case_dispositions[case_id]
        context = self.contexts.get(case_id, {})
        if not context.get("snapshot_published"):
            entry["state"] = "collection_failed"
        elif stage in ("qualification", "post-export"):
            if entry["state"] not in (
                "rejected",
                "cleanup_failed",
                "collection_failed",
            ):
                entry["state"] = "rejected"
        elif entry["state"] not in ("rejected", "collection_failed"):
            entry["state"] = "cleanup_failed"
        entry["error"] = entry["error"] or old.error_value(error)
        if stage not in ("qualification", "post-export"):
            records = [dict(stage=stage, **old.error_value(error))] + [
                dict(stage=stage, **item) for item in (cleanup_errors or [])
            ]
            for item in records:
                if item not in entry["cleanup_errors"]:
                    entry["cleanup_errors"].append(item)

    def release_case_reference(self, case_id, *, original=None):
        try:
            super().release_case_reference(case_id, original=original)
        except BaseException as error:
            self.post_snapshot_error(
                case_id,
                error,
                stage="manager-reference",
                cleanup_errors=getattr(error, "manager_cleanup_errors", []),
            )
            raise

    def write_disposition(self):
        value = dict(
            schema_version="edge-fresh-run-disposition/v1",
            protocol_sha256=self.protocol_sha256,
            source_revision=self.source_revision,
            run_ref=self.run_ref,
            started_ns=self.run_started_ns,
            finished_ns=time.monotonic_ns(),
            cases=[self.case_dispositions[case] for case in CASES],
            errors=self.outer_errors,
        )
        raw = accounting.canonical(value)
        return raw

    def replay_run(self, disposition):
        cases, snapshots, casepins, snapshotpins = {}, {}, {}, {}
        for case_id in CASES:
            context = self.contexts.get(case_id)
            snap = context.get("snapshot") if context else None
            directory = self.g.BASE / self.public_directory / case_id
            slots = {}
            for name in self.core.FILES:
                try:
                    slots[name] = stable_read(
                        directory / name, self.core.file_limit(name)
                    )[0]
                except FileNotFoundError:
                    slots[name] = None
            cases[case_id] = slots
            try:
                snapshots[case_id] = stable_read(
                    directory.parent / (case_id + "-snapshot.json"), 131072
                )[0]
            except FileNotFoundError:
                snapshots[case_id] = None
            casepins[case_id] = (
                snap["files"] if snap else dict.fromkeys(self.core.FILES)
            )
            original_snapshot = context.get("snapshot_raw") if context else None
            snapshotpins[case_id] = (
                accounting.sha256(original_snapshot)
                if original_snapshot is not None
                else None
            )
        return self.core.evaluate_fresh_run_evidence(
            cases,
            snapshots,
            disposition,
            expected=dict(
                cases=casepins,
                snapshots=snapshotpins,
                disposition=accounting.sha256(disposition),
            ),
        )

    def exercise(self):
        failure = None
        try:
            super().exercise()
        except BaseException as error:
            failure = error
            self.outer_errors.append(dict(stage="run", **old.error_value(error)))
            raise
        finally:
            try:
                disposition = self.write_disposition()
                replay = self.replay_run(disposition)
                if replay["status"] != "qualified" and failure is None:
                    self.outer_errors.append(
                        dict(
                            stage="final-replay",
                            type="AssertionError",
                            message=str(replay["reasons"])[:4096],
                        )
                    )
                    disposition = self.write_disposition()
                    replay = self.replay_run(disposition)
                exclusive_public(
                    self.g.BASE / self.public_directory / "disposition.json",
                    disposition,
                )
                actual_disposition = stable_read(
                    self.g.BASE / self.public_directory / "disposition.json", 131072
                )[0]
                assert actual_disposition == disposition, (
                    "published disposition changed"
                )
                self.g.record(
                    "fresh-v2-final-replay",
                    status=replay["status"],
                    reasons=replay["reasons"],
                )
                if failure is None:
                    assert replay["status"] == "qualified", replay
            except BaseException as error:
                if failure is None:
                    raise
                self.g.record(
                    "fresh-v2-disposition-failure",
                    error=old.error_value(error),
                    primary_error_preserved=True,
                )
