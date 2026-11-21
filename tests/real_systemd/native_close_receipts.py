"""Fixed offline close/refusal collection in the unchanged disposable AA lab.

All original stores remain in place. This controller never signs, repairs or
reconstructs Source; private child reports are accepted only from Root's sink.
"""

import base64
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import time

import native_accounting as accounting

PROTOCOL_SHA256 = "27b5674e1d2b7704bbb4e788ab5581fde2d7ee2f968c17d6519793217fb5639b"
PROTOCOL_NAME = "native-close-receipts-protocol-v1.json"
CASE_IDS = frozenset(
    (
        "normal-four",
        "restart-one",
        "witness-stopped-close",
        "interrupted-prefix",
        "interrupted-restart-refused",
        "receiver-killed-prefix",
        "receiver-restart-refused",
    )
)
PUBLIC_FILES = frozenset(
    (
        "protocol.json",
        "trust.json",
        "registration.json",
        "close-controller.json",
        "root-custody.raw",
        "root-custody-object.json",
        "actor-fd-custody.json",
        "native-close.raw",
        "receiver-close.raw",
        "launcher-systemd.json",
        "unit-exec-start.raw",
        "launcher-journal.raw",
        "source-before.raw",
        "source-after.raw",
        "anchors-before.raw",
        "anchors-after.raw",
        "journal-before.raw",
        "journal-after.raw",
        "readback-source.raw",
        "reader-binding.json",
        "witness-boundary.json",
        "code-pins.json",
        "failure.json",
        "evaluation.json",
    )
)
OBJECT_LIMIT = 8 * 1024 * 1024
ROOT_LIMIT = 32768
BUS = (
    "/usr/bin/busctl",
    "--system",
    "--json=short",
    "get-property",
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1/unit/azazel_2dedge_2dcore_2eservice",
    "org.freedesktop.systemd1.Service",
)


def stable_read(path, limit):
    """One real read-only FD with equal full metadata around read and path."""
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        initial = accounting.source_metadata(os.fstat(fd), detailed=True)
        assert initial == accounting.source_metadata(before, detailed=True)
        assert initial["size"] <= limit
        chunks, size = [], 0
        while size <= limit:
            part = os.read(fd, min(65536, limit + 1 - size))
            if not part:
                break
            chunks.append(part)
            size += len(part)
        raw = b"".join(chunks)
        after = accounting.source_metadata(os.fstat(fd), detailed=True)
        assert (
            after == initial == accounting.source_metadata(path.lstat(), detailed=True)
        )
        assert len(raw) == initial["size"] <= limit
        return raw, dict(object=initial, bytes=len(raw), sha256=accounting.sha256(raw))
    finally:
        os.close(fd)


def fd_object(pid, number):
    info = Path(f"/proc/{pid}/fd/{number}").stat()
    flags = next(
        line.split()[1]
        for line in Path(f"/proc/{pid}/fdinfo/{number}").read_text().splitlines()
        if line.startswith("flags:")
    )
    return dict(
        fd=number,
        device=info.st_dev,
        inode=info.st_ino,
        owner_uid=info.st_uid,
        mode=info.st_mode,
        nlink=info.st_nlink,
        flags=int(flags, 8),
    )


def descriptor_inventory(actor):
    pid = actor["pid"]
    result = dict(
        pid=pid, start_ticks=actor["start_ticks"], complete=False, entries=[], errors=[]
    )
    try:
        entries = list(Path(f"/proc/{pid}/fd").iterdir())
        assert len(entries) <= 256, "descriptor inventory exceeds bound"
        for entry in sorted(entries, key=lambda p: int(p.name)):
            try:
                result["entries"].append(fd_object(pid, int(entry.name)))
            except (OSError, ValueError, StopIteration) as exc:
                result["errors"].append(
                    dict(fd=int(entry.name), error=type(exc).__name__)
                )
        actual = accounting.actor(pid)
        result["complete"] = (
            not result["errors"] and actual["start_ticks"] == actor["start_ticks"]
        )
    except (OSError, AssertionError) as exc:
        result["errors"].append(dict(fd=None, error=str(exc)))
    return result


def same_object(left, right):
    return all(
        left[key] == right[key]
        for key in ("device", "inode", "owner_uid", "mode", "nlink")
    )


def check_fd_custody(inventories, root_object):
    """No child descriptor can be mistaken for the exclusive Root sink."""
    assert all(
        inventories[name]["complete"] for name in ("launcher", "native", "receiver")
    )
    by_role = {
        name: {entry["fd"]: entry for entry in inventories[name]["entries"]}
        for name in ("launcher", "native", "receiver")
    }
    assert same_object(by_role["launcher"][1], root_object)
    pipes = [by_role[name][1] for name in ("native", "receiver")]
    assert all(stat.S_ISFIFO(pipe["mode"]) for pipe in pipes)
    assert (pipes[0]["device"], pipes[0]["inode"]) != (
        pipes[1]["device"],
        pipes[1]["inode"],
    )
    for name in ("native", "receiver"):
        assert not any(
            (entry["device"], entry["inode"])
            == (root_object["device"], root_object["inode"])
            for entry in by_role[name].values()
        )
        assert (by_role[name][2]["device"], by_role[name][2]["inode"]) != (
            root_object["device"],
            root_object["inode"],
        )
    assert all(
        any(
            (entry["device"], entry["inode"]) == (pipe["device"], pipe["inode"])
            for entry in by_role["launcher"].values()
        )
        for pipe in pipes
    )
    return by_role["launcher"][1]


def typed_property(g, name, expected_type):
    raw = g.command(*BUS, name).stdout.encode()
    assert len(raw) <= 65536
    value = json.loads(raw)
    assert set(value) == {"type", "data"} and value["type"] == expected_type
    return value["data"], raw


class CloseReceiptLab:
    def __init__(self, g, role_command):
        self.g, self.role_command = g, role_command
        self.protocol_raw = Path(__file__).with_name(PROTOCOL_NAME).read_bytes()
        assert accounting.sha256(self.protocol_raw) == PROTOCOL_SHA256
        self.protocol = json.loads(self.protocol_raw)
        self.cases = {case["case_id"]: case for case in self.protocol["cases"]}
        assert set(self.cases) == CASE_IDS
        self.contexts = {}

    def _store_paths(self):
        return dict(
            source=self.g.BUNDLE / "input",
            anchors=self.g.BUNDLE / "witness/anchors/anchors.journal",
            journal=self.g.BUNDLE / "observer/observations.journal",
        )

    def stores(self, context, phase):
        g = self.g
        for name, path in self._store_paths().items():
            raw, observed = stable_read(path, OBJECT_LIMIT)
            context["files"][name + "-" + phase + ".raw"] = raw
            context["controller"]["stores"][name][phase] = observed
            if name == "source":
                context["controller"]["stores"][name][phase + "_checkpoint"] = (
                    accounting.checkpoint(g, raw)
                )
            elif name == "anchors":
                context["controller"]["stores"][name][phase + "_checkpoint"] = (
                    accounting.witness_boundary(raw)["anchor_checkpoint"]
                )

    def begin(self, case_id, *, previous_session=None):
        assert (
            case_id in getattr(self, "allowed_case_ids", CASE_IDS)
            and case_id not in self.contexts
        )
        g = self.g
        self.prepare_case_start(case_id, previous_session=previous_session)
        case = self.cases[case_id]
        nonce = secrets.token_hex(16)
        directory = g.BASE / "close-custody"
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        assert (
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o700
        )
        path = directory / (case_id + "-" + nonce + ".raw")
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            prepared = accounting.source_metadata(os.fstat(fd), detailed=True)
            assert (
                prepared["owner_uid"] == 0
                and prepared["nlink"] == 1
                and stat.S_IMODE(prepared["mode"]) == 0o600
            )
            os.fsync(fd)
        finally:
            os.close(fd)
        trust, _ = stable_read(g.BUNDLE / "trust.json", 32768)
        registration, _ = stable_read(g.BUNDLE / "origin.json", 32768)
        revision = (g.SRC / "SOURCE_REVISION").read_text().strip()
        controller = dict(
            schema_version="edge-native-close-controller/v1",
            case_id=case_id,
            protocol_sha256=getattr(self, "protocol_sha256", PROTOCOL_SHA256),
            source_revision=revision,
            core_image_sha256=json.loads(registration)["binary_sha256"],
            trust_sha256=accounting.sha256(trust),
            registration_sha256=accounting.sha256(registration),
            boot_id=g.boot(),
            source_boot_ref=g.boot().replace("-", ""),
            session_ref=previous_session,
            previous_session_ref=previous_session,
            attempt_ref=nonce,
            action=case["action"],
            started_ns=time.monotonic_ns(),
            finished_ns=None,
            custody_mode=case["custody_mode"],
            actors=dict(launcher=None, native=None, receiver=None),
            invocation=None,
            root_custody=dict(
                relative_name=str(path.relative_to(g.BASE)),
                prepared=prepared,
                launcher_fd1=None,
                after=None,
                bytes=None,
                sha256=None,
            ),
            fd_custody=None,
            stores={
                name: dict(
                    before=None,
                    after=None,
                    **(
                        {"before_checkpoint": None, "after_checkpoint": None}
                        if name != "journal"
                        else {}
                    ),
                )
                for name in ("source", "anchors", "journal")
            },
            reader=None,
            outcome=None,
            error=None,
        )
        context = dict(
            controller=controller,
            path=path,
            exported=False,
            analysis_accepted=False,
            files={
                "protocol.json": self.protocol_raw,
                "trust.json": trust,
                "registration.json": registration,
            },
        )
        self.contexts[case_id] = context
        self.stores(context, "before")
        dropin = g.UNITS / (g.UNIT + ".d") / "40-close-custody.conf"
        if dropin.exists():
            old = dropin.lstat()
            assert (
                stat.S_ISREG(old.st_mode)
                and old.st_uid == 0
                and old.st_nlink == 1
                and not old.st_mode & 0o022
            )
        fd = os.open(
            dropin,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o644,
        )
        try:
            content = (
                "[Service]\nStandardOutput=append:"
                + str(path)
                + "\nStandardError=journal\n"
            ).encode()
            assert os.write(fd, content) == len(content), "short unit fixture write"
            os.fsync(fd)
        finally:
            os.close(fd)
        g.systemctl("daemon-reload")
        self.policy_probe(context)

    def verify_case_start(self, case_id, *, previous_session=None):
        """Validate original archive/Source/manager guards without mutation."""
        from azazel_edge.outcome.input_auth import SourceVerifier

        g = self.g
        system = g.Systemd()
        assert not system.cores(), "Root output assignment requires no running core"
        assert system.snapshot()["ActiveState"] in ("inactive", "failed"), (
            "case preparation requires inactive/failed manager"
        )
        for context in self.contexts.values():
            assert context["exported"] and context.get("analysis_accepted"), (
                "previous case must be archived and accepted before counter preparation"
            )
            required = {
                "root-custody.raw",
                "launcher-systemd.json",
                *(
                    name + "-" + phase + ".raw"
                    for name in ("source", "anchors", "journal")
                    for phase in ("before", "after")
                ),
            }
            assert required <= context["files"].keys(), (
                "previous original snapshots are incomplete"
            )
            assert (
                context["controller"]["invocation"]["exec_main_exit_monotonic_us"] > 0
            ), "previous actual wait must be archived"
        verifier = SourceVerifier(g.fixture().p)
        tip = verifier.verify(g.source())
        refusal = self.cases[case_id]["custody_mode"] == "managed_prelaunch_refusal"
        if refusal:
            assert (
                not verifier.live_state.closed
                and previous_session is not None
                and verifier.live_state.session == previous_session
            ), "refusal requires the exact prior unclosed session"
        else:
            assert verifier.live_state.closed and previous_session is None, (
                "new native case requires verified closed history"
            )
        return tip, refusal

    def _reset_case_counter(self, case_id, previous_session, expected_tip):
        self.g.systemctl("reset-failed", self.g.UNIT)

    def prepare_case_start(self, case_id, *, previous_session=None):
        """One explicit fixture preparation, never a retry or production change."""
        tip, refusal = self.verify_case_start(
            case_id, previous_session=previous_session
        )
        self._reset_case_counter(case_id, previous_session, tip)
        g = self.g
        g.record(
            "native-close-case-start-counter-prepared",
            case_id=case_id,
            source_checkpoint=tip,
            expected_source_closed=not refusal,
            prior_session_ref=previous_session,
            archived_cases=list(self.contexts),
            action="single-explicit-reset-failed",
        )

    def policy_probe(self, context):
        """Existing grant controls, explicitly separate from actual core work."""
        g = self.g
        raw, _ = stable_read(context["path"], ROOT_LIMIT)
        assert raw == b""  # Root's unconfined positive read of the real object.
        script = (
            "import errno,json,os,sys;from pathlib import Path;"
            "assert os.getuid()==61001 and os.getgid()==61001;"
            "assert not os.getgroups();"
            "assert Path('/proc/self/attr/apparmor/current').read_text().strip()=='unconfined';"
            "\nfor flags in (os.O_RDONLY,os.O_WRONLY|os.O_APPEND):"
            "\n try: fd=os.open(sys.argv[1],flags)"
            "\n except OSError as e: assert e.errno in (errno.EACCES,errno.EPERM)"
            "\n else: os.close(fd);raise AssertionError('Root sink unexpectedly accessible')"
            "\nprint(json.dumps({'uid':os.getuid(),'probe':'unconfined-producer-DAC-control','denied':True}))"
        )
        dac = subprocess.run(
            [str(g.PYTHON), "-I", "-c", script, str(context["path"])],
            user=61001,
            group=61001,
            extra_groups=[],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert dac.returncode == 0, dac.stderr
        native = g.command(
            "systemd-run",
            "--wait",
            "--pipe",
            "--collect",
            "-p",
            "NoNewPrivileges=yes",
            "-p",
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID CAP_NET_ADMIN",
            "-p",
            "RestrictAddressFamilies=AF_UNIX",
            str(g.PYTHON),
            "-I",
            str(g.SRC / "tests/real_systemd/native_probe.py"),
            "--close-sink-name",
            context["path"].name,
        )
        g.record(
            "native-close-root-sink-independent-policy-controls",
            case_id=context["controller"]["case_id"],
            root_read_positive=True,
            capture_dac=json.loads(dac.stdout),
            native_profile_helper=json.loads(native.stdout),
            actual_core_activity=False,
        )

    def started(self, case_id, native_pid, session_ref):
        context = self.contexts[case_id]
        control = context["controller"]
        control["session_ref"] = session_ref
        control["actors"] = accounting.process_receipt(self.g, native_pid)
        assert all(control["actors"].values())
        inventories = {
            name: descriptor_inventory(actor)
            for name, actor in control["actors"].items()
        }
        inventories["sampled_ns"] = time.monotonic_ns()
        control["fd_custody"] = inventories
        context["files"]["actor-fd-custody.json"] = accounting.canonical(inventories)
        control["root_custody"]["launcher_fd1"] = check_fd_custody(
            inventories, control["root_custody"]["prepared"]
        )
        self.invocation(context)
        assert (
            control["invocation"]["exec_main_pid"]
            == control["actors"]["launcher"]["pid"]
        )

    def invocation(self, context):
        g = self.g
        properties = (
            "InvocationID",
            "ExecMainPID",
            "ExecMainStartTimestampMonotonic",
            "ExecMainExitTimestampMonotonic",
            "ActiveState",
            "Result",
            "ExecMainCode",
            "ExecMainStatus",
        )
        raw = g.systemctl(
            "show", g.UNIT, *("--property=" + name for name in properties)
        ).stdout
        state = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        observed = dict(
            unit=g.UNIT,
            invocation_id=state.get("InvocationID"),
            exec_main_pid=int(state["ExecMainPID"])
            if state.get("ExecMainPID")
            else None,
            exec_main_start_monotonic_us=int(state["ExecMainStartTimestampMonotonic"])
            if state.get("ExecMainStartTimestampMonotonic")
            else None,
            exec_main_exit_monotonic_us=int(state["ExecMainExitTimestampMonotonic"])
            if state.get("ExecMainExitTimestampMonotonic")
            else None,
            active_state=state.get("ActiveState"),
            result=state.get("Result"),
            exec_main_code=int(state["ExecMainCode"])
            if state.get("ExecMainCode")
            else None,
            exec_main_status=int(state["ExecMainStatus"])
            if state.get("ExecMainStatus")
            else None,
            exec_start_sha256=None,
            exec_start=None,
            standard_output=None,
            standard_error=None,
        )
        commands, _ = typed_property(g, "ExecStart", "a(sasbttttuii)")
        raw_commands = accounting.canonical(commands)
        observed["exec_start"] = commands
        observed["exec_start_sha256"] = accounting.sha256(raw_commands)
        context["files"]["unit-exec-start.raw"] = raw_commands
        mode, _ = typed_property(g, "StandardOutput", "s")
        path = None
        try:
            path, _ = typed_property(g, "StandardOutputFile", "s")
            if path == "":
                path = None  # No actual typed file path was exposed.
        except (subprocess.CalledProcessError, AssertionError, ValueError):
            pass  # Actual unexposed path stays null; never reconstruct from text.
        observed["standard_output"] = dict(mode=mode, path=path)
        observed["standard_error"], _ = typed_property(g, "StandardError", "s")
        prior = context["controller"]["invocation"]
        if prior is not None:
            assert (
                observed["invocation_id"] == prior["invocation_id"]
                and observed["exec_main_pid"] == prior["exec_main_pid"]
            )
        context["controller"]["invocation"] = observed
        context["files"]["launcher-systemd.json"] = accounting.canonical(observed)

    def stopped(self, case_id):
        context = self.contexts[case_id]
        control = context["controller"]
        raw, observed = stable_read(context["path"], ROOT_LIMIT)
        assert (
            observed["object"]["owner_uid"] == 0
            and stat.S_IMODE(observed["object"]["mode"]) == 0o600
        )
        assert same_object(observed["object"], control["root_custody"]["prepared"])
        control["root_custody"].update(
            after=observed["object"], bytes=len(raw), sha256=accounting.sha256(raw)
        )
        context["files"]["root-custody.raw"] = raw
        context["files"]["root-custody-object.json"] = accounting.canonical(
            control["root_custody"]
        )
        self.invocation(context)
        assert control["invocation"]["active_state"] in ("inactive", "failed")
        # Custody/child parsing is an independent pure annex responsibility.
        # Copy only exact decoded original stream bytes from the typed Root row.
        try:
            rows = [json.loads(line) for line in raw.splitlines()]
            finals = [
                row
                for row in rows
                if type(row) is dict
                and row.get("schema_version")
                == getattr(self, "custody_schema", "outcome-live-close-custody/v1")
            ]
            if len(finals) == 1:
                for name in ("native", "receiver"):
                    context["files"][name + "-close.raw"] = base64.b64decode(
                        finals[0][name + "_stream"]["raw_b64"], validate=True
                    )
        except (ValueError, TypeError, KeyError):
            # Keep original malformed custody; pure validation must reject it.
            # A plausible marker never turns these unbound bytes into receipts.
            pass
        invocation = control["invocation"]["invocation_id"]
        result = self.g.command(
            "journalctl",
            "--quiet",
            "--no-pager",
            "--output=json",
            "--lines=161",
            "_SYSTEMD_INVOCATION_ID=" + invocation,
        )
        lines = result.stdout.encode().splitlines(keepends=True)
        count_truncated = len(lines) > 160
        journal = b"".join(lines[:160])
        bytes_truncated = len(journal) > 65536
        if count_truncated or bytes_truncated:
            journal = journal[:65536]
            control["error"] = dict(
                type="DiagnosticTruncated",
                message=f"journal diagnostic truncated: record_limit160={count_truncated}, byte_limit65536={bytes_truncated}",
            )
        context["files"]["launcher-journal.raw"] = journal

    def _reader(self, case_id):
        context = self.contexts[case_id]
        result = accounting.observed_readback(
            self.g, self.role_command, case_id, context["files"]
        )
        raw = base64.b64decode(result["source_base64"], validate=True)
        assert raw == context["files"]["source-after.raw"]
        return result["receipt"], raw

    def finalized(self, case_id, *, reader=None, readback=None, reader_binding=None):
        context = self.contexts[case_id]
        if context["exported"]:
            assert context["analysis_accepted"], (
                "cannot replace rejected case originals"
            )
            return
        self.stores(context, "after")
        if (
            reader is None
            and self.cases[case_id]["custody_mode"] == "live_parent_and_children"
        ):
            reader, readback = self._reader(case_id)
        context["controller"]["reader"] = reader
        if readback is not None:
            context["files"]["readback-source.raw"] = readback
        if reader_binding is not None:
            context["files"]["reader-binding.json"] = reader_binding
        context["controller"]["outcome"] = "collected"
        self.export(case_id)

    def export(self, case_id):
        context = self.contexts[case_id]
        assert not context["exported"]
        control, files = context["controller"], context["files"]
        control["finished_ns"] = time.monotonic_ns()
        files["close-controller.json"] = accounting.canonical(control)
        files["actor-fd-custody.json"] = accounting.canonical(control["fd_custody"])
        files["code-pins.json"] = accounting.canonical(
            dict(
                source_revision=control["source_revision"],
                core_image_sha256=control["core_image_sha256"],
                protocol_sha256=PROTOCOL_SHA256,
            )
        )
        if files.get("anchors-after.raw"):
            files["witness-boundary.json"] = accounting.canonical(
                accounting.witness_boundary(files["anchors-after.raw"])
            )
        directory = self.g.BASE / "native-close-receipts-public" / case_id
        directory.mkdir(parents=True, exist_ok=False)
        assert set(files) <= PUBLIC_FILES
        for name, raw in files.items():
            if raw is not None:
                self.g.write(directory / name, raw)
        context["exported"] = True
        from azazel_edge.benchmark.native_close_receipts import (
            evaluate_native_close_receipts,
        )

        artifacts = {name: files.get(name) for name in PUBLIC_FILES}
        expected = {
            name: accounting.sha256(raw) if raw is not None else None
            for name, raw in artifacts.items()
        }
        result = evaluate_native_close_receipts(artifacts, expected=expected)
        self.g.write(directory / "evaluation.json", accounting.canonical(result))
        if control["outcome"] == "failure":
            return  # Preserve original collection failure; never assert success.
        expected_status = (
            "bound_prelaunch_refusal"
            if control["custody_mode"] == "managed_prelaunch_refusal"
            else (
                "bound_finite_close"
                if case_id in ("normal-four", "restart-one")
                else "bound_partial_close"
            )
        )
        assert result["status"] == expected_status, result
        if expected_status == "bound_finite_close":
            assert (
                result["native_local_worker_ack_observed"] is True
                and result["witness_covers_selected_end"] is True
            )
            assert result["native_returncode"] == result["receiver_returncode"] == 0
        elif expected_status == "bound_prelaunch_refusal":
            assert (
                result["managed_refusal_verified"] is True
                and result["stores_unchanged"] is True
            )
        elif case_id == "witness-stopped-close":
            assert (
                result["selected_end_present"] is True
                and result["witness_covers_selected_end"] is False
            )
        else:
            assert result["selected_end_present"] is False
            assert (
                result[
                    "native_returncode"
                    if case_id == "interrupted-prefix"
                    else "receiver_returncode"
                ]
                == -signal.SIGKILL
            )
        self.g.record(
            "native-close-receipts-" + case_id, public_directory=str(directory)
        )
        context["analysis_accepted"] = True

    def refuse_restart(self, prior_case):
        name = (
            "interrupted-restart-refused"
            if prior_case == "interrupted-prefix"
            else "receiver-restart-refused"
        )
        prior_session = self.contexts[prior_case]["controller"]["session_ref"]
        self.begin(name, previous_session=prior_session)
        self.g.systemctl("start", self.g.UNIT, check=False)
        self.g.wait_for(
            lambda: self.g.Systemd().snapshot()["ActiveState"] == "failed"
            and not self.g.Systemd().cores()
        )
        self.stopped(name)
        context = self.contexts[name]
        self.stores(context, "after")
        for store in ("source", "anchors", "journal"):
            assert (
                context["files"][store + "-before.raw"]
                == context["files"][store + "-after.raw"]
            )
            assert (
                context["controller"]["stores"][store]["before"]
                == context["controller"]["stores"][store]["after"]
            )
        self.finalized(name)

    def witness_stopped_close(self):
        g, case_id = self.g, "witness-stopped-close"
        self.begin(case_id)
        g.systemctl("start", g.UNIT)
        pid = g.live()
        session = g.events()[-1]["capture_origin"]["session_ref"]
        self.started(case_id, pid, session)
        accounting.await_input_start(g)
        g.alert(90122001)
        g.wait_for(lambda: g.saw(90122001))
        g.systemctl("stop", g.WITNESS)
        assert (
            accounting.actor(pid)["start_ticks"]
            == self.contexts[case_id]["controller"]["actors"]["native"]["start_ticks"]
        )
        g.stop()
        self.stopped(case_id)
        self.finalized(case_id)  # Original short anchors/readback before recovery.
        g.systemctl("start", g.WITNESS)
        g.observer()  # Continuation only; never rewrite the exported checkpoint.

    def receiver_fault(self):
        g, case_id = self.g, "receiver-killed-prefix"
        try:
            g.stop()
            g.observer()
            self.begin(case_id)
            g.systemctl("start", g.UNIT)
            pid = g.live()
            self.started(case_id, pid, g.events()[-1]["capture_origin"]["session_ref"])
            accounting.await_input_start(g)
            g.alert(90122002)
            g.wait_for(lambda: g.saw(90122002))
            control = self.contexts[case_id]["controller"]
            os.kill(control["actors"]["receiver"]["pid"], signal.SIGKILL)
            g.wait_for(
                lambda: not Path(
                    f"/proc/{control['actors']['receiver']['pid']}"
                ).exists()
            )
            assert (
                accounting.actor(pid)["start_ticks"]
                == control["actors"]["native"]["start_ticks"]
            )
            assert g.Systemd().cores()[0]["pid"] == pid
            g.systemctl("stop", g.UNIT)
            g.wait_for(lambda: not g.Systemd().cores())
            self.stopped(case_id)
            self.finalized(case_id)
            self.refuse_restart(case_id)
        except BaseException as exc:
            g.systemctl("disable", g.UNIT, check=False)
            g.systemctl("stop", g.UNIT, g.WITNESS, check=False)
            self.retain_failures(exc)
            raise

    def retain_failures(self, error):
        for case_id, context in self.contexts.items():
            if context["exported"]:
                if (
                    not context.get("analysis_accepted")
                    and "failure.json" not in context["files"]
                ):
                    raw = accounting.canonical(
                        dict(type=type(error).__name__, message=str(error))
                    )
                    self.g.write(
                        self.g.BASE
                        / getattr(
                            self, "public_directory", "native-close-receipts-public"
                        )
                        / case_id
                        / "failure.json",
                        raw,
                    )
                    context["files"]["failure.json"] = raw
                continue
            context["controller"]["error"] = dict(
                type=type(error).__name__, message=str(error)
            )
            context["controller"]["outcome"] = "failure"
            context["files"]["failure.json"] = accounting.canonical(
                context["controller"]["error"]
            )
            try:
                self.stopped(case_id)
            except (
                OSError,
                AssertionError,
                ValueError,
                KeyError,
                subprocess.CalledProcessError,
            ):
                pass  # Preserve every available original; no successful fallback.
            try:
                self.stores(context, "after")
            except (OSError, AssertionError, ValueError, KeyError):
                pass
            self.export(case_id)
