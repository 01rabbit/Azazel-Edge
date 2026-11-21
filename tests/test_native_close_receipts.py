"""Real TEST-key crypto and SYNTHETIC custody receipts; never native attestation."""

import base64
from copy import deepcopy
import json
from pathlib import Path
import stat

import pytest

from azazel_edge.benchmark import native_close_receipts as annex
from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
from azazel_edge.outcome.input_transport import transport
from azazel_edge.outcome.journal import _json
from safety_observation_data import digest
from source_witness_data import anchor_checkpoint
from test_native_source_accounting import (
    fixture as accounting_fixture,
    source_bytes,
    anchors,
    BOOT,
)


def wire(value):
    return _json(value) + b"\n"


def obj(inode, owner, raw, permissions=0o600):
    return dict(
        device=8,
        inode=inode,
        owner_uid=owner,
        mode=stat.S_IFREG | permissions,
        nlink=1,
        size=len(raw),
        mtime_ns=100,
        ctime_ns=100,
    )


def stream(raw):
    return dict(raw_b64=base64.b64encode(raw).decode(), eof=True, over_limit=False)


def reader_binding(reader, case):
    challenge = "1" * 32
    bootstrap = dict(
        schema_version="edge-native-source-reader-bootstrap/v1",
        pid=reader["actor"]["pid"],
        challenge=challenge,
        invocation_id="2" * 32,
        actor=deepcopy(reader["actor"]),
    )
    return dict(
        schema_version="edge-native-source-reader-binding/v1",
        unit="edge400-accounting-reader-" + case + "-" + challenge + ".service",
        challenge=challenge,
        bootstrap=bootstrap,
        unit_properties=dict(
            MainPID=str(reader["actor"]["pid"]), InvocationID="2" * 32
        ),
        actual_actor=deepcopy(reader["actor"]),
        command_verified=True,
        status="verified_root_observed_role",
        error=None,
        runner_stderr="",
        runner_stdout_base64=base64.b64encode(wire(bootstrap)).decode(),
        runner_stderr_base64="",
        runner_stdout_bytes=len(wire(bootstrap)),
        runner_stderr_bytes=0,
        runner_stdout_truncated=False,
        runner_stderr_truncated=False,
        runner_returncode=0,
        cleanup=None,
    )


def fixture(case="normal-four"):
    refusal = case.endswith("restart-refused")
    partial = case in ("interrupted-prefix", "receiver-killed-prefix") or refusal
    parentcase = (
        "restart-one"
        if case in ("restart-one", "witness-stopped-close")
        else "interrupted-prefix"
        if partial
        else "normal-four"
    )
    old, oldpolicy, events, base = accounting_fixture(parentcase)
    r = json.loads(old["registration"])
    r["environment"]["AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS"] = "v1"
    p = TrustPolicy(
        {
            **dict(oldpolicy.data),
            "schema_version": "outcome-input-trust/v4",
            "origin_registration_sha256": digest(_json(r)),
            "witness_transport": transport(
                oldpolicy.data["scope_ref"], dict(cookie=123, kernel_boot_id=BOOT)
            ),
        }
    )
    sid = (
        90122001
        if case == "witness-stopped-close"
        else 90122002
        if case in ("receiver-killed-prefix", "receiver-restart-refused")
        else None
    )
    for event in events:
        event["capture_origin"]["registration_sha256"] = p.data[
            "origin_registration_sha256"
        ]
        if sid is not None and event["capture_origin"]["kind"] == "decision_execution":
            event["normalized"]["sid"] = sid
    after = source_bytes(p, events)
    before = after if partial else b"".join(after.splitlines(keepends=True)[:-1])
    bt, at = SourceVerifier(p).verify(before), SourceVerifier(p).verify(after)
    awtip = bt if case == "witness-stopped-close" else at
    ab, aa = anchors(p, bt), anchors(p, awtip)
    rootobj = obj(900, 0, b"")
    actors = deepcopy({k: base[k] for k in ("launcher", "native", "receiver")})
    sourceobj = obj(200, 61001, after, 0o644)
    reader = deepcopy(base["reader"])
    reader.update(
        source_before=sourceobj,
        source_after=deepcopy(sourceobj),
        bytes_read=len(after),
        sha256=digest(after),
    )
    invocation_id = "f" * 32
    native = (
        wire(
            dict(
                schema_version="outcome-native-close-receipt/v1",
                session_ref=base["session_ref"],
                native_pid=11,
                local_worker_ack_observed=case != "receiver-killed-prefix",
            )
        )
        if case != "interrupted-prefix" and not refusal
        else b""
    )
    receiver = b'{"ready":true}\n'
    if not partial:
        receiver += wire(
            dict(
                schema_version="outcome-live-receiver-close-receipt/v1",
                session_ref=base["session_ref"],
                receiver_pid=12,
                launcher_pid=10,
                registration_sha256=p.data["origin_registration_sha256"],
                trust_sha256=p.digest,
                source_checkpoint=at,
                clean_eof_observed=True,
                terminal_append_fsync_completed=True,
                source_writer_close_completed=True,
            )
        )
    if refusal:
        native, receiver = b"", b""
        root = dict(
            schema_version="outcome-managed-restart-refusal/v1",
            stage="managed_ready_unclosed_history",
            attempted_session_ref=None,
            prior_session_ref=base["session_ref"],
            source_checkpoint=at,
            registration_sha256=p.data["origin_registration_sha256"],
            trust_sha256=p.digest,
            launcher_pid=10,
            boot_ref=base["source_boot_ref"],
            invocation_id=invocation_id,
            core_spawn_attempted=False,
            receiver_spawn_attempted=False,
            root_stdout=rootobj,
        )
    else:
        root = dict(
            schema_version="outcome-live-close-custody/v1",
            registration_sha256=p.data["origin_registration_sha256"],
            trust_sha256=p.digest,
            session_ref=base["session_ref"],
            boot_ref=base["source_boot_ref"],
            launcher_pid=10,
            core_pid=11,
            receiver_pid=12,
            core_returncode=-9 if case == "interrupted-prefix" else 0,
            receiver_returncode=-9
            if case == "receiver-killed-prefix"
            else 1
            if partial
            else 0,
            receiver_wait_timed_out=False,
            forwarded_signal=15,
            native_stream=stream(native),
            receiver_stream=stream(receiver),
            root_stdout=rootobj,
        )
    rawroot = (b"" if refusal else b'{"core_started":true}\n') + wire(root)
    rootcustody = dict(
        relative_name="close-custody/" + case + "-" + "a" * 32 + ".raw",
        prepared=rootobj,
        launcher_fd1=None if refusal else deepcopy(rootobj),
        after=obj(900, 0, rawroot),
        bytes=len(rawroot),
        sha256=digest(rawroot),
    )
    command = "/opt/edge400-runtime/bin/python"
    commands = [
        [
            command,
            [
                command,
                "-I",
                "-m",
                "azazel_edge.outcome.service_entry",
                "--bundle",
                "/var/lib/edge400-systemd-lab/bundle",
                "--boot-ref",
                base["source_boot_ref"],
            ],
        ]
    ]
    failed = partial
    inv = dict(
        unit="azazel-edge-core.service",
        invocation_id=invocation_id,
        exec_main_pid=10,
        exec_main_start_monotonic_us=100,
        exec_main_exit_monotonic_us=200,
        active_state="failed" if failed else "inactive",
        result="exit-code" if failed else "success",
        exec_main_code=1,
        exec_main_status=1 if failed else 0,
        exec_start_sha256=digest(wire(commands)),
        exec_start=commands,
        standard_output=dict(mode="append", path=None),
        standard_error="journal",
    )
    fd = dict(sampled_ns=150)
    for role, actor in actors.items():
        entry = (
            {k: rootobj[k] for k in ("device", "inode", "owner_uid", "mode", "nlink")}
            if role == "launcher"
            else dict(
                device=9,
                inode=901 if role == "native" else 902,
                owner_uid=0 if role == "native" else 61001,
                mode=stat.S_IFIFO | 0o600,
                nlink=1,
            )
        )
        entry.update(fd=1, flags=1 | 0o2000000 | (0o4000 if role == "native" else 0))
        stderr = dict(
            fd=2,
            device=10,
            inode=903,
            owner_uid=0,
            mode=stat.S_IFSOCK | 0o600,
            nlink=1,
            flags=1,
        )
        fd[role] = dict(
            pid=actor["pid"],
            start_ticks=actor["start_ticks"],
            complete=True,
            entries=[entry, stderr],
            errors=[],
        )
    bodies = {
        "source": (before, after),
        "anchors": (ab, aa),
        "journal": (b"{}\n", b"{}\n"),
    }
    stores = {}
    for number, (name, (br, ar)) in enumerate(bodies.items(), 300):
        owner = {"source": 61001, "anchors": 0, "journal": 61002}[name]
        entry = {
            when: dict(
                object=obj(
                    200 if name == "source" else number,
                    owner,
                    raw,
                    0o644 if name == "source" else 0o600,
                ),
                bytes=len(raw),
                sha256=digest(raw),
            )
            for when, raw in (("before", br), ("after", ar))
        }
        if name == "source":
            entry.update(before_checkpoint=bt, after_checkpoint=at)
        elif name == "anchors":
            entry.update(
                before_checkpoint=anchor_checkpoint(ab),
                after_checkpoint=anchor_checkpoint(aa),
            )
        stores[name] = entry
    control = dict(
        schema_version="edge-native-close-controller/v1",
        case_id=case,
        protocol_sha256=annex.PROTOCOL_SHA256,
        source_revision="d" * 40,
        core_image_sha256=r["binary_sha256"],
        trust_sha256=p.digest,
        registration_sha256=p.data["origin_registration_sha256"],
        boot_id=BOOT,
        source_boot_ref=base["source_boot_ref"],
        session_ref=base["session_ref"],
        previous_session_ref=base["session_ref"] if refusal else None,
        attempt_ref="a" * 32,
        action=annex.CASES[case][0],
        custody_mode="managed_prelaunch_refusal"
        if refusal
        else "live_parent_and_children",
        started_ns=100,
        finished_ns=200,
        actors={k: None for k in actors} if refusal else actors,
        invocation=inv,
        root_custody=rootcustody,
        fd_custody=None if refusal else fd,
        stores=stores,
        reader=None if refusal else reader,
        outcome="collected",
        error=None,
    )
    artifact = {name: None for name in annex.FILES}
    artifact.update(
        {
            "protocol.json": (
                Path(__file__).parent
                / "real_systemd/native-close-receipts-protocol-v1.json"
            ).read_bytes(),
            "trust.json": _json(dict(p.data)),
            "registration.json": _json(r),
            "close-controller.json": wire(control),
            "root-custody.raw": rawroot,
            "root-custody-object.json": wire(rootcustody),
            "actor-fd-custody.json": wire(control["fd_custody"]),
            "native-close.raw": native,
            "receiver-close.raw": receiver,
            "launcher-systemd.json": wire(inv),
            "unit-exec-start.raw": wire(commands),
            "launcher-journal.raw": b"diagnostic only\n",
            "readback-source.raw": after,
            "reader-binding.json": wire(reader_binding(reader, case))
            if not refusal
            else wire(None),
            "witness-boundary.json": wire(
                dict(source_checkpoint=awtip, anchor_checkpoint=anchor_checkpoint(aa))
            ),
            "code-pins.json": wire(
                {
                    k: control[k]
                    for k in ("source_revision", "protocol_sha256", "core_image_sha256")
                }
            ),
        }
    )
    for name, (br, ar) in bodies.items():
        artifact[name + "-before.raw"], artifact[name + "-after.raw"] = br, ar
    return artifact, control, root, p


def evaluate(artifact, expected=None):
    pins = {k: digest(v) if isinstance(v, bytes) else None for k, v in artifact.items()}
    return annex.evaluate_native_close_receipts(
        artifact, expected=pins if expected is None else expected
    )


def rewrite(artifact, control, root):
    raw = (
        b""
        if control["case_id"].endswith("restart-refused")
        else b'{"core_started":true}\n'
    ) + wire(root)
    control["root_custody"].update(
        after=obj(900, 0, raw), bytes=len(raw), sha256=digest(raw)
    )
    artifact.update(
        {
            "root-custody.raw": raw,
            "root-custody-object.json": wire(control["root_custody"]),
            "close-controller.json": wire(control),
            "launcher-systemd.json": wire(control["invocation"]),
            "actor-fd-custody.json": wire(control["fd_custody"]),
        }
    )


@pytest.mark.parametrize(
    "case,status",
    [
        ("normal-four", "bound_finite_close"),
        ("restart-one", "bound_finite_close"),
        ("witness-stopped-close", "bound_partial_close"),
        ("interrupted-prefix", "bound_partial_close"),
        ("receiver-killed-prefix", "bound_partial_close"),
        ("interrupted-restart-refused", "bound_prelaunch_refusal"),
        ("receiver-restart-refused", "bound_prelaunch_refusal"),
    ],
)
def test_synthetic_case_fact_legs_are_distinct_and_never_authority(case, status):
    artifact, _, _, p = fixture(case)
    original = deepcopy(artifact)
    result = evaluate(artifact)
    assert result["status"] == status, result["reasons"]
    assert result["source_tip"] == SourceVerifier(p).verify(
        artifact["source-after.raw"]
    )
    assert not any(result["authority_flags"].values())
    assert artifact == original and evaluate(artifact) == result
    if case.endswith("restart-refused"):
        assert result["managed_refusal_verified"] is result["stores_unchanged"] is True
        assert (
            result["native_local_worker_ack_observed"]
            is result["receiver_close_report"]
            is None
        )
    elif case == "witness-stopped-close":
        assert result["native_local_worker_ack_observed"] is True
        assert result["receiver_close_report"] is not None
        assert result["witness_covers_selected_end"] is False
    elif case == "interrupted-prefix":
        assert result["native_returncode"] == -9
    elif case == "receiver-killed-prefix":
        assert result["receiver_returncode"] == -9


def child_bytes(artifact, root, role, body):
    artifact[role + "-close.raw"] = body
    root[role + "_stream"] = stream(body)


@pytest.mark.parametrize(
    "fault",
    [
        "false_ack",
        "missing_native",
        "missing_receiver",
        "receiver_before_close",
        "native_wrong_pid",
        "native_wrong_session",
        "native_duplicate",
        "native_partial",
        "native_oversize",
        "receiver_wrong_parent",
        "receiver_duplicate",
        "native_incomplete_eof",
        "native_over_limit",
    ],
)
def test_child_receipt_fault_does_not_erase_authentic_end_or_readback(fault):
    artifact, c, root, _ = fixture()
    native = json.loads(artifact["native-close.raw"])
    receiver = json.loads(artifact["receiver-close.raw"][15:])
    if fault == "false_ack":
        native["local_worker_ack_observed"] = False
    elif fault == "native_wrong_pid":
        native["native_pid"] = 99
    elif fault == "native_wrong_session":
        native["session_ref"] = "a" * 32
    if fault in ("false_ack", "native_wrong_pid", "native_wrong_session"):
        child_bytes(artifact, root, "native", wire(native))
    elif fault == "missing_native":
        child_bytes(artifact, root, "native", b"")
    elif fault == "missing_receiver":
        child_bytes(artifact, root, "receiver", b'{"ready":true}\n')
    elif fault == "receiver_before_close":
        receiver["source_writer_close_completed"] = False
        child_bytes(artifact, root, "receiver", b'{"ready":true}\n' + wire(receiver))
    elif fault == "native_duplicate":
        child_bytes(artifact, root, "native", wire(native) * 2)
    elif fault == "native_partial":
        child_bytes(artifact, root, "native", wire(native)[:-2])
    elif fault == "native_oversize":
        child_bytes(artifact, root, "native", b"x" * 1025)
    elif fault == "receiver_wrong_parent":
        receiver["launcher_pid"] = 99
        child_bytes(artifact, root, "receiver", b'{"ready":true}\n' + wire(receiver))
    elif fault == "receiver_duplicate":
        child_bytes(
            artifact, root, "receiver", artifact["receiver-close.raw"] + wire(receiver)
        )
    elif fault == "native_incomplete_eof":
        root["native_stream"]["eof"] = False
    elif fault == "native_over_limit":
        root["native_stream"]["over_limit"] = True
    rewrite(artifact, c, root)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert (
        result["source_authenticated"]
        is result["selected_end_present"]
        is result["source_readback_verified"]
        is True
    )
    assert result["witness_covers_selected_end"] is True
    if fault == "false_ack":
        assert result["native_local_worker_ack_observed"] is False
    elif fault.startswith("native") or fault == "missing_native":
        assert result["native_local_worker_ack_observed"] is None
    assert not any(result["authority_flags"].values())


@pytest.mark.parametrize(
    "fault",
    [
        "actor_pid",
        "root_pid",
        "root_inode",
        "pipe_shared",
        "pipe_cloexec",
        "pipe_nonblock",
        "pipe_inherit_Root",
        "fd_incomplete",
        "fd_duplicate",
        "manager_invocation",
        "manager_execstart",
        "root_extra",
        "root_duplicate",
        "root_partial",
        "root_sink_owner",
        "reader_copy",
    ],
)
def test_synthetic_custody_mismatch_never_upgrades_raw_child_markers(fault):
    artifact, c, root, _ = fixture()
    if fault == "actor_pid":
        c["actors"]["native"]["pid"] = 99
    elif fault == "root_pid":
        root["launcher_pid"] = 99
    elif fault == "root_inode":
        root["root_stdout"] = {**root["root_stdout"], "inode": 999}
    elif fault == "pipe_shared":
        c["fd_custody"]["native"]["entries"][0]["inode"] = 902
    elif fault == "pipe_cloexec":
        c["fd_custody"]["native"]["entries"][0]["flags"] &= ~0o2000000
    elif fault == "pipe_nonblock":
        c["fd_custody"]["native"]["entries"][0]["flags"] &= ~0o4000
    elif fault == "pipe_inherit_Root":
        extra = {k: c["root_custody"]["prepared"][k] for k in annex.IDENTITY}
        extra.update(fd=3, flags=1)
        c["fd_custody"]["receiver"]["entries"].append(extra)
    elif fault == "fd_incomplete":
        c["fd_custody"]["native"]["complete"] = False
    elif fault == "fd_duplicate":
        c["fd_custody"]["native"]["entries"].append(
            deepcopy(c["fd_custody"]["native"]["entries"][0])
        )
    elif fault == "manager_invocation":
        c["invocation"]["exec_main_pid"] = 99
    elif fault == "manager_execstart":
        c["invocation"]["exec_start"][0][1][3] = "other.module"
        artifact["unit-exec-start.raw"] = wire(c["invocation"]["exec_start"])
        c["invocation"]["exec_start_sha256"] = digest(artifact["unit-exec-start.raw"])
    elif fault == "root_extra":
        root["derived_success"] = True
    elif fault == "root_sink_owner":
        c["root_custody"]["prepared"]["owner_uid"] = 61001
    rewrite(artifact, c, root)
    if fault in ("root_duplicate", "root_partial"):
        raw = artifact["root-custody.raw"] + (
            wire(root) if fault == "root_duplicate" else b"{"
        )
        c["root_custody"].update(
            after=obj(900, 0, raw), bytes=len(raw), sha256=digest(raw)
        )
        artifact.update(
            {
                "root-custody.raw": raw,
                "root-custody-object.json": wire(c["root_custody"]),
                "close-controller.json": wire(c),
            }
        )
    if fault == "reader_copy":
        independent = json.loads(artifact["reader-binding.json"])
        independent["actual_actor"]["uid"] = 123
        artifact["reader-binding.json"] = wire(independent)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is result["selected_end_present"] is True
    assert not any(result["authority_flags"].values())


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_invocation",
        "wrong_pid",
        "attempted_session",
        "spawned",
        "store_mutation",
        "no_actual_attempt",
    ],
)
def test_managed_refusal_needs_actual_attempt_and_exact_nonmutation(fault):
    artifact, c, root, _ = fixture("interrupted-restart-refused")
    if fault == "wrong_invocation":
        root["invocation_id"] = "e" * 32
    elif fault == "wrong_pid":
        root["launcher_pid"] = 99
    elif fault == "attempted_session":
        root["attempted_session_ref"] = "a" * 32
    elif fault == "spawned":
        root["core_spawn_attempted"] = True
    elif fault == "no_actual_attempt":
        c["invocation"]["exec_main_pid"] = 0
    elif fault == "store_mutation":
        body = b"changed\n"
        artifact["journal-after.raw"] = body
        c["stores"]["journal"]["after"].update(
            object=obj(302, 61002, body), bytes=len(body), sha256=digest(body)
        )
    rewrite(artifact, c, root)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["managed_refusal_verified"] is None
    assert result["source_authenticated"] is True
    if fault == "store_mutation":
        assert result["stores_unchanged"] is False


@pytest.mark.parametrize("case", ["interrupted-prefix", "receiver-killed-prefix"])
def test_partial_case_cannot_claim_manager_success_for_failed_child(case):
    artifact, c, root, _ = fixture(case)
    c["invocation"].update(
        active_state="inactive", result="success", exec_main_status=0
    )
    rewrite(artifact, c, root)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is True


def test_journal_markers_are_diagnostics_and_never_replace_private_pipe_custody():
    artifact, c, root, _ = fixture()
    artifact["launcher-journal.raw"] = (
        artifact["root-custody.raw"]
        + artifact["native-close.raw"]
        + artifact["receiver-close.raw"]
    )
    child_bytes(artifact, root, "native", b"")
    child_bytes(artifact, root, "receiver", b"")
    rewrite(artifact, c, root)
    result = evaluate(artifact)
    assert result["status"] == "unknown"
    assert (
        result["native_local_worker_ack_observed"]
        is result["receiver_close_report"]
        is None
    )
    assert result["source_authenticated"] is True


@pytest.mark.parametrize(
    "name",
    [
        "source-after.raw",
        "root-custody.raw",
        "trust.json",
        "native-close.raw",
        "witness-boundary.json",
    ],
)
def test_substitution_without_external_pin_never_manufactures_leg(name):
    artifact, _, _, _ = fixture()
    expected = {
        k: digest(v) if isinstance(v, bytes) else None for k, v in artifact.items()
    }
    expected[name] = "e" * 64
    result = evaluate(artifact, expected)
    assert result["status"] == "unknown"
    assert result["pins"][name] is False
    if name not in ("trust.json", "source-after.raw"):
        assert result["source_authenticated"] is True
    if name == "source-after.raw":
        assert result["authenticated_prefix_tip"] is not None


def test_bad_after_suffix_retains_original_authenticated_prefix():
    artifact, _, _, p = fixture()
    artifact["source-after.raw"] += b"{broken"
    result = evaluate(artifact)
    assert result["status"] == "unknown"
    assert result["source_authenticated"] is None
    assert result["authenticated_prefix_tip"] == SourceVerifier(p).verify(
        artifact["source-before.raw"]
    )


@pytest.mark.parametrize(
    "name",
    ["trust.json", "close-controller.json", "root-custody.raw", "native-close.raw"],
)
@pytest.mark.parametrize("fault", ["duplicate", "nonfinite", "oversize", "missing"])
def test_bounded_strict_originals_are_not_repaired(name, fault):
    artifact, _, _, _ = fixture()
    if fault == "duplicate":
        artifact[name] = b'{"x":1,"x":2}\n'
    elif fault == "nonfinite":
        artifact[name] = b'{"x":NaN}\n'
    elif fault == "oversize":
        artifact[name] = b"x" * (annex._limit(name) + 1)
    elif fault == "missing":
        artifact[name] = None
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    if fault == "oversize":
        assert result["raw_sha256"][name] is None


def test_pure_evaluation_performs_no_io_and_preserves_all_raw_inputs(monkeypatch):
    import builtins
    import os
    import socket
    import subprocess

    artifact, _, _, _ = fixture()
    original = deepcopy(artifact)

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected evaluator I/O")

    for target, name in (
        (builtins, "open"),
        (Path, "read_bytes"),
        (os, "open"),
        (os, "write"),
        (os, "fsync"),
        (socket, "socket"),
        (subprocess, "Popen"),
    ):
        monkeypatch.setattr(target, name, forbidden)
    result = evaluate(artifact)
    assert result["status"] == "bound_finite_close", result["reasons"]
    assert artifact == original


@pytest.mark.parametrize(
    "name",
    [
        "actor-fd-custody.json",
        "reader-binding.json",
        "journal-after.raw",
        "evaluation.json",
    ],
)
def test_even_optional_output_pins_cannot_be_silently_ignored(name):
    artifact, _, _, _ = fixture()
    # Output-only evaluation may be absent; a supplied pin still has to match.
    if artifact[name] is None:
        artifact[name] = b"{}\n"
    expected = {
        k: digest(v) if isinstance(v, bytes) else None for k, v in artifact.items()
    }
    expected[name] = "e" * 64
    result = evaluate(artifact, expected)
    assert result["status"] == "unknown", result
    assert result["pins"][name] is not True
    assert result["source_authenticated"] is True


@pytest.mark.parametrize(
    "fault",
    [
        "timeout",
        "native_code",
        "receiver_code",
        "manager_signal",
        "root_stdout_missing",
    ],
)
def test_exact_wait_facts_are_not_inferred_from_end_or_aggregate_exit(fault):
    artifact, c, root, _ = fixture()
    if fault == "timeout":
        root["receiver_wait_timed_out"] = True
    elif fault == "native_code":
        root["core_returncode"] = -9
    elif fault == "receiver_code":
        root["receiver_returncode"] = -9
    elif fault == "manager_signal":
        c["invocation"].update(exec_main_code=2, exec_main_status=9)
    elif fault == "root_stdout_missing":
        root["root_stdout"] = None
    rewrite(artifact, c, root)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is result["selected_end_present"] is True
    if fault == "native_code":
        assert result["native_returncode"] == -9
    if fault == "receiver_code":
        assert result["receiver_returncode"] == -9


@pytest.mark.parametrize("fault", ["mode", "owner", "bool_device", "changed_inode"])
def test_source_object_claims_require_original_typed_producer_owned_regular_0644(fault):
    artifact, c, root, _ = fixture()
    object_ = c["stores"]["source"]["after"]["object"]
    if fault == "mode":
        object_["mode"] = stat.S_IFREG | 0o666
    elif fault == "owner":
        object_["owner_uid"] = 0
    elif fault == "bool_device":
        object_["device"] = True
    elif fault == "changed_inode":
        object_["inode"] = 999
    rewrite(artifact, c, root)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is True


@pytest.mark.parametrize(
    "fault", ["extra_artifact", "missing_artifact", "extra_pin", "missing_pin"]
)
def test_exact_twenty_four_artifact_and_pin_envelopes_are_mandatory(fault):
    artifact, _, _, _ = fixture()
    expected = {
        k: digest(v) if isinstance(v, bytes) else None for k, v in artifact.items()
    }
    if fault == "extra_artifact":
        artifact["derived_success"] = True
    elif fault == "missing_artifact":
        del artifact["native-close.raw"]
    elif fault == "extra_pin":
        expected["derived_success"] = "a" * 64
    elif fault == "missing_pin":
        del expected["native-close.raw"]
    result = evaluate(artifact, expected)
    assert result["status"] == "unknown"
    assert "exact_artifact_pin_envelope" in result["reasons"]


def replace_source(artifact, c, root, p, events):
    after = source_bytes(p, events)
    refusal = c["case_id"].endswith("restart-refused")
    partial = events[-1]["capture_origin"]["kind"] != "session_end"
    before = after if partial else b"".join(after.splitlines(keepends=True)[:-1])
    bt, at = SourceVerifier(p).verify(before), SourceVerifier(p).verify(after)
    for when, body, tip in (("before", before, bt), ("after", after, at)):
        artifact["source-" + when + ".raw"] = body
        c["stores"]["source"][when].update(
            object=obj(200, 61001, body, 0o644), bytes=len(body), sha256=digest(body)
        )
        c["stores"]["source"][when + "_checkpoint"] = tip
    witness_tip = bt if c["case_id"] == "witness-stopped-close" else at
    for when, tip in (("before", bt), ("after", witness_tip)):
        body = anchors(p, tip)
        artifact["anchors-" + when + ".raw"] = body
        c["stores"]["anchors"][when].update(
            object=obj(301, 0, body), bytes=len(body), sha256=digest(body)
        )
        c["stores"]["anchors"][when + "_checkpoint"] = anchor_checkpoint(body)
    artifact["witness-boundary.json"] = wire(
        dict(
            source_checkpoint=witness_tip,
            anchor_checkpoint=anchor_checkpoint(artifact["anchors-after.raw"]),
        )
    )
    if refusal:
        root["source_checkpoint"] = at
    else:
        c["reader"].update(
            source_before=obj(200, 61001, after, 0o644),
            source_after=obj(200, 61001, after, 0o644),
            bytes_read=len(after),
            sha256=digest(after),
        )
        artifact["readback-source.raw"] = after
        artifact["reader-binding.json"] = wire(
            reader_binding(c["reader"], c["case_id"])
        )
        body = artifact["receiver-close.raw"]
        if len(body) > 15:
            receiver = json.loads(body[15:])
            receiver["source_checkpoint"] = at
            child_bytes(artifact, root, "receiver", body[:15] + wire(receiver))
    rewrite(artifact, c, root)


@pytest.mark.parametrize("fault", ["legacy_profile", "applied", "wrong_sid"])
def test_reauthenticated_source_facts_do_not_replace_frozen_native_case(fault):
    artifact, c, root, p = fixture()
    events = [
        json.loads(line)["event"] for line in artifact["source-after.raw"].splitlines()
    ]
    if fault == "legacy_profile":
        events[1]["capture_lifecycle"] = {"state": "start"}
        events[-1]["capture_lifecycle"] = {"state": "end"}
    elif fault == "applied":
        events[2]["enforcement"]["result"] = "applied"
    elif fault == "wrong_sid":
        events[2]["normalized"]["sid"] = 1
    replace_source(artifact, c, root, p, events)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is True
    assert result["source_tip"] == SourceVerifier(p).verify(
        artifact["source-after.raw"]
    )


@pytest.mark.parametrize(
    "case", ["interrupted-restart-refused", "receiver-restart-refused"]
)
def test_refusal_must_select_actual_prior_interrupted_challenge(case):
    artifact, c, root, p = fixture(case)
    events = [
        json.loads(line)["event"] for line in artifact["source-after.raw"].splitlines()
    ]
    events[-1]["normalized"]["sid"] = (
        90121007 if case == "receiver-restart-refused" else 90122002
    )
    replace_source(artifact, c, root, p, events)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is True
    assert result["stores_unchanged"] is True


@pytest.mark.parametrize(
    "fault", ["challenge", "pid", "invocation", "actor", "status", "command", "missing"]
)
def test_reader_binding_requires_the_independent_challenged_role(fault):
    artifact, _, _, _ = fixture()
    binding = json.loads(artifact["reader-binding.json"])
    if fault == "challenge":
        binding["bootstrap"]["challenge"] = "3" * 32
    elif fault == "pid":
        binding["unit_properties"]["MainPID"] = "999"
    elif fault == "invocation":
        binding["unit_properties"]["InvocationID"] = "4" * 32
    elif fault == "actor":
        binding["bootstrap"]["actor"]["uid"] = 0
    elif fault == "status":
        binding["status"] = "planned"
    elif fault == "command":
        binding["command_verified"] = False
    artifact["reader-binding.json"] = None if fault == "missing" else wire(binding)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is True
    assert result["source_readback_verified"] is None


@pytest.mark.parametrize(
    "fault",
    [
        "relative_binary",
        "nul_binary",
        "dotdot_binary",
        "relative_input",
        "dotdot_input",
        "evidence_alias",
        "ai_role_alias",
    ],
)
def test_resigned_registration_must_retain_same_pure_structural_launch_boundary(fault):
    artifact, c, root, p = fixture()
    r = json.loads(artifact["registration.json"])
    if fault == "relative_binary":
        r["binary_path"] = "synthetic/core"
    elif fault == "nul_binary":
        r["binary_path"] = "/synthetic/core\x00hidden"
    elif fault == "dotdot_binary":
        r["binary_path"] = "/synthetic/../core"
    elif fault == "relative_input":
        r["environment"]["AZAZEL_EVE_PATH"] = "relative/eve"
    elif fault == "dotdot_input":
        r["environment"]["AZAZEL_EVE_PATH"] = "/synthetic/../eve"
    elif fault == "evidence_alias":
        r["environment"]["AZAZEL_EVE_PATH"] = p.data["source_path"]
    elif fault == "ai_role_alias":
        r["ai_socket_uid"] = 61001
    artifact["registration.json"] = _json(r)
    p = TrustPolicy(
        {
            **dict(p.data),
            "origin_registration_sha256": digest(artifact["registration.json"]),
        }
    )
    artifact["trust.json"] = _json(dict(p.data))
    for target in (c, root):
        target.update(
            registration_sha256=p.data["origin_registration_sha256"],
            trust_sha256=p.digest,
        )
    events = [
        json.loads(line)["event"] for line in artifact["source-after.raw"].splitlines()
    ]
    for event in events:
        event["capture_origin"]["registration_sha256"] = p.data[
            "origin_registration_sha256"
        ]
    receiver = json.loads(artifact["receiver-close.raw"][15:])
    receiver.update(
        registration_sha256=p.data["origin_registration_sha256"], trust_sha256=p.digest
    )
    child_bytes(artifact, root, "receiver", b'{"ready":true}\n' + wire(receiver))
    replace_source(artifact, c, root, p, events)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is True
    assert result["legs"]["registration"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "before_counter_bool",
        "after_checkpoint_wrong",
        "before_bytes_ahead",
        "after_bad_signature",
    ],
)
def test_original_anchor_snapshot_checkpoint_and_signature_are_independent_gates(fault):
    artifact, c, root, _ = fixture()
    if fault == "before_counter_bool":
        c["stores"]["anchors"]["before_checkpoint"]["counter"] = True
    elif fault == "after_checkpoint_wrong":
        c["stores"]["anchors"]["after_checkpoint"]["head"] = "e" * 64
    else:
        when = "before" if fault == "before_bytes_ahead" else "after"
        if fault == "before_bytes_ahead":
            body = artifact["anchors-after.raw"]
        else:
            rows = [
                json.loads(line) for line in artifact["anchors-after.raw"].splitlines()
            ]
            signature = rows[-1]["signature"]
            rows[-1]["signature"] = ("0" if signature[0] != "0" else "1") + signature[
                1:
            ]
            body = b"".join(wire(row) for row in rows)
        artifact["anchors-" + when + ".raw"] = body
        c["stores"]["anchors"][when].update(
            object=obj(301, 0, body), bytes=len(body), sha256=digest(body)
        )
        checkpoint = anchor_checkpoint(body)
        c["stores"]["anchors"][when + "_checkpoint"] = checkpoint
        if when == "after":
            witness = json.loads(artifact["witness-boundary.json"])
            witness["anchor_checkpoint"] = checkpoint
            artifact["witness-boundary.json"] = wire(witness)
    rewrite(artifact, c, root)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is result["selected_end_present"] is True
    assert result["legs"]["store_snapshots"] is False
    assert not any(result["authority_flags"].values())


@pytest.mark.parametrize(
    "fault",
    [
        "unit",
        "replayed_other_case",
        "returncode",
        "returncode_bool",
        "bootstrap_pid_float",
    ],
)
def test_reader_challenged_unit_and_exact_returncode_are_not_guessable(fault):
    artifact, _, _, _ = fixture()
    binding = json.loads(artifact["reader-binding.json"])
    if fault == "unit":
        binding["unit"] = (
            "edge400-accounting-reader-normal-four-" + "5" * 32 + ".service"
        )
    elif fault == "replayed_other_case":
        other, _, _, _ = fixture("restart-one")
        binding = json.loads(other["reader-binding.json"])
    elif fault == "returncode":
        binding["runner_returncode"] = 1
    elif fault == "returncode_bool":
        binding["runner_returncode"] = False
    elif fault == "bootstrap_pid_float":
        binding["bootstrap"]["pid"] = 13.0
    artifact["reader-binding.json"] = wire(binding)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is True
    assert result["source_readback_verified"] is None
    assert result["legs"]["readback"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "root_pid_float",
        "root_core_pid_float",
        "native_pid_float",
        "receiver_pid_float",
        "image_uid_float",
        "image_nlink_bool",
    ],
)
def test_pid_and_image_integer_types_cannot_be_replaced_by_equal_python_numbers(fault):
    artifact, c, root, _ = fixture()
    if fault == "root_pid_float":
        root["launcher_pid"] = 10.0
    elif fault == "root_core_pid_float":
        root["core_pid"] = 11.0
    elif fault == "native_pid_float":
        report = json.loads(artifact["native-close.raw"])
        report["native_pid"] = 11.0
        child_bytes(artifact, root, "native", wire(report))
    elif fault == "receiver_pid_float":
        report = json.loads(artifact["receiver-close.raw"][15:])
        report["receiver_pid"] = 12.0
        child_bytes(artifact, root, "receiver", b'{"ready":true}\n' + wire(report))
    elif fault == "image_uid_float":
        c["actors"]["native"]["image"]["owner_uid"] = 0.0
    elif fault == "image_nlink_bool":
        c["actors"]["native"]["image"]["nlink"] = False
    rewrite(artifact, c, root)
    result = evaluate(artifact)
    assert result["status"] == "unknown", result
    assert result["source_authenticated"] is result["selected_end_present"] is True


@pytest.mark.parametrize(
    "trust_schema", ["outcome-input-trust/v3", "outcome-input-trust/v4"]
)
@pytest.mark.parametrize("native_registration_v4", [True, False])
def test_existing_trust_versions_require_actual_native_v4_registration(
    trust_schema, native_registration_v4
):
    artifact, c, root, original_policy = fixture()
    registration = json.loads(artifact["registration.json"])
    if not native_registration_v4:
        registration["schema_version"] = "outcome-live-origin-registration/v3"
        registration.pop("native_apparmor_profile")
    artifact["registration.json"] = _json(registration)
    policy_data = {
        **dict(original_policy.data),
        "schema_version": trust_schema,
        "origin_registration_sha256": digest(artifact["registration.json"]),
    }
    if trust_schema == "outcome-input-trust/v3":
        policy_data.pop("witness_transport")
    policy = TrustPolicy(policy_data)
    artifact["trust.json"] = _json(dict(policy.data))
    for record in (c, root):
        record.update(
            trust_sha256=policy.digest,
            registration_sha256=policy.data["origin_registration_sha256"],
        )
    events = [
        json.loads(line)["event"] for line in artifact["source-after.raw"].splitlines()
    ]
    for event in events:
        event["capture_origin"]["registration_sha256"] = policy.data[
            "origin_registration_sha256"
        ]
    receiver = json.loads(artifact["receiver-close.raw"][15:])
    receiver.update(
        trust_sha256=policy.digest,
        registration_sha256=policy.data["origin_registration_sha256"],
    )
    child_bytes(artifact, root, "receiver", b'{"ready":true}\n' + wire(receiver))
    replace_source(artifact, c, root, policy, events)
    result = evaluate(artifact)
    assert result["legs"]["trust"] is True
    assert result["source_authenticated"] is True
    assert result["source_tip"] == SourceVerifier(policy).verify(
        artifact["source-after.raw"]
    )
    if native_registration_v4:
        assert result["status"] == "bound_finite_close", result["reasons"]
        assert result["legs"]["registration"] is True
    else:
        assert result["status"] == "unknown", result
        assert result["legs"]["registration"] is False
    assert not any(result["authority_flags"].values())
