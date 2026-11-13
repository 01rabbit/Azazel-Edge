"""SYNTHETIC runtime metadata/journal, real TEST signatures; no actors or I/O proof."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from azazel_edge.benchmark import forged_input_refusal as f
from azazel_edge.benchmark import forged_refusal_collection as intake
from azazel_edge.benchmark import safety_collection
from azazel_edge.outcome.journal import _json, ZERO_HASH
from source_recovery_data import make_source_case, BOOT
from source_witness_data import sign_anchors, anchor_checkpoint


def raw(value):
    return _json(value) + b"\n"


def build(directory, *, closed_prefix=False):
    source = make_source_case(
        directory, case="source_closed" if closed_prefix else "source_open"
    )
    trust = source["trust"]
    if closed_prefix:
        prefix = source["valid_source"]
        tip = f.SourceVerifier(trust).verify(prefix)
        other = make_source_case(directory / "other", session_ref="a" * 32)
        poisoned = json.loads(other["valid_source"].splitlines()[0])
        poisoned.update(seq=tip["seq"] + 1, prev=tip["head"])
    else:
        prefix, nextrow = source["valid_source"].splitlines(keepends=True)
        poisoned = json.loads(nextrow)
    source["arguments"]["expected_prefix_checkpoint"] = f.SourceVerifier(trust).verify(
        prefix
    )
    poisoned["signature"] = "0" * 128
    submitted = prefix + raw(poisoned)
    source_identity = dict(
        device=2,
        inode=3,
        uid=61001,
        gid=61001,
        mode=0o644,
        nlink=1,
        size=len(submitted),
        mtime_ns=1,
        ctime_ns=1,
    )
    journal_identity = dict(source_identity, inode=4, uid=61002, mode=0o600)
    anchor_identity = dict(source_identity, inode=5, uid=0, mode=0o600)
    config = dict(
        schema_version="outcome-observation-journal/v3",
        scope_ref=trust.data["scope_ref"],
        input_config=dict(
            authentication=trust.binding(),
            device=2,
            inode=3,
            uid=61001,
            path_sha256=f._sha(trust.data["source_path"].encode()),
        ),
    )
    empty = dict(offset=0, sha256=f._sha(b""))
    position = dict(offset=len(prefix), sha256=f._sha(prefix))
    items = [
        ("header", config),
        ("session_open", {"boot_id": "synthetic-observer"}),
        ("input_ready", empty),
        ("cursor", dict(position=position, missed=True)),
        ("session_close", {"boot_id": "synthetic-observer"}),
    ]
    journal, head, rows = b"", ZERO_HASH, []
    source_tip = source["arguments"]["expected_prefix_checkpoint"]
    anchors = []
    for index in range(len(items) + 1):
        if index:
            kind, data = items[index - 1]
            core = dict(seq=index, prev=head, kind=kind, data=data)
            head = f._sha(_json(core))
            rows.append(dict(core, sha256=head))
            journal += raw(rows[-1])
        tip = (
            source_tip
            if index >= 4
            else dict(seq=0, head=ZERO_HASH, size=0, sha256=f._sha(b""))
        )
        state = {"source_" + key: value for key, value in tip.items()}
        state.update(
            journal_seq=index,
            journal_head=head,
            journal_size=len(journal),
            journal_sha256=f._sha(journal),
            journal_device=2 if index else 0,
            journal_inode=4 if index else 0,
        )
        anchors.append(
            dict(
                schema_version="outcome-input-anchor/v1",
                counter=index + 1,
                prev=ZERO_HASH,
                trust_sha256=trust.digest,
                state=state,
            )
        )
    anchor_raw = sign_anchors(anchors)
    before = dict(source=submitted, journal=journal, anchors=anchor_raw)
    identities = dict(
        source=source_identity, journal=journal_identity, anchors=anchor_identity
    )
    samples = {}
    for phase in ("before", "after"):
        samples[phase] = {}
        for kind in f.KINDS:
            samples[phase][kind] = dict(
                sha256=f._sha(before[kind]),
                read_started_ns=10 if phase == "before" else 40,
                read_finished_ns=11 if phase == "before" else 41,
                identity=dict(identities[kind], size=len(before[kind])),
            )
    worker = dict(
        pid=12,
        uid=61002,
        code_sha256="c" * 64,
        started_ns=20,
        exited_ns=30,
        returncode=1,
        forced=False,
        error=None,
        stdout_sha256=f._sha(b""),
        stderr_sha256=f._sha(f.REFUSAL),
    )
    plan = dict(
        schema_version="edge-forged-input-refusal-plan/v1",
        capture_id="synthetic-capture",
        kernel_boot_id=BOOT,
        expected_trust_sha256=f._sha(source["trust_raw"]),
        expected_context=source["arguments"]["expected_context"],
        expected_source_checkpoint=source_tip,
        expected_anchor_checkpoint=anchor_checkpoint(anchor_raw),
        samples=samples,
        worker=worker,
    )
    return dict(
        plan=plan,
        trust_raw=source["trust_raw"],
        before=before,
        after=deepcopy(before),
        stdout_raw=b"",
        stderr_raw=f.REFUSAL,
        source=source,
        rows=rows,
    )


def evaluate(case):
    wire = raw(case["plan"])
    return f.verify_forged_input_refusal(
        wire,
        expected_plan_sha256=f._sha(wire),
        **{
            key: case[key]
            for key in ("trust_raw", "before", "after", "stdout_raw", "stderr_raw")
        },
    )


def refresh(case, phase, kind):
    value = case[phase][kind]
    descriptor = case["plan"]["samples"][phase][kind]
    descriptor["sha256"] = f._sha(value)
    descriptor["identity"]["size"] = len(value)


def test_real_crypto_synthetic_consistent_refusal(tmp_path):
    case = build(tmp_path)
    original = deepcopy({k: v for k, v in case.items() if k != "source"})
    result = evaluate(case)
    assert result["status"] == "recorded_refusal_consistent"
    assert result["sampled_state_unchanged"] is True
    assert result["observed_persistent_change"] is False
    assert result["journal_cursor_structurally_verified"] is True
    assert result["full_journal_semantics_verified"] is False
    assert result["qualified_safety_count"] is None
    assert all(result[key] is False for key in f.safety.FLAGS)
    assert {k: v for k, v in case.items() if k != "source"} == original


@pytest.mark.parametrize("kind", f.KINDS)
def test_bound_change_survives_missing_sibling_and_bad_worker(tmp_path, kind):
    case = build(tmp_path)
    case["after"][kind] += b"changed"
    refresh(case, "after", kind)
    sibling = next(k for k in f.KINDS if k != kind)
    case["after"][sibling] = None
    case["plan"]["samples"]["after"][sibling] = None
    case["plan"]["worker"]["returncode"] = 0
    result = evaluate(case)
    assert result["status"] == "unknown"
    assert result["changes"][kind] is True
    assert result["observed_persistent_change"] is True
    assert result["sampled_state_unchanged"] is False


@pytest.mark.parametrize(
    "fault",
    ["generic", "stdout", "timeout", "kill", "exit_only", "forced", "wrong_uid"],
)
def test_no_exit_only_refusal(tmp_path, fault):
    case = build(tmp_path)
    if fault == "generic":
        case["stderr_raw"] = b"ValueError: invalid\n"
    elif fault == "stdout":
        case["stdout_raw"] = b"success\n"
    elif fault == "timeout":
        case["plan"]["worker"]["error"] = "timeout"
    elif fault == "kill":
        case["plan"]["worker"]["returncode"] = -9
    elif fault == "exit_only":
        case["stderr_raw"] = b""
    elif fault == "forced":
        case["plan"]["worker"]["forced"] = True
    elif fault == "wrong_uid":
        case["plan"]["worker"]["uid"] = 61001
    for key in ("stdout", "stderr"):
        case["plan"]["worker"][key + "_sha256"] = f._sha(case[key + "_raw"])
    result = evaluate(case)
    assert result["status"] == "unknown"
    assert result["sampled_state_unchanged"] is True


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "oversize",
        "wrong_hash",
        "wrong_owner",
        "wrong_clock",
        "changed_inode",
    ],
)
def test_unavailable_sample_not_zero(tmp_path, fault):
    case = build(tmp_path)
    d = case["plan"]["samples"]["after"]["journal"]
    if fault == "missing":
        case["after"]["journal"] = None
    elif fault == "oversize":
        case["after"]["journal"] = b"x" * (f.MAX_ARTIFACT + 1)
    elif fault == "wrong_hash":
        d["sha256"] = "a" * 64
    elif fault == "wrong_owner":
        d["identity"]["uid"] = 61001
    elif fault == "wrong_clock":
        d["read_started_ns"] = 29
    elif fault == "changed_inode":
        d["identity"]["inode"] = 99
    result = evaluate(case)
    assert result["status"] == "unknown"
    if fault == "changed_inode":
        assert result["observed_persistent_change"] is True
    else:
        assert result["changes"]["journal"] is None
        assert result["observed_persistent_change"] is None
        assert result["sampled_state_unchanged"] is None


@pytest.mark.parametrize(
    "fault",
    [
        "signature_shape",
        "identity",
        "boot",
        "valid_signature",
        "bad_anchor",
        "bad_journal",
        "cursor",
    ],
)
def test_challenge_and_baseline_not_asserted_by_worker(tmp_path, fault):
    case = build(tmp_path)
    if fault in ("signature_shape", "identity", "boot", "valid_signature"):
        rows = case["before"]["source"].splitlines(keepends=True)
        row = json.loads(rows[-1])
        if fault == "signature_shape":
            row["signature"] = "xx"
        elif fault == "identity":
            row["scope_ref"] = "wrong"
        elif fault == "boot":
            row["boot_ref"] = "f" * 32
        else:
            row = json.loads(case["source"]["valid_source"].splitlines()[-1])
        for phase in ("before", "after"):
            case[phase]["source"] = rows[0] + raw(row)
            refresh(case, phase, "source")
    elif fault == "bad_anchor":
        for phase in ("before", "after"):
            case[phase]["anchors"] = case[phase]["anchors"].replace(
                b'"signature":"', b'"signature":"0', 1
            )
            refresh(case, phase, "anchors")
    else:
        for phase in ("before", "after"):
            case[phase]["journal"] = case[phase]["journal"].replace(
                b'"missed":true',
                b'"missed":false' if fault == "bad_journal" else b'"offset":999',
                1,
            )
            refresh(case, phase, "journal")
    result = evaluate(case)
    assert result["status"] == "unknown"


@pytest.mark.parametrize("fault", ["bool", "duplicate", "noncanonical", "deep", "pin"])
def test_bad_global_plan_raises(tmp_path, fault):
    case = build(tmp_path)
    if fault == "bool":
        case["plan"]["worker"]["pid"] = True
    wire = raw(case["plan"])
    if fault == "duplicate":
        wire = b'{"capture_id":0,' + wire[1:]
    elif fault == "noncanonical":
        wire = b" " + wire
    elif fault == "deep":
        wire = b'{"x":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}\n"
    pin = f._sha(wire) if fault != "pin" else "a" * 64
    with pytest.raises(f.ForgedInputRefusalInputError):
        f.verify_forged_input_refusal(
            wire,
            expected_plan_sha256=pin,
            **{
                k: case[k]
                for k in ("trust_raw", "before", "after", "stdout_raw", "stderr_raw")
            },
        )


def sealed(case):
    files = {
        "/sealed/plan": raw(case["plan"]),
        "/sealed/trust": case["trust_raw"],
        "/sealed/stdout": case["stdout_raw"],
        "/sealed/stderr": case["stderr_raw"],
    }
    paths = {k: "/sealed/" + k for k in intake.SLOTS}
    for phase in ("before", "after"):
        for kind in f.KINDS:
            files[paths[phase + "_" + kind]] = case[phase][kind]
    enrollment = dict(
        schema_version="edge-forged-input-refusal-enrollment/v1",
        plan_sha256=f._sha(files[paths["plan"]]),
        reader_uid=65533,
        kernel_boot_id=BOOT,
        paths=paths,
    )
    files["/sealed/enrollment"] = raw(enrollment)
    return files, enrollment


@pytest.mark.parametrize(
    "fault", [None, "root", "producer", "consumer", "boot", "close", "race", "unsafe"]
)
def test_synthetic_sealed_fences(tmp_path, monkeypatch, fault):
    case = build(tmp_path)
    files, enrollment = sealed(case)
    activity = []

    class Held:
        def read(self, path, maximum):
            activity.append(path)
            if fault == "unsafe":
                raise safety_collection.SafetyCollectionError(
                    "SYNTHETIC unsafe metadata"
                )
            assert len(files[path]) <= maximum
            return files[path]

        def verify(self):
            if fault == "race":
                raise safety_collection.SafetyCollectionError("SYNTHETIC replacement")

        def close(self):
            activity.append("closed")
            return ["OSError"] if fault == "close" else []

    uid = {"root": 0, "producer": 61001, "consumer": 61002}.get(fault, 65533)
    monkeypatch.setattr(intake, "os", SimpleNamespace(geteuid=lambda: uid))
    monkeypatch.setattr(
        safety_collection, "_kernel_boot_id", lambda: "bad" if fault == "boot" else BOOT
    )
    monkeypatch.setattr(safety_collection, "_HeldFiles", Held)
    args = dict(
        expected_enrollment_sha256=f._sha(files["/sealed/enrollment"]),
        expected_plan_sha256=enrollment["plan_sha256"],
    )
    if fault:
        with pytest.raises(safety_collection.SafetyCollectionError):
            intake.collect_forged_input_refusal("/sealed/enrollment", **args)
    else:
        result = intake.collect_forged_input_refusal("/sealed/enrollment", **args)
        assert result["evaluation"]["status"] == "recorded_refusal_consistent"
        assert set(activity[:-1]) == set(files)
    assert activity[-1] == "closed"


def test_pure_path_has_no_filesystem_or_process_actions(tmp_path, monkeypatch):
    import builtins
    import subprocess

    case = build(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("pure verifier attempted I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert evaluate(case)["status"] == "recorded_refusal_consistent"


@pytest.mark.parametrize("value", [None, True, 42, [], {}])
def test_global_boot_types_are_public_input_errors(tmp_path, value):
    case = build(tmp_path)
    case["plan"]["kernel_boot_id"] = value
    with pytest.raises(f.ForgedInputRefusalInputError):
        evaluate(case)


def test_other_session_after_authentic_closed_prefix_cannot_be_selected_challenge(
    tmp_path,
):
    case = build(tmp_path, closed_prefix=True)
    # Existing SourceVerifier genuinely reaches the invalid signature for a NEW
    # otherwise eligible session after the old one closed. That alone is not the
    # externally selected session binding promised by this diagnostic.
    verifier = f.SourceVerifier(case["source"]["trust"])
    with pytest.raises(
        f.OutcomeJournalError, match="^authentication signature invalid$"
    ):
        verifier.verify(case["before"]["source"])
    plan = case["plan"]
    baseline = f.verify_witnessed_source_prefix(
        case["trust_raw"],
        case["before"]["source"],
        case["before"]["anchors"],
        **{
            key: plan[key]
            for key in (
                "expected_trust_sha256",
                "expected_context",
                "expected_source_checkpoint",
                "expected_anchor_checkpoint",
            )
        },
    )
    assert baseline["witness_prefix_authenticated"] is True
    result = evaluate(case)
    assert result["invalid_signature_verified"] is False
    assert result["status"] == "unknown"
    assert result["sampled_state_unchanged"] is True


@pytest.mark.parametrize(
    "event",
    [
        None,
        [],
        True,
        {"capture_origin": True},
        {"capture_origin": {"session_ref": True}},
    ],
)
def test_bad_challenge_origin_types_remain_unknown(tmp_path, event):
    case = build(tmp_path)
    lines = case["before"]["source"].splitlines(keepends=True)
    row = json.loads(lines[-1])
    row["event"] = event
    for phase in ("before", "after"):
        case[phase]["source"] = lines[0] + raw(row)
        refresh(case, phase, "source")
    assert evaluate(case)["status"] == "unknown"
