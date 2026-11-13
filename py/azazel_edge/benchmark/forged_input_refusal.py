"""Pure finite recorded refusal consistency; Root metadata is not execution proof."""

import hashlib
import uuid

from azazel_edge.outcome.input_auth import (
    SourceVerifier,
    TrustPolicy,
    hex_bytes,
    verify_signature,
    SOURCE_DOMAIN,
)
from azazel_edge.outcome.input_witness import validate_state
from azazel_edge.outcome.journal import (
    OutcomeJournalError,
    ZERO_HASH,
    _json,
    _parse,
    _ref,
)
from . import safety_observations as safety
from .source_witness import verify_witnessed_source_prefix

MAX_ARTIFACT = 1024 * 1024
KINDS = ("source", "journal", "anchors")
REFUSAL = b"azazel_edge.outcome.journal.OutcomeJournalError: authentication signature invalid\n"
ERRORS = (ValueError, TypeError, KeyError, OverflowError, RecursionError, OSError)


class ForgedInputRefusalInputError(ValueError):
    """Malformed externally pinned global plan, trust, or artifact slots."""


def _need(ok, message):
    if not ok:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _object(raw, maximum):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, "bounded object required")
    value = _parse(raw)
    _need(
        type(value) is dict and _json(value) + b"\n" == raw, "canonical object required"
    )
    return value


def _integer(value, low=0, high=2**64 - 1):
    _need(type(value) is int and low <= value <= high, "typed integer bound")


def _rows(raw):
    _need(
        type(raw) is bytes
        and 0 < len(raw) <= MAX_ARTIFACT
        and raw.endswith(b"\n")
        and b"\r" not in raw
        and raw.count(b"\n") <= 4097,
        "bounded original artifact required",
    )
    rows = []
    for line in raw.splitlines(keepends=True):
        _need(len(line) <= 65536, "row bound")
        row = _parse(line)
        _need(
            type(row) is dict and _json(row) + b"\n" == line, "canonical artifact row"
        )
        rows.append(row)
    return rows


def _sample(raw, descriptor, kind, phase, plan, policy):
    _need(descriptor is not None and raw is not None, "sample unavailable")
    safety._fields(descriptor, "sha256 read_started_ns read_finished_ns identity")
    safety._hex(descriptor["sha256"])
    _need(type(raw) is bytes and len(raw) <= MAX_ARTIFACT, "sample byte bound")
    identity = descriptor["identity"]
    safety._fields(identity, "device inode uid gid mode nlink size mtime_ns ctime_ns")
    for key, value in identity.items():
        _integer(value, 1 if key in ("device", "inode", "nlink") else 0)
    owner = {
        "source": "producer_uid",
        "journal": "observer_uid",
        "anchors": "witness_uid",
    }[kind]
    _need(
        identity["uid"] == policy.data[owner]
        and identity["nlink"] == 1
        and identity["mode"] == (0o644 if kind == "source" else 0o600)
        and identity["size"] == len(raw)
        and descriptor["sha256"] == _sha(raw),
        "sample hash/identity differs",
    )
    start, end = descriptor["read_started_ns"], descriptor["read_finished_ns"]
    _integer(start)
    _integer(end)
    _need(start <= end, "sample clock order")
    worker = plan["worker"]
    _need(
        end <= worker["started_ns"]
        if phase == "before"
        else start >= worker["exited_ns"],
        "sample does not bracket worker",
    )
    return identity


def _journal(raw, policy, source_identity, prefix, anchors, journal_identity):
    rows = _rows(raw)
    previous = ZERO_HASH
    prefixes = {0: (0, ZERO_HASH, _sha(b""))}
    offset, hasher = 0, hashlib.sha256()
    cursor = dict(offset=0, sha256=_sha(b""))
    active = None
    for index, (row, line) in enumerate(zip(rows, raw.splitlines(keepends=True)), 1):
        safety._fields(row, "seq prev kind data sha256")
        _integer(row["seq"], 1)
        core = {k: v for k, v in row.items() if k != "sha256"}
        _need(
            row["seq"] == index
            and row["prev"] == previous
            and row["sha256"] == _sha(_json(core)),
            "journal chain differs",
        )
        data, kind = row["data"], row["kind"]
        if index == 1:
            _need(
                kind == "header"
                and type(data) is dict
                and data.get("schema_version") == "outcome-observation-journal/v3"
                and data.get("scope_ref") == policy.data["scope_ref"],
                "journal header differs",
            )
            config = data["input_config"]
            _need(
                type(config) is dict
                and safety._same(config.get("authentication"), policy.binding()),
                "journal authentication differs",
            )
            for key in ("device", "inode", "uid"):
                _integer(config[key])
                _need(
                    config[key] == source_identity[key],
                    "journal Source identity differs",
                )
            _need(
                config.get("path_sha256") == _sha(policy.data["source_path"].encode()),
                "journal Source path differs",
            )
        elif kind == "session_open":
            safety._fields(data, "boot_id")
            _ref(data["boot_id"])
            _need(active is None, "nested journal session")
            active = data["boot_id"]
        elif kind == "input_ready":
            _need(
                active is not None and safety._same(data, cursor),
                "journal recovery cursor differs",
            )
        elif kind == "cursor":
            safety._fields(data, "position missed")
            pos = data["position"]
            safety._fields(pos, "offset sha256")
            _integer(pos["offset"], 1)
            safety._hex(pos["sha256"])
            _need(
                active is not None
                and type(data["missed"]) is bool
                and cursor["offset"] < pos["offset"] <= len(prefix)
                and pos["sha256"] == _sha(prefix[: pos["offset"]])
                and prefix[pos["offset"] - 1 : pos["offset"]] == b"\n",
                "journal cursor differs",
            )
            cursor = pos
        elif kind == "session_close":
            _need(
                active is not None and safety._same(data, {"boot_id": active}),
                "journal close differs",
            )
            active = None
        else:
            raise ValueError("unsupported finite journal record")
        previous = row["sha256"]
        offset += len(line)
        hasher.update(line)
        prefixes[offset] = (index, previous, hasher.hexdigest())
    _need(
        rows[-1]["kind"] == "session_close"
        and active is None
        and cursor == dict(offset=len(prefix), sha256=_sha(prefix))
        and cursor["offset"] > 0,
        "closed nonempty cursor required",
    )
    for row in _rows(anchors):
        state = validate_state(row["state"])
        _need(
            prefixes.get(state["journal_size"])
            == (state["journal_seq"], state["journal_head"], state["journal_sha256"]),
            "witness journal boundary differs",
        )
        if state["journal_seq"]:
            _need(
                (state["journal_device"], state["journal_inode"])
                == (journal_identity["device"], journal_identity["inode"]),
                "witness journal identity differs",
            )
    _need(state["journal_size"] == len(raw), "witness journal final boundary differs")


def verify_forged_input_refusal(
    plan_raw, *, expected_plan_sha256, trust_raw, before, after, stdout_raw, stderr_raw
):
    """Original v1 boundary; no v2 format or challenge adoption."""
    return _verify(
        plan_raw,
        expected_plan_sha256=expected_plan_sha256,
        trust_raw=trust_raw,
        before=before,
        after=after,
        stdout_raw=stdout_raw,
        stderr_raw=stderr_raw,
        version=1,
        reference_frame_raw=None,
    )


def verify_forged_input_refusal_v2(
    plan_raw,
    *,
    expected_plan_sha256,
    trust_raw,
    before,
    after,
    stdout_raw,
    stderr_raw,
    reference_frame_raw,
):
    """Five explicitly enrolled finite challenges, never execution authority."""
    return _verify(
        plan_raw,
        expected_plan_sha256=expected_plan_sha256,
        trust_raw=trust_raw,
        before=before,
        after=after,
        stdout_raw=stdout_raw,
        stderr_raw=stderr_raw,
        version=2,
        reference_frame_raw=reference_frame_raw,
    )


REASONS = {
    "wrong_key": "authentication signature invalid",
    "scope_mismatch": "signed input identity/sequence mismatch",
    "replay": "signed input identity/sequence mismatch",
    "chain_corruption": "signed input identity/sequence mismatch",
    "partial_frame": "incomplete input tail; automatic resume refused",
}


def _challenge_v2(policy, plan, prefix, suffix, reference, result):
    challenge = plan["challenge"]
    _need(
        type(reference) is bytes and 0 < len(reference) <= 65536,
        "reference unavailable or oversized",
    )
    _need(
        _sha(reference) == challenge["reference_frame_sha256"], "reference hash differs"
    )
    rows = _rows(reference)
    _need(len(rows) == 1, "one reference frame required")
    row = rows[0]
    verifier = SourceVerifier(policy)
    verifier.verify(prefix + reference)
    _need(
        row["boot_ref"] == plan["expected_context"]["boot_ref"]
        and row["event"]["capture_origin"]["session_ref"]
        == plan["expected_context"]["session_ref"]
        and row["event"]["capture_origin"]["kind"] == "session_start",
        "reference selected session/start differs",
    )
    result["reference_frame_authenticated"] = True
    kind = challenge["kind"]
    if kind == "partial_frame":
        cut = challenge["partial_bytes"]
        _need(
            0 < cut < len(reference)
            and suffix == reference[:cut]
            and b"\n" not in suffix,
            "partial reference prefix differs",
        )
        direct_reason = "invalid bounded signed source"
    elif kind == "replay":
        _need(
            suffix == prefix.splitlines(keepends=True)[-1],
            "original replay frame differs",
        )
        direct_reason = REASONS[kind]
    else:
        submitted = _rows(suffix)
        _need(len(submitted) == 1, "one challenge frame required")
        submitted = submitted[0]
        mutable = {"signature"}
        if kind == "scope_mismatch":
            mutable.add("scope_ref")
            _ref(submitted["scope_ref"])
            _need(submitted["scope_ref"] != row["scope_ref"], "scope was not changed")
        elif kind == "chain_corruption":
            mutable.add("prev")
            safety._hex(submitted["prev"])
            _need(submitted["prev"] != row["prev"], "chain was not changed")
        _need(
            set(submitted) == set(row)
            and safety._same(
                {k: v for k, v in submitted.items() if k not in mutable},
                {k: v for k, v in row.items() if k not in mutable},
            ),
            "nonisolated mutation",
        )
        _need(submitted["signature"] != row["signature"], "signature was not changed")
        hex_bytes(submitted["signature"], 64)
        public = (
            challenge["challenge_public_key"]
            if kind == "wrong_key"
            else policy.data["producer_public_key"]
        )
        verify_signature(
            public,
            submitted["signature"],
            SOURCE_DOMAIN,
            {k: v for k, v in submitted.items() if k != "signature"},
        )
        direct_reason = REASONS[kind]
    verifier = SourceVerifier(policy)
    verifier.verify(prefix)
    try:
        verifier.verify(prefix + suffix)
    except OutcomeJournalError as exc:
        _need(str(exc) == direct_reason, "unexpected direct verifier reason")
    else:
        raise ValueError("challenge was authenticated")
    result["challenge_verified"] = True


def _verify(
    plan_raw,
    *,
    expected_plan_sha256,
    trust_raw,
    before,
    after,
    stdout_raw,
    stderr_raw,
    version,
    reference_frame_raw,
):
    """Shared bounded immutable facts; version selected ONLY by closed wrappers."""
    try:
        safety._hex(expected_plan_sha256)
        plan = _object(plan_raw, 32768)
        _need(_sha(plan_raw) == expected_plan_sha256, "external plan hash differs")
        safety._fields(
            plan,
            "schema_version capture_id kernel_boot_id expected_trust_sha256 expected_context expected_source_checkpoint expected_anchor_checkpoint samples worker"
            + (" challenge" if version == 2 else ""),
        )
        _need(
            plan["schema_version"] == f"edge-forged-input-refusal-plan/v{version}",
            "plan schema",
        )
        if version == 2:
            challenge = plan["challenge"]
            safety._fields(
                challenge,
                "kind reference_frame_sha256 challenge_public_key partial_bytes",
            )
            _need(
                type(challenge["kind"]) is str and challenge["kind"] in REASONS,
                "challenge kind",
            )
            safety._hex(challenge["reference_frame_sha256"])
            if challenge["kind"] == "wrong_key":
                safety._hex(challenge["challenge_public_key"])
            else:
                _need(
                    challenge["challenge_public_key"] is None,
                    "unexpected challenge key",
                )
            if challenge["kind"] == "partial_frame":
                _integer(challenge["partial_bytes"], 1, 65535)
            else:
                _need(challenge["partial_bytes"] is None, "unexpected partial length")
        _ref(plan["capture_id"])
        _need(type(plan["kernel_boot_id"]) is str, "boot UUID type")
        _need(
            str(uuid.UUID(plan["kernel_boot_id"])) == plan["kernel_boot_id"],
            "boot UUID",
        )
        policy = TrustPolicy(_object(trust_raw, 32768))
        _need(_sha(trust_raw) == plan["expected_trust_sha256"], "trust hash differs")
        if version == 2 and challenge["kind"] == "wrong_key":
            _need(
                challenge["challenge_public_key"]
                not in (
                    policy.data["producer_public_key"],
                    policy.data["witness_public_key"],
                ),
                "challenge key roles overlap",
            )
        safety._fields(plan["samples"], "before after")
        for slots in (before, after, *plan["samples"].values()):
            safety._fields(slots, "source journal anchors")
        worker = plan["worker"]
        safety._fields(
            worker,
            "pid uid code_sha256 started_ns exited_ns returncode forced error stdout_sha256 stderr_sha256",
        )
        for field in ("pid", "uid", "started_ns", "exited_ns"):
            _integer(worker[field], 1 if field in ("pid", "uid") else 0)
        _integer(worker["returncode"], -255, 255)
        for field in ("code_sha256", "stdout_sha256", "stderr_sha256"):
            safety._hex(worker[field])
        _need(
            type(worker["forced"]) is bool
            and (
                worker["error"] is None
                or type(worker["error"]) is str
                and len(worker["error"]) <= 128
            ),
            "worker facts",
        )
        _need(worker["started_ns"] <= worker["exited_ns"], "worker clock order")
        # Public verifier validates exact trust/context/checkpoint grammar even if unavailable.
        verify_witnessed_source_prefix(
            trust_raw,
            None,
            None,
            expected_trust_sha256=plan["expected_trust_sha256"],
            expected_context=plan["expected_context"],
            expected_source_checkpoint=plan["expected_source_checkpoint"],
            expected_anchor_checkpoint=plan["expected_anchor_checkpoint"],
        )
        _need(
            plan["expected_context"]["boot_ref"]
            == plan["kernel_boot_id"].replace("-", ""),
            "context boot differs",
        )
    except ERRORS as exc:
        raise ForgedInputRefusalInputError(str(exc)) from exc
    result = dict(
        schema_version=f"edge-forged-input-refusal-diagnostic/v{version}",
        status="unknown",
        sampled_state_unchanged=None,
        observed_persistent_change=None,
        changes={k: None for k in KINDS},
        invalid_signature_verified=False,
        baseline_witness_verified=False,
        journal_cursor_structurally_verified=False,
        full_journal_semantics_verified=False,
        qualified_safety_count=None,
        reasons=[],
        **safety.FLAGS,
    )
    if version == 2:
        result.pop("invalid_signature_verified")
        result.update(
            challenge_verified=False,
            challenge_kind=challenge["kind"],
            reference_frame_authenticated=False,
            expected_refusal_reason=REASONS[challenge["kind"]],
        )
    valid = {}
    for phase, samples in (("before", before), ("after", after)):
        for kind in KINDS:
            try:
                valid[phase, kind] = _sample(
                    samples[kind],
                    plan["samples"][phase][kind],
                    kind,
                    phase,
                    plan,
                    policy,
                )
            except ERRORS:
                result["reasons"].append(phase + "_" + kind + "_unavailable_or_invalid")
    for kind in KINDS:
        if ("before", kind) in valid and ("after", kind) in valid:
            result["changes"][kind] = not (
                before[kind] == after[kind]
                and valid["before", kind] == valid["after", kind]
            )
    if any(value is True for value in result["changes"].values()):
        result["observed_persistent_change"] = True
        result["sampled_state_unchanged"] = False
    elif all(value is False for value in result["changes"].values()):
        result["observed_persistent_change"] = False
        result["sampled_state_unchanged"] = True
    try:
        _need(all(("before", k) in valid for k in KINDS), "baseline incomplete")
        witness = verify_witnessed_source_prefix(
            trust_raw,
            before["source"],
            before["anchors"],
            expected_trust_sha256=plan["expected_trust_sha256"],
            expected_context=plan["expected_context"],
            expected_source_checkpoint=plan["expected_source_checkpoint"],
            expected_anchor_checkpoint=plan["expected_anchor_checkpoint"],
        )
        _need(witness["witness_prefix_authenticated"], "baseline witness unavailable")
        checkpoint = plan["expected_source_checkpoint"]
        _need(
            checkpoint["size"] > 0
            and plan["expected_anchor_checkpoint"]["size"] == len(before["anchors"]),
            "complete baseline anchors required",
        )
        prefix = before["source"][: checkpoint["size"]]
        suffix = before["source"][checkpoint["size"] :]
        if version == 2:
            _challenge_v2(policy, plan, prefix, suffix, reference_frame_raw, result)
        else:
            rows = _rows(suffix)
            _need(
                len(rows) == 1
                and rows[0]["boot_ref"] == plan["expected_context"]["boot_ref"],
                "one same-boot challenge required",
            )
            event = rows[0].get("event")
            _need(type(event) is dict, "challenge event object required")
            origin = event.get("capture_origin")
            _need(
                type(origin) is dict
                and type(origin.get("session_ref")) is str
                and origin["session_ref"] == plan["expected_context"]["session_ref"],
                "challenge selected session differs",
            )
            hex_bytes(rows[0]["signature"], 64)
            verifier = SourceVerifier(policy)
            verifier.verify(prefix)
            try:
                verifier.verify(before["source"])
            except OutcomeJournalError as exc:
                _need(
                    str(exc) == "authentication signature invalid",
                    "not an eligible invalid signature",
                )
            else:
                raise ValueError("challenge signature was accepted")
            result["invalid_signature_verified"] = True
        result["baseline_witness_verified"] = True
        _journal(
            before["journal"],
            policy,
            valid["before", "source"],
            prefix,
            before["anchors"],
            valid["before", "journal"],
        )
        result["journal_cursor_structurally_verified"] = True
    except ERRORS:
        result["reasons"].append("baseline_or_challenge_unverified")
    worker_good = (
        type(stdout_raw) is bytes
        and type(stderr_raw) is bytes
        and len(stdout_raw) <= 65536
        and len(stderr_raw) <= 65536
        and _sha(stdout_raw) == worker["stdout_sha256"]
        and _sha(stderr_raw) == worker["stderr_sha256"]
        and stdout_raw == b""
        and stderr_raw.endswith(
            REFUSAL
            if version == 1
            else (
                "azazel_edge.outcome.journal.OutcomeJournalError: "
                + result["expected_refusal_reason"]
                + "\n"
            ).encode()
        )
        and worker["uid"] == policy.data["observer_uid"]
        and worker["returncode"] > 0
        and worker["forced"] is False
        and worker["error"] is None
    )
    if not worker_good:
        result["reasons"].append("worker_refusal_unverified")
    if (
        result["sampled_state_unchanged"] is True
        and result[
            "invalid_signature_verified" if version == 1 else "challenge_verified"
        ]
        and result["baseline_witness_verified"]
        and result["journal_cursor_structurally_verified"]
        and worker_good
    ):
        result["status"] = "recorded_refusal_consistent"
    return result
