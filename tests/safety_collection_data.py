"""PUBLIC synthetic signed-artifact builder. No filesystem writes or key files."""

from copy import deepcopy
import json
from pathlib import Path

from safety_observation_data import build, sign, wire, digest

BOOT = "00000000-0000-4000-8000-000000000001"
NAMES = ("enrollment", "contract", "observations", "checkpoint")
CASE_FILE = Path(__file__).parent / "fixtures/safety-collection/v1/cases.json"
CASES = json.loads(CASE_FILE.read_bytes())["cases"]


def build_bundle(
    directory, case="complete", *, boot_id=None, observer_uid=61002, producer_uid=61001
):
    """Caller stages returned public bytes; only caller owns permission/UID fixtures."""
    assert case in {row["id"] for row in CASES}
    directory = Path(directory)
    assert directory.is_absolute()
    paths = {name: directory / (name + ".json") for name in NAMES}
    recipe = (
        "violation-protected_escape"
        if case in ("violation", "null-head-violation", "gap-violation")
        else "all-four-complete-finite-zero"
    )
    contract_raw, observation_raw, _ = build(recipe)
    contract, observation = json.loads(contract_raw), json.loads(observation_raw)
    old_owner = deepcopy(contract["scope"]["owner"])
    scope = contract["scope"]
    scope["kernel_boot_id"] = boot_id or BOOT
    if case == "wrong-boot":
        scope["kernel_boot_id"] = (
            "00000000-0000-4000-8000-000000000002"
            if scope["kernel_boot_id"] != "00000000-0000-4000-8000-000000000002"
            else BOOT
        )
    scope["owner"] = dict(observer_uid=observer_uid, producer_uid=producer_uid)
    for descriptor in contract["channels"].values():
        descriptor["collector_boot_id"] = scope["kernel_boot_id"]
        uid = descriptor["source_actor_uid"]
        if uid == old_owner["observer_uid"]:
            descriptor["source_actor_uid"] = observer_uid
        elif uid == old_owner["producer_uid"]:
            descriptor["source_actor_uid"] = producer_uid
    contract_raw = wire(contract)
    contract_sha = digest(contract_raw)
    observation["scope"] = deepcopy(scope)
    observation["contract_sha256"] = contract_sha
    heads = {}
    for category, channel in observation["channels"].items():
        for row in channel["rows"]:
            row["scope"] = deepcopy(scope)
            row["contract_sha256"] = contract_sha
        # FULL substitutions precede signing and external checkpoint retention.
        heads[category] = sign(channel["rows"])
    checkpoint = dict(
        schema_version="edge-safety-checkpoint/v1",
        contract_sha256=contract_sha,
        scope=deepcopy(scope),
        capture_ids={
            cat: descriptor["capture_id"]
            for cat, descriptor in contract["channels"].items()
        },
        stream_heads=deepcopy(heads),
    )
    enrollment = dict(
        schema_version="edge-safety-enrollment/v1",
        contract_sha256=contract_sha,
        scope=deepcopy(scope),
        observer_uid=observer_uid,
        paths={
            name: str(paths[name])
            for name in ("contract", "observations", "checkpoint")
        },
    )
    # Named semantic/checkpoint fixtures. No evaluator-derived or repaired heads.
    protected = observation["channels"]["protected_escape"]
    if case in ("null-head", "null-head-violation"):
        checkpoint["stream_heads"]["protected_escape"] = None
    elif case in ("gap", "gap-violation"):
        protected["rows"] = [
            row for row in protected["rows"] if row["kind"] != "challenge_begin"
        ]
    elif case == "missing-channel":
        del observation["channels"]["protected_escape"]
    elif case == "bad-signature":
        value = protected["rows"][2]["signature"]
        protected["rows"][2]["signature"] = ("0" if value[0] != "0" else "1") + value[
            1:
        ]
    elif case == "wrong-head":
        checkpoint["stream_heads"]["protected_escape"] = digest(
            wire(protected["rows"][-2])
        )
    elif case == "wrong-contract-pin":
        enrollment["contract_sha256"] = "f" * 64
    elif case == "wrong-scope":
        checkpoint["scope"]["session_ref"] = "f" * 32
    elif case == "wrong-capture":
        checkpoint["capture_ids"]["protected_escape"] = "synthetic-foreign-capture"
    elif case == "path-alias":
        enrollment["paths"]["observations"] = enrollment["paths"]["contract"]
    files = dict(
        enrollment=wire(enrollment),
        contract=contract_raw,
        observations=wire(observation),
        checkpoint=wire(checkpoint),
    )
    pins = dict(
        expected_enrollment_sha256=digest(files["enrollment"]),
        expected_checkpoint_sha256=digest(files["checkpoint"]),
    )
    # Corrupt submitted files only AFTER external registration/checkpoint hashes.
    if case == "wrong-enrollment-pin":
        pins["expected_enrollment_sha256"] = "f" * 64
    elif case == "wrong-checkpoint-pin":
        pins["expected_checkpoint_sha256"] = "f" * 64
    elif case == "unregistered":
        del files["enrollment"]
    elif case == "missing-artifact":
        del files["observations"]
    elif case == "noncanonical":
        files["enrollment"] = json.dumps(enrollment, indent=2).encode() + b"\n"
    elif case == "duplicate-key":
        files["enrollment"] = files["enrollment"].replace(
            b'{"contract_sha256":',
            b'{"schema_version":"duplicate","contract_sha256":',
            1,
        )
    elif case == "oversize":
        files["observations"] += b" " * (
            2 * 1024 * 1024 + 1 - len(files["observations"])
        )
    return dict(paths=paths, files=files, scope=deepcopy(scope), **pins)
