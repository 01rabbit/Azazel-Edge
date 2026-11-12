"""PUBLIC TEST-ONLY keys and closed frozen recipe builder; never runtime tooling."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from azazel_edge.outcome.input_auth import SOURCE_DOMAIN
from azazel_edge.outcome.journal import _json

ROOT = Path(__file__).parent / "fixtures/safety-observations/v1"
DOMAIN = b"azazel-edge:finite-safety-observation:v1\x00"
HASHES = {
    "contract.json": "2f2c1b8c8f9b47e622eba02ad2d1f51bf0f73793e412807726895dd4dd207082",
    "corpus.json": "a798b1d9f87335144eb5efa38d25b65318981e1b440f57bc2649f1b2aec0bd74",
    "expected.json": "fe38bf39e6daaa916492da75c3a6cfcdd08132a9adb058cae66caa7a9c4516fd",
}
SCENARIO_OPS = frozenset(
    {
        "empty_other_opportunity_lists",
        "empty_all_opportunity_lists",
        "replace_fact_with_violation",
        "append_duplicate_and_conflicting_violation_facts",
        "forged_disposition_error_unchanged",
        "insert_loss",
        "frozen_invalid_challenge_suffix",
    }
)

PUBLIC_TEST_SEEDS = (bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32)
KEYS = tuple(Ed25519PrivateKey.from_private_bytes(seed) for seed in PUBLIC_TEST_SEEDS)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return _json(value) + b"\n"


def frozen():
    raw = {name: (ROOT / name).read_bytes() for name in HASHES}
    assert all(digest(raw[name]) == expected for name, expected in HASHES.items())
    return tuple(json.loads(raw[name]) for name in HASHES)


def sign(rows, key=KEYS[0], domain=DOMAIN):
    previous = "0" * 64
    for index, row in enumerate(rows, 1):
        row.pop("signature", None)
        row["seq"], row["prev"] = index, previous
        row["signature"] = key.sign(domain + _json(row)).hex()
        previous = digest(_json(row))
    return previous


def build(case_id):
    """Construct frozen semantic scenario, retain heads, then mutate submitted copy."""
    contract, corpus, _ = frozen()
    recipe = next(case for case in corpus["cases"] if case["id"] == case_id)
    mutations, template = recipe["mutations"], corpus["base_template"]
    assert all(
        m["phase"] == ("scenario" if m["op"] in SCENARIO_OPS else "post_checkpoint")
        for m in mutations
    )
    scenario = [m for m in mutations if m["phase"] == "scenario"]
    post_checkpoint = [m for m in mutations if m["phase"] == "post_checkpoint"]
    for mutation in scenario:
        op = mutation["op"]
        if op in ("empty_other_opportunity_lists", "empty_all_opportunity_lists"):
            for category in contract["opportunities"]:
                if category != mutation.get("keep"):
                    contract["opportunities"][category] = []
    contract_raw = wire(contract)
    contract_hash = digest(contract_raw)
    observations = dict(
        schema_version="edge-finite-safety-observations/v1",
        contract_sha256=contract_hash,
        scope=deepcopy(contract["scope"]),
        channels={},
    )
    for category, descriptor in contract["channels"].items():
        opportunity = contract["opportunities"][category]
        facts = deepcopy(template["zero_facts"][category])
        relevant = [m for m in scenario if m.get("category") == category]
        if any(m["op"] == "replace_fact_with_violation" for m in relevant):
            facts = deepcopy(template["violation_facts"][category])
        if category == "forged_evidence_accepted" and any(
            m["op"] == "forged_disposition_error_unchanged" for m in scenario
        ):
            facts["disposition"] = "error"
        definitions = [("open", 1000000000, None, dict(boundary_ns=1000000000))]
        if opportunity:
            item = opportunity[0]
            definitions += [
                (
                    "challenge_begin",
                    2000000000,
                    item["id"],
                    dict(challenge_sha256=item["challenge_sha256"]),
                ),
                (template["fact_kinds"][category], 3000000000, item["id"], facts),
            ]
            if any(
                m["op"] == "append_duplicate_and_conflicting_violation_facts"
                for m in relevant
            ):
                definitions += [
                    (
                        template["fact_kinds"][category],
                        3000000000,
                        item["id"],
                        deepcopy(facts),
                    ),
                    (
                        template["fact_kinds"][category],
                        3000000000,
                        item["id"],
                        deepcopy(template["violation_facts"][category]),
                    ),
                ]
            if any(m["op"] == "insert_loss" for m in relevant):
                definitions.append(("loss", 3500000000, None, dict(lost_records=1)))
            definitions.append(
                (
                    "challenge_end",
                    4000000000,
                    item["id"],
                    dict(challenge_sha256=item["challenge_sha256"]),
                )
            )
        definitions.append(("close", 9000000000, None, dict(boundary_ns=9000000000)))
        rows = [
            dict(
                schema_version="edge-finite-safety-row/v1",
                contract_sha256=contract_hash,
                scope=deepcopy(contract["scope"]),
                category=category,
                channel_id=descriptor["channel_id"],
                capture_id=descriptor["capture_id"],
                kind=kind,
                monotonic_ns=clock,
                opportunity_id=opp,
                data=data,
                raw_ref_sha256=template["raw_ref_sha256"],
            )
            for kind, clock, opp, data in definitions
        ]
        sign(rows)
        observations["channels"][category] = dict(
            channel_id=descriptor["channel_id"],
            capture_id=descriptor["capture_id"],
            rows=rows,
        )
    # Independently supplied test checkpoints are fixed before submitted-bundle faults.
    heads = {
        category: digest(_json(channel["rows"][-1]))
        for category, channel in observations["channels"].items()
    }
    arguments = dict(
        expected_contract_sha256=contract_hash,
        **contract["keypins"],
        expected_stream_heads=deepcopy(heads),
    )
    for mutation in post_checkpoint:
        op, category = mutation["op"], mutation.get("category")
        if op == "contract_collector_uid":
            contract["channels"][category]["collector_uid"] = mutation["value"]
            continue
        if op == "contract_window_start_bool":
            next(iter(contract["opportunities"].values()))[0]["start_ns"] = True
            continue
        if op == "remove_channel":
            del observations["channels"][category]
            continue
        if op == "external_observer_key_equals_producer_key":
            arguments["observer_public_key"] = arguments["source_producer_public_key"]
        if category is None or category not in observations["channels"]:
            continue
        channel = observations["channels"][category]
        rows = channel["rows"]
        fact = next(
            (row for row in rows if row["kind"] == template["fact_kinds"][category]),
            None,
        )
        if op == "remove_begin_end_close":
            channel["rows"] = [
                row
                for row in rows
                if row["kind"] not in ("challenge_begin", "challenge_end", "close")
            ]
        elif op == "remove_begin_without_rechaining":
            channel["rows"] = [row for row in rows if row["kind"] != "challenge_begin"]
        elif op == "sign_channel_with_producer_key":
            sign(rows, key=KEYS[1])
        elif op == "sign_channel_with_source_domain":
            sign(rows, domain=SOURCE_DOMAIN)
        elif op in (
            "resign_channel_with_wrong_scope_session",
            "resign_channel_with_wrong_boot",
            "resign_channel_with_wrong_scope_owner",
        ):
            for row in rows:
                if op.endswith("scope_session"):
                    row["scope"]["session_ref"] = "f" * 32
                elif op.endswith("wrong_boot"):
                    row["scope"]["kernel_boot_id"] = (
                        "00000000-0000-4000-8000-000000000002"
                    )
                else:
                    row["scope"]["owner"]["observer_uid"] = 61003
            sign(rows)
        elif op == "resign_fact_after_window":
            fact["monotonic_ns"] = 4000000001
            sign(rows)
        elif op == "external_head_points_to_preclose_row":
            arguments["expected_stream_heads"][category] = digest(_json(rows[-2]))
        elif op == "external_head_none":
            arguments["expected_stream_heads"][category] = None
        elif op == "replay_signed_previous_capture":
            channel["capture_id"] = "synthetic-previous-capture"
            for row in rows:
                row["capture_id"] = channel["capture_id"]
            sign(rows)
        elif op == "malformed_complete_fact_shape":
            fact["data"] = dict(unexpected=True)
            sign(rows)
        elif op == "resign_wrong_protected_tuple":
            fact["data"]["tuple"]["dst_port"] = 18081
            sign(rows)
        elif op in ("resign_wrong_advisory_input", "resign_wrong_forged_input"):
            fact["data"]["input_sha256"] = "f" * 64
            sign(rows)
    observations_raw = wire(observations)
    if any(m["op"] == "observations_nonfinite_nan" for m in mutations):
        observations["channels"]["protected_escape"]["rows"][2]["data"]["delivered"] = (
            float("nan")
        )
        observations_raw = (
            json.dumps(
                observations, sort_keys=True, separators=(",", ":"), allow_nan=True
            ).encode()
            + b"\n"
        )
    if any(m["op"] == "observations_exceed_2mib_by_one" for m in mutations):
        observations_raw = observations_raw + b" " * (
            2 * 1024 * 1024 + 1 - len(observations_raw)
        )
    return wire(contract), observations_raw, arguments
