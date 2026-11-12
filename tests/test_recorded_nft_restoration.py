"""SYNTHETIC enrollment/query statements; real registered Source crypto, no NFT I/O."""

from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from azazel_edge.benchmark.recorded_nft_restoration import (
    evaluate_recorded_nft_restoration,
)
from safety_observation_data import digest, wire
from recorded_nft_restoration_data import (
    make_restoration_case,
    change_receipt,
    retain_plan,
)

POSITIVE = "sampled_fixed_chain_returned_to_baseline"


def evaluate(value):
    return evaluate_recorded_nft_restoration(
        value["plan_raw"],
        expected_plan_sha256=value["expected_plan_sha256"],
        source_inputs=value["source_inputs"],
        receipts=value["receipts"],
    )


def assert_no_authority(result):
    assert result["qualified_safety_count"] is None
    assert result["network_mechanism_restored"] is None
    assert result["execution_fact_verified"] is False
    assert result["independently_measured"] is False
    for name in (
        "authorizes_transition",
        "resume_authorized",
        "experiment",
        "measurement_completed",
        "production_admission",
    ):
        assert result[name] is False


def owner(snapshot):
    return next(
        row["rule"]
        for row in snapshot["nftables"]
        if "rule" in row and row["rule"]["comment"].startswith("azazel-edge:")
    )


def test_valid_exact_triplet_and_original_signed_wire_pin(tmp_path):
    value = make_restoration_case(tmp_path)
    assert value["plan"]["source_event_sha256"] == digest(value["signed_event_wire"])
    assert value["signed_event_wire"].endswith(b"\n")
    result = evaluate(value)
    assert result["status"] == POSITIVE
    assert_no_authority(result)


@pytest.mark.parametrize("kind", ["rate", "duplicate", "baseline_owner"])
def test_any_exact_owner_row_is_residue_not_semantic_absence(tmp_path, kind):
    value = make_restoration_case(tmp_path)
    owned = deepcopy(owner(value["snapshots"]["applied"]))
    if kind == "rate":
        owned["expr"][-2]["limit"]["rate"] = 17
        change_receipt(
            value,
            "released",
            snapshot_mutator=lambda s: s["nftables"].append({"rule": owned}),
        )
    elif kind == "duplicate":
        duplicate = deepcopy(owned)
        duplicate["handle"] = 6
        change_receipt(
            value,
            "applied",
            snapshot_mutator=lambda s: s["nftables"].append({"rule": duplicate}),
        )
    else:
        change_receipt(
            value,
            "baseline",
            snapshot_mutator=lambda s: s["nftables"].append({"rule": owned}),
        )
    result = evaluate(value)
    assert result["status"] != POSITIVE
    assert_no_authority(result)


@pytest.mark.parametrize(
    "kind",
    [
        "foreign_row",
        "handle",
        "counter",
        "order",
        "chain",
        "missing_chain",
        "bool",
        "float",
    ],
)
def test_complete_typed_structure_not_python_equality(tmp_path, kind):
    value = make_restoration_case(tmp_path)

    def mutate(snapshot):
        rows = snapshot["nftables"]
        if kind == "foreign_row":
            rows[2]["rule"]["comment"] = "foreign-changed"
        elif kind == "handle":
            rows[2]["rule"]["handle"] = 9
        elif kind == "counter":
            rows[2]["rule"]["expr"][0]["counter"]["packets"] = 2
        elif kind == "order":
            rows[2], rows[3] = rows[3], rows[2]
        elif kind == "chain":
            rows[1]["chain"]["handle"] = 4
        elif kind == "missing_chain":
            rows.pop(1)
        else:
            rows[2]["rule"]["expr"][0]["counter"]["packets"] = (
                True if kind == "bool" else 1.0
            )

    change_receipt(value, "released", snapshot_mutator=mutate)
    result = evaluate(value)
    assert result["status"] != POSITIVE
    assert_no_authority(result)


@pytest.mark.parametrize("phase", ["baseline", "applied", "released"])
def test_missing_phase_never_supplies_an_empty_snapshot(tmp_path, phase):
    value = make_restoration_case(tmp_path)
    value["receipts"][phase] = None
    value["plan"]["receipts"][phase] = None
    retain_plan(value)
    assert evaluate(value)["status"] != POSITIVE


@pytest.mark.parametrize(
    "kind",
    [
        "denied",
        "query",
        "boot",
        "namespace",
        "source",
        "binary",
        "pid",
        "argv",
        "uid_bool",
        "return_bool",
        "boundary",
        "label",
    ],
)
def test_wrong_receipt_context_is_unknown(tmp_path, kind):
    value = make_restoration_case(tmp_path)

    def mutate(r):
        if kind == "denied":
            r.update(returncode=1, stderr="permission denied")
        elif kind == "query":
            r["argv"].append("extra")
        elif kind == "boot":
            r["kernel_boot_id"] = "00000000-0000-4000-8000-000000000002"
        elif kind == "namespace":
            r["netns_inode"] += 1
        elif kind == "source":
            r["source_identity"]["helper_sha256"] = "e" * 64
        elif kind == "binary":
            r["nft_binary_sha256"] = "e" * 64
        elif kind == "pid":
            r["root_pid"] += 1
        elif kind == "argv":
            r["actual_child_argv"].append("extra")
        elif kind == "uid_bool":
            r["root_uid"] = False
        elif kind == "return_bool":
            r["returncode"] = False
        elif kind == "boundary":
            r["capture_boundary"] = "claimed"
        else:
            r["source"] = "synthetic-self-authentication"

    change_receipt(value, "applied", mutate)
    assert evaluate(value)["status"] != POSITIVE


@pytest.mark.parametrize(
    "kind", ["truncated", "duplicate_key", "nan", "deep", "oversize"]
)
def test_raw_receipt_strict_framing_and_bounds(tmp_path, kind):
    value = make_restoration_case(tmp_path)
    raw = value["receipts"]["applied"]
    if kind == "truncated":
        raw = raw[:-1]
    elif kind == "duplicate_key":
        raw = raw.replace(b'"root_uid": 0', b'"root_uid": 0,"root_uid": 0')
    elif kind == "nan":
        raw = raw.replace(b'"root_uid": 0', b'"root_uid": NaN')
    elif kind == "deep":
        raw = b"[" * 14 + b"0" + b"]" * 14
    else:
        raw = b" " * (8 * 1024 * 1024 + 1)
    value["receipts"]["applied"] = raw
    value["plan"]["receipts"]["applied"]["sha256"] = digest(raw)
    retain_plan(value)
    assert evaluate(value)["status"] != POSITIVE


@pytest.mark.parametrize("kind", ["reverse", "outside", "naive"])
def test_recorded_wall_clock_order_and_window(tmp_path, kind):
    value = make_restoration_case(tmp_path)
    start = {
        "reverse": "2026-11-13T00:00:00+00:00",
        "outside": "2026-11-13T00:02:00+00:00",
        "naive": "2026-11-13T00:00:11",
    }[kind]
    change_receipt(value, "applied", lambda r: r.update(query_started_at=start))
    assert evaluate(value)["status"] != POSITIVE


@pytest.mark.parametrize(
    "kind", ["mode", "result", "zero", "failed", "release_boolean"]
)
def test_authenticated_producer_assertions_must_describe_apply(tmp_path, kind):
    def mutate(e):
        if kind == "mode":
            e["enforcement"]["mode"] = "dry-run"
        elif kind == "result":
            e["enforcement"]["result"] = "failed"
        elif kind == "zero":
            e["enforcement"]["executed_count"] = 0
        elif kind == "failed":
            e["enforcement"]["failed_count"] = 1
        else:
            e["enforcement"].update(result="skipped", executed_count=0)
            e["enforcement"]["metadata"]["released"] = True

    value = make_restoration_case(tmp_path, native_mutator=mutate)
    assert evaluate(value)["status"] != POSITIVE


@pytest.mark.parametrize(
    "kind", ["wrong_seq", "unsigned_hash", "missing", "signature", "suffix"]
)
def test_exact_authenticated_selected_source_wire_required(tmp_path, kind):
    value = make_restoration_case(tmp_path)
    if kind == "wrong_seq":
        value["plan"]["source_event_seq"] = 2
    elif kind == "unsigned_hash":
        value["plan"]["source_event_sha256"] = digest(
            wire(json.loads(value["signed_event_wire"])["event"])
        )
    elif kind == "missing":
        value["source_inputs"]["source_raw"] = None
    elif kind == "signature":
        rows = value["source_inputs"]["source_raw"].splitlines(keepends=True)
        row = json.loads(rows[2])
        row["signature"] = "0" * 128
        rows[2] = wire(row)
        value["source_inputs"]["source_raw"] = b"".join(rows)
    else:
        value["source_inputs"]["source_raw"] += b'{"bad":'
    retain_plan(value)
    assert evaluate(value)["status"] != POSITIVE


def test_input_immutability_and_no_files_process_or_network(tmp_path):
    value = make_restoration_case(tmp_path)
    original = deepcopy((value["plan_raw"], value["source_inputs"], value["receipts"]))
    with (
        patch("builtins.open", side_effect=AssertionError("I/O")),
        patch("os.open", side_effect=AssertionError("I/O")),
        patch("socket.socket", side_effect=AssertionError("network")),
        patch("subprocess.Popen", side_effect=AssertionError("process")),
    ):
        result = evaluate(value)
    assert result["status"] == POSITIVE
    assert (value["plan_raw"], value["source_inputs"], value["receipts"]) == original


def test_frozen_case_inventory_keeps_actual_file_cases_separate():
    rows = json.loads(
        (
            Path(__file__).parent / "fixtures/recorded-nft-restoration/v1/cases.json"
        ).read_bytes()
    )["cases"]
    assert len(rows) == 29
    assert sum(row["evidence"] == "actual_linux_filesystem_only" for row in rows) == 2


@pytest.mark.parametrize("bad_phase", ["baseline", "applied"])
def test_released_residue_survives_invalid_sibling(tmp_path, bad_phase):
    value = make_restoration_case(tmp_path)
    owned = deepcopy(owner(value["snapshots"]["applied"]))
    owned["expr"][-2]["limit"]["rate"] = 999
    change_receipt(
        value,
        "released",
        snapshot_mutator=lambda s: s["nftables"].append({"rule": owned}),
    )
    change_receipt(value, bad_phase, lambda r: r.update(returncode=1, stderr="denied"))
    result = evaluate(value)
    assert result["status"] == "recorded_residue_or_change"
    assert result["phases"]["released"]["disposition"] == "valid_recorded_snapshot"
    assert result["phases"]["released"]["owner_rule_count"] == 1
    assert result["phases"][bad_phase]["owner_rule_count"] is None
    assert_no_authority(result)


def test_zero_owner_requires_valid_sample_and_source_owner_binding(tmp_path):
    value = make_restoration_case(tmp_path)
    result = evaluate(value)
    assert result["source_owner_bound"] is True
    assert result["phases"]["released"]["owner_rule_count"] == 0
    value["source_inputs"]["source_raw"] = None
    result = evaluate(value)
    assert result["source_owner_bound"] is False
    assert result["phases"]["released"]["owner_rule_count"] is None


@pytest.mark.parametrize(
    "kind", ["duplicate_handle", "bool_handle", "wrong_attachment"]
)
def test_structurally_invalid_full_chain_is_never_a_zero(tmp_path, kind):
    value = make_restoration_case(tmp_path)

    def mutate(snapshot):
        if kind == "duplicate_handle":
            snapshot["nftables"][3]["rule"]["handle"] = snapshot["nftables"][2]["rule"][
                "handle"
            ]
        elif kind == "bool_handle":
            snapshot["nftables"][2]["rule"]["handle"] = True
        else:
            snapshot["nftables"][1]["chain"]["prio"] = -149

    change_receipt(value, "released", snapshot_mutator=mutate)
    result = evaluate(value)
    assert result["phases"]["released"]["owner_rule_count"] is None
    assert result["status"] != POSITIVE


@pytest.mark.parametrize(
    "kind",
    [
        "plan_pin",
        "plan_bool_seq",
        "plan_bool_ns",
        "plan_extra",
        "source_slot",
        "receipt_slot",
    ],
)
def test_invalid_global_enrollment_is_an_input_error(tmp_path, kind):
    from azazel_edge.benchmark.recorded_nft_restoration import (
        RecordedNFTRestorationInputError,
    )

    value = make_restoration_case(tmp_path)
    if kind == "plan_pin":
        value["expected_plan_sha256"] = "e" * 64
    elif kind == "plan_bool_seq":
        value["plan"]["source_event_seq"] = True
        retain_plan(value)
    elif kind == "plan_bool_ns":
        value["plan"]["netns_inode"] = True
        retain_plan(value)
    elif kind == "plan_extra":
        value["plan"]["trusted"] = True
        retain_plan(value)
    elif kind == "source_slot":
        value["source_inputs"]["trusted"] = True
    else:
        value["receipts"]["extra"] = None
    with pytest.raises(RecordedNFTRestorationInputError):
        evaluate(value)
