"""Real crypto over explicitly SYNTHETIC anchors, not durable witness execution."""

from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from azazel_edge.benchmark.source_witness import (
    verify_witnessed_source_prefix,
    SourceWitnessInputError,
)
from azazel_edge.outcome.input_witness import ANCHOR_DOMAIN
from safety_observation_data import KEYS, digest, wire
from source_witness_data import make_witness_case, sign_anchors, anchor_checkpoint


def verify(value):
    return verify_witnessed_source_prefix(
        value["trust_raw"],
        value["source_raw"],
        value["anchors_raw"],
        **value["arguments"],
    )


def rewrite(value, mutate, **signing):
    rows = deepcopy(value["rows"])
    mutate(rows)
    raw = sign_anchors(rows, **signing)
    value["anchors_raw"] = raw
    value["arguments"]["expected_anchor_checkpoint"] = anchor_checkpoint(raw)


def assert_unqualified(result):
    assert result["schema_version"] == "edge-source-witness-prefix-diagnostic/v1"
    assert result["journal_verified"] is False
    assert result["qualified_safety_count"] is None
    for key in (
        "authorizes_transition",
        "resume_authorized",
        "experiment",
        "measurement_completed",
        "production_admission",
    ):
        assert result[key] is False


@pytest.mark.parametrize(
    "case",
    [
        "valid_pinned_prefix",
        "bad_source_suffix_preserves_prefix",
        "bad_anchor_suffix_preserves_prefix",
    ],
)
def test_authenticated_checkpoint_ignores_only_later_suffix(tmp_path, case):
    value = make_witness_case(tmp_path, case)
    original = deepcopy(value["arguments"])
    result = verify(value)
    assert_unqualified(result)
    assert result["source_prefix_authenticated"] is True
    assert result["witness_prefix_authenticated"] is True
    assert result["source_checkpoint"] == original["expected_source_checkpoint"]
    assert result["anchor_checkpoint"] == original["expected_anchor_checkpoint"]
    assert value["arguments"] == original
    assert verify(value) == result


@pytest.mark.parametrize(
    "case",
    [
        "missing_source",
        "empty_source",
        "missing_anchor",
        "missing_checkpoint",
        "old_log_vs_new_pin",
    ],
)
def test_missing_or_rolled_back_evidence_is_unknown(tmp_path, case):
    result = verify(make_witness_case(tmp_path, case))
    assert_unqualified(result)
    assert result["witness_prefix_authenticated"] is False
    assert result["anchor_checkpoint"] is None


@pytest.mark.parametrize(
    "mutation",
    [
        "key",
        "domain",
        "policy",
        "counter_gap",
        "counter_bool",
        "duplicate",
        "reorder",
        "prev",
        "source_hash",
        "source_head",
        "source_seq",
        "nonboundary",
        "genesis",
        "journal_seq",
        "journal_identity",
        "zero_identity",
        "source_regress",
        "same_seq_changed_tip",
        "journal_bool",
    ],
)
def test_resigned_chain_and_state_corruption_fails(tmp_path, mutation):
    value = make_witness_case(tmp_path)

    def change(rows):
        state = rows[-1]["state"]
        if mutation == "policy":
            rows[-1]["trust_sha256"] = "e" * 64
        elif mutation == "counter_gap":
            rows[-1]["counter"] = 3
        elif mutation == "counter_bool":
            rows[-1]["counter"] = True
        elif mutation == "duplicate":
            rows.append(deepcopy(rows[-1]))
        elif mutation == "reorder":
            rows.reverse()
        elif mutation == "source_hash":
            state["source_sha256"] = "e" * 64
        elif mutation == "source_head":
            state["source_head"] = "e" * 64
        elif mutation == "source_seq":
            state["source_seq"] = 2
        elif mutation == "nonboundary":
            state["source_size"] -= 1
        elif mutation == "genesis":
            rows[0]["state"]["journal_inode"] = 2
        elif mutation == "journal_seq":
            state["journal_seq"] = 2
        elif mutation == "zero_identity":
            state["journal_inode"] = 0
        elif mutation in ("journal_identity", "source_regress", "same_seq_changed_tip"):
            extra = deepcopy(rows[-1])
            extra["counter"] = 3
            extra["state"]["journal_seq"] = 2
            if mutation == "journal_identity":
                extra["state"]["journal_inode"] = 4
            elif mutation == "source_regress":
                extra["state"]["source_seq"] = 0
            else:
                extra["state"]["source_sha256"] = "e" * 64
            rows.append(extra)
        elif mutation == "journal_bool":
            state["journal_inode"] = True

    rewrite(
        value,
        change,
        key=KEYS[0] if mutation == "key" else KEYS[2],
        domain=b"wrong-domain\x00" if mutation == "domain" else ANCHOR_DOMAIN,
    )
    if mutation == "counter_bool":
        # Malformed submitted counter must not also corrupt the external typed pin.
        value["arguments"]["expected_anchor_checkpoint"]["counter"] = 2
    if mutation == "prev":
        rows = json.loads(b"[" + b",".join(value["anchors_raw"].splitlines()) + b"]")
        rows[-1]["prev"] = "e" * 64
        rows[-1].pop("signature")
        from azazel_edge.outcome.journal import _json

        rows[-1]["signature"] = KEYS[2].sign(ANCHOR_DOMAIN + _json(rows[-1])).hex()
        value["anchors_raw"] = b"".join(wire(row) for row in rows)
        value["arguments"]["expected_anchor_checkpoint"] = anchor_checkpoint(
            value["anchors_raw"]
        )
    result = verify(value)
    assert result["source_prefix_authenticated"] is True
    assert result["witness_prefix_authenticated"] is False
    assert_unqualified(result)


@pytest.mark.parametrize("field", ["boot_ref", "session_ref"])
def test_external_context_mismatch_does_not_authenticate(tmp_path, field):
    value = make_witness_case(tmp_path)
    value["arguments"]["expected_context"][field] = "a" * 32
    result = verify(value)
    assert result["source_prefix_authenticated"] is False
    assert result["witness_prefix_authenticated"] is False


@pytest.mark.parametrize("field", ["head", "sha256", "size", "counter"])
def test_independent_anchor_checkpoint_mismatch(tmp_path, field):
    value = make_witness_case(tmp_path)
    checkpoint = value["arguments"]["expected_anchor_checkpoint"]
    checkpoint[field] = (
        "e" * 64 if field in ("head", "sha256") else checkpoint[field] + 1
    )
    assert verify(value)["witness_prefix_authenticated"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("counter", True),
        ("size", -1),
        ("head", "E" * 64),
        ("sha256", "x"),
        ("extra", 1),
    ],
)
def test_invalid_global_checkpoint_raises(tmp_path, field, value):
    fixture = make_witness_case(tmp_path)
    fixture["arguments"]["expected_anchor_checkpoint"][field] = value
    with pytest.raises(SourceWitnessInputError):
        verify(fixture)


@pytest.mark.parametrize(
    "kind", ["pretty", "duplicate_key", "partial", "deep", "oversize"]
)
def test_original_anchor_framing_is_strict(tmp_path, kind):
    value = make_witness_case(tmp_path)
    if kind == "pretty":
        raw = json.dumps(value["rows"][0], indent=2).encode() + b"\n"
    elif kind == "duplicate_key":
        raw = wire(value["rows"][0]).replace(b'"counter":1', b'"counter":1,"counter":1')
    elif kind == "partial":
        raw = value["valid_anchors"][:-1]
    elif kind == "deep":
        raw = b"[" * 1001 + b"0" + b"]" * 1001 + b"\n"
    else:
        raw = b" " * 8193 + b"\n"
    value["anchors_raw"] = raw
    value["arguments"]["expected_anchor_checkpoint"].update(
        size=len(raw), sha256=digest(raw)
    )
    assert verify(value)["witness_prefix_authenticated"] is False


def test_pure_no_files_network_private_keys_or_mutation(tmp_path):
    value = make_witness_case(tmp_path)
    before = deepcopy(value["arguments"])
    with (
        patch("builtins.open", side_effect=AssertionError("I/O")),
        patch("os.open", side_effect=AssertionError("I/O")),
        patch("socket.socket", side_effect=AssertionError("network")),
    ):
        assert verify(value)["witness_prefix_authenticated"] is True
    assert value["arguments"] == before


def test_frozen_case_ids_are_covered():
    rows = json.loads(
        (
            Path(__file__).parent / "fixtures/source-witness-prefix/v1/cases.json"
        ).read_bytes()
    )["cases"]
    assert len(rows) == 24
    assert sum(row["evidence"] == "actual_linux" for row in rows) == 2


@pytest.mark.parametrize(
    "kind", ["trust_pin", "context_bool", "source_checkpoint_bool", "anchors_type"]
)
def test_invalid_global_inputs_do_not_become_diagnostics(tmp_path, kind):
    value = make_witness_case(tmp_path)
    if kind == "trust_pin":
        value["arguments"]["expected_trust_sha256"] = "e" * 64
    elif kind == "context_bool":
        value["arguments"]["expected_context"]["producer_uid"] = True
    elif kind == "source_checkpoint_bool":
        value["arguments"]["expected_source_checkpoint"]["seq"] = True
    else:
        value["anchors_raw"] = "not bytes"
    with pytest.raises(SourceWitnessInputError):
        verify(value)


def test_missing_source_checkpoint_cannot_be_supplied_by_signed_anchor(tmp_path):
    value = make_witness_case(tmp_path)
    value["arguments"]["expected_source_checkpoint"] = None
    result = verify(value)
    assert result["source_prefix_authenticated"] is False
    assert result["witness_prefix_authenticated"] is False


def test_invalid_source_signature_cannot_be_supplied_by_witness(tmp_path):
    value = make_witness_case(tmp_path)
    row = json.loads(value["source"]["valid_prefix"])
    row["signature"] = "0" * 128
    value["source_raw"] = wire(row)
    result = verify(value)
    assert result["source_prefix_authenticated"] is False
    assert result["witness_prefix_authenticated"] is False
