"""Real signatures with SYNTHETIC witness assertions/ownership; not journal proof."""

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from azazel_edge.benchmark import witnessed_proofs as p
from azazel_edge.outcome.journal import _json
from safety_observation_data import digest, wire
from source_recovery_data import make_safety_proof_inputs
from test_safety_collection import SyntheticRootOS
from witnessed_proofs_data import anchors_for_source, make_witness_bundle


def witness_arguments(inputs):
    anchors, checkpoint = anchors_for_source(inputs["source"])
    plan = dict(
        schema_version="edge-source-witness-plan/v1",
        contract_sha256=digest(inputs["contract_raw"]),
        source_plan_sha256=inputs["arguments"]["expected_source_plan_sha256"],
        anchor_checkpoint=checkpoint,
    )
    raw = wire(plan)
    return dict(
        witness_plan_raw=raw,
        expected_witness_plan_sha256=digest(raw),
        anchors_raw=anchors,
    )


def evaluate(inputs, arguments):
    return p.evaluate_witnessed_safety_proofs(
        inputs["contract_raw"],
        inputs["observations_raw"],
        proof_arguments=inputs["arguments"],
        **arguments,
    )


def assert_positive_and_unchanged(inputs, result):
    original = p.proofs.evaluate_safety_proofs(
        inputs["contract_raw"], inputs["observations_raw"], **inputs["arguments"]
    )
    assert _json(result["base_evaluation"]) == _json(original)
    assert (
        result["base_evaluation"]["safety_evaluation"]["categories"][
            "forged_evidence_accepted"
        ]["observed_violation_count"]
        == 1
    )
    assert result["qualified_safety_count"] is None
    assert not any(result["authority_flags"].values())
    assert result["source_witness"]["journal_verified"] is False
    for flag in result["authority_flags"]:
        assert result[flag] is False


@pytest.mark.parametrize(
    "source_case", ["source_closed", "source_bad_suffix", "source_missing"]
)
def test_actual_bytes_composition_preserves_independent_positive(source_case, tmp_path):
    inputs = make_safety_proof_inputs(tmp_path, source_case)
    arguments = witness_arguments(inputs)
    before = (
        inputs["contract_raw"],
        inputs["observations_raw"],
        deepcopy(inputs["arguments"]),
        deepcopy(arguments),
    )
    result = evaluate(inputs, arguments)
    assert_positive_and_unchanged(inputs, result)
    assert result["source_witness"]["witness_prefix_authenticated"] is (
        source_case != "source_missing"
    )
    assert (
        inputs["contract_raw"],
        inputs["observations_raw"],
        inputs["arguments"],
        arguments,
    ) == before
    if source_case == "source_bad_suffix":
        assert (
            result["base_evaluation"]["source_authentication"]["authenticated_prefix"]
            is True
        )
        assert (
            result["base_evaluation"]["source_authentication"][
                "authenticated_full_source"
            ]
            is False
        )


@pytest.mark.parametrize(
    "fault",
    [
        "missing_plan",
        "missing_anchor",
        "missing_checkpoint",
        "bad_pin",
        "wrong_contract",
        "wrong_source_plan",
        "bad_signature",
        "bad_checkpoint",
        "extra",
        "deep",
        "malformed_checkpoint",
    ],
)
def test_optional_witness_failure_never_erases_unchanged_base_positive(tmp_path, fault):
    inputs = make_safety_proof_inputs(tmp_path)
    arguments = witness_arguments(inputs)
    plan = json.loads(arguments["witness_plan_raw"])
    if fault == "missing_plan":
        arguments.update(witness_plan_raw=None, expected_witness_plan_sha256=None)
    elif fault == "missing_anchor":
        arguments["anchors_raw"] = None
    elif fault == "bad_pin":
        arguments["expected_witness_plan_sha256"] = "e" * 64
    elif fault == "bad_signature":
        rows = [json.loads(line) for line in arguments["anchors_raw"].splitlines()]
        rows[-1]["signature"] = "00" * 64
        arguments["anchors_raw"] = b"".join(wire(row) for row in rows)
    elif fault == "deep":
        raw = b'{"nested":' + b"[" * 1001 + b"0" + b"]" * 1001 + b"}\n"
        arguments.update(witness_plan_raw=raw, expected_witness_plan_sha256=digest(raw))
    else:
        if fault == "missing_checkpoint":
            plan["anchor_checkpoint"] = None
        elif fault == "wrong_contract":
            plan["contract_sha256"] = "e" * 64
        elif fault == "wrong_source_plan":
            plan["source_plan_sha256"] = "e" * 64
        elif fault == "bad_checkpoint":
            plan["anchor_checkpoint"]["head"] = "e" * 64
        elif fault == "extra":
            plan["approved"] = True
        else:
            plan["anchor_checkpoint"] = {
                "counter": [],
                "head": "0" * 64,
                "size": 1,
                "sha256": "0" * 64,
            }
        raw = wire(plan)
        arguments.update(witness_plan_raw=raw, expected_witness_plan_sha256=digest(raw))
    result = evaluate(inputs, arguments)
    assert_positive_and_unchanged(inputs, result)
    assert result["source_witness"]["witness_prefix_authenticated"] is False


def test_bad_unselected_anchor_tail_is_never_adopted(tmp_path):
    inputs = make_safety_proof_inputs(tmp_path, "source_bad_suffix")
    arguments = witness_arguments(inputs)
    original = deepcopy(arguments)
    arguments["anchors_raw"] += b'{"broken":'
    result = evaluate(inputs, arguments)
    assert_positive_and_unchanged(inputs, result)
    assert result["source_witness"]["witness_prefix_authenticated"] is True
    assert (
        result["source_witness"]["anchor_checkpoint"]
        == json.loads(original["witness_plan_raw"])["anchor_checkpoint"]
    )
    assert result["source_witness"]["raw_sha256"]["anchor_suffix"] == digest(
        b'{"broken":'
    )


def test_malformed_global_safety_pin_is_not_masked_by_optional_proof(tmp_path):
    inputs = make_safety_proof_inputs(tmp_path)
    arguments = witness_arguments(inputs)
    inputs["arguments"]["safety_pins"]["expected_contract_sha256"] = "e" * 64
    with pytest.raises(ValueError):
        evaluate(inputs, arguments)


def test_pure_composition_does_not_open_files_endpoints_or_processes(tmp_path):
    inputs = make_safety_proof_inputs(tmp_path, "source_bad_suffix")
    arguments = witness_arguments(inputs)

    def forbidden(*a, **k):
        raise AssertionError("pure verifier attempted I/O/action")

    with (
        patch("builtins.open", forbidden),
        patch("os.open", forbidden),
        patch("socket.socket", forbidden),
        patch("subprocess.Popen", forbidden),
    ):
        result = evaluate(inputs, arguments)
    assert_positive_and_unchanged(inputs, result)
    assert result["source_witness"]["witness_prefix_authenticated"] is True


def staged(tmp_path, monkeypatch):
    directory = tmp_path / "sealed"
    directory.mkdir()
    bundle = make_witness_bundle(directory)
    for name, raw in bundle["files"].items():
        bundle["paths"][name].write_bytes(raw)
        bundle["paths"][name].chmod(0o444)
    proxy = SyntheticRootOS(bundle, "complete")
    monkeypatch.setattr(p.collection, "os", proxy)
    monkeypatch.setattr(p.proofs, "os", proxy)
    monkeypatch.setattr(p, "os", proxy)
    monkeypatch.setattr(
        p.collection, "_kernel_boot_id", lambda: bundle["scope"]["kernel_boot_id"]
    )
    return bundle, proxy


def collect(bundle):
    return p.collect_witnessed_safety_proofs(
        bundle["paths"]["enrollment"],
        bundle["paths"]["supplement"],
        bundle["paths"]["witness_supplement"],
        **{
            key: bundle[key]
            for key in (
                "expected_enrollment_sha256",
                "expected_checkpoint_sha256",
                "expected_supplement_sha256",
                "expected_witness_supplement_sha256",
            )
        },
    )


def test_sealed_synthetic_intake_preserves_bytes_closes_all_fds_and_attests_no_journal(
    tmp_path, monkeypatch
):
    bundle, proxy = staged(tmp_path, monkeypatch)
    before = {
        name: path.read_bytes()
        for name, path in bundle["paths"].items()
        if path.exists()
    }
    base = p.proofs.collect_safety_proofs(
        bundle["paths"]["enrollment"],
        bundle["paths"]["supplement"],
        **{
            key: bundle[key]
            for key in (
                "expected_enrollment_sha256",
                "expected_checkpoint_sha256",
                "expected_supplement_sha256",
            )
        },
    )
    result = collect(bundle)
    assert _json(result["base_collection"]) == _json(base)
    assert result["source_witness"]["witness_prefix_authenticated"] is True
    assert (
        result["source_witness"]["journal_verified"] is False
        and result["qualified_safety_count"] is None
    )
    assert not any(result["authority_flags"].values())
    assert before == {
        name: path.read_bytes()
        for name, path in bundle["paths"].items()
        if path.exists()
    }
    assert sorted(proxy.opened) == sorted(proxy.closed)


@pytest.mark.parametrize(
    "fault",
    [
        "pin",
        "mutated_anchors",
        "mode",
        "symlink",
        "alias",
        "close_failure",
        "unmatched_none",
    ],
)
def test_unsafe_new_supplement_never_returns_and_attempts_all_closes(
    tmp_path, monkeypatch, fault
):
    bundle, proxy = staged(tmp_path, monkeypatch)
    if fault == "pin":
        bundle["expected_witness_supplement_sha256"] = "e" * 64
    elif fault == "close_failure":
        original_close = proxy.close
        failed = []

        def fail_new_leg_close(fd):
            is_anchor = proxy.paths[fd] == bundle["paths"]["anchors"]
            original_close(fd)
            if is_anchor and not failed:
                failed.append(fd)
                raise OSError(
                    "synthetic NEW witness leg close failure after actual close"
                )

        proxy.close = fail_new_leg_close
    elif fault in ("alias", "unmatched_none"):
        path = bundle["paths"]["witness_supplement"]
        value = json.loads(path.read_bytes())
        if fault == "alias":
            value.update(
                anchors_path=str(bundle["paths"]["contract"]),
                anchors_sha256=digest(bundle["files"]["contract"]),
            )
        else:
            value["anchors_path"] = None
        path.chmod(0o644)
        path.write_bytes(wire(value))
        path.chmod(0o444)
        bundle["expected_witness_supplement_sha256"] = digest(path.read_bytes())
    else:
        path = bundle["paths"]["anchors"]
        if fault == "symlink":
            path.unlink()
            path.symlink_to(bundle["paths"]["contract"])
        elif fault == "mode":
            path.chmod(0o644)
        else:
            path.chmod(0o644)
            path.write_bytes(b"changed")
            path.chmod(0o444)
    with pytest.raises(p.collection.SafetyCollectionError):
        collect(bundle)
    if fault == "close_failure":
        assert len(failed) == 1
    assert sorted(proxy.opened) == sorted(proxy.closed)


@pytest.mark.parametrize("fault", ["uid", "boot"])
def test_immediate_base_reader_mismatch_refuses_before_new_held_reads(
    tmp_path, monkeypatch, fault
):
    provenance = dict(
        observer_uid=61002, kernel_boot_id="00000000-0000-4000-8000-000000000001"
    )
    monkeypatch.setattr(
        p.proofs, "collect_safety_proofs", lambda *a, **k: dict(provenance=provenance)
    )
    monkeypatch.setattr(
        p, "os", SimpleNamespace(geteuid=lambda: 61003 if fault == "uid" else 61002)
    )
    monkeypatch.setattr(
        p.collection,
        "_kernel_boot_id",
        lambda: "00000000-0000-4000-8000-000000000002"
        if fault == "boot"
        else provenance["kernel_boot_id"],
    )
    reads = []

    def forbidden(*args):
        reads.append(args)
        raise AssertionError("held read before reader context check")

    monkeypatch.setattr(p.collection._HeldFiles, "read", forbidden)
    with pytest.raises(p.collection.SafetyCollectionError):
        p.collect_witnessed_safety_proofs(
            tmp_path / "en",
            tmp_path / "sp",
            tmp_path / "ws",
            expected_enrollment_sha256="a" * 64,
            expected_checkpoint_sha256="b" * 64,
            expected_supplement_sha256="c" * 64,
            expected_witness_supplement_sha256="d" * 64,
        )
    assert reads == []


@pytest.mark.parametrize("missing", ["plan", "anchors"])
def test_enrolled_matched_none_witness_bytes_stay_unknown_without_losing_base(
    tmp_path, monkeypatch, missing
):
    bundle, proxy = staged(tmp_path, monkeypatch)
    path = bundle["paths"]["witness_supplement"]
    value = json.loads(path.read_bytes())
    value[missing + "_path"] = value[missing + "_sha256"] = None
    path.chmod(0o644)
    path.write_bytes(wire(value))
    path.chmod(0o444)
    bundle["expected_witness_supplement_sha256"] = digest(path.read_bytes())
    result = collect(bundle)
    assert result["source_witness"]["witness_prefix_authenticated"] is False
    assert (
        result["base_collection"]["evaluation"]["safety_evaluation"]["categories"][
            "forged_evidence_accepted"
        ]["observed_violation_count"]
        == 1
    )
    assert sorted(proxy.opened) == sorted(proxy.closed)


@pytest.mark.parametrize("fault", ["mutation", "uid", "boot"])
def test_post_witness_evaluation_fences_block_result_and_close_all(
    tmp_path, monkeypatch, fault
):
    bundle, proxy = staged(tmp_path, monkeypatch)
    original = p._witness
    changed = []
    if fault == "boot":
        monkeypatch.setattr(
            p.collection,
            "_kernel_boot_id",
            lambda: "00000000-0000-4000-8000-000000000002"
            if changed
            else bundle["scope"]["kernel_boot_id"],
        )

    def alter_after_verified_witness(*args, **kwargs):
        result = original(*args, **kwargs)
        assert result["witness_prefix_authenticated"] is True
        if fault == "mutation":
            path = bundle["paths"]["anchors"]
            path.chmod(0o644)
            path.write_bytes(path.read_bytes() + b" ")
            path.chmod(0o444)
        elif fault == "uid":
            proxy.case = "wrong-reader"
        changed.append(True)
        return result

    monkeypatch.setattr(p, "_witness", alter_after_verified_witness)
    with pytest.raises(p.collection.SafetyCollectionError):
        collect(bundle)
    assert changed == [True] and sorted(proxy.opened) == sorted(proxy.closed)
