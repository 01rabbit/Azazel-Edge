"""Actual original wrong-key/control path; expected UNKNOWN late-close binding."""

import json
import os
import sys
import uuid

import pytest

from common_event_binding_lab import Capture
import test_forged_input_refusal_v2_linux as original
from test_forged_input_refusal_v2_linux import fresh_prefix  # noqa: F401

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="mandatory trial requires isolated Linux Root and existing separate actor UIDs",
)


@pytest.fixture(scope="module")
def capture_group():
    return {"id": "actual-common-event-" + uuid.uuid4().hex, "scopes": set()}


@pytest.mark.parametrize("negative", [False, True], ids=["valid-control", "wrong-key"])
def test_original_actual_path_with_prospective_common_event_receipt(
    fresh_prefix,
    monkeypatch,
    capture_group,
    negative,  # noqa: F811
):
    capture = Capture(fresh_prefix, capture_group["id"], negative)
    scope = fresh_prefix[4]["expected_context"]["scope_ref"]
    assert scope not in capture_group["scopes"]
    capture_group["scopes"].add(scope)
    original_run, sealed, snapshot = (
        original._run,
        original._sealed_and_exported,
        original.snapshot,
    )
    failure = None
    try:
        with monkeypatch.context() as patch:
            patch.setattr(
                original,
                "_run",
                lambda fixture, script, **kwargs: capture.run(
                    original_run, original.PRODUCER, fixture, script, **kwargs
                ),
            )
            patch.setattr(
                original,
                "_sealed_and_exported",
                lambda *args: capture.sealed(sealed, *args),
            )
            patch.setattr(
                original,
                "snapshot",
                lambda *args, **kwargs: capture.snapshot(snapshot, *args, **kwargs),
            )
            original.test_actual_five_refusal_recipes(
                fresh_prefix, (None, {}), "wrong_key", negative
            )
        if negative:
            result = capture.evaluate()
            item = result["bindings"][0]
            assert item["status"] == "unknown", item
            assert (
                "main_complete_authenticated_channel_and_coverage_unavailable"
                in item["reasons"]
            )
            assert len(item["finite_layer_coverage"]) == 8
            assert all(
                layer["verified"] is True
                for layer in item["finite_layer_coverage"].values()
            )
            replay = result["composition_evaluation"]["supplemental_items"][0][
                "replayed_evaluation"
            ]
            assert replay == json.loads(capture.raw["original-evaluation.json"])
            assert replay["status"] == "recorded_refusal_consistent"
            assert result["qualified_safety_count"] is None
            assert result["comparison_eligibility"] is False
            assert all(value is False for value in result["authority_flags"].values())
            assert capture.report["actual_close_ns"] >= capture.report["frozen_end_ns"]
            plan = json.loads(capture.raw["original-plan.json"])
            receipt = json.loads(capture.raw["prelaunch-receipt.json"])
            assert receipt["saved_monotonic_ns"] <= plan["worker"]["started_ns"]
        else:
            state = json.loads(capture.raw["worker.stdout"])
            assert state["control_only"] is True
            assert capture.original is None and "main-contract.json" not in capture.raw
    except BaseException as error:
        failure = error
        raise
    finally:
        capture.export(failure)
