"""SYNTHETIC held-file/reader metadata; real signatures and unchanged evaluators.

No files are created. These mocks test propagation/fencing, not OS permissions,
which belong to the separate actual Linux sealed-intake tests.
"""

from copy import deepcopy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark import udp_payload_copy_collection as c
from safety_observation_data import digest, wire
from test_udp_payload_copy import fixture, capture

BOOT2 = "00000000-0000-4000-8000-000000000002"


def setup(monkeypatch, *, positive=True):
    contract, plan, pins, *_ = fixture(monkeypatch, positive)
    report = capture(contract, plan, pins)
    parsed = json.loads(contract)
    scope = parsed["scope"]
    paths = {
        name: Path("/synthetic-rootsealed") / (name + ".json")
        for name in (
            "enrollment",
            "contract",
            "observations",
            "checkpoint",
            "plan",
            "report",
        )
    }
    files = dict(contract=contract, plan=plan, report=report)
    files["observations"] = wire(
        dict(
            schema_version="edge-finite-safety-observations/v1",
            contract_sha256=digest(contract),
            scope=scope,
            channels={},
        )
    )
    files["checkpoint"] = wire(
        dict(
            schema_version="edge-safety-checkpoint/v1",
            contract_sha256=digest(contract),
            scope=scope,
            capture_ids={
                category: d["capture_id"] for category, d in parsed["channels"].items()
            },
            stream_heads=dict.fromkeys(parsed["channels"]),
        )
    )
    files["enrollment"] = wire(
        dict(
            schema_version="edge-safety-enrollment/v1",
            contract_sha256=digest(contract),
            scope=scope,
            observer_uid=scope["owner"]["observer_uid"],
            paths={
                name: str(paths[name])
                for name in ("contract", "observations", "checkpoint")
            },
        )
    )
    args = dict(
        expected_enrollment_sha256=digest(files["enrollment"]),
        expected_checkpoint_sha256=digest(files["checkpoint"]),
        expected_plan_sha256=digest(plan),
        expected_report_sha256=digest(report),
    )
    state = SimpleNamespace(
        uid=scope["owner"]["observer_uid"],
        boot=scope["kernel_boot_id"],
        fail_read=None,
        fail_verify=None,
        fail_close=None,
        instances=[],
        trace=[],
    )

    class SyntheticHeld:
        def __init__(self):
            self.number = len(state.instances)
            self.paths = []
            self.closed = []
            self.verifications = 0
            state.instances.append(self)

        def read(self, path, maximum):
            path = Path(path)
            self.paths.append(path)
            state.trace.append(("read", self.number, path))
            if state.fail_read == path:
                raise OSError("SYNTHETIC unsafe file metadata")
            raw = files[path.stem]
            assert len(raw) <= maximum
            return raw

        def verify(self):
            self.verifications += 1
            state.trace.append(("verify", self.number, self.verifications))
            if state.fail_verify == (self.number, self.verifications):
                raise OSError("SYNTHETIC retained inode/metadata changed")

        def close(self):
            errors = []
            for path in self.paths:
                self.closed.append(path)
                state.trace.append(("close", self.number, path))
                if state.fail_close == (self.number, path):
                    errors.append("SYNTHETIC close failed")
            return errors

    monkeypatch.setattr(c.collection, "_HeldFiles", SyntheticHeld)
    monkeypatch.setattr(c, "os", SimpleNamespace(geteuid=lambda: state.uid))
    monkeypatch.setattr(
        c.collection, "os", SimpleNamespace(geteuid=lambda: state.uid, fspath=os.fspath)
    )
    monkeypatch.setattr(c.collection, "_kernel_boot_id", lambda: state.boot)
    return paths, files, args, state


def collect(paths, args):
    return c.collect_udp_payload_copy(
        paths["enrollment"], paths["plan"], paths["report"], **args
    )


def all_closed(state):
    assert state.instances
    assert all(instance.closed == instance.paths for instance in state.instances)


@pytest.mark.parametrize("positive", [True, False])
def test_synthetic_six_held_files_real_evaluation_and_no_delivery_fill(
    monkeypatch, positive
):
    paths, files, args, state = setup(monkeypatch, positive=positive)
    original = deepcopy(files)
    result = collect(paths, args)
    outer, base = state.instances
    assert set(outer.paths) == set(paths.values()) and len(outer.paths) == 6
    assert set(base.paths) == {
        paths[name] for name in ("enrollment", "contract", "observations", "checkpoint")
    }
    assert outer.verifications == base.verifications == 2
    assert result["payload_copy"]["protocol_payload_copy_observed_count"] == (
        1 if positive else None
    )
    assert result["payload_copy"]["successful_syscall_count"] is None
    assert result["payload_copy"]["application_delivery_count"] is None
    assert result["payload_copy"]["qualified_safety_count"] is None
    assert all(
        category["observed_violation_count"] is None
        for category in result["collection"]["evaluation"]["categories"].values()
    )
    assert files == original
    all_closed(state)


@pytest.mark.parametrize("fault", ["reader", "root_reader", "bool_reader", "boot"])
def test_wrong_synthetic_reader_or_boot_refuses_composite(monkeypatch, fault):
    paths, files, args, state = setup(monkeypatch)
    if fault == "reader":
        state.uid += 1
    elif fault == "root_reader":
        state.uid = 0
    elif fault == "bool_reader":
        state.uid = True
    else:
        state.boot = BOOT2
    original = deepcopy(files)
    with pytest.raises(c.UDPPayloadCopyError):
        collect(paths, args)
    assert files == original
    all_closed(state)


@pytest.mark.parametrize("name", ["enrollment", "checkpoint", "plan", "report"])
def test_external_pin_failure_never_publishes_new_result(monkeypatch, name):
    paths, files, args, state = setup(monkeypatch)
    original = files["report"]
    args["expected_" + name + "_sha256"] = "e" * 64
    with pytest.raises(c.UDPPayloadCopyError):
        collect(paths, args)
    assert files["report"] == original
    all_closed(state)


@pytest.mark.parametrize(
    "name", ["enrollment", "contract", "observations", "checkpoint", "plan", "report"]
)
def test_synthetic_unsafe_metadata_on_any_held_input_stays_failure_and_closes(
    monkeypatch, name
):
    paths, files, args, state = setup(monkeypatch)
    state.fail_read = paths[name]
    original = deepcopy(files)
    with pytest.raises(c.UDPPayloadCopyError):
        collect(paths, args)
    assert files == original
    all_closed(state)


@pytest.mark.parametrize("instance,verification", [(0, 1), (0, 2), (1, 1), (1, 2)])
def test_initial_or_final_metadata_recheck_failure_blocks_return(
    monkeypatch, instance, verification
):
    paths, files, args, state = setup(monkeypatch)
    state.fail_verify = (instance, verification)
    with pytest.raises(c.UDPPayloadCopyError):
        collect(paths, args)
    assert ("verify", instance, verification) in state.trace
    all_closed(state)


@pytest.mark.parametrize("instance", [0, 1])
def test_close_failure_blocks_result_but_attempts_every_owned_close(
    monkeypatch, instance
):
    paths, files, args, state = setup(monkeypatch)
    state.fail_close = (instance, paths["enrollment"])
    original = files["report"]
    with pytest.raises(c.UDPPayloadCopyError, match="FD close"):
        collect(paths, args)
    assert files["report"] == original
    all_closed(state)
    assert len(state.instances) == 2


@pytest.mark.parametrize("field", ["uid", "boot"])
def test_reader_drift_after_real_evaluation_refuses_without_altering_published_bytes(
    monkeypatch, field
):
    paths, files, args, state = setup(monkeypatch)
    original = deepcopy(files)
    real = c.evaluate_udp_payload_copy
    calculated = []

    def evaluate(*a, **k):
        result = real(*a, **k)
        calculated.append(result)
        if field == "uid":
            state.uid += 1
        else:
            state.boot = BOOT2
        return result

    monkeypatch.setattr(c, "evaluate_udp_payload_copy", evaluate)
    with pytest.raises(c.UDPPayloadCopyError, match="UID/boot changed"):
        collect(paths, args)
    assert calculated[0]["protocol_payload_copy_observed_count"] == 1
    assert files == original
    all_closed(state)


def test_path_alias_refuses_before_duplicate_intake(monkeypatch):
    paths, files, args, state = setup(monkeypatch)
    with pytest.raises(c.UDPPayloadCopyError, match="six distinct"):
        c.collect_udp_payload_copy(
            paths["enrollment"], paths["contract"], paths["report"], **args
        )
    all_closed(state)
