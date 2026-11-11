"""Pure fixed contract checks; no alias, unit, worker, policy or VM is created."""

from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_contract as c
import telemetry_isolation_contract as old
from signed_network_plan import names


def test_fixed_new_specs_match_actual_manual_assets_names_and_keep_full_runtime():
    assert tuple(names().values()) == c.NAMESPACE_NAMES
    assert c.NSFS_TARGETS == tuple("/run/netns/" + value for value in names().values())
    for mode, unit in (("initialize", c.INITIALIZER_UNIT), ("live", c.OBSERVER_UNIT)):
        spec = c.observer_spec(mode)
        assert spec["unit"] == unit and spec["role"] == "telemetry_lab_v2"
        assert spec["namespace"] == names()["edge"]
        assert spec["properties"] == dict(
            User="edge400-observer",
            Group="edge400-observer",
            AppArmorProfile=c.PROFILE,
            CapabilityBoundingSet="",
            AmbientCapabilities="",
            NoNewPrivileges="yes",
            RestrictAddressFamilies="AF_UNIX",
            Restart="no",
            DefaultDependencies="no",
            RuntimeMaxSec="40",
            TimeoutStopSec="5",
            ProtectProc="ptraceable",
            ProcSubset="all",
            MountAPIVFS="yes",
            NetworkNamespacePath="/run/netns/" + names()["edge"],
        )
        assert "argv" not in spec and "ExecStart" not in spec["properties"]
        assert json.loads(json.dumps(spec)) == spec
    assert c.INITIALIZER_UNIT != c.OBSERVER_UNIT
    assert not ({c.INITIALIZER_UNIT, c.OBSERVER_UNIT} & {unit for unit, _ in old.ROLES.values()})


def test_exact_protocol_markers_are_not_readiness_or_authority():
    spec = c.observer_spec("initialize")
    assert spec["alias"] == old.ALIAS and spec["properties"]["AppArmorProfile"] == old.PROFILE
    assert spec["source"] == "/opt/edge400-src/tests/real_systemd/signed_network_observer.py"
    assert spec["cli_flag"] == "--telemetry-lab-v2"
    assert spec["protocol"] == dict(
        ready_kind="signed_observer_pre_api_ready", go_ascii="continue-authenticated-api\n"
    )
    assert c.GO == b"continue-authenticated-api\n"
    assert not {"input_ready", "qualified", "admitted", "measurement_completed", "ready"} & set(spec)


@pytest.mark.parametrize("mode", [None, True, 1, "probe", "peer", "legacy", "live ", "../live", "", ["live"]])
def test_unknown_modes_have_no_fallback(mode):
    with pytest.raises(ValueError):
        c.observer_spec(mode)


def test_specs_are_independent_and_cannot_modify_legacy_precheck_defaults():
    before = deepcopy(old.ROLES)
    spec = c.observer_spec("live")
    spec["properties"]["AppArmorProfile"] = "unconfined"
    spec["nsfs_targets"].append("/run/netns/foreign")
    spec["protocol"]["go_ascii"] = "fake\n"
    assert c.observer_spec("live")["properties"]["AppArmorProfile"] == c.PROFILE
    assert c.observer_spec("live")["nsfs_targets"] == list(c.NSFS_TARGETS)
    assert c.observer_spec("live")["protocol"]["go_ascii"] == c.GO.decode()
    assert old.ROLES == before
    with pytest.raises(TypeError):
        c.observer_spec("live", profile="unconfined")


@pytest.mark.parametrize("target", c.NSFS_TARGETS)
def test_legacy_precheck_proc_view_does_not_gain_manual_namespace_targets(target):
    raw = (
        "1 0 8:1 / / rw - ext4 /dev/root rw\n"
        "30 1 0:4 / /proc rw - proc proc rw,hidepid=ptraceable\n"
        f"40 1 0:5 net:[123] {target} rw - nsfs nsfs rw\n"
    )
    with pytest.raises(ValueError, match="namespace mount"):
        old.validate_proc_view(raw, own_mount_ns=(4, 10), pid1_mount_ns=(4, 11), proc_device=(0, 4))
