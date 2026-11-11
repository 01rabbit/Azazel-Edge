"""Frozen test-only signed-network plan; no VM execution or provisioning."""

# ruff: noqa: E402
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path
import sys

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(SRC / "py"),
    str(SRC / "tests"),
    str(Path(__file__).resolve().parent),
]
import network_measure_driver as n
import provider as p
from azazel_edge.benchmark.benefit import BenefitInputError, manifest_digest

g = p.g
BASE_ENV = dict(g.ENV)
POLICY_PATH = SRC / "tests/fixtures/signed_network_observer_policy.json"
SERVICE_NS = "edge400-provider-service"
SCOPE = "v4_confined_fresh_vm_network_instrumentation_only"
VERSION = "signed-v4-network-v1"
INTERVAL = 0.25
PROTECTED = """protected_flows:
  version: 1
  entries:
    - {name: legit, role: management, network: 10.91.2.2/32}
    - {name: expert, role: expert_contact, network: 203.0.113.9/32}
  roles_not_applicable:
    - {role: mission, approved_by: closed-lab, reason: no mission asset in this isolated trial}
"""


def need(condition, message):
    if not condition:
        raise BenefitInputError(message)


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate artifact key")
            result[key] = value
        return result

    def finite(value):
        number = float(value)
        need(math.isfinite(number), "nonfinite artifact")
        return number

    def refuse(_):
        raise BenefitInputError("nonfinite artifact")

    return json.loads(
        raw, object_pairs_hook=pairs, parse_float=finite, parse_constant=refuse
    )


def native_environment(arm):
    need(arm in n.ARMS, "unknown fixed arm")
    return dict(
        BASE_ENV,
        AZAZEL_DEFENSE_ENFORCE="1" if arm == "flow_throttle" else "0",
        AZAZEL_DEFENSE_DRY_RUN="0",
        AZAZEL_DEFENSE_IFACE="es",
        AZAZEL_EVE_FROM_START="0",
        AZAZEL_REDIRECT_POLICY_PATH=str(g.BASE / "native/no-redirect.yaml"),
        AZAZEL_PROTECTED_FLOWS_PATH=str(g.BASE / "native/protected.yaml"),
        AZAZEL_DEFENSE_ENFORCE_LEVEL="full-auto",
        AZAZEL_DEFENSE_ACTION_TTL_SEC="30",
        AZAZEL_FORWARD_LOG="1",
    )


def arm_configuration(arm, core, binding, observer_sha, protected_sha):
    return dict(
        network_plan=n.plan(arm, core),
        binding=binding,
        native_environment=native_environment(arm),
        observer_policy=observer_sha,
        protected_policy=protected_sha,
    )


def configure_assignment(value, *, observer_initializer):
    # provider.configure captures raw_write for its template-stage files. This
    # wrapper MUST be installed first; a later wrapper misses those writes.
    original = g.write

    def protected_write(path, data, mode=0o644):
        if path == g.BASE / "native/protected.yaml":
            data = PROTECTED
        return original(path, data, mode)

    g.write = protected_write
    p.configure()
    expected = native_environment(value["assignment"]["arm"])
    g.ENV.clear()
    g.ENV.update(expected)
    g.observer = observer_initializer


def planned(source, core):
    value, safety = n.instrumentation_registration(source, core)
    value["experiment_id"] = VERSION + "-" + source[:12]
    value["scope"] = SCOPE
    value["observer_policy_sha256"] = hashlib.sha256(
        POLICY_PATH.read_bytes()
    ).hexdigest()
    value["protected_policy_sha256"] = hashlib.sha256(PROTECTED.encode()).hexdigest()
    value["measurement_binding"] = dict(
        registration="v4",
        native_profile="edge400-provider",
        capture_profile="edge400-capture",
        observer_profile="edge400-observer",
        interface="es",
        sample_seconds=INTERVAL,
        pre_seconds=1,
        post_seconds=2,
        fresh_boots=4,
        eve_from_start="0",
        observer_initialization="new_empty_scope_only",
    )
    for arm in value["arms"]:
        arm["environment_id"] = "independent_fresh_cold_boot_v4_vm"
        arm["config_sha256"] = manifest_digest(
            arm_configuration(
                arm["id"],
                core,
                value["measurement_binding"],
                value["observer_policy_sha256"],
                value["protected_policy_sha256"],
            )
        )
    for arm in value["arms"]:
        if arm["id"] == "c0":
            arm["role"] = "observe_only"
    old_safety = safety
    safety = {}
    for assignment in value["assignments"]:
        previous = assignment["id"]
        assignment["pair_id"] = "pair-" + assignment["pair_id"]
        assignment["id"] = assignment["pair_id"] + "-" + assignment["arm"]
        safety[assignment["id"]] = old_safety[previous]
    value["measurement_binding"].update(
        service_horizon_seconds=5,
        client_origin_offset_ns=1_250_000_000,
        root_probe="explicit_separate_operator_record_not_observer_authority",
    )
    for arm in value["arms"]:
        arm["config_sha256"] = manifest_digest(
            arm_configuration(
                arm["id"],
                core,
                value["measurement_binding"],
                value["observer_policy_sha256"],
                value["protected_policy_sha256"],
            )
        )
    # G5 compares this exact canonical telemetry policy, never a mixed config.
    value["provenance"]["policy_sha256"] = manifest_digest(
        strict(POLICY_PATH.read_bytes())
    )
    return value, safety


def validate_manifest(value, core):
    source = value["provenance"]["repo_commits"]["01rabbit/Azazel-Edge"]
    expected, safety = planned(source, core)
    need(value == expected, "exact frozen new signed experiment required")
    return safety


def order(manifest):
    return sorted(manifest["assignments"], key=lambda a: (a["pair_id"], a["order"]))


def names():
    return dict(edge=p.EDGE, client=p.CLIENT, service=SERVICE_NS)
