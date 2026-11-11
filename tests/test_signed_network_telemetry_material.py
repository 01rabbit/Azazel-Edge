"""Synthetic Root/tool observations only; never actual policy/role commissioning."""

from copy import deepcopy
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_plan as plan
import signed_network_telemetry_contract as role
import signed_network_telemetry_material as material

ABI = b"PUBLIC synthetic ABI4\n"
IMAGE = b"PUBLIC synthetic installed interpreter\n"
PINS = dict(
    abi_sha256=hashlib.sha256(ABI).hexdigest(),
    interpreter_sha256=hashlib.sha256(IMAGE).hexdigest(),
)


def test_new_plan_is_exact_explicit_and_all_arm_configs_bind_fixed_role_and_pins():
    legacy, old_safety = plan.planned("a" * 40, "b" * 64)
    before = deepcopy(legacy)
    value, safety = plan.planned_telemetry(
        "a" * 40, "b" * 64, source_archive_sha256="e" * 64, **PINS
    )
    assert legacy == before and plan.planned("a" * 40, "b" * 64) == (before, old_safety)
    assert value["experiment_id"] == "signed-v4-network-telemetry-v2-" + "a" * 12
    assert value["experiment_id"] != legacy["experiment_id"] and safety == old_safety
    spec = value["measurement_binding"]["telemetry_lab"]
    assert spec["initialize"] == role.observer_spec("initialize")
    assert spec["live"] == role.observer_spec("live")
    assert spec["abi_sha256"] == PINS["abi_sha256"]
    assert spec["interpreter_sha256"] == PINS["interpreter_sha256"]
    assert spec["source_sha256"] == material.source_hashes()
    assert plan.validate_telemetry_manifest(value, "b" * 64) == safety
    assert len(value["assignments"]) == 4
    with pytest.raises(plan.BenefitInputError):
        plan.validate_manifest(value, "b" * 64)  # Legacy preparation cannot consume v2.
    for arm, old in zip(value["arms"], legacy["arms"]):
        assert arm["config_sha256"] != old["config_sha256"]
        assert arm["config_sha256"] == plan.manifest_digest(
            plan.arm_configuration(
                arm["id"],
                "b" * 64,
                value["measurement_binding"],
                value["observer_policy_sha256"],
                value["protected_policy_sha256"],
            )
        )


@pytest.mark.parametrize("name", list(PINS))
@pytest.mark.parametrize("bad", [None, True, 1, "A" * 64, "a" * 63, "x" * 64])
def test_external_constructor_pins_are_mandatory_exact_strings(name, bad):
    pins = dict(PINS, **{name: bad})
    with pytest.raises(ValueError):
        plan.planned_telemetry(
            "a" * 40, "b" * 64, source_archive_sha256="e" * 64, **pins
        )


def test_missing_external_pins_have_no_default_or_old_receipt_fallback():
    with pytest.raises(TypeError):
        plan.planned_telemetry("a" * 40, "b" * 64)
    with pytest.raises(TypeError):
        material.verify_current(receipt={"status": "new_role_precheck_complete"})


@pytest.mark.parametrize(
    "fault",
    [
        "label",
        "unit",
        "alias",
        "runtime",
        "pin",
        "helper",
        "unknown",
        "version",
        "typed",
    ],
)
def test_exact_new_manifest_refuses_any_role_material_or_version_substitution(fault):
    value, _ = plan.planned_telemetry(
        "a" * 40, "b" * 64, source_archive_sha256="e" * 64, **PINS
    )
    spec = value["measurement_binding"]["telemetry_lab"]
    if fault == "label":
        spec["live"]["properties"]["AppArmorProfile"] = "unconfined"
    elif fault == "unit":
        spec["initialize"]["unit"] = role.OBSERVER_UNIT
    elif fault == "alias":
        spec["live"]["alias"] += "-other"
    elif fault == "runtime":
        spec["live"]["properties"]["RuntimeMaxSec"] = "41"
    elif fault == "pin":
        spec["abi_sha256"] = True
    elif fault == "helper":
        spec["source_sha256"][next(iter(spec["source_sha256"]))] = "c" * 64
    elif fault == "unknown":
        spec["approved"] = True
    elif fault == "version":
        value["experiment_id"] = "signed-v4-network-telemetry-v3-" + "a" * 12
    else:
        value["measurement_binding"]["fresh_boots"] = 4.0
    before = deepcopy(value)
    with pytest.raises((ValueError, plan.BenefitInputError)):
        plan.validate_telemetry_manifest(value, "b" * 64)
    assert value == before


def observation_fixture(tmp_path, monkeypatch, fault=None):
    python = tmp_path / "python"
    python.write_bytes(IMAGE)
    monkeypatch.setattr(material.preflight.old.g, "PYTHON", python)
    monkeypatch.setattr(
        material,
        "os",
        SimpleNamespace(
            geteuid=lambda: 1 if fault == "uid" else 0,
            environ={material.FLAG: "0" if fault == "optin" else "1"},
        ),
    )
    reads = []

    def read(path, limit=1024 * 1024, mode=None):
        path = Path(path)
        reads.append(path)
        if fault == "protected" and path == Path(role.ALIAS):
            raise PermissionError("synthetic unsafe parent")
        if path == python or path == Path(role.ALIAS):
            assert limit == 64 * 1024 * 1024 and mode == 0o755
            return IMAGE + (
                b"changed" if fault == "alias" and path == Path(role.ALIAS) else b""
            )
        if path == material.preflight.ABI:
            return ABI + (b"changed" if fault == "abi" else b"")
        if path == material.INSTALLED_POLICY:
            return material.SOURCE_POLICY.read_bytes() + (
                b"changed" if fault == "policy" else b""
            )
        return path.read_bytes()

    monkeypatch.setattr(material, "_read", read)

    def kernel(path, limit):
        if path.endswith("profiles"):
            suffix = " (complain)\n" if fault == "label" else " (enforce)\n"
            return (
                role.PROFILE
                + suffix
                + (role.PROFILE + "//child (enforce)\n" if fault == "child" else "")
            )
        if path == material.preflight.FEATURES["namespaces"]:
            return "unrelated\n" if fault == "feature" else "userns_create\n"
        return "read\n" if fault == "ptrace" else "read trace\n"

    monkeypatch.setattr(material.preflight.cg, "_kernel_text", kernel)
    return reads


def test_current_root_material_is_independent_of_old_receipt_and_creates_nothing(
    tmp_path, monkeypatch
):
    reads = observation_fixture(tmp_path, monkeypatch)
    before = set(tmp_path.iterdir())
    result = material.verify_current(**PINS)
    assert set(tmp_path.iterdir()) == before
    assert result["source_sha256"] == material.source_hashes()
    assert (
        result["authorizes_transition"]
        is result["experiment"]
        is result["production_admission"]
        is False
    )
    assert material.INSTALLED_POLICY in reads and Path(role.ALIAS) in reads
    assert not any("key.raw" in str(p) for p in reads)


@pytest.mark.parametrize(
    "fault",
    [
        "uid",
        "optin",
        "alias",
        "policy",
        "abi",
        "label",
        "child",
        "feature",
        "ptrace",
        "protected",
        "interpreterpin",
    ],
)
def test_wrong_current_material_or_missing_kernel_fact_refuses(
    tmp_path, monkeypatch, fault
):
    reads = observation_fixture(tmp_path, monkeypatch, fault)
    pins = dict(PINS)
    if fault == "interpreterpin":
        pins["interpreter_sha256"] = "a" * 64
    with pytest.raises((ValueError, AssertionError, PermissionError)):
        material.verify_current(**pins)
    if fault in ("uid", "optin"):
        assert reads == []


@pytest.mark.parametrize(
    "fault", [None, "warning", "nonzero", "timeout", "empty", "drift"]
)
def test_current_compile_retains_originals_never_loads_and_rechecks_material(
    tmp_path, monkeypatch, fault
):
    observation_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(material.preflight, "_output", lambda path: None)
    invocations = []

    def query(argv, prefix, output):
        invocations.append(argv)
        assert argv == [
            "apparmor_parser",
            "--skip-kernel-load",
            "--skip-cache",
            "--stdout",
            "--warn=all",
            "--Werror",
            str(material.SOURCE_POLICY),
        ]
        assert prefix == "telemetry-compile"
        binary = b"" if fault == "empty" else b"PUBLIC synthetic compile result"
        code = None if fault == "timeout" else 1 if fault == "nonzero" else 0
        material.preflight.lab.save(output / (prefix + ".stdout"), binary)
        material.preflight.lab.save(
            output / (prefix + ".stderr"), b"warning" if fault == "warning" else b""
        )
        if fault == "drift":
            prior = material.verify_current

            def changed(**pins):
                value = prior(**pins)
                value["source_sha256"] = {"changed": "f" * 64}
                return value

            monkeypatch.setattr(material, "verify_current", changed)
        return code, binary

    monkeypatch.setattr(material.preflight.old, "_retained_query", query)
    if fault is None:
        assert material.compile_current(tmp_path, **PINS)["role"] == role.ROLE
    else:
        with pytest.raises(AssertionError):
            material.compile_current(tmp_path, **PINS)
    assert len(invocations) == 1
    for name in (
        "telemetry-material-before.json",
        "telemetry-material-after.json",
        "telemetry-policy.raw",
        "telemetry-abi4.raw",
        "telemetry-compile.stdout",
        "telemetry-compile.stderr",
    ):
        assert (tmp_path / name).exists()


@pytest.mark.parametrize("fault", ["missing", "changed"])
def test_reviewed_proof_module_is_real_mandatory_source_material(fault):
    path = material.SRC / "tests/real_systemd/signed_network_telemetry_proof.py"
    key = str(path.relative_to(material.SRC))
    value, _ = plan.planned_telemetry(
        "a" * 40, "b" * 64, source_archive_sha256="e" * 64, **PINS
    )
    sources = value["measurement_binding"]["telemetry_lab"]["source_sha256"]
    assert sources[key] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert (
        sources[key]
        == "8c72eb7901a31edd95de99f6412415446c251c148be81502c006664e9ea1c231"
    )
    if fault == "missing":
        del sources[key]
    else:
        sources[key] = "0" * 64
    with pytest.raises(plan.BenefitInputError):
        plan.validate_telemetry_manifest(value, "b" * 64)


@pytest.mark.parametrize("fault", ["missing", "changed"])
def test_actual_initializer_caller_is_mandatory_source_pin(fault):
    path = material.SRC / "tests/real_systemd/signed_network_telemetry_initialize.py"
    key = str(path.relative_to(material.SRC))
    value, _ = plan.planned_telemetry(
        "a" * 40, "b" * 64, source_archive_sha256="e" * 64, **PINS
    )
    sources = value["measurement_binding"]["telemetry_lab"]["source_sha256"]
    assert sources[key] == hashlib.sha256(path.read_bytes()).hexdigest()
    if fault == "missing":
        del sources[key]
    else:
        sources[key] = "0" * 64
    with pytest.raises(plan.BenefitInputError):
        plan.validate_telemetry_manifest(value, "b" * 64)


@pytest.mark.parametrize("fault", ["missing", "changed"])
def test_current_public_auth_binding_implementation_is_mandatory_source_pin(fault):
    path = material.SRC / "tests/real_systemd/signed_network_telemetry_binding.py"
    key = str(path.relative_to(material.SRC))
    value, _ = plan.planned_telemetry(
        "a" * 40, "b" * 64, source_archive_sha256="e" * 64, **PINS
    )
    sources = value["measurement_binding"]["telemetry_lab"]["source_sha256"]
    assert sources[key] == hashlib.sha256(path.read_bytes()).hexdigest()
    if fault == "missing":
        del sources[key]
    else:
        sources[key] = "0" * 64
    with pytest.raises(plan.BenefitInputError):
        plan.validate_telemetry_manifest(value, "b" * 64)


def test_current_manual_product_source_pins_include_used_switch_code():
    path = material.SRC / "py/azazel_edge/outcome/service_switch.py"
    assert path in material.source_paths()
    assert (
        material.source_hashes()[str(path.relative_to(material.SRC))]
        == hashlib.sha256(path.read_bytes()).hexdigest()
    )
