"""Current Root-only lab material checks, not installation or role admission.

External Root archive verification authenticates the source. Hashes returned here
are observations to compare with that frozen plan, not self-authenticating JSON.
No imported old receipt, key, actor, policy load or trial is accepted/created.
"""

import hashlib
import os
from pathlib import Path
import re

import signed_network_telemetry_contract as role
import telemetry_isolation_preflight as preflight
from azazel_edge.outcome.input_auth import read_regular

SRC = Path(__file__).resolve().parents[2]
SOURCE_POLICY = SRC / "tests/real_systemd/edge400-observer-telemetry-lab.apparmor"
INSTALLED_POLICY = Path("/etc/apparmor.d") / role.PROFILE
FLAG = "EDGE_SIGNED_NETWORK_TELEMETRY"
SOURCE_FILES = (
    "signed_network_telemetry_phase.py",
    "signed_network_telemetry_switch_witness.py",
    "signed_network_telemetry_transport.py",
    "signed_network_plan.py",
    "signed_network_telemetry_contract.py",
    "signed_network_telemetry_binding.py",
    "signed_network_telemetry_material.py",
    "signed_network_telemetry_proof.py",
    "signed_network_telemetry_initialize.py",
    "signed_network_telemetry_commission_setup.py",
    "signed_network_telemetry_marker.py",
    "signed_network_telemetry_namespaces.py",
    "signed_network_telemetry_commission.py",
    "signed_network_telemetry_negative.py",
    "signed_network_telemetry_fault.py",
    "signed_network_telemetry_refusal.py",
    "signed_network_telemetry_live.py",
    "signed_network_observer.py",
    "telemetry_isolation_contract.py",
    "telemetry_isolation_preflight.py",
    "telemetry_isolation_result.py",
    "telemetry_preflight.py",
    "terminal_cgroup.py",
)


def pin(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("mandatory external lowercase SHA256 pin required")
    return value


def source_paths():
    return [SRC / "tests/real_systemd" / name for name in SOURCE_FILES] + [
        SOURCE_POLICY,
        *(
            SRC / "py/azazel_edge/outcome" / (name + ".py")
            for name in (
                "service_switch",
                "input_transport",
                "input_auth",
                "input_witness",
                "input_service",
                "input_live",
                "input_resume",
                "input_terminal",
            )
        ),
    ]


def source_hashes():
    """Plan construction on Root's verified source checkout; not guest proof."""
    return {
        str(path.relative_to(SRC)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source_paths()
    }


def _read(path, limit=1024 * 1024, mode=None):
    return read_regular(path, owner=0, mode=mode, max_bytes=limit)[0]


def verify_current(*, abi_sha256, interpreter_sha256):
    """Read-only prerequisites BEFORE output/keys/actors; pins are external inputs.

    This helper does not establish VM freshness or effective actor confinement.
    Those remain separate caller gates. The old v6 receipt is never an input.
    """
    pin(abi_sha256)
    pin(interpreter_sha256)
    preflight.lab.need(
        os.geteuid() == 0 and os.environ.get(FLAG) == "1",
        "explicit Root new-role opt-in required",
    )
    interpreter = _read(
        preflight.old.g.PYTHON.resolve(strict=True), 64 * 1024 * 1024, 0o755
    )
    alias = _read(Path(role.ALIAS), 64 * 1024 * 1024, 0o755)
    policy = _read(SOURCE_POLICY)
    abi = _read(preflight.ABI, 65536)
    sources = {
        str(path.relative_to(SRC)): hashlib.sha256(_read(path)).hexdigest()
        for path in source_paths()
    }
    masks = {
        name: preflight.cg._kernel_text(path, 4096)
        for name, path in preflight.FEATURES.items()
    }
    loaded = preflight.cg._kernel_text(
        "/sys/kernel/security/apparmor/profiles", 256 * 1024
    )
    preflight.lab.need(
        alias == interpreter
        and hashlib.sha256(interpreter).hexdigest() == interpreter_sha256
        and _read(INSTALLED_POLICY) == policy
        and sources[str(SOURCE_POLICY.relative_to(SRC))]
        == hashlib.sha256(policy).hexdigest()
        and hashlib.sha256(abi).hexdigest() == abi_sha256
        and "userns_create" in masks["namespaces"].split()
        and {"read", "trace"} <= set(masks["ptrace"].split())
        and [
            line
            for line in loaded.splitlines()
            if line.split(" (", 1)[0] == role.PROFILE
            or line.startswith(role.PROFILE + "//")
        ]
        == [role.PROFILE + " (enforce)"],
        "current protected telemetry material/feature/label differs",
    )
    return dict(
        role=role.ROLE,
        abi_sha256=abi_sha256,
        interpreter_sha256=interpreter_sha256,
        source_sha256=sources,
        feature_masks=masks,
        loaded_profiles=loaded,
        authorizes_transition=False,
        experiment=False,
        production_admission=False,
    )


def compile_current(output, *, abi_sha256, interpreter_sha256):
    """Retain a current Werror compile ONLY, at an existing protected output.

    Never loads policy, installs aliases, repairs files or authorizes API access.
    The caller must run this before any keys/actors, after independent freshness.
    """
    before = verify_current(
        abi_sha256=abi_sha256, interpreter_sha256=interpreter_sha256
    )
    output = Path(output)
    preflight._output(output)
    preflight.lab.save_json(output / "telemetry-material-before.json", before)
    preflight.lab.save(output / "telemetry-policy.raw", _read(SOURCE_POLICY))
    preflight.lab.save(output / "telemetry-abi4.raw", _read(preflight.ABI, 65536))
    code, binary = preflight.old._retained_query(
        [
            "apparmor_parser",
            "--skip-kernel-load",
            "--skip-cache",
            "--stdout",
            "--warn=all",
            "--Werror",
            str(SOURCE_POLICY),
        ],
        "telemetry-compile",
        output,
    )
    after = verify_current(abi_sha256=abi_sha256, interpreter_sha256=interpreter_sha256)
    preflight.lab.save_json(output / "telemetry-material-after.json", after)
    preflight.lab.need(
        code == 0
        and 0 < len(binary) <= 1024 * 1024
        and _read(output / "telemetry-compile.stderr") == b""
        and before == after,
        "current telemetry compilation failed/warned/material drift",
    )
    return before
