"""Synthetic actor/setup/role facts; real fault file IO and signature verifier.

No VM, systemd, native process, key provisioning, LSM or witness server runs.
"""

from contextlib import contextmanager
from pathlib import Path
import os
import sys
from types import SimpleNamespace

import pytest
from azazel_edge.outcome.input_auth import SourceVerifier
from azazel_edge.outcome.journal import OutcomeJournalError

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_refusal as controller
from test_signed_network_telemetry_fault import fixture as fault_fixture, retained_live, BOOT


@pytest.fixture
def tmp_path():
    import tempfile

    with tempfile.TemporaryDirectory(prefix="refusal-", dir="/tmp") as directory:
        yield Path(directory).resolve()


def fixture(tmp_path, monkeypatch, fault=None):
    root, fault_output, live_output, trust, initialized = fault_fixture(
        tmp_path, monkeypatch
    )
    fault_output.rmdir()
    live_output.rmdir()
    events = []
    main = controller.main
    monkeypatch.setattr(
        main.WitnessProof,
        "sample_namespace",
        lambda self: dict(cookie=71, kernel_boot_id=BOOT),
    )

    class SyntheticSystemd:
        def cores(self):
            return []

        def witness(self, *args):
            raise AssertionError("negative fixture must never invoke sealed Switch")

    monkeypatch.setattr(controller.g, "Systemd", SyntheticSystemd)
    monkeypatch.setattr(controller.g, "BASE", tmp_path / "scope")
    monkeypatch.setattr(controller.g, "UNITS", tmp_path / "units")
    controller.g.UNITS.mkdir()
    monkeypatch.setattr(controller.g, "ENV", dict(controller.g.ENV))
    monkeypatch.setattr(controller.material, "SRC", Path("/opt/edge400-src"))
    current = initialized["binding"]["material"]
    key = str(Path(controller.setup.role.SOURCE).relative_to(controller.material.SRC))
    current["source_sha256"][key] = "d" * 64
    initialized["proof"]["actor"] = dict(
        evidence=dict(before={"synthetic-init-unit": True})
    )
    pins = dict(
        source_commit="a" * 40,
        archive_sha256="b" * 64,
        core_sha256="c" * 64,
        abi_sha256="a" * 64,
        interpreter_sha256="b" * 64,
    )
    baseline = dict(
        pins=pins,
        kernel_boot_id=initialized["binding"]["kernel_boot_id"],
        material=current,
    )

    def preflight(output, **actual):
        events.append("preflight")
        assert output == tmp_path and actual == pins
        return baseline

    monkeypatch.setattr(controller.setup, "preflight", preflight)
    monkeypatch.setattr(
        controller.material.preflight.old,
        "private_output",
        lambda path: path.mkdir(mode=0o700),
    )

    class Namespace:
        failed = False

        def __init__(self, output, value):
            assert output == tmp_path and value is baseline

        def prepare(self):
            events.append("ns-prepare")
            if fault == "prepare":
                self.failed = True
                raise RuntimeError("synthetic NS failure")

        def edge(self):
            events.append("ns-fence")
            return 99, [5, 20]

        def close(self):
            events.append("ns-close")
            return dict(
                cleanup_verified=not self.failed and fault != "namespace-cleanup",
                errors=["synthetic unknown"] if fault == "namespace-cleanup" else [],
            )

    monkeypatch.setattr(main, "NamespaceSetup", Namespace)
    monkeypatch.setattr(main.plan.p, "configure", lambda: None)

    def initialize(output, **kwargs):
        events.append("init")
        assert kwargs["namespace_fd"] == 99 and kwargs["namespace_identity"] == [5, 20]
        if fault == "initialize":
            raise RuntimeError("synthetic initializer refusal")
        return initialized

    monkeypatch.setattr(main.initializer, "initialize", initialize)
    monkeypatch.setattr(main, "_base_created", lambda output: events.append("new-base"))

    def metadata(path, **kwargs):
        info = os.stat(path, **kwargs)
        return SimpleNamespace(
            st_uid=0,
            st_mode=info.st_mode,
            st_nlink=info.st_nlink,
            st_dev=info.st_dev,
            st_ino=info.st_ino,
        )

    monkeypatch.setattr(controller, "os", SimpleNamespace(stat=metadata, path=os.path))

    def provision():
        events.append("provision")
        controller.g.BASE.mkdir()
        controller.g.write(
            controller.g.UNITS / controller.g.UNIT, "[Service]\nExecStart=/unexecuted\n"
        )
        controller.g.write(
            controller.g.UNITS / controller.g.WITNESS,
            "[Service]\nType=notify\nNotifyAccess=main\nExecStart="
            + str(controller.g.PYTHON)
            + " -I -m azazel_edge.outcome.input_witness --policy "
            + str(controller.g.BUNDLE / "trust.json")
            + " --private-key "
            + str(controller.g.BUNDLE / "witness/key.raw")
            + " --systemd-notify --apparmor-profile edge400-witness\n",
        )
        events.append("witness-ready")
        controller.g.observer(True)

    monkeypatch.setattr(controller.g, "prepare_lab", provision)
    monkeypatch.setattr(
        controller.lab, "unit_snapshot", lambda unit: dict(MainPID="123")
    )
    reading = controller.material._read
    # Direct public policy fixture only; the real helper still checks TrustPolicy/layout.
    from azazel_edge.outcome.journal import _json

    def read(path, *args):
        if path == controller.g.BUNDLE / "trust.json":
            return _json(dict(trust.data))
        return reading(path, *args)

    monkeypatch.setattr(controller.material, "_read", read)
    monkeypatch.setattr(
        main,
        "registration",
        lambda public, path: dict(
            schema_version="outcome-live-origin-registration/v4",
            environment=controller.plan.native_environment("c0"),
            binary_sha256=pins["core_sha256"],
        ),
    )
    original_capture = controller.fault.capture_init
    original_inject = controller.fault.inject

    def capture(*args, **kwargs):
        events.append("capture")
        return original_capture(*args, **kwargs)

    def inject(*args, **kwargs):
        events.append("inject")
        value = original_inject(*args, **kwargs)
        fixture.snapshot = value
        return value

    monkeypatch.setattr(controller.fault, "capture_init", capture)
    monkeypatch.setattr(controller.fault, "inject", inject)

    @contextmanager
    def live(output, *, initialization, **kwargs):
        events.append("live")
        assert initialization is initialized and output == live_output
        yield SimpleNamespace(result=None)
        if fault == "accepted":
            return
        if fault == "generic":
            raise RuntimeError("unrelated worker error")
        # Real cryptographic refusal on actual appended fixture bytes.
        with pytest.raises(
            OutcomeJournalError, match="^authentication signature invalid$"
        ) as caught:
            SourceVerifier(trust).verify((root / "input").read_bytes())
        retained_live(live_output, fixture.snapshot)
        if fault == "drift":
            with (root / "observer/observations.journal").open("ab") as stream:
                stream.write(b"CHANGED")
        expected = AssertionError("actual live worker failed")
        if fault == "live-cleanup":
            expected.add_note("synthetic live cleanup error")
        raise expected from caught.value

    monkeypatch.setattr(main, "live", live)

    def no_native(*args, **kwargs):
        pytest.fail("negative controller MUST NOT start core/Switch/native/traffic")

    monkeypatch.setattr(controller.g, "systemctl", no_native)
    monkeypatch.setattr(controller.g, "Switch", no_native)
    monkeypatch.setattr(controller.g, "live", no_native)
    monkeypatch.setattr(controller.g, "stop", no_native)
    cleanup_units = []

    def cleanup(units, tracked):
        events.append("outer-cleanup")
        cleanup_units.extend(units)
        assert (
            units[-1:] == (controller.g.WITNESS,) if "witness-ready" in events else True
        )
        return dict(
            errors=["synthetic actor unknown"] if fault == "outer-cleanup" else []
        )

    monkeypatch.setattr(controller.lab, "cleanup", cleanup)
    saving = controller.lab.save_json

    def save(path, value):
        if path.name == "refusal-actor-cleanup.json" and fault == "cleanup-receipt":
            raise OSError("synthetic cleanup receipt failure")
        return saving(path, value)

    monkeypatch.setattr(controller.lab, "save_json", save)
    original = (
        controller.g.write,
        controller.g.prepare,
        controller.g.observer,
        dict(controller.g.ENV),
        controller.plan.p.a.NATIVE,
    )
    return pins, events, cleanup_units, original


def restored(original):
    assert (
        controller.g.write,
        controller.g.prepare,
        controller.g.observer,
        dict(controller.g.ENV),
        controller.plan.p.a.NATIVE,
    ) == original


def test_real_fault_helpers_compose_with_synthetic_witness_first_init_and_all_cleanup(
    tmp_path, monkeypatch
):
    pins, events, units, original = fixture(tmp_path, monkeypatch)
    result = controller.refuse_synthetic_input(tmp_path, **pins)
    assert result["status"] == "synthetic_input_refusal_complete"
    assert (
        result["authorizes_transition"]
        is result["experiment"]
        is result["production_admission"]
        is result["measurement_completed"]
        is False
    )
    assert (
        events.index("witness-ready")
        < events.index("init")
        < events.index("capture")
        < events.index("inject")
        < events.index("live")
        < events.index("outer-cleanup")
        < events.index("ns-close")
    )
    assert units[-1] == controller.g.WITNESS
    assert (tmp_path / "refusal-result.json").exists()
    assert (tmp_path / "fault/fault-refusal.json").exists()
    assert not (tmp_path / "live/live-result.json").exists()
    assert result["namespace_cleanup"]["cleanup_verified"] is True
    restored(original)


@pytest.mark.parametrize(
    "fault",
    [
        "prepare",
        "initialize",
        "accepted",
        "generic",
        "drift",
        "live-cleanup",
        "outer-cleanup",
        "namespace-cleanup",
        "cleanup-receipt",
    ],
)
def test_failure_or_cleanup_unknown_never_completes_case_and_restores_globals(
    tmp_path, monkeypatch, fault
):
    pins, events, units, original = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, ValueError, OSError, RuntimeError)):
        controller.refuse_synthetic_input(tmp_path, **pins)
    assert "outer-cleanup" in events and "ns-close" in events
    assert not (tmp_path / "refusal-result.json").exists()
    restored(original)
    if fault in ("outer-cleanup", "namespace-cleanup", "cleanup-receipt"):
        assert (
            tmp_path / "fault/fault-refusal.json"
        ).exists()  # Narrow refusal stays outer-pending.


def test_all_actual_controller_and_dependency_bytes_are_mandatory_source_pins():
    pins = controller.material.source_hashes()
    for name in (
        "signed_network_telemetry_refusal.py",
        "signed_network_telemetry_fault.py",
        "signed_network_telemetry_negative.py",
        "signed_network_telemetry_commission.py",
    ):
        assert "tests/real_systemd/" + name in pins
