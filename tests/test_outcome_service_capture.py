"""Static single-unit profile contracts; no host manager or key operations."""

from pathlib import Path
import pytest
from azazel_edge.outcome.service_switch import profile, UNIT, digest


def test_profile_keeps_single_unit_and_explicit_stopping_semantics():
    body = profile(
        Path("/etc/azazel-edge/capture/b1"), Path("/opt/azazel-edge/venv/bin/python")
    ).decode()
    assert UNIT == "azazel-edge-core.service"
    assert "Restart=no\n" in body and "KillMode=mixed\n" in body
    assert "-I -m azazel_edge.outcome.service_entry" in body
    assert "--boot-ref %b" in body and "ExecStart=\n" in body
    assert "LD_PRELOAD" in body and "WantedBy" not in body
    assert "systemctl" not in body and "nft" not in body


@pytest.mark.parametrize(
    "path", ["relative", "/tmp/x%y", "/tmp/a b", "/tmp/a\nb", "/tmp/a/../b"]
)
def test_profile_paths_cannot_inject_unit_settings_or_specifiers(path):
    with pytest.raises(OSError):
        profile(Path(path), Path("/usr/bin/python3"))


def test_plan_digest_binds_nested_process_and_configuration_state():
    one = dict(
        before=dict(MainPID="1"),
        cores=[dict(environment={"AZAZEL_DEFENSE_ENFORCE": "false"})],
    )
    two = dict(before=dict(MainPID="2"), cores=one["cores"])
    assert digest(one) != digest(two)


def test_cutover_cannot_drop_custom_ttl_or_coerce_nonboolean_configuration():
    from azazel_edge.outcome.service_switch import _same_configuration

    with pytest.raises(OSError):
        _same_configuration(
            {"environment": {"AZAZEL_DEFENSE_ACTION_TTL_SEC": "50"}},
            {"environment": {}},
        )
    with pytest.raises(OSError):
        _same_configuration(
            {"environment": {"AZAZEL_DEFENSE_IFACE": "0"}},
            {"environment": {"AZAZEL_DEFENSE_IFACE": "false"}},
        )
    _same_configuration(
        {"environment": {"AZAZEL_DEFENSE_DRY_RUN": "true"}},
        {"environment": {"AZAZEL_DEFENSE_DRY_RUN": "1"}},
    )


def test_managed_start_cannot_bypass_proof_when_not_called_by_switch_controller():
    from unittest.mock import patch
    from azazel_edge.outcome import service_entry

    with patch.object(
        service_entry, "ready", side_effect=OSError("missing protected proof")
    ), patch.object(service_entry, "launch") as launch:
        assert (
            service_entry.main(["--bundle", "/unverified", "--boot-ref", "boot"]) == 1
        )
        launch.assert_not_called()
