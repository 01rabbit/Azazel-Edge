"""Real sealed ELF failure boundary. Enforcing success is mandatory in VM CI."""

import fcntl
import hashlib
import os
import subprocess
from unittest.mock import patch
import pytest
from test_outcome_live_origin_linux import register_live
from test_outcome_input_auth_linux import Fixture
from azazel_edge.outcome.input_auth import TrustPolicy, _json
from azazel_edge.outcome.input_live import launch

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or not hasattr(os, "memfd_create"),
    reason="isolated Linux root required",
)


@pytest.fixture
def live():
    f = Fixture()
    try:
        register_live(f)
        yield f
    finally:
        f.clean()


@pytest.mark.parametrize(
    "command",
    [
        "--health",
        "--version",
        "--capture-origin-once",
        "--release-ledger-status",
        "--release-ledger-compact",
        None,
    ],
)
@pytest.mark.parametrize("seals", [0, 1, 7, 15])
def test_unavailable_profile_never_reaches_any_command_or_configuration(
    live, command, seals
):
    f = live
    image = os.memfd_create("edge-live-origin", os.MFD_ALLOW_SEALING)
    try:
        os.write(image, f.binary.read_bytes())
        os.fchmod(image, 0o500)
        if seals:
            fcntl.fcntl(image, fcntl.F_ADD_SEALS, seals)
        before = f.source.read_bytes()
        target = f.root / "must-not-create-state"
        result = subprocess.run(
            [
                f"/proc/self/fd/{image}",
                "--native-apparmor-profile",
                "edge400-unregistered-profile",
                *([command] if command else []),
            ],
            pass_fds=(image,),
            input=b"{}\n",
            capture_output=True,
            timeout=5,
            env={
                "AZAZEL_DEFENSE_RELEASE_LEDGER": str(target / "ledger"),
                "AZAZEL_NORMALIZED_EVENT_LOG": str(target / "log"),
            },
        )
        assert result.returncode == 3, result.stderr
        assert result.stdout == b""
        assert not target.exists() and f.source.read_bytes() == before
    finally:
        os.close(image)


def test_mutable_disk_health_cannot_claim_native_confinement(live):
    result = subprocess.run(
        [str(live.binary), "--health", "--native-apparmor-profile", "edge400-native"],
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 3 and result.stdout == b""


def test_direct_launch_refuses_native_preflight_before_signing_session(live):
    import sys
    import json

    f = live
    r = json.loads(f.registration.read_bytes())
    r.update(
        schema_version="outcome-live-origin-registration/v4",
        ai_socket_uid=0,
        capture_apparmor_profile="edge400-capture",
        native_apparmor_profile="edge400-unregistered-profile",
    )
    data = _json(r)
    f.registration.write_bytes(data)
    f.p = TrustPolicy(
        {
            **dict(f.p.data),
            "origin_registration_sha256": hashlib.sha256(data).hexdigest(),
        }
    )
    f.policy_file.write_bytes(_json(dict(f.p.data)))
    before = f.source.read_bytes()
    # Isolate native failure from the independently kernel-tested signer gate.
    with (
        patch(
            "azazel_edge.outcome.confinement.capture_image",
            return_value=(sys.executable, {}),
        ),
        pytest.raises(OSError, match="native AppArmor preflight"),
    ):
        launch(f.policy_file, f.registration, f.pk, "native-test-boot")
    assert f.source.read_bytes() == before


def test_sealed_image_cannot_be_written_resized_or_unsealed(live):
    import errno
    import json
    from azazel_edge.outcome.input_live import sealed_image

    r = json.loads(live.registration.read_bytes())
    fd = sealed_image(r)
    try:
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) == 15
        size = os.fstat(fd).st_size
        for operation in [
            lambda: os.write(fd, b"x"),
            lambda: os.ftruncate(fd, 0),
            lambda: os.ftruncate(fd, size + 1),
            lambda: fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 0),
        ]:
            with pytest.raises(OSError) as failure:
                operation()
            assert failure.value.errno == errno.EPERM
        os.lseek(fd, 0, os.SEEK_SET)
        assert hashlib.sha256(os.read(fd, size)).hexdigest() == r["binary_sha256"]
    finally:
        os.close(fd)


def test_native_public_enrollment_is_readonly_and_cannot_omit_signer(live):
    import json
    from azazel_edge.outcome.input_live_enroll import prepare

    f = live
    d = dict(f.p.data)
    d.pop("origin_registration_sha256")
    d["schema_version"] = "outcome-input-trust/v1"
    template = TrustPolicy(d)
    environment = json.loads(f.registration.read_bytes())["environment"]
    before = {
        path: path.read_bytes()
        for path in [f.registration, f.policy_file, f.source, f.pk]
    }
    candidate = prepare(
        template,
        f.binary,
        environment,
        capture_apparmor_profile="edge400-capture",
        native_apparmor_profile="edge400-native",
    )
    assert (
        candidate["registration"]["schema_version"]
        == "outcome-live-origin-registration/v4"
    )
    assert all(path.read_bytes() == raw for path, raw in before.items())
    with pytest.raises(OSError, match="requires registered capture"):
        prepare(
            template, f.binary, environment, native_apparmor_profile="edge400-native"
        )
