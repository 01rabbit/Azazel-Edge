"""Real protected-file checks in an isolated Linux root fixture; no execution."""

import hashlib
import json
import os
import sys

import pytest

pytest.importorskip("cryptography")
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux root needed for protected public artifact boundaries",
)
from test_outcome_service_capture_linux import bundle, unprovisioned  # noqa: E402, F401
from azazel_edge.outcome import commission_precheck as check  # noqa: E402
from azazel_edge.outcome.input_auth import TrustPolicy  # noqa: E402
from azazel_edge.outcome.input_service import public_receipt  # noqa: E402
from azazel_edge.outcome.journal import _json  # noqa: E402


@pytest.fixture
def enrolled(bundle):  # noqa: F811
    f = bundle
    r = json.loads(f.registration.read_bytes())
    r.update(
        schema_version="outcome-live-origin-registration/v4",
        ai_socket_uid=0,
        capture_apparmor_profile="precheck-capture",
        native_apparmor_profile="precheck-native",
    )
    raw = _json(r)
    f.registration.write_bytes(raw)
    f.p = TrustPolicy(
        {**f.p.data, "origin_registration_sha256": hashlib.sha256(raw).hexdigest()}
    )
    f.policy_file.write_bytes(_json(dict(f.p.data)))
    (f.bundle / "provisioned.json").write_bytes(_json(public_receipt(f.bundle, f.p, r)))
    return f


def test_public_precheck_preserves_bytes_and_never_opens_private_keys(
    enrolled, monkeypatch
):
    f = enrolled
    before = {p: p.read_bytes() for p in f.bundle.rglob("*") if p.is_file()}
    real_open = os.open

    def guarded(path, flags, *args, **kwargs):
        assert str(path) != "key.raw", "PRECHECK attempted private-key access"
        assert flags & os.O_ACCMODE == os.O_RDONLY
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded)
    result = check.precheck(f.bundle, expected_trust_sha256=f.p.digest)
    assert result["authorizes_transition"] is False
    assert all(p.read_bytes() == raw for p, raw in before.items())
    assert {p for p in f.bundle.rglob("*") if p.is_file()} == set(before)


@pytest.mark.parametrize(
    "fault", ["symlink", "hardlink", "writable", "hash", "partial"]
)
def test_real_protected_artifact_faults_refuse_without_repair(enrolled, fault):
    f = enrolled
    if fault == "symlink":
        original = f.binary.with_name("original-core")
        f.binary.rename(original)
        f.binary.symlink_to(original)
    elif fault == "hardlink":
        os.link(f.binary, f.binary.with_name("extra-link"))
    elif fault == "writable":
        f.binary.chmod(0o777)
    elif fault == "hash":
        with f.binary.open("ab") as stream:
            stream.write(b"changed")
    else:
        (f.bundle / "provisioned.json").unlink()
    before = f.binary.read_bytes()
    with pytest.raises(OSError):
        check.precheck(f.bundle, expected_trust_sha256=f.p.digest)
    assert f.binary.read_bytes() == before
