"""Actual isolated Linux Root/separate UID sockets; no systemd, LSM or VM claim."""

import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys

import pytest

from test_outcome_input_auth_linux import Fixture, Child, ROOT
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_transport import (
    transport,
    abstract_address,
    socket_namespace,
)
from azazel_edge.outcome import input_witness as w
from azazel_edge.outcome.journal import OutcomeJournalError, _json

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux Root required for real UID boundary",
)


@pytest.fixture
def f():
    value = Fixture()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unbound:
        namespace = socket_namespace(unbound)
    scope = "abstract-" + secrets.token_hex(12)
    value.p = TrustPolicy(
        dict(
            value.p.data,
            schema_version="outcome-input-trust/v4",
            scope_ref=scope,
            origin_registration_sha256="f" * 64,
            witness_transport=transport(scope, namespace),
        )
    )
    value.policy_file.write_bytes(_json(dict(value.p.data)))
    try:
        yield value
    finally:
        value.clean()


def client(f, script, uid=65534, policy=None):
    return subprocess.run(
        [sys.executable, "-c", script, str(policy or f.policy_file)],
        user=uid,
        group=uid,
        extra_groups=[],
        capture_output=True,
        text=True,
        timeout=10,
        env=dict(os.environ, PYTHONPATH=str(ROOT / "py")),
    )


def test_real_uid_signed_witness_close_reopens_same_history_without_pathname_touch(
    f, monkeypatch
):
    # An occupied unrelated filesystem object is deliberately irrelevant to v4.
    unused = Path(f.p.data["socket_path"])
    unused.write_bytes(b"untouched-pathname")
    monkeypatch.setattr(
        w,
        "retire_stale_endpoint",
        lambda *a: pytest.fail("abstract transport must never retire a pathname"),
    )
    f.start(initialize=True)
    child = Child(f, True)
    try:
        assert child.initial.get("ready"), child.initial
    finally:
        child.close()
    before = f.anchors.read_bytes(), f.journal.read_bytes(), f.source.read_bytes()
    f.halt()
    f.start()
    child = Child(f)
    try:
        assert child.initial.get("ready"), child.initial
    finally:
        child.close()
    assert unused.read_bytes() == b"untouched-pathname"
    assert (
        f.source.read_bytes() == before[2]
        and f.anchors.read_bytes().startswith(before[0])
        and f.journal.read_bytes().startswith(before[1])
    )


def test_actual_foreign_uid_is_refused_before_request_and_no_anchor_append(f):
    f.start(initialize=True)
    before = f.anchors.read_bytes()
    result = client(
        f,
        """
import sys,socket,json
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_transport import abstract_address
from azazel_edge.outcome.input_witness import send_message,recv_message
p=TrustPolicy(json.loads(Path(sys.argv[1]).read_bytes()))
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
 s.settimeout(1);s.connect(abstract_address(p,s));send_message(s,{'op':'read'});print(recv_message(s))
""",
        uid=1000,
    )
    assert result.returncode == 0, result.stderr
    assert (
        "continuity_unavailable" in result.stdout and f.anchors.read_bytes() == before
    )


@pytest.mark.parametrize("fault", ["wrong_peer_uid", "signature"])
def test_actual_observer_rejects_wrong_peer_or_response_signature(
    f, monkeypatch, fault
):
    if fault == "signature":
        original = w.send_message

        def changed(conn, value):
            if value.get("schema_version") == "outcome-input-witness-response/v1":
                value = dict(value, signature="0" * 128)
            return original(conn, value)

        monkeypatch.setattr(w, "send_message", changed)
    f.start(initialize=True)
    policy = f.policy_file
    if fault == "wrong_peer_uid":
        policy = f.root / "wrong-witness.json"
        policy.write_bytes(_json(dict(f.p.data, witness_uid=1)))
        policy.chmod(0o644)
    result = client(
        f,
        """
import sys
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_witness import WitnessClient
p=TrustPolicy.from_file(Path(sys.argv[1]),role='observer') if 'wrong-witness' not in sys.argv[1] else TrustPolicy(__import__('json').loads(Path(sys.argv[1]).read_bytes()))
WitnessClient(p).call('read')
""",
        policy=policy,
    )
    assert result.returncode != 0
    assert (
        "witness peer uid mismatch"
        if fault == "wrong_peer_uid"
        else "authentication signature invalid"
    ) in result.stderr


def test_occupied_abstract_address_refuses_without_retiring_or_replacing(
    f, monkeypatch
):
    monkeypatch.setattr(
        w, "retire_stale_endpoint", lambda *a: pytest.fail("no abstract takeover")
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as holder:
        address = abstract_address(f.p, holder)
        holder.bind(address)
        holder.listen(1)
        with pytest.raises(OSError):
            f.start(initialize=True)
        assert holder.getsockname() == address
        assert not Path(f.p.data["socket_path"]).exists()


def test_wrong_namespace_refuses_before_anchor_creation_or_filesystem_fallback(f):
    value = json.loads(_json(dict(f.p.data)))
    value["witness_transport"]["network_namespace"]["cookie"] += 1
    bad = TrustPolicy(value)
    with pytest.raises(OutcomeJournalError, match="network namespace mismatch"):
        w.serve(bad, f.wk, initialize=True)
    assert not f.anchors.exists() and not Path(f.p.data["socket_path"]).exists()
    f.policy_file.write_bytes(_json(value))
    result = client(
        f,
        """
import sys
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_witness import WitnessClient
WitnessClient(TrustPolicy.from_file(Path(sys.argv[1]),role='observer')).call('read')
""",
    )
    assert result.returncode != 0 and "network namespace mismatch" in result.stderr
    assert not f.anchors.exists() and not Path(f.p.data["socket_path"]).exists()


def test_explicit_public_preparation_and_provision_preserve_exact_v4_while_default_v3(
    f,
):
    from azazel_edge.outcome.input_service import prepare, provision, verify

    template = dict(f.p.data)
    template.pop("witness_transport")
    template.pop("origin_registration_sha256")
    template["schema_version"] = "outcome-input-trust/v1"
    template_file = f.root / "template.json"
    template_file.write_bytes(_json(template))
    template_file.chmod(0o644)
    # Only the structural ELF preparation check is exercised; no binary executes.
    binary = f.root / "never-executed-elf"
    binary.write_bytes(b"\x7fELFsynthetic-public-preparation-fixture")
    binary.chmod(0o755)
    environment = {
        "AZAZEL_" + key: str(f.root / key.lower())
        for key in (
            "EVE_PATH",
            "NORMALIZED_EVENT_LOG",
            "DEFENSE_RELEASE_LEDGER",
            "REDIRECT_POLICY_PATH",
            "PROTECTED_FLOWS_PATH",
        )
    }
    environment.update(
        {
            "AZAZEL_" + key: value
            for key, value in dict(
                FORWARD_AI="0",
                FORWARD_LOG="0",
                EVENT_STDOUT="off",
                DEFENSE_ENFORCE="0",
                DEFENSE_DRY_RUN="1",
                EVE_FROM_START="0",
            ).items()
        }
    )
    for key in (
        "EVE_PATH",
        "NORMALIZED_EVENT_LOG",
        "DEFENSE_RELEASE_LEDGER",
        "REDIRECT_POLICY_PATH",
        "PROTECTED_FLOWS_PATH",
    ):
        path = Path(environment["AZAZEL_" + key])
        path.write_bytes(b"")
        path.chmod(0o600)
    env_file = f.root / "environment.json"
    env_file.write_bytes(_json(environment))
    env_file.chmod(0o644)
    bundle = f.root / "new-bundle"
    legacy = prepare(bundle, template_file, binary, env_file)
    explicit = prepare(
        bundle,
        template_file,
        binary,
        env_file,
        witness_network_namespace=dict(
            f.p.data["witness_transport"]["network_namespace"]
        ),
    )
    assert (
        legacy["trust_policy"]["schema_version"] == "outcome-input-trust/v3"
        and "witness_transport" not in legacy["trust_policy"]
    )
    assert explicit["registration"] == legacy["registration"] and not bundle.exists()
    expected = dict(
        legacy["trust_policy"],
        schema_version="outcome-input-trust/v4",
        witness_transport=f.p.data["witness_transport"],
    )
    assert explicit["trust_policy"] == expected
    candidate = f.root / "candidate.json"
    candidate.write_bytes(_json(explicit["trust_policy"]))
    candidate.chmod(0o644)
    registration = f.root / "registration.json"
    registration.write_bytes(_json(explicit["registration"]))
    registration.chmod(0o644)
    incoming = f.root / "private/incoming"
    incoming.write_bytes(f.pk.read_bytes())
    incoming.chmod(0o600)
    provision(bundle, candidate, registration, incoming, f.wk)
    policy, registered = verify(bundle)
    assert (
        dict(policy.data) == explicit["trust_policy"]
        and registered == explicit["registration"]
    )
    before = {
        path: path.read_bytes()
        for path in (
            bundle / "trust.json",
            bundle / "origin.json",
            bundle / "input",
            bundle / "producer/key.raw",
            bundle / "witness/key.raw",
        )
    }
    provision(bundle, candidate, registration, incoming, f.wk)
    assert all(path.read_bytes() == raw for path, raw in before.items())
