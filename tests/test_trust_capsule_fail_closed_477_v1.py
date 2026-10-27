"""Trust capsules are not signed with a public key (Edge#477).

Without AZAZEL_TRUST_CAPSULE_HMAC_KEY the capsule is written unsigned
(signature_state "unsigned", empty hmac_sig) instead of being signed with the
former built-in key, which is public. The installer creates a random key in
/etc/azazel-edge/trust-capsule.env (0600 root:root) that the AI agent's unit
reads, and keeps an existing key when it runs again. The keys below are set
by the tests themselves and are not device keys.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from azazel_edge._util import stable_json
from azazel_edge.explanations import DecisionExplainer, validate_v2_explanation
from azazel_edge.explanations import trust_capsule

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "installer" / "internal" / "provision_trust_capsule_key.sh"
PROVISION = ROOT / "installer" / "internal" / "provision_mattermost_workspace.sh"
MIGRATED = ROOT / "installer" / "internal" / "install_migrated_tools.sh"
AGENT_UNIT = ROOT / "systemd" / "azazel-edge-ai-agent.service"
KEY_VAR = "AZAZEL_TRUST_CAPSULE_HMAC_KEY"
PUBLIC_FORMER_DEFAULT = "azazel-edge-dev-key"
TEST_KEY = "test-only-capsule-key-not-for-devices"

needs_gnu = pytest.mark.skipif(
    shutil.which("bash") is None
    or subprocess.run(["mv", "--version"], capture_output=True).returncode != 0,
    reason="write_private_file uses GNU mv -T, as on the device",
)


def _explain(path: Path | None = None) -> dict:
    explainer = DecisionExplainer(output_path=path or Path("unused.jsonl"))
    return explainer.explain(
        noc={"summary": {"status": "good"}},
        soc={"summary": {"status": "critical", "ai_attack_candidates": ["T1190"]}},
        arbiter={
            "action": "redirect",
            "reason": "soc_high_confidence_redirect",
            "release_condition": "noc_recovers",
            "chosen_evidence_ids": ["ev1"],
            "rejected_alternatives": [],
            "policy": {"version": "p1", "hash": "cfg123"},
        },
        trace_id="trace-capsule",
        persist=path is not None,
    )


def _hmac(capsule: dict, key: str) -> str:
    body = {k: v for k, v in capsule.items() if k != "hmac_sig"}
    return hmac.new(key.encode("utf-8"), stable_json(body).encode("utf-8"), hashlib.sha256).hexdigest()


# --- capsule ---------------------------------------------------------------

@pytest.mark.parametrize("value", [None, "", "   ", PUBLIC_FORMER_DEFAULT])
def test_no_usable_key_gives_an_unsigned_capsule(value, caplog) -> None:
    env = {k: v for k, v in os.environ.items() if k != KEY_VAR}
    if value is not None:
        env[KEY_VAR] = value
    with mock.patch.dict(os.environ, env, clear=True), \
            mock.patch.object(trust_capsule, "_warned_unsigned", False), \
            caplog.at_level("WARNING", logger="azazel_edge.explanations.trust_capsule"):
        capsule = _explain()["trust_capsule"]
    assert capsule["signature_state"] == "unsigned"
    assert capsule["hmac_sig"] == ""
    # Never a signature under the public former default key.
    assert capsule["hmac_sig"] != _hmac(capsule, PUBLIC_FORMER_DEFAULT)
    assert any("unsigned" in r.getMessage() for r in caplog.records)
    assert all(PUBLIC_FORMER_DEFAULT not in r.getMessage() for r in caplog.records)


def test_explicit_key_signs_and_the_signature_covers_the_state() -> None:
    with mock.patch.dict(os.environ, {KEY_VAR: TEST_KEY}):
        capsule = _explain()["trust_capsule"]
    assert capsule["signature_state"] == "signed"
    assert re.fullmatch(r"[0-9a-f]{64}", capsule["hmac_sig"])
    assert hmac.compare_digest(capsule["hmac_sig"], _hmac(capsule, TEST_KEY))
    # Flipping the state breaks the signature.
    assert _hmac(dict(capsule, signature_state="unsigned"), TEST_KEY) != capsule["hmac_sig"]


def test_key_value_is_not_logged(caplog) -> None:
    with mock.patch.dict(os.environ, {KEY_VAR: TEST_KEY}), \
            caplog.at_level("DEBUG"):
        _explain()
    assert all(TEST_KEY not in r.getMessage() for r in caplog.records)


def test_no_built_in_key_is_used_to_sign() -> None:
    src = (ROOT / "py" / "azazel_edge" / "explanations" / "trust_capsule.py").read_text(encoding="utf-8")
    assert not re.search(r"environ\.get\(\s*[\"']?%s[\"']?\s*,\s*[\"'][^\"']+[\"']" % KEY_VAR, src)
    assert not re.search(r"environ\.get\(\s*KEY_ENV\s*,\s*[\"'][^\"']+[\"']", src)
    assert src.count(PUBLIC_FORMER_DEFAULT) == 1  # only the refused constant


def test_unsigned_record_is_written_and_valid(tmp_path) -> None:
    out = tmp_path / "decision-explanations.jsonl"
    with mock.patch.dict(os.environ, {KEY_VAR: ""}):
        _explain(out)
    row = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
    assert row["trust_capsule"]["signature_state"] == "unsigned"
    assert validate_v2_explanation(row) == []


def test_schema_refuses_a_capsule_that_looks_signed_when_it_is_not() -> None:
    with mock.patch.dict(os.environ, {KEY_VAR: TEST_KEY}):
        record = _explain()
    assert validate_v2_explanation(record) == []
    bad = json.loads(json.dumps(record))
    bad["trust_capsule"]["signature_state"] = "unsigned"
    assert any("unsigned but carries" in p for p in validate_v2_explanation(bad))
    bad = json.loads(json.dumps(record))
    bad["trust_capsule"]["hmac_sig"] = ""
    assert any("signed but hmac_sig is empty" in p for p in validate_v2_explanation(bad))
    bad = json.loads(json.dumps(record))
    bad["trust_capsule"]["signature_state"] = "dev"
    assert any("unknown signature_state" in p for p in validate_v2_explanation(bad))
    # A record from before signature_state existed is still accepted.
    legacy = json.loads(json.dumps(record))
    del legacy["trust_capsule"]["signature_state"]
    assert validate_v2_explanation(legacy) == []


# --- unit and installer ----------------------------------------------------

def test_agent_unit_reads_the_key_file_after_the_security_file() -> None:
    lines = AGENT_UNIT.read_text(encoding="utf-8").splitlines()
    env_files = [line for line in lines if line.startswith("EnvironmentFile=")]
    assert env_files == [
        "EnvironmentFile=-/etc/default/azazel-edge-security",
        "EnvironmentFile=-/etc/azazel-edge/trust-capsule.env",
    ]


def test_no_unit_carries_or_reads_the_key_except_the_agent() -> None:
    for unit in sorted((ROOT / "systemd").iterdir()):
        text = unit.read_text(encoding="utf-8")
        assert KEY_VAR not in text, unit.name
        if unit != AGENT_UNIT:
            assert "trust-capsule.env" not in text, unit.name


def test_installer_provisions_the_key_before_the_agent_starts() -> None:
    src = MIGRATED.read_text(encoding="utf-8")
    install = 'install -m 0755 "$REPO_ROOT/installer/internal/provision_trust_capsule_key.sh" /opt/azazel-edge/provision_trust_capsule_key.sh'
    call = '/opt/azazel-edge/provision_trust_capsule_key.sh /etc/azazel-edge/trust-capsule.env "$SECURITY_ENV"'
    assert install in src and call in src
    assert src.index('SECURITY_ENV="/etc/default/azazel-edge-security"') < src.index(call)
    assert src.index(call) < src.index("systemctl enable --now azazel-edge-ai-agent.service")
    assert os.access(SCRIPT, os.X_OK)


def _function(path: Path, name: str) -> str:
    src = path.read_text(encoding="utf-8")
    start = src.index(f"{name}() {{")
    return src[start:src.index("\n}\n", start) + 3]


def test_write_private_file_is_the_shared_one() -> None:
    assert _function(SCRIPT, "write_private_file") == _function(PROVISION, "write_private_file")


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=30)


def _key(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 and lines[0].startswith(f"{KEY_VAR}=")
    return lines[0].split("=", 1)[1]


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


@needs_gnu
def test_new_key_is_random_private_and_never_printed(tmp_path) -> None:
    env_file, security = tmp_path / "etc" / "trust-capsule.env", tmp_path / "security"
    security.write_text("AZAZEL_RUNTIME_DIR_MODE=0750\n", encoding="utf-8")
    first = _run(str(env_file), str(security))
    assert first.returncode == 0, first.stderr
    key = _key(env_file)
    assert re.fullmatch(r"[0-9a-f]{64}", key)
    assert _mode(env_file) == 0o600
    assert key not in first.stdout + first.stderr
    # A second device gets a different key.
    other = tmp_path / "other.env"
    assert _run(str(other), str(security)).returncode == 0
    assert _key(other) != key


@needs_gnu
def test_rerun_keeps_the_key_and_narrows_the_mode(tmp_path) -> None:
    env_file, security = tmp_path / "trust-capsule.env", tmp_path / "security"
    assert _run(str(env_file), str(security)).returncode == 0
    key = _key(env_file)
    env_file.chmod(0o644)
    again = _run(str(env_file), str(security))
    assert again.returncode == 0, again.stderr
    assert _key(env_file) == key
    assert _mode(env_file) == 0o600
    assert "keeping the key" in again.stdout
    assert key not in again.stdout + again.stderr


@needs_gnu
def test_key_set_by_hand_in_the_security_file_is_carried_over(tmp_path) -> None:
    env_file, security = tmp_path / "trust-capsule.env", tmp_path / "security"
    security.write_text(f'{KEY_VAR}="{TEST_KEY}"\n', encoding="utf-8")
    result = _run(str(env_file), str(security))
    assert result.returncode == 0, result.stderr
    assert _key(env_file) == TEST_KEY
    assert _mode(env_file) == 0o600
    assert TEST_KEY not in result.stdout + result.stderr
    assert "NOTICE" in result.stdout
    assert security.read_text(encoding="utf-8") == f'{KEY_VAR}="{TEST_KEY}"\n'


@needs_gnu
@pytest.mark.parametrize("content", [f"{KEY_VAR}={PUBLIC_FORMER_DEFAULT}\n", f"{KEY_VAR}=\n", "OTHER=1\n"])
def test_file_without_a_usable_key_gets_a_new_one(tmp_path, content) -> None:
    env_file, security = tmp_path / "trust-capsule.env", tmp_path / "security"
    security.write_text(f"{KEY_VAR}={PUBLIC_FORMER_DEFAULT}\n", encoding="utf-8")
    env_file.write_text(content, encoding="utf-8")
    result = _run(str(env_file), str(security))
    assert result.returncode == 0, result.stderr
    assert re.fullmatch(r"[0-9a-f]{64}", _key(env_file))


@needs_gnu
def test_symlink_is_refused(tmp_path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("x\n", encoding="utf-8")
    link = tmp_path / "trust-capsule.env"
    link.symlink_to(target)
    result = _run(str(link), str(tmp_path / "security"))
    assert result.returncode != 0
    assert target.read_text(encoding="utf-8") == "x\n"
