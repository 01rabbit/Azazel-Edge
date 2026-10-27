"""#389 rest: digest key, port to a service (off by default), read-only
incident export, and the two known masking leaks.

Every key in this file is made by the test itself and is not a device key.
Keys that look like test keys are refused by design; the usable ones here
are random and live only in tmp_path.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from azazel_edge.mio import DEFAULT_PLAYBOOKS, BoundedReasoningLoop
from azazel_edge.mio.lifecycle import ReasoningCoordinator
from azazel_edge.mio.redaction import redact_text
from azazel_edge.mio.trace_audit import MAX_RECORD_BYTES, encode_record, project_outcome
from azazel_edge.mio.trace_export import EXPORT_SCHEMA, export_incident, valid_record
from azazel_edge.mio.trace_recorder import (
    TRACE_AUDIT_CONFIG_SCHEMA,
    TraceAuditConfig,
    key_is_usable,
    load_audit_key,
    load_trace_audit_config,
    open_trace_audit,
    parse_trace_audit_config,
)

from test_mio_reasoning_trace_audit import SECRET_TEXT, SECRETS, Broker, frame, model

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "installer" / "internal" / "provision_mio_trace_audit_key.sh"
CAPSULE_SCRIPT = ROOT / "installer" / "internal" / "provision_trust_capsule_key.sh"
EXPORT_CLI = ROOT / "bin" / "azazel-mio-trace-export"
SHIPPED_CONFIG = ROOT / "config" / "mio_trace_audit.json"
PLAYBOOK = DEFAULT_PLAYBOOKS["auth-ambiguity-v1"]

needs_gnu = pytest.mark.skipif(
    shutil.which("bash") is None
    or subprocess.run(["mv", "--version"], capture_output=True).returncode != 0,
    reason="write_private_file uses GNU mv -T, as on the device",
)


def _random_key() -> str:
    return secrets.token_hex(32)


def _key_file(tmp_path: Path, value: str, mode: int = 0o600) -> Path:
    path = tmp_path / "mio-trace-audit.key"
    path.write_text(value, encoding="ascii")
    path.chmod(mode)
    return path


def _cycle(trace_id: str = "trace-1", echo: str = "", coord: ReasoningCoordinator | None = None, n: int = 0):
    f = frame(trace_id=trace_id, known_facts=[f"{20 + n} SSH failures in 60s", "same source"])
    coord = coord or ReasoningCoordinator()
    ticket = coord.begin(f)
    loop = BoundedReasoningLoop(model=model(echo=echo), broker=Broker())
    outcome = loop.run(frame=f, playbook=PLAYBOOK, cycle_id=ticket.cycle_id, cancel_check=coord.cancel_check(ticket), stale_check=coord.stale_check(ticket))
    return f, ticket, outcome


def _config(tmp_path: Path, key_file: Path | str = "", **kw) -> TraceAuditConfig:
    # The sink does not create directories (a service's unit owns them).
    if not (tmp_path / "audit").exists():
        (tmp_path / "audit").mkdir(mode=0o700)
    return TraceAuditConfig(enabled=True, path=str(tmp_path / "audit" / "trace.jsonl"), key_file=str(key_file), **kw)


# --- the two known masking leaks (issue comment of #449) ----------------------

@pytest.mark.parametrize("text, secret_parts", [
    # 1. Opener before the label, closer inside the secret.
    ("(pw: p) ss)", ("p) ss",)),
    ("(pw: p) ss) next", ("ss",)),
    ("[token: ab] cd]", ("ab", "cd")),
    ("(password: a) b) c", ("a) b",)),
    # 2. A comma (or ; &) inside the value.
    ("token: expired, abc123", ("abc123",)),
    ("token: expired,abc123", ("abc123",)),
    ("token: expired; abc123", ("abc123",)),
    ("auth: failed, s3cr3t", ("s3cr3t",)),
    ("pin: 3 hosts, 1234", ("1234",)),
    ("password: a,b", (",b",)),
    ("password: hunter2, extra-part", ("hunter2", "extra-part")),
    ("pw=a&b", ("&b",)),
    ("(token: expired, abc123) ok", ("abc123",)),
    ("password: x,, y", ("y",)),
])
def test_known_leaks_are_masked(text, secret_parts):
    out = redact_text(text)
    assert "[redacted:" in out, out
    for part in secret_parts:
        assert part not in out, out


@pytest.mark.parametrize("text, expected", [
    ("(pw: p) ss) next", "([redacted:secret_kv]) next"),
    ("(password: hunter2) next", "([redacted:secret_kv]) next"),
    ("password: x, user: admin", "[redacted:secret_kv], user: admin"),
    ("?password=a&b=c", "?[redacted:secret_kv]&b=c"),
    ("password: x,", "[redacted:secret_kv],"),
])
def test_value_ends_where_the_next_field_starts(text, expected):
    assert redact_text(text) == expected


@pytest.mark.parametrize("text", [
    "auth: failed, admin",
    "auth: failed for admin, 3 attempts",
    "token: expired, retry later",
    "token: expired; retry later",
    "(auth: failed) admin logged in from (lab)",
    "(token: expired) user admin (host a)",
    "pin: 3 hosts, 2 devices",
])
def test_ordinary_text_with_commas_and_brackets_is_kept(text):
    assert redact_text(text) == text


# Inputs that were quadratic before (a rescan from the line start for every
# label, and a "eyJ" scan from every position of a long run) and neighbours.
_LINEAR_UNITS = (
    "token: expired, ",
    "(pw: a); ",
    "pw: \"",
    "(token: expired, ",
    "pw: a, ",
    "(pw: a) b) ",
    "eyJ",
    "eyJ_",
    "ftp://a:b ",
    "a:b c:d ",
    "authorization: ",
    "password is ",
    "パスワード ",
    "a" * 31 + " ",
    "x-",
    "(",
    "a@b.",
)


@pytest.mark.parametrize("unit", _LINEAR_UNITS)
def test_masking_is_linear_on_one_megabyte(unit):
    def run(size: int) -> float:
        text = (unit * (size // len(unit) + 1))[:size]
        start = time.perf_counter()
        redact_text(text)
        return time.perf_counter() - start

    small = run(1 << 17)
    large = run(1 << 20)  # 8x the input
    # Linear is about 8x; quadratic would be about 64x. The absolute bound
    # catches a slow machine as well as a regression.
    assert large < 30, (unit, large)
    assert large < max(small, 0.005) * 24, (unit, small, large)


# --- digest key ---------------------------------------------------------------

def test_random_key_in_a_private_file_is_loaded(tmp_path):
    value = _random_key()
    state = load_audit_key(str(_key_file(tmp_path, f"  {value}\r\n")))
    assert state.state == "persistent" and state.key == value.encode()
    assert value not in repr(state) and value not in state.reason


@pytest.mark.parametrize("value", [
    "",
    "short-key-123",
    "k" * 32,                                      # the trace audit tests' key
    "z" * 32,
    "abcabcabcabcabcabcabcabcabcabcab",           # too few different characters
    "test-only-capsule-key-not-for-devices",     # the trust capsule tests' key
    "example-key-0123456789abcdefghijklmnop",
    "Dummy0123456789abcdefghijklmnopqrstu",
    "ChangeMe0123456789abcdefghijklmnopqr",
    "azazel-edge-devkey-0123456789abcdefgh",
    _random_key() + "\n" + _random_key(),        # two values
    _random_key() + "$HOME",                       # outside the character set
    "\"" + _random_key() + "\"",                   # quotes are not removed
])
def test_unusable_or_test_keys_are_refused(tmp_path, value):
    state = load_audit_key(str(_key_file(tmp_path, value)))
    assert state.state == "refused" and state.key is None and state.reason == "not_usable"
    assert not key_is_usable(value.strip())


def test_key_file_must_be_private_regular_and_not_a_symlink(tmp_path):
    value = _random_key()
    wide = _key_file(tmp_path, value, 0o640)
    assert load_audit_key(str(wide)).reason == "mode_too_wide"
    wide.chmod(0o600)
    link = tmp_path / "link.key"
    link.symlink_to(wide)
    assert load_audit_key(str(link)).reason == "symlink"
    assert load_audit_key(str(tmp_path)).state == "refused"
    assert load_audit_key(str(tmp_path / "missing.key")).state == "absent"
    assert load_audit_key("").reason == "not_configured"


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to give the file another owner")
def test_key_file_of_another_user_is_refused(tmp_path):
    path = _key_file(tmp_path, _random_key())
    os.chown(path, 4321, 4321)
    assert load_audit_key(str(path)).reason == "owner"


def test_no_environment_variable_or_built_in_key():
    src = (ROOT / "py" / "azazel_edge" / "mio" / "trace_recorder.py").read_text(encoding="utf-8")
    assert "os.environ" not in src and "getenv" not in src
    script = SCRIPT.read_text(encoding="utf-8")
    assert "${AZAZEL" not in script and "EnvironmentFile" not in script


# --- port: off by default -----------------------------------------------------

def test_shipped_config_is_disabled_and_nothing_starts_the_port():
    config = load_trace_audit_config(str(SHIPPED_CONFIG))
    assert config.enabled is False
    assert open_trace_audit(config) is None
    # No unit, installer step or running service loads the config or the port.
    for base in ("systemd", "installer", "azazel_edge_web", "py/azazel_edge_ai", "py/azazel_edge_control"):
        for path in (ROOT / base).rglob("*"):
            if path.is_file() and path != SCRIPT:
                text = path.read_text(encoding="utf-8", errors="replace")
                for needle in ("mio_trace_audit.json", "trace_recorder", "provision_mio_trace_audit_key", "mio-trace-audit.key", "azazel-mio-trace-export"):
                    assert needle not in text, (path, needle)


def test_missing_config_file_is_disabled(tmp_path):
    assert load_trace_audit_config(str(tmp_path / "none.json")) == TraceAuditConfig()
    assert TraceAuditConfig().enabled is False


@pytest.mark.parametrize("data", [
    [],
    {"enabled": True, "path": "/var/x.jsonl"},                                       # no schema
    {"schema": TRACE_AUDIT_CONFIG_SCHEMA, "enabled": "true", "path": "/var/x.jsonl"},
    {"schema": TRACE_AUDIT_CONFIG_SCHEMA, "enabled": True},                          # no path
    {"schema": TRACE_AUDIT_CONFIG_SCHEMA, "enabled": True, "path": "relative.jsonl"},
    {"schema": TRACE_AUDIT_CONFIG_SCHEMA, "enabled": False, "path": "/var/x.jsonl", "max_files": 0},
    {"schema": TRACE_AUDIT_CONFIG_SCHEMA, "enabled": False, "path": "/var/x.jsonl", "max_file_bytes": 10},
    {"schema": TRACE_AUDIT_CONFIG_SCHEMA, "enabled": False, "path": "/var/x.jsonl", "approve": True},
])
def test_invalid_config_is_rejected(data):
    with pytest.raises(ValueError, match="invalid_trace_audit_config"):
        parse_trace_audit_config(data)


def test_persistent_key_makes_digests_comparable_across_restarts(tmp_path):
    key_file = _key_file(tmp_path, _random_key())
    f, ticket, outcome = _cycle()
    first = open_trace_audit(_config(tmp_path, key_file))
    second = open_trace_audit(_config(tmp_path, key_file))  # "after a restart"
    assert first.digest_key == second.digest_key == "persistent"
    assert first.record(ticket=ticket, outcome=outcome, frame=f) is True
    assert second.record(ticket=ticket, outcome=outcome, frame=f) is True
    rows = [json.loads(x) for x in (tmp_path / "audit" / "trace.jsonl").read_text().splitlines()]
    assert rows[0]["digest_key"] == "persistent" and rows[0]["schema"] == "mio.trace_audit.v2"
    assert rows[0]["recommendation"]["summary"] == rows[1]["recommendation"]["summary"]
    assert key_file.read_text().strip() not in json.dumps(rows) + repr(first) + json.dumps(first.stats())
    assert first.stats()["key_reason"] == "loaded"


@pytest.mark.parametrize("key_value", [None, "k" * 32, "test-only-capsule-key-not-for-devices"])
def test_without_a_usable_key_records_say_ephemeral(tmp_path, key_value):
    key_file = "" if key_value is None else _key_file(tmp_path, key_value)
    f, ticket, outcome = _cycle()
    a = open_trace_audit(_config(tmp_path, key_file))
    b = open_trace_audit(_config(tmp_path, key_file))
    assert a.digest_key == "ephemeral"
    assert a.record(ticket=ticket, outcome=outcome, frame=f) and b.record(ticket=ticket, outcome=outcome, frame=f)
    rows = [json.loads(x) for x in (tmp_path / "audit" / "trace.jsonl").read_text().splitlines()]
    assert {r["digest_key"] for r in rows} == {"ephemeral"}
    # A fresh random key per process: digests differ, no known key is used.
    assert rows[0]["recommendation"]["summary"]["digest"] != rows[1]["recommendation"]["summary"]["digest"]
    known = project_outcome(ticket=ticket, outcome=outcome, key=b"k" * 32, frame=f)
    assert rows[0]["recommendation"]["summary"] != known["recommendation"]["summary"]


def test_recorder_withholds_the_advisory_when_the_sink_fails(tmp_path):
    f, ticket, outcome = _cycle()
    blocked = tmp_path / "audit"
    blocked.write_text("not a directory", encoding="utf-8")
    rec = open_trace_audit(_config(tmp_path))
    assert rec.record(ticket=ticket, outcome=outcome, frame=f) is False
    assert rec.stats()["advisory_allowed"] is False


def test_projection_rejects_an_unknown_digest_key_state():
    f, ticket, outcome = _cycle()
    with pytest.raises(ValueError):
        project_outcome(ticket=ticket, outcome=outcome, key=b"x" * 32, frame=f, digest_key="approved")


# --- provisioner --------------------------------------------------------------

def _function(path: Path, name: str) -> str:
    src = path.read_text(encoding="utf-8")
    start = src.index(f"{name}() {{")
    return src[start:src.index("\n}\n", start) + 3]


def test_provisioner_shares_write_private_file_and_is_not_run_by_the_installer():
    assert _function(SCRIPT, "write_private_file") == _function(CAPSULE_SCRIPT, "write_private_file")
    assert os.access(SCRIPT, os.X_OK)


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=30)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


@needs_gnu
def test_provisioner_writes_a_random_private_key_and_keeps_it(tmp_path):
    key_file = tmp_path / "etc" / "mio-trace-audit.key"
    first = _run(str(key_file))
    assert first.returncode == 0, first.stderr
    key = key_file.read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{64}", key) and key_file.read_text() == key + "\n"
    assert _mode(key_file) == 0o600
    assert key not in first.stdout + first.stderr
    assert load_audit_key(str(key_file)).state == "persistent"
    key_file.chmod(0o644)
    again = _run(str(key_file))
    assert again.returncode == 0 and "keeping the key" in again.stdout
    assert key_file.read_text().strip() == key and _mode(key_file) == 0o600
    other = tmp_path / "other.key"
    assert _run(str(other)).returncode == 0 and other.read_text().strip() != key


@needs_gnu
@pytest.mark.parametrize("content", ["", "abc123\n", "k" * 32 + "\n", "test-only-capsule-key-not-for-devices\n", "example-key-0123456789abcdefghijklmnop\n"])
def test_provisioner_replaces_weak_or_test_keys_with_a_notice(tmp_path, content):
    key_file = tmp_path / "mio-trace-audit.key"
    key_file.write_text(content, encoding="ascii")
    result = _run(str(key_file))
    assert result.returncode == 0, result.stderr
    assert "NOTICE" in result.stdout
    new = key_file.read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{64}", new)
    if content.strip():
        assert content.strip() not in result.stdout + result.stderr


@needs_gnu
def test_provisioner_keeps_a_usable_hand_set_key(tmp_path):
    value = secrets.token_urlsafe(40)
    key_file = tmp_path / "mio-trace-audit.key"
    key_file.write_text(f"  {value}\r\n", encoding="ascii")
    key_file.chmod(0o600)
    result = _run(str(key_file))
    assert result.returncode == 0 and "keeping the key" in result.stdout
    assert value not in result.stdout + result.stderr
    assert load_audit_key(str(key_file)).key == value.encode()


@needs_gnu
def test_provisioner_refuses_a_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("x\n", encoding="utf-8")
    link = tmp_path / "mio-trace-audit.key"
    link.symlink_to(target)
    assert _run(str(link)).returncode != 0
    assert target.read_text(encoding="utf-8") == "x\n"


@needs_gnu
@pytest.mark.parametrize("value", [
    "abcabcabcabcabcabcabcabcabcabcab",
    "0123456789abcdef0123456789abcdef",
    "TESTkey0123456789abcdefghijklmnopq",
    secrets.token_hex(32),
    secrets.token_urlsafe(32),
])
def test_provisioner_and_loader_agree(tmp_path, value):
    key_file = tmp_path / "mio-trace-audit.key"
    key_file.write_text(value + "\n", encoding="ascii")
    key_file.chmod(0o600)
    kept = "keeping the key" in _run(str(key_file)).stdout
    assert kept == key_is_usable(value)


# --- read-only incident export -------------------------------------------------

def _write_records(tmp_path: Path, n_traces=("trace-1", "trace-2"), echo: str = "") -> Path:
    rec = open_trace_audit(_config(tmp_path, max_file_bytes=MAX_RECORD_BYTES, max_files=3))
    coord = ReasoningCoordinator()
    for n, trace in enumerate(n_traces):
        f, ticket, outcome = _cycle(trace, echo=echo, coord=coord, n=n)
        assert rec.record(ticket=ticket, outcome=outcome, frame=f, edge_decision_ref="edge-dec:42")
    return Path(rec.sink.path)


def _snapshot(directory: Path) -> dict:
    return {p.name: (p.stat().st_size, p.stat().st_mtime_ns, stat.S_IMODE(p.stat().st_mode)) for p in directory.iterdir()}


def test_export_selects_one_trace_across_rotated_files_and_changes_nothing(tmp_path):
    path = _write_records(tmp_path, ("trace-1", "trace-2", "trace-1"))
    assert (path.parent / (path.name + ".1")).exists()  # rotation happened
    before = _snapshot(path.parent)
    out = export_incident(str(path), trace_id="trace-1", max_files=3)
    assert _snapshot(path.parent) == before
    assert out["schema"] == EXPORT_SCHEMA and out["authority"] == "advisory_only"
    assert len(out["records"]) == 2 and {r["trace_id"] for r in out["records"]} == {"trace-1"}
    assert out["records"][0]["edge_decision_ref"] == "edge-dec:42"
    assert out["skipped"] == {"malformed": 0, "oversize": 0, "invalid": 0}
    assert [f["name"] for f in out["files"]] == ["trace.jsonl.2", "trace.jsonl.1", "trace.jsonl"]
    one = export_incident(str(path), trace_id="trace-1", max_files=3, cycle_id=out["records"][0]["cycle_id"])
    assert len(one["records"]) == 1
    newest = export_incident(str(path), trace_id="trace-1", max_files=3, limit=1)
    assert newest["records"] == out["records"][1:] and newest["omitted"] == 1


def test_export_never_prints_secrets_free_text_or_tampered_records(tmp_path):
    path = _write_records(tmp_path, ("trace-1",), echo=SECRET_TEXT)
    good = json.loads(path.read_text().splitlines()[0])
    tampered = []
    for change in (
        {"note": SECRET_TEXT},
        {"errors": [SECRETS[0]]},
        {"trace_id": "trace-1", "frame_id": SECRETS[4]},
        {"recommendation": dict(good["recommendation"], summary=SECRET_TEXT)},
        {"recommendation": dict(good["recommendation"], executable=True)},
        {"edge_decision_ref": "trace-1:e0:c1:advisory"},
        {"broker": [{"request_id": "x", "capability": "q", "result": SECRET_TEXT, "evidence_refs": []}]},
        {"hypotheses": [dict(good["hypotheses"][0], supporting_evidence_refs=[SECRETS[1]])]},
        {"digest_key": "approved"},
    ):
        tampered.append(json.dumps(dict(good, **change)))
    with open(path, "a", encoding="ascii") as fh:
        fh.write("\n".join(tampered) + "\n")
        fh.write("{not json\n")
        fh.write(json.dumps(dict(good, pad="x" * MAX_RECORD_BYTES)) + "\n")
        fh.write('{"torn": ')
    out = export_incident(str(path), trace_id="trace-1", max_files=3)
    blob = json.dumps(out)
    for secret in SECRETS:
        assert secret not in blob
    assert len(out["records"]) == 1
    assert out["skipped"] == {"malformed": 2, "oversize": 1, "invalid": len(tampered)}


def test_export_accepts_v1_records_and_refuses_odd_files(tmp_path):
    f, ticket, outcome = _cycle()
    rec = project_outcome(ticket=ticket, outcome=outcome, key=secrets.token_bytes(32), frame=f)
    v1 = {k: v for k, v in rec.items() if k != "digest_key"}
    v1["schema"] = "mio.trace_audit.v1"
    assert valid_record(v1) and valid_record(rec)
    assert not valid_record(dict(v1, digest_key="persistent"))
    path = tmp_path / "trace.jsonl"
    path.write_bytes(encode_record(v1))
    path.chmod(0o600)
    link = tmp_path / "link.jsonl"
    link.symlink_to(path)
    assert export_incident(str(path), trace_id="trace-1")["records"] == [v1]
    refused = export_incident(str(link), trace_id="trace-1")
    assert refused["records"] == [] and refused["files"][-1]["state"] == "refused:symlink"
    with pytest.raises(ValueError):
        export_incident(str(path), trace_id="bad id\n")
    with pytest.raises(ValueError):
        export_incident(str(path), trace_id="trace-1", limit=0)


def test_export_cli_prints_json_and_does_not_echo_bad_arguments(tmp_path):
    path = _write_records(tmp_path, ("trace-1",))
    env = dict(os.environ, PYTHONPATH=str(ROOT / "py"))
    ok = subprocess.run([sys.executable, str(EXPORT_CLI), "--path", str(path), "--max-files", "3", "--trace-id", "trace-1"], capture_output=True, text=True, env=env, timeout=60)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["records"][0]["trace_id"] == "trace-1"
    config = tmp_path / "cfg.json"
    config.write_text(json.dumps({"schema": TRACE_AUDIT_CONFIG_SCHEMA, "enabled": False, "path": str(path), "max_files": 3}))
    via_config = subprocess.run([sys.executable, str(EXPORT_CLI), "--config", str(config), "--trace-id", "trace-1"], capture_output=True, text=True, env=env, timeout=60)
    assert via_config.returncode == 0 and json.loads(via_config.stdout) == json.loads(ok.stdout)
    bad = subprocess.run([sys.executable, str(EXPORT_CLI), "--path", str(path), "--trace-id", SECRETS[1] + " x"], capture_output=True, text=True, env=env, timeout=60)
    assert bad.returncode == 2 and SECRETS[1] not in bad.stdout + bad.stderr


def test_export_cli_has_no_write_options():
    src = EXPORT_CLI.read_text(encoding="utf-8") + (ROOT / "py" / "azazel_edge" / "mio" / "trace_export.py").read_text(encoding="utf-8")
    for needle in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "ftruncate", "os.remove", "os.replace", "os.rename", "flock", '"w"', '"a"', "'w'", "'a'"):
        assert needle not in src, needle
