from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("azazel_hil", ROOT / "tools/hil/azazel_hil.py")
assert SPEC and SPEC.loader
hil = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hil)


def test_report_is_concise_and_redacts_secret(tmp_path: Path) -> None:
    raw = tmp_path / "r0-test" / "raw"
    raw.mkdir(parents=True)
    (raw / "events.jsonl").write_text("\n".join((
        json.dumps({"kind": "provenance", "data": {"git_sha": "abc", "bearer_token": "nope"}}),
        json.dumps({"kind": "test_end", "test_id": "profile.qwen3.5:2b", "status": "passed", "exit_code": 0, "detail": {"summary": "profile complete"}}),
        json.dumps({"kind": "test_end", "test_id": "observer.retention", "status": "skipped", "exit_code": 0, "detail": {"reason": "not installed"}}),
    )) + "\n", encoding="utf-8")
    report = tmp_path / "CHATGPT_PASTE.md"
    summary = hil.write_report(raw, report)
    body = report.read_text(encoding="utf-8")
    assert summary == {"passed": 1, "skipped": 1, "failed": 0, "events": 3}
    assert "nope" not in body
    assert "[REDACTED]" in body
    assert "profile.qwen3.5:2b" in body


def test_cli_parses_ssh_target_and_resume_session() -> None:
    args = hil.parser().parse_args(["--target", "pi.local", "--user", "edge", "--port", "2222", "--session", "r0-resume", "preflight"])
    assert (args.target, args.user, args.port, args.session, args.command) == ("pi.local", "edge", 2222, "r0-resume", "preflight")


def test_redaction_never_leaks_private_key_or_bearer() -> None:
    value = "Authorization: Bearer abc.def\n-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"
    cleaned = hil.redact(value)
    assert "abc.def" not in cleaned and "\nsecret\n" not in cleaned
