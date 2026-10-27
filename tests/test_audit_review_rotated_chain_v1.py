"""audit_review verifies the core decision chain after it rotated (Edge#462
item 1, Edge#477).

The chain files are written by the real ``P0AuditLogger`` rotation
(``max_bytes``, keep=1; ``azazel_edge.audit.segments``). Read only: nothing
here decides, enforces or changes the P0 path.
"""

from __future__ import annotations

import io
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge import audit_review  # noqa: E402
from azazel_edge.audit import P0AuditLogger  # noqa: E402
from azazel_edge.audit.segments import read_chain, segment_path  # noqa: E402
from azazel_edge.audit_review import verify_audit_chain  # noqa: E402


# ---------------------------------------------------------------- helpers
def _write(path: Path, n: int, max_bytes=None, start: int = 0) -> P0AuditLogger:
    audit = P0AuditLogger(path, max_bytes=max_bytes, keep=1)
    for i in range(start, start + n):
        audit.log_action_decision(f"d{i}", "s", action="isolate")
    return audit


def _lines(path: Path) -> list:
    return path.read_text(encoding="utf-8").splitlines()


def _put(path: Path, lines: list) -> None:
    path.write_text("".join(x + "\n" for x in lines), encoding="utf-8")


def _rehash(row: dict) -> dict:
    row = dict(row)
    row.pop("chain_hash", None)
    row["chain_hash"] = P0AuditLogger._compute_chain_hash(row)
    return row


def _dump(row: dict) -> str:
    return json.dumps(row, ensure_ascii=True, separators=(",", ":"))


def _rotated_twice(tmp_path: Path, start: int = 0):
    """A chain rotated so often that its genesis is gone: ``.1`` and the
    active file both start at a rotation boundary."""
    path = tmp_path / "core-decision-audit.jsonl"
    audit = _write(path, 40, max_bytes=1500, start=start)
    assert audit.rotated_total >= 3
    assert len(_lines(path)) >= 3 and len(_lines(segment_path(path, 1))) >= 3
    return path, audit


def _review(audit_path: Path, tmp_path: Path, *flags: str):
    explanations = tmp_path / "decision-explanations.jsonl"
    explanations.write_text(json.dumps({"trace_id": "t1", "selected_action": "isolate"}) + "\n", encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out):
        rc = audit_review.main(["--explanations-path", str(explanations), "--audit-path", str(audit_path), *flags])
    return rc, out.getvalue()


def _agrees_with_the_reconcile(path: Path, result: dict) -> None:
    """OK scopes mean what the P0 relay's reconcile reads (read_chain)."""
    snap = read_chain(path)
    assert result["entries"] == len(snap["lines"])
    assert (result["scope"] == "from_rotation_boundary") is bool(snap["anchored"])
    assert len(result["files"]) == snap["segments"]
    assert result["chain_id"] == snap["chain_id"]


# --------------------------------------------------------- not rotated
def test_a_chain_that_never_rotated_verifies_from_its_genesis(tmp_path):
    path = tmp_path / "core-decision-audit.jsonl"
    audit = _write(path, 5)
    result = verify_audit_chain(path)
    assert result["ok"] is True and result["entries"] == 5 and result["error"] == ""
    assert result["scope"] == "from_genesis" and result["genesis_retained"] is True
    assert result["files"] == [path.name] and result["chain_id"] == audit.chain_id
    # The same answer as the single-file verifier it replaces.
    assert P0AuditLogger.verify_chain(path) == {"ok": True, "entries": 5, "error": ""}
    _agrees_with_the_reconcile(path, result)


def test_the_old_verifier_failed_on_a_rotated_chain_and_the_new_one_does_not(tmp_path):
    path, _ = _rotated_twice(tmp_path)
    old = P0AuditLogger.verify_chain(path)
    assert old["ok"] is False and old["error"] == "chain_prev_mismatch_at:1"
    assert verify_audit_chain(path)["ok"] is True


# ------------------------------------------------------------- rotated
def test_rotated_once_with_the_genesis_in_dot1_verifies_from_the_genesis(tmp_path):
    path = tmp_path / "core-decision-audit.jsonl"
    audit = P0AuditLogger(path, max_bytes=1500, keep=1)
    n = 0
    while audit.rotated_total == 0:
        audit.log_action_decision(f"d{n}", "s", action="isolate")
        n += 1
    audit.log_action_decision(f"d{n}", "s", action="isolate")
    result = verify_audit_chain(path)
    assert result["ok"] is True and result["entries"] == n + 1
    assert result["scope"] == "from_genesis" and result["genesis_retained"] is True
    assert result["files"] == [path.name + ".1", path.name]
    assert result["chain_id"] == audit.chain_id
    _agrees_with_the_reconcile(path, result)


def test_rotated_with_dot1_verifies_both_files_from_the_rotation_boundary(tmp_path):
    path, audit = _rotated_twice(tmp_path)
    result = verify_audit_chain(path)
    expected = len(_lines(segment_path(path, 1))) + len(_lines(path))
    assert result["ok"] is True and result["entries"] == expected
    assert result["scope"] == "from_rotation_boundary" and result["genesis_retained"] is False
    assert result["files"] == [path.name + ".1", path.name]
    assert result["chain_id"] == audit.chain_id
    _agrees_with_the_reconcile(path, result)


def test_rotated_without_dot1_verifies_the_active_file_from_its_boundary(tmp_path):
    path, audit = _rotated_twice(tmp_path)
    segment_path(path, 1).unlink()
    result = verify_audit_chain(path)
    assert result["ok"] is True and result["entries"] == len(_lines(path))
    assert result["scope"] == "from_rotation_boundary" and result["genesis_retained"] is False
    assert result["files"] == [path.name] and result["chain_id"] == audit.chain_id
    _agrees_with_the_reconcile(path, result)


def test_only_dot1_left_by_a_crash_mid_rotation_verifies(tmp_path):
    path, audit = _rotated_twice(tmp_path)
    segment_path(path, 1).unlink()
    os.replace(path, segment_path(path, 1))  # renamed, the next record not yet written
    result = verify_audit_chain(path)
    assert result["ok"] is True and result["files"] == [path.name + ".1"]
    assert result["scope"] == "from_rotation_boundary" and result["chain_id"] == audit.chain_id


def test_the_logger_continues_after_review_and_still_verifies(tmp_path):
    path, _ = _rotated_twice(tmp_path)
    assert verify_audit_chain(path)["ok"] is True
    _write(path, 30, max_bytes=1500, start=100)  # a restart: the same chain continues
    result = verify_audit_chain(path)
    assert result["ok"] is True and result["scope"] == "from_rotation_boundary"


# ------------------------------------------------------------ tampering
@pytest.mark.parametrize("target", ["dot1", "active"])
def test_a_rewritten_record_fails(tmp_path, target):
    path, _ = _rotated_twice(tmp_path)
    f = segment_path(path, 1) if target == "dot1" else path
    lines = _lines(f)
    row = json.loads(lines[1])
    row["action"] = "observe"
    lines[1] = _dump(row)
    _put(f, lines)
    result = verify_audit_chain(path)
    assert result["ok"] is False and result["scope"] == "not_verified"
    assert result["error"].startswith("chain_hash_mismatch_at:")


@pytest.mark.parametrize("target", ["dot1", "active"])
def test_a_removed_record_fails(tmp_path, target):
    path, _ = _rotated_twice(tmp_path)
    f = segment_path(path, 1) if target == "dot1" else path
    lines = _lines(f)
    assert len(lines) >= 3
    del lines[1]
    _put(f, lines)
    result = verify_audit_chain(path)
    assert result["ok"] is False and result["error"].startswith("chain_prev_mismatch_at:")


def test_reordered_records_fail(tmp_path):
    path, _ = _rotated_twice(tmp_path)
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    _put(path, lines)
    result = verify_audit_chain(path)
    assert result["ok"] is False and result["error"].startswith("chain_prev_mismatch_at:")


def test_a_cut_tail_of_dot1_is_not_hidden_by_dropping_dot1(tmp_path):
    # read_chain stops at a rotated file the next one does not continue; the
    # review must not then verify the active file alone and say OK.
    path, _ = _rotated_twice(tmp_path)
    _put(segment_path(path, 1), _lines(segment_path(path, 1))[:-1])
    result = verify_audit_chain(path)
    assert result["ok"] is False and result["error"] == "rotated_file_not_continued:1"


def test_a_cut_start_without_dot1_fails(tmp_path):
    path = tmp_path / "core-decision-audit.jsonl"
    _write(path, 6)  # never rotated: the second record has no chain_id
    _put(path, _lines(path)[2:])
    result = verify_audit_chain(path)
    assert result["ok"] is False
    assert result["error"] == "start_cut:oldest_record_is_not_a_rotation_boundary"


def test_a_cut_start_of_the_active_file_with_dot1_fails(tmp_path):
    path, _ = _rotated_twice(tmp_path)
    _put(path, _lines(path)[1:])
    result = verify_audit_chain(path)
    assert result["ok"] is False and result["error"] == "rotated_file_not_continued:1"


def test_a_torn_last_line_fails(tmp_path):
    path, _ = _rotated_twice(tmp_path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"kind":"action_decision"')
    result = verify_audit_chain(path)
    assert result["ok"] is False and result["error"] == f"incomplete_last_line:{path.name}"


def test_a_line_that_is_not_json_fails(tmp_path):
    path = tmp_path / "core-decision-audit.jsonl"
    _write(path, 3)
    lines = _lines(path)
    lines.insert(1, "not json")
    _put(path, lines)
    result = verify_audit_chain(path)
    assert result["ok"] is False and result["error"] == "parse_error_at:2"


# -------------------------------------------- another chain (chain_replaced)
def test_an_active_file_replaced_by_a_new_chain_fails(tmp_path):
    path, _ = _rotated_twice(tmp_path)
    other = tmp_path / "other.jsonl"
    _write(other, 3)
    os.replace(other, path)
    result = verify_audit_chain(path)
    assert result["ok"] is False and result["error"] == "rotated_file_not_continued:1"


def test_a_dot1_of_another_chain_fails(tmp_path):
    path, _ = _rotated_twice(tmp_path)
    other_dir = tmp_path / "o"
    other_dir.mkdir()
    other, _ = _rotated_twice(other_dir, start=1000)
    os.replace(segment_path(other, 1), segment_path(path, 1))
    result = verify_audit_chain(path)
    assert result["ok"] is False and result["error"] == "rotated_file_not_continued:1"


def test_a_chain_id_other_than_the_chains_fails(tmp_path):
    # The active file's head links to .1 and its hash matches, but it names
    # another chain.
    path, _ = _rotated_twice(tmp_path)
    head = json.loads(_lines(path)[0])
    head["chain_id"] = "0" * 64
    _put(path, [_dump(_rehash(head))])
    result = verify_audit_chain(path)
    assert result["ok"] is False and result["error"] == "chain_id_mismatch_at:" + str(len(_lines(segment_path(path, 1))) + 1)


def test_a_whole_other_rotated_chain_is_told_by_its_chain_id(tmp_path):
    # Both files of another chain, consistent in themselves: they verify (the
    # hashes are not keyed), but the reported chain_id is the other chain's,
    # which is what the P0 relay's chain_replaced compares.
    path, audit = _rotated_twice(tmp_path)
    other_dir = tmp_path / "o"
    other_dir.mkdir()
    other, other_audit = _rotated_twice(other_dir, start=1000)
    os.replace(segment_path(other, 1), segment_path(path, 1))
    os.replace(other, path)
    result = verify_audit_chain(path)
    assert result["ok"] is True
    assert result["chain_id"] == other_audit.chain_id != audit.chain_id


# ---------------------------------------------------------------- empty
def test_an_empty_or_missing_file_is_empty_not_ok(tmp_path):
    path = tmp_path / "core-decision-audit.jsonl"
    for state in ("missing", "empty"):
        if state == "empty":
            path.write_bytes(b"")
        result = verify_audit_chain(path)
        assert result["ok"] is True and result["entries"] == 0 and result["scope"] == "empty"
        rc, full = _review(path, tmp_path)
        assert rc == 0 and "EMPTY (0 entries): nothing was verified" in full and "  OK (" not in full
        rc, compact = _review(path, tmp_path, "--compact")
        assert rc == 0 and "chain:EMPTY(0)" in compact and "chain:OK" not in compact
        rc, js = _review(path, tmp_path, "--json")
        chain = json.loads(js)["chain"]
        assert chain["scope"] == "empty" and "nothing was verified" in chain["meaning"]


# ------------------------------------------------------- the three outputs
def test_outputs_say_what_ok_means_for_a_rotated_chain(tmp_path):
    path, audit = _rotated_twice(tmp_path)
    segment_path(path, 1).unlink()
    entries = len(_lines(path))
    rc, full = _review(path, tmp_path)
    assert rc == 0
    assert f"  OK ({entries} entries, from_rotation_boundary)" in full
    assert "were rotated out, are not retained and were not verified" in full
    assert f"files         : {path.name}" in full and "records are not signed" in full
    rc, compact = _review(path, tmp_path, "--compact")
    assert rc == 0 and len(compact.splitlines()) == 1
    assert f"chain:OK({entries}) chain_scope=from_rotation_boundary chain_files=1" in compact
    rc, js = _review(path, tmp_path, "--json")
    chain = json.loads(js)["chain"]
    assert rc == 0 and chain["ok"] is True and chain["entries"] == entries
    assert chain["scope"] == "from_rotation_boundary" and chain["genesis_retained"] is False
    assert chain["files"] == [path.name] and chain["chain_id"] == audit.chain_id


def test_outputs_of_a_chain_from_its_genesis(tmp_path):
    path = tmp_path / "core-decision-audit.jsonl"
    _write(path, 4)
    rc, full = _review(path, tmp_path)
    assert rc == 0 and "  OK (4 entries, from_genesis)" in full
    rc, compact = _review(path, tmp_path, "--compact")
    assert "chain:OK(4) chain_scope=from_genesis chain_files=1" in compact


def test_a_failure_never_reads_as_ok(tmp_path):
    path, _ = _rotated_twice(tmp_path)
    _put(segment_path(path, 1), _lines(segment_path(path, 1))[:-1])
    rc, full = _review(path, tmp_path)
    assert rc == 3 and "MISMATCH: rotated_file_not_continued:1" in full
    assert "the chain is NOT OK" in full and "  OK (" not in full
    rc, compact = _review(path, tmp_path, "--compact")
    assert rc == 3 and "chain:MISMATCH:rotated_file_not_continued:1" in compact and "chain:OK" not in compact
    rc, js = _review(path, tmp_path, "--json")
    chain = json.loads(js)["chain"]
    assert rc == 3 and chain["ok"] is False and chain["scope"] == "not_verified"
    assert "not OK" in chain["meaning"]


def test_the_review_writes_nothing(tmp_path):
    path, _ = _rotated_twice(tmp_path)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    for flags in ((), ("--compact",), ("--json",)):
        _review(path, tmp_path, *flags)
    after = {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.name != "decision-explanations.jsonl"}
    before.pop("decision-explanations.jsonl", None)
    assert after == before


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
@pytest.mark.parametrize("what", ["file", "directory"])
def test_an_unreadable_chain_is_an_error_not_empty(tmp_path, what):
    d = tmp_path / "log"
    d.mkdir()
    path = d / "core-decision-audit.jsonl"
    _write(path, 3)
    target = path if what == "file" else d
    target.chmod(0)
    try:
        err = io.StringIO()
        with redirect_stderr(err):
            rc, out = _review(path, tmp_path, "--compact")
    finally:
        target.chmod(0o700)
    assert rc == 3 and "error reading audit log" in err.getvalue()
    assert "chain:MISMATCH:" in out and "chain:EMPTY" not in out and "chain:OK" not in out
