"""Carry the P0 relay's reconcile cursor to a moved audit file (Edge#471 stage 2).

The relay's cursor rows in the P0 queue are scoped by the audit file's path
(``audit_path``) and chain id (``p0_alert.P0AlertRelay._queue_cursor_and_hashes``).
Stage 2 moves ``core-decision-audit.jsonl`` (and ``.1``) and the P0 queue from
``/var/log/azazel-edge`` to ``/var/log/azazel-edge/ai``, together. Without
this step the relay finds no cursor of the new path and treats the chain as
``fresh_chain``: every P0 record it does not find among the queue's alerts
(for example ones the queue has since evicted) would be alerted again as a
past decision.

``carry_cursor`` appends one ``relay_status`` record
(``event: audit_path_migrated``) to the moved queue that repeats the old
path's last cursor under the new path, so the relay resumes with
``cursor_found``. It writes nothing unless:

* the queue has a scoped cursor (path and chain id) of the old path, and
* the chain at the new path has the same chain id and contains that cursor.

It is run once by the installer as root, with the agent stopped. It is not a
service API.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from azazel_edge.audit.segments import read_chain
from azazel_edge.notify.p0_alert import P0AlertQueue

EVENT = "audit_path_migrated"
# The files that move together: the chain, its rotated file, its Fabric
# sidecar and the P0 queue (whose cursors point into the chain).
CHAIN_FILES = (
    "core-decision-audit.jsonl",
    "core-decision-audit.jsonl.1",
    "core-decision-audit.fabric.jsonl",
    "p0-alert-queue.jsonl",
)
# AZAZEL_AI_AUDIT_LOG values for which the chain lives in the old or the new
# default directory (the chain and the queue sit beside the AI audit log).
OLD_DEFAULT_AUDIT_LOG = "/var/log/azazel-edge/ai-audit.jsonl"
NEW_DEFAULT_AUDIT_LOG = "/var/log/azazel-edge/ai/ai-audit.jsonl"


def _last_scoped_cursor(entries: List[Dict[str, Any]], path_id: str) -> Optional[Dict[str, str]]:
    found: Optional[Dict[str, str]] = None
    for row in entries:
        cursor = row.get("audit_cursor_chain_hash")
        chain_id = row.get("audit_chain_id")
        if (isinstance(cursor, str) and cursor and isinstance(chain_id, str) and chain_id
                and row.get("audit_path") == path_id):
            found = {"cursor": cursor, "chain_id": chain_id}
    return found


def carry_cursor(queue_path: str | Path, old_audit_path: str | Path, new_audit_path: str | Path) -> Dict[str, Any]:
    old_id = os.path.abspath(str(old_audit_path))
    new_id = os.path.abspath(str(new_audit_path))
    out: Dict[str, Any] = {"carried": False, "old_audit_path": old_id, "new_audit_path": new_id}
    if old_id == new_id:
        out["reason"] = "same_path"
        return out
    queue = P0AlertQueue(queue_path)
    entries = queue.read_entries()
    if _last_scoped_cursor(entries, new_id) is not None:
        out["reason"] = "new_path_already_has_a_cursor"
        return out
    old = _last_scoped_cursor(entries, old_id)
    if old is None:
        out["reason"] = "no_cursor_for_old_path"
        return out
    snapshot = read_chain(new_audit_path)
    if snapshot["chain_id"] != old["chain_id"]:
        out["reason"] = "chain_id_differs"
        return out
    hashes = set()
    for line in snapshot["lines"]:
        try:
            row = json.loads(line)
        except Exception:
            continue
        if isinstance(row, dict) and isinstance(row.get("chain_hash"), str):
            hashes.add(row["chain_hash"])
    if old["cursor"] not in hashes:
        out["reason"] = "cursor_not_in_moved_chain"
        return out
    queue.append_status({
        "event": EVENT,
        "audit_cursor_chain_hash": old["cursor"],
        "audit_chain_id": old["chain_id"],
        "audit_path": new_id,
        "migrated_from_audit_path": old_id,
    })
    out.update(carried=True, cursor=old["cursor"], chain_id=old["chain_id"])
    return out


def _regular(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    import stat as _stat
    return _stat.S_ISREG(st.st_mode)


def _present(path: Path) -> bool:
    return os.path.lexists(path)


def migrate_chain(old_dir: str | Path, new_dir: str | Path, audit_log_setting: str = "") -> Dict[str, Any]:
    """Move the chain files and the queue from ``old_dir`` to ``new_dir`` as
    one set and carry the relay's cursor. Safe to run again after a crash at
    any point:

    * ``audit_log_setting`` (the configured AZAZEL_AI_AUDIT_LOG) other than
      empty or one of the two defaults: the agent keeps its chain beside that
      file, so nothing is moved (``custom_audit_log``);
    * a name present in both directories: nothing is moved or overwritten
      (``clash``; resolve by hand);
    * any file in ``old_dir`` that is not a regular file: nothing is moved
      (``not_regular``);
    * ``old_dir`` and ``new_dir`` on different filesystems (``link`` fails
      with EXDEV): the move stops before that file, which stays in
      ``old_dir``; nothing is copied, unlinked or carried
      (``cross_filesystem``; move by hand, see the installer's notice);
    * otherwise every file still in ``old_dir`` is moved into ``new_dir`` by
      link + unlink (one filesystem; link never replaces an existing name);
      files already in ``new_dir`` from an interrupted earlier run stay, and
      a file left under both names by a crash between link and unlink is
      finished. Then the cursor is carried (a no-op when it already was, or
      when there is nothing to carry).
    """

    old_dir, new_dir = Path(old_dir), Path(new_dir)
    out: Dict[str, Any] = {"moved": [], "kept_in_new": [], "state": "", "carry": None}
    setting = str(audit_log_setting or "").strip().strip("\"'")
    if setting and setting not in (OLD_DEFAULT_AUDIT_LOG, NEW_DEFAULT_AUDIT_LOG):
        out["state"] = "custom_audit_log"
        out["audit_log_setting"] = setting
        return out
    # A crash between link and unlink below leaves one file under both names:
    # finish that move first.
    for name in CHAIN_FILES:
        a, b = old_dir / name, new_dir / name
        if _regular(a) and _regular(b) and os.path.samefile(a, b):
            os.unlink(a)
    in_old = [n for n in CHAIN_FILES if _present(old_dir / n)]
    in_new = [n for n in CHAIN_FILES if _present(new_dir / n)]
    clash = sorted(set(in_old) & set(in_new))
    if clash:
        out.update(state="clash", clash=clash)
        return out
    bad = [n for n in in_old if not _regular(old_dir / n)] + [n for n in in_new if not _regular(new_dir / n)]
    if bad:
        out.update(state="not_regular", not_regular=sorted(bad))
        return out
    out["kept_in_new"] = in_new
    for name in in_old:
        # link() never replaces an existing name (EEXIST), unlike rename().
        try:
            os.link(old_dir / name, new_dir / name)
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
            # The two directories are on different filesystems: link() cannot
            # move, and a copy + unlink would not be one step. Stop here; the
            # file stays in old_dir (its only copy) and nothing is unlinked.
            out.update(state="cross_filesystem", not_moved=[n for n in in_old if n not in out["moved"]])
            return out
        os.unlink(old_dir / name)
        out["moved"].append(name)
    if out["moved"]:
        out["state"] = "resumed" if in_new else "moved"
    else:
        out["state"] = "already_moved" if in_new else "nothing_to_move"
    try:
        os.unlink(old_dir / "p0-alert-queue.jsonl.lock")
    except FileNotFoundError:
        pass
    if _regular(new_dir / "p0-alert-queue.jsonl") and _regular(new_dir / "core-decision-audit.jsonl"):
        out["carry"] = carry_cursor(new_dir / "p0-alert-queue.jsonl", old_dir / "core-decision-audit.jsonl",
                                    new_dir / "core-decision-audit.jsonl")
    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--old-dir", required=True, help="where the chain and the queue are now")
    parser.add_argument("--new-dir", required=True, help="where they move to (same filesystem)")
    parser.add_argument("--audit-log-setting", default="", help="the configured AZAZEL_AI_AUDIT_LOG, if any")
    args = parser.parse_args(argv)
    result = migrate_chain(args.old_dir, args.new_dir, args.audit_log_setting)
    print(json.dumps(result, ensure_ascii=False))
    if result["state"] in ("clash", "not_regular", "custom_audit_log", "cross_filesystem"):
        return 2
    carry = result.get("carry")
    if carry is None or carry["carried"] or carry.get("reason") in ("no_cursor_for_old_path",
                                                                  "new_path_already_has_a_cursor"):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
