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
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from azazel_edge.audit.segments import read_chain
from azazel_edge.notify.p0_alert import P0AlertQueue

EVENT = "audit_path_migrated"


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


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--queue", required=True, help="the moved P0 queue")
    parser.add_argument("--old-audit", required=True, help="the core-decision audit file's old path")
    parser.add_argument("--new-audit", required=True, help="the core-decision audit file's new path")
    args = parser.parse_args(argv)
    result = carry_cursor(args.queue, args.old_audit, args.new_audit)
    print(json.dumps(result, ensure_ascii=False))
    if result["carried"] or result.get("reason") in ("no_cursor_for_old_path", "new_path_already_has_a_cursor"):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
