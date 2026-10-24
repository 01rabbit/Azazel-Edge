"""Child process for the SO-07 process-kill harness. Not a product entry point.

It drives Edge's real ``P0AuditLogger`` and reports each action as complete on
stdout only after ``log()`` has returned -- which is how every Edge caller
treats a completed audit write. The parent kills this process at chosen
instants and then checks, from a fresh process, that every action reported
complete has its record.

Fault-injection points that sit *inside* ``log()`` are reached by pausing the
child at that point (it announces ``PAUSE`` and blocks), so the parent's kill
lands exactly there. The pause wraps the logger's own file handle and its own
projection hook; it changes no record and no ordering. It exists only in this
child, never in the product.

Protocol (stdout, one line each): ``READY``, ``COMPLETE <seq> <trace_id>``,
``PAUSE <seq> <point>``, and for ``--restart``: ``PRESENT <json list>``,
``CHAIN <json>``.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def _out(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _block_forever() -> None:
    while True:
        time.sleep(3600)


def _install_pause(point: str, pause_at: int, audit_path: Path, state: dict) -> None:
    import azazel_edge.audit.logger as logger_mod

    if point == "between_write_and_close":
        original_open = Path.open

        def patched_open(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            fh = original_open(self, *args, **kwargs)
            if Path(self) != audit_path or state["seq"] != pause_at:
                return fh
            real_close = fh.close

            class _Paused:
                def __init__(self, inner):
                    self._inner = inner

                def write(self, data):
                    return self._inner.write(data)

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    # The record is written into the handle's buffer, not yet
                    # flushed or closed. Kill lands here.
                    _out(f"PAUSE {state['seq']} {point}")
                    _block_forever()
                    real_close()  # pragma: no cover - unreachable

            return _Paused(fh)

        Path.open = patched_open  # type: ignore[assignment]
        logger_mod.Path.open = patched_open  # type: ignore[attr-defined]
    elif point in ("after_close_before_return", "during_fabric_projection"):
        import azazel_edge.audit.fabric_adapter as fabric_mod

        original = fabric_mod.project_audit_record

        def patched(record, path):  # type: ignore[no-untyped-def]
            # log() calls the projection after the chained file is closed and
            # before returning. "after_close_before_return" pauses on entry,
            # "during_fabric_projection" after the projection ran.
            if state["seq"] == pause_at and point == "after_close_before_return":
                _out(f"PAUSE {state['seq']} {point}")
                _block_forever()
            result = original(record, path)
            if state["seq"] == pause_at and point == "during_fabric_projection":
                _out(f"PAUSE {state['seq']} {point}")
                _block_forever()
            return result

        fabric_mod.project_audit_record = patched


def run_writer(args: argparse.Namespace) -> int:
    from azazel_edge.audit import P0AuditLogger

    audit_path = Path(args.audit)
    state = {"seq": 0}
    if args.point in ("between_write_and_close", "after_close_before_return", "during_fabric_projection"):
        _install_pause(args.point, args.pause_at, audit_path, state)
    logger = P0AuditLogger(audit_path)
    _out("READY")
    payload_pad = "x" * max(0, int(args.pad))
    for seq in range(1, int(args.count) + 1):
        state["seq"] = seq
        trace_id = f"{args.prefix}-{seq:05d}"
        logger.log(args.kind, trace_id=trace_id, source="so07_harness", seq=seq, pad=payload_pad)
        # log() has returned: this is the moment any Edge caller reports the
        # action complete.
        _out(f"COMPLETE {seq} {trace_id}")
        if args.interval_ms > 0:
            time.sleep(args.interval_ms / 1000.0)
    _out("DONE")
    return 0


def run_restart(args: argparse.Namespace) -> int:
    from azazel_edge.audit import P0AuditLogger

    audit_path = Path(args.audit)
    # Restart exactly as Edge does: construct the logger on the existing file
    # (it re-reads the chain head), then write one record after the restart.
    logger = P0AuditLogger(audit_path)
    logger.log("event_receive", trace_id=f"{args.prefix}-post-restart", source="so07_harness_restart")
    present = []
    torn = 0
    if audit_path.exists():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            try:
                present.append(str(json.loads(line).get("trace_id") or ""))
            except Exception:
                torn += 1
    try:
        chain = P0AuditLogger.verify_chain(audit_path)
    except Exception as exc:  # a torn line makes verify_chain raise
        chain = {"ok": False, "entries": None, "error": f"verify_chain_raised:{type(exc).__name__}"}
    chain["torn_lines"] = torn
    _out("PRESENT " + json.dumps(present))
    _out("CHAIN " + json.dumps(chain, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--kind", default="event_receive")
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--interval-ms", type=float, default=0.0)
    parser.add_argument("--point", default="")
    parser.add_argument("--pause-at", type=int, default=0)
    parser.add_argument("--pad", type=int, default=0)
    parser.add_argument("--restart", action="store_true")
    args = parser.parse_args(argv)
    return run_restart(args) if args.restart else run_writer(args)


if __name__ == "__main__":
    raise SystemExit(main())
