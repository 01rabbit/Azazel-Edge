#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PY_ROOT = Path(__file__).resolve().parent
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.runbook_review import propose_runbooks, review_runbook_id
from azazel_edge.runbooks import execute_runbook, get_runbook, list_runbooks


def main() -> int:
    parser = argparse.ArgumentParser(description="Azazel-Edge runbook broker")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list")

    show = sub.add_parser("show")
    show.add_argument("runbook_id")

    review = sub.add_parser("review")
    review.add_argument("runbook_id")
    review.add_argument("--context-json", default="{}")

    propose = sub.add_parser("propose")
    propose.add_argument("--question", required=True)
    propose.add_argument("--audience", default="beginner")
    propose.add_argument("--max-items", type=int, default=3)
    propose.add_argument("--context-json", default="{}")

    execute = sub.add_parser("execute")
    execute.add_argument("runbook_id")
    execute.add_argument("--args-json", default="{}")
    execute.add_argument("--run", action="store_true", help="execute instead of dry-run")
    execute.add_argument("--approved", action="store_true")
    execute.add_argument("--allow-controlled-exec", action="store_true")

    ns = parser.parse_args()
    if ns.cmd == "list":
        print(json.dumps({"ok": True, "items": list_runbooks()}, ensure_ascii=False, indent=2))
        return 0
    if ns.cmd == "show":
        print(json.dumps({"ok": True, "runbook": get_runbook(ns.runbook_id)}, ensure_ascii=False, indent=2))
        return 0
    if ns.cmd == "review":
        context = json.loads(ns.context_json or "{}")
        if not isinstance(context, dict):
            raise SystemExit("context-json must decode to object")
        print(json.dumps(review_runbook_id(ns.runbook_id, context=context), ensure_ascii=False, indent=2))
        return 0
    if ns.cmd == "propose":
        context = json.loads(ns.context_json or "{}")
        if not isinstance(context, dict):
            raise SystemExit("context-json must decode to object")
        print(
            json.dumps(
                propose_runbooks(ns.question, audience=ns.audience, max_items=max(1, min(ns.max_items, 10)), context=context),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    args = json.loads(ns.args_json or "{}")
    if not isinstance(args, dict):
        raise SystemExit("args-json must decode to object")
    result = execute_runbook(
        ns.runbook_id,
        args=args,
        dry_run=not ns.run,
        approved=bool(ns.approved),
        allow_controlled_exec=bool(ns.allow_controlled_exec),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
