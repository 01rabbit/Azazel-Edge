#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azazel-Edge menu compatibility launcher.

The control menu is now integrated in the unified monitor:
  python3 py/azazel_edge/cli_unified.py --menu
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Azazel-Edge menu compatibility launcher"
    )
    parser.add_argument(
        "--textual",
        action="store_true",
        help="Kept for backward compatibility (ignored; Textual is always used).",
    )
    parser.add_argument(
        "--curses",
        action="store_true",
        help="Ignored for this launcher (menu requires Textual).",
    )
    parser.add_argument("--enable-epd", action="store_true", help="Enable E-Paper display updates")
    parser.add_argument("--disable-epd", action="store_true", help="Disable E-Paper display updates")
    args, passthrough = parser.parse_known_args()
    if args.curses:
        print("[Menu] --curses is ignored; launching Textual monitor menu.", file=sys.stderr)

    here = Path(__file__).resolve().parent
    monitor = here / "azazel_edge" / "cli_unified.py"
    cmd = [sys.executable, str(monitor), "--menu"]
    if args.enable_epd:
        cmd.append("--enable-epd")
    if args.disable_epd:
        cmd.append("--disable-epd")
    cmd.extend(passthrough)

    os.execv(cmd[0], cmd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
