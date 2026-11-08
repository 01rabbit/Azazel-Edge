#!/usr/bin/env python3
"""macOS/Linux demo readiness report; does not install or change system state."""
from __future__ import annotations
import argparse
import importlib.util
import json
import platform
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

def check() -> dict:
    modules = ["yaml", "requests", "azazel_edge"]
    sys.path.insert(0, str(ROOT / "py"))
    available = {name: importlib.util.find_spec(name) is not None for name in modules}
    files = {name: (ROOT / name).is_file() for name in (
        "bin/azazel-edge-scenario-replay", "config/soc_policy_profiles/demo.yaml",
        "tools/arsenal_bheurope_2026.py", "tools/arsenal_bheurope_monitor.py")}
    python_ok = sys.version_info >= (3, 10)
    return {"ok": python_ok and all(available.values()) and all(files.values()),
            "python": platform.python_version(), "platform": platform.platform(),
            "architecture": platform.machine(), "python_compatible": python_ok,
            "imports": available, "files": files,
            "mode": "synthetic_replay_no_enforcement",
            "note": "Static preflight only. Execute replay gate to establish functional readiness."}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = check()
    body = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body)
    print(body, end="")
    return 0 if report["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
