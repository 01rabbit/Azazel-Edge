from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = "/tmp/azazel-edge-bhusa-offline-bundle"
DEFAULT_FILES: tuple[tuple[str, str], ...] = (
    ("docs/arsenal/bhusa-2026-booth-message.md", "booth-message.md"),
    ("docs/arsenal/bhusa-2026-talk-track.md", "talk-track.md"),
    ("docs/arsenal/bhusa-2026-replay-runbook.md", "replay-runbook.md"),
    ("docs/arsenal/bhusa-2026-audit-walkthrough.md", "audit-walkthrough.md"),
    ("docs/arsenal/bhusa-2026-live-boundary.md", "live-boundary.md"),
    ("docs/arsenal/bhusa-2026-booth-runbook.md", "booth-runbook.md"),
    ("docs/arsenal/bhusa-2026-freeze-candidate.md", "freeze-candidate.md"),
    ("docs/arsenal/bhusa-2026-final-command-sheet.md", "final-command-sheet.md"),
    ("docs/ARSENAL_DEMO_PROFILE.md", "arsenal-demo-profile.md"),
    ("README.md", "README.md"),
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-bhusa-bundle",
        description="Build an offline BHUSA 2026 booth document bundle.",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to populate (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing output directory.",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")
    return parser


def _bundle_files(output_dir: Path) -> Dict[str, Any]:
    docs_dir = output_dir / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    copied: List[Dict[str, str]] = []
    for src_rel, dest_name in DEFAULT_FILES:
        src = ROOT_DIR / src_rel
        if not src.exists():
            raise ValueError(f"missing source file for bundle: {src_rel}")
        dest = docs_dir / dest_name
        shutil.copyfile(src, dest)
        copied.append(
            {
                "source": src_rel,
                "bundle_path": str(dest.relative_to(output_dir)),
            }
        )

    index_lines = [
        "# BHUSA 2026 Offline Bundle",
        "",
        "This directory is the booth-safe offline document bundle for the Black Hat USA 2026 Arsenal session.",
        "",
        "## Included documents",
        "",
    ]
    for item in copied:
        index_lines.append(f"- `{item['bundle_path']}` <- `{item['source']}`")
    (output_dir / "INDEX.md").write_text("\n".join(index_lines) + "\n", encoding="utf-8")

    manifest = {
        "title": "BHUSA 2026 Offline Bundle",
        "root": str(output_dir),
        "documents": copied,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    return {
        "ok": True,
        "output_dir": str(output_dir),
        "document_count": len(copied),
        "documents": copied,
    }


def _format_text(report: Dict[str, Any]) -> str:
    lines = [
        "BHUSA 2026 OFFLINE BUNDLE",
        f"output_dir: {report['output_dir']}",
        f"document_count: {report['document_count']}",
    ]
    for item in report["documents"]:
        lines.append(f"document: {item['bundle_path']} <- {item['source']}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir)
    try:
        if output_dir.exists():
            if not args.force:
                raise ValueError(f"output directory already exists: {output_dir}")
            shutil.rmtree(output_dir)
        report = _bundle_files(output_dir)
    except ValueError as exc:
        if args.json_output:
            print(json.dumps({"ok": False, "errors": [str(exc)]}, ensure_ascii=False, indent=2))
        else:
            print(f"result: FAIL\nerror: {exc}")
        return 2

    if args.json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(_format_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
