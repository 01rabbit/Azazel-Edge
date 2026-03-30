from __future__ import annotations

import ast
import sys
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
CHECK_SUFFIXES = {".py", ".md", ".html", ".txt"}


def iter_files():
    for path in WORKSPACE_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if ".venv" in path.parts or "__pycache__" in path.parts:
            continue
        if path.name == "Makefile" or path.suffix in CHECK_SUFFIXES:
            yield path


def main() -> int:
    errors: list[str] = []

    for path in iter_files():
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if line.rstrip() != line:
                errors.append(f"{path}:{line_no}: trailing whitespace")
            if path.suffix == ".py" and "\t" in line:
                errors.append(f"{path}:{line_no}: tab character in python file")
        if path.suffix == ".py":
            try:
                ast.parse(text, filename=str(path))
            except SyntaxError as exc:
                errors.append(f"{path}:{exc.lineno}: syntax error: {exc.msg}")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("lint: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

