from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any, Dict, List


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _write_json_file(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _parse_json_dict_lenient(text: str) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        pass
    try:
        decoder = json.JSONDecoder()
        parsed, _idx = decoder.raw_decode(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _read_json_file(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            data = _parse_json_dict_lenient(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        return {}
    return {}


def _tail_jsonl(path: Path, limit: int = 20) -> List[Dict[str, Any]]:
    rows: deque[Dict[str, Any]] = deque(maxlen=max(1, int(limit)))
    try:
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except Exception:
                    continue
                if isinstance(payload, dict):
                    rows.append(payload)
    except Exception:
        return []
    return list(rows)


def _tail_first_existing_jsonl(paths: List[Path], limit: int = 20) -> List[Dict[str, Any]]:
    for path in paths:
        rows = _tail_jsonl(path, limit=limit)
        if rows:
            return rows
    return []
