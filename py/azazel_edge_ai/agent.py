#!/usr/bin/env python3
"""Local AI advisory agent for normalized events from Rust core."""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from pathlib import Path
from typing import Any, Dict

SOCKET_PATH = Path(os.environ.get("AZAZEL_AI_SOCKET", "/run/azazel-edge/ai-bridge.sock"))
ADVISORY_PATH = Path(os.environ.get("AZAZEL_AI_ADVISORY", "/run/azazel-edge/ai_advisory.json"))
EVENT_LOG_PATH = Path(os.environ.get("AZAZEL_AI_EVENT_LOG", "/var/log/azazel-edge/ai-events.jsonl"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("azazel-edge-ai-agent")


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _recommendation(ev: Dict[str, Any], score: int) -> str:
    port = int(ev.get("target_port") or 0)
    if score >= 80:
        return f"Block source and route to decoy immediately (port={port})"
    if score >= 60:
        return f"Apply delay policy and increase telemetry (port={port})"
    return "Observe and continue baseline monitoring"


def _build_advisory(event: Dict[str, Any]) -> Dict[str, Any]:
    norm = event.get("normalized") if isinstance(event, dict) else {}
    if not isinstance(norm, dict):
        norm = {}

    risk_score = int(norm.get("risk_score") or 0)
    advisory = {
        "ts": time.time(),
        "source": "ai_agent",
        "risk_level": _risk_level(risk_score),
        "risk_score": risk_score,
        "attack_type": str(norm.get("attack_type") or "unknown"),
        "src_ip": str(norm.get("src_ip") or ""),
        "dst_ip": str(norm.get("dst_ip") or ""),
        "target_port": int(norm.get("target_port") or 0),
        "recommendation": _recommendation(norm, risk_score),
    }
    return advisory


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    _ensure_parent(path)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    _ensure_parent(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _handle_line(raw: str) -> None:
    raw = raw.strip()
    if not raw:
        return

    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        return

    advisory = _build_advisory(event)
    _append_jsonl(EVENT_LOG_PATH, {"event": event, "advisory": advisory})
    _write_json(ADVISORY_PATH, advisory)


def _serve() -> None:
    _ensure_parent(SOCKET_PATH)
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(SOCKET_PATH))
    os.chmod(SOCKET_PATH, 0o666)
    srv.listen(16)
    logger.info("AI advisory agent listening on %s", SOCKET_PATH)

    while True:
        conn, _ = srv.accept()
        with conn:
            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    _handle_line(line.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    _serve()
