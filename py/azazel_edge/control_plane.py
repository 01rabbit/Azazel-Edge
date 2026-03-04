from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Any, Dict, Generator, Optional, Tuple

from .path_schema import command_path_candidates, snapshot_path_candidates, warn_if_legacy_path

CONTROL_SOCKET = Path("/run/azazel-edge/control.sock")


def _socket_request(
    payload: Dict[str, Any],
    timeout_sec: float = 1.0,
    socket_path: Path = CONTROL_SOCKET,
) -> Dict[str, Any]:
    if not socket_path.exists():
        return {"ok": False, "error": f"control socket not found: {socket_path}"}
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        sock.connect(str(socket_path))
        sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        sock.close()
        if not chunks:
            return {"ok": False, "error": "empty response"}
        text = b"".join(chunks).decode("utf-8").strip()
        if not text:
            return {"ok": False, "error": "empty response"}
        return json.loads(text)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def send_action(
    action: str,
    params: Optional[Dict[str, Any]] = None,
    timeout_sec: float = 1.5,
    socket_path: Path = CONTROL_SOCKET,
) -> Dict[str, Any]:
    req: Dict[str, Any] = {"action": action, "ts": time.time()}
    if params is not None:
        req["params"] = params
    return _socket_request(req, timeout_sec=timeout_sec, socket_path=socket_path)


def read_snapshot_from_control_plane(
    timeout_sec: float = 0.8,
    socket_path: Path = CONTROL_SOCKET,
) -> Optional[Dict[str, Any]]:
    resp = send_action("get_snapshot", timeout_sec=timeout_sec, socket_path=socket_path)
    if not isinstance(resp, dict) or not resp.get("ok"):
        return None
    snap = resp.get("snapshot")
    if isinstance(snap, dict):
        return snap
    return None


def watch_snapshots(
    interval_sec: float = 1.0,
    socket_path: Path = CONTROL_SOCKET,
    timeout_sec: float = 5.0,
) -> Generator[Dict[str, Any], None, None]:
    if not socket_path.exists():
        return
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        sock.connect(str(socket_path))
        req = {"action": "watch_snapshot", "params": {"interval_sec": float(interval_sec)}}
        sock.sendall(json.dumps(req).encode("utf-8") + b"\n")
        buffer = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line_text = line.decode("utf-8", errors="ignore").strip()
                if not line_text:
                    continue
                payload = json.loads(line_text)
                if isinstance(payload, dict) and payload.get("ok") and isinstance(payload.get("snapshot"), dict):
                    yield payload["snapshot"]
    except Exception:
        return


def read_snapshot_from_files(logger: Any = None) -> Tuple[Optional[Dict[str, Any]], Optional[Path]]:
    candidates = snapshot_path_candidates()
    runtime_only = [p for p in candidates if str(p).startswith("/run/")]
    if not runtime_only:
        runtime_only = candidates[:2]
    for path in runtime_only:
        try:
            if not path.exists():
                continue
            warn_if_legacy_path(path, logger=logger)
            return json.loads(path.read_text(encoding="utf-8")), path
        except Exception:
            continue
    return None, None


def read_snapshot_payload(
    prefer_control_plane: bool = True,
    logger: Any = None,
) -> Tuple[Optional[Dict[str, Any]], str]:
    if prefer_control_plane:
        snap = read_snapshot_from_control_plane()
        if snap is not None:
            return snap, "CONTROL_PLANE"
    data, path = read_snapshot_from_files(logger=logger)
    if data is not None:
        return data, f"FILE:{path}"
    return None, "NONE"


def write_command_file_fallback(
    action: str,
    logger: Any = None,
    explicit_path: Optional[Path] = None,
) -> Optional[Path]:
    now = time.time()
    candidates = [explicit_path] if explicit_path is not None else command_path_candidates()
    out_path: Optional[Path] = None
    for p in candidates:
        if p is None:
            continue
        if p.exists() or p.parent.exists():
            out_path = p
            break
    if out_path is None and candidates:
        out_path = candidates[0]
    if out_path is None:
        return None
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps({"ts": now, "action": action}), encoding="utf-8")
        warn_if_legacy_path(out_path, logger=logger)
        return out_path
    except Exception:
        return None


def send_action_with_fallback(
    action: str,
    params: Optional[Dict[str, Any]] = None,
    logger: Any = None,
    fallback_cmd_path: Optional[Path] = None,
) -> Dict[str, Any]:
    resp = send_action(action, params=params)
    if resp.get("ok"):
        return resp
    fallback = write_command_file_fallback(action, logger=logger, explicit_path=fallback_cmd_path)
    if fallback is None:
        return resp
    return {
        "ok": True,
        "action": action,
        "fallback": "command_file",
        "path": str(fallback),
        "error": resp.get("error"),
        "ts": time.time(),
    }
