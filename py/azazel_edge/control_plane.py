from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path
from typing import Any, Dict, Generator, Optional, Tuple

from .path_schema import command_path_candidates, runtime_snapshot_path_candidates, warn_if_legacy_path

CONTROL_SOCKET = Path(os.environ.get("AZAZEL_CONTROL_SOCKET", "/run/azazel-edge/control.sock"))


def _socket_request(
    payload: Dict[str, Any],
    timeout_sec: float = 1.0,
    socket_path: Path = CONTROL_SOCKET,
) -> Dict[str, Any]:
    """One request on control.sock (Edge#477).

    * A reply from the daemon is returned as it is (a reply that is not a
      JSON object is a failure, ``invalid response``).
    * ``"transport_error": True``: the request never reached the daemon (no
      socket, the socket could not be created, connect failed). Only this
      may be handed to another path.
    * ``"delivery_unknown": True``: the request was (or may have been) sent
      but no reply came (send failed part way, timeout, or the connection
      closed before a reply). The daemon may have carried it out, so this is
      never retried or handed elsewhere.
    """
    if not socket_path.exists():
        return {"ok": False, "error": f"control socket not found: {socket_path}", "transport_error": True}
    sock: Optional[socket.socket] = None
    try:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout_sec)
            sock.connect(str(socket_path))
        except Exception as exc:
            return {"ok": False, "error": str(exc), "transport_error": True}
        chunks: list[bytes] = []
        try:
            sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
        except Exception as exc:
            if not chunks:
                return {"ok": False, "error": f"no reply from the control daemon: {exc}", "delivery_unknown": True}
            # part of a reply arrived: the daemon answered, but not usably
            return {"ok": False, "error": f"invalid response: incomplete reply ({exc})"}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    text = b"".join(chunks).decode("utf-8", errors="replace").strip()
    if not text:
        return {"ok": False, "error": "no reply from the control daemon: closed before a reply",
                "delivery_unknown": True}
    try:
        reply = json.loads(text.splitlines()[0])
    except (ValueError, RecursionError) as exc:
        return {"ok": False, "error": f"invalid response: {type(exc).__name__}"}
    if not isinstance(reply, dict):
        return {"ok": False, "error": "invalid response: not an object"}
    return reply


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
    errors: Optional[list] = None,
) -> Generator[Dict[str, Any], None, None]:
    """Yield snapshots from the daemon's watch_snapshot stream.

    The stream ends when the daemon closes it (also right after refusing it,
    for example ``busy`` when too many streams are open) or the socket fails.
    When ``errors`` is a list, the reason the stream ended is appended to it
    (the daemon's last error string, ``socket_missing``, ``stream_closed`` or
    ``stream_error:<exception>``), so a caller can report the end instead of
    stopping silently (Edge#477).
    """
    def _note(reason: str) -> None:
        if errors is not None:
            errors.append(str(reason))

    if not socket_path.exists():
        _note("socket_missing")
        return
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        sock.connect(str(socket_path))
        req = {"action": "watch_snapshot", "params": {"interval_sec": float(interval_sec)}}
        sock.sendall(json.dumps(req).encode("utf-8") + b"\n")
        buffer = b""
        last_error = ""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                # A refusal ("busy", "forbidden") is the last line before the
                # daemon closes; report it rather than a bare close.
                _note(last_error or "stream_closed")
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line_text = line.decode("utf-8", errors="ignore").strip()
                if not line_text:
                    continue
                payload = json.loads(line_text)
                if isinstance(payload, dict) and payload.get("ok") and isinstance(payload.get("snapshot"), dict):
                    last_error = ""
                    yield payload["snapshot"]
                elif isinstance(payload, dict) and payload.get("ok") is False:
                    # Not a snapshot (no snapshot yet, or a refusal such as
                    # "busy" right before the daemon closes). Keep reading;
                    # the stream itself decides whether it ends.
                    last_error = str(payload.get("error") or "daemon_error")[:64]
    except Exception as exc:
        _note(f"stream_error:{type(exc).__name__}")
        return
    finally:
        # Close at once (also when the consumer stops iterating), so the
        # daemon sees the end of stream and frees the watch slot.
        try:
            sock.close()
        except Exception:
            pass


def read_snapshot_from_files(logger: Any = None) -> Tuple[Optional[Dict[str, Any]], Optional[Path]]:
    for path in runtime_snapshot_path_candidates():
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
    """Send ``action`` to the control daemon.

    Whatever the daemon answers is returned as it is, also a refusal
    (``forbidden``, ``busy``, a rate limit, an unknown action, a failed
    script, ``not_implemented``): a refusal is never turned into success.

    Only when the request never reached the daemon (``transport_error``: no
    socket, connect failed) is the legacy command file ``ui_command.json``
    written. When it was sent but no reply came (``delivery_unknown``), the
    daemon may have carried it out, so nothing is written and that result is
    returned. Nothing in Azazel-Edge reads that
    file, so the result stays ``ok: False`` with ``undelivered: True`` and the
    path; it is not reported as done (Edge#477; before, it was ``ok: True``).
    """
    resp = send_action(action, params=params)
    if resp.get("ok") or not resp.get("transport_error"):
        return resp
    fallback = write_command_file_fallback(action, logger=logger, explicit_path=fallback_cmd_path)
    if fallback is None:
        return resp
    return {
        "ok": False,
        "action": action,
        "undelivered": True,
        "fallback": "command_file",
        "path": str(fallback),
        "error": (f"control daemon not reached ({resp.get('error')}); the request was written to "
                  f"{fallback}, which nothing in Azazel-Edge reads: not delivered"),
        "ts": time.time(),
    }


def describe_action_failure(result: Any, label: str) -> str:
    """One line for a CLI saying why ``label`` was not done (Edge#477).

    ``not_implemented`` and an undelivered command file are named as such, so
    neither reads like an ordinary success or a vague failure."""
    if not isinstance(result, dict):
        return f"• action failed: {label} (unexpected response)"
    if result.get("not_implemented") or result.get("error") == "not_implemented":
        return f"• action not implemented: {label} (nothing was done)"
    if result.get("undelivered"):
        return f"• action not delivered: {label} (control daemon not reached)"
    if result.get("delivery_unknown"):
        return (f"• no reply from the control daemon: {label} (it may have been carried out; "
                "check the state before running it again)")
    return f"• action failed: {label} ({result.get('error', 'unknown error')})"
