from __future__ import annotations

import sys
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

from flask import g, jsonify, request


def _state():
    return sys.modules["azazel_edge_web.app"]


def _normalize_role(role: str, default: str = "viewer") -> str:
    state = _state()
    role_norm = str(role or "").strip().lower()
    return role_norm if role_norm in state._ROLE_RANK else default


def _role_allows(actual_role: str, required_role: str) -> bool:
    state = _state()
    return state._ROLE_RANK.get(_normalize_role(actual_role), 0) >= state._ROLE_RANK.get(_normalize_role(required_role), 0)


def _load_mtls_allowlist() -> set[str]:
    state = _state()
    allowed = set(state.AUTH_MTLS_FINGERPRINTS)
    try:
        if state.AUTH_MTLS_FINGERPRINTS_FILE.exists():
            for line in state.AUTH_MTLS_FINGERPRINTS_FILE.read_text(encoding="utf-8").splitlines():
                item = line.strip().lower()
                if item and not item.startswith("#"):
                    allowed.add(item)
    except Exception:
        pass
    return allowed


def _load_auth_tokens() -> List[Dict[str, str]]:
    state = _state()
    try:
        if state.AUTH_TOKENS_FILE.exists():
            payload = state._parse_json_dict_lenient(state.AUTH_TOKENS_FILE.read_text(encoding="utf-8"))
            items = payload.get("tokens") if isinstance(payload.get("tokens"), list) else payload.get("items")
            if isinstance(items, list):
                out: List[Dict[str, str]] = []
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    token = str(item.get("token") or "").strip()
                    if not token:
                        continue
                    out.append(
                        {
                            "token": token,
                            "principal": str(item.get("principal") or "unknown").strip() or "unknown",
                            "role": _normalize_role(str(item.get("role") or "viewer"), default="viewer"),
                        }
                    )
                if out:
                    return out
    except Exception:
        pass
    legacy = state.load_token()
    if legacy:
        return [{"token": legacy, "principal": "legacy-token", "role": "admin"}]
    return []


def _authenticate_request() -> Dict[str, Any]:
    state = _state()
    req_token = (
        request.headers.get("X-AZAZEL-TOKEN")
        or request.headers.get("X-Auth-Token")
        or request.args.get("token")
    )
    req_token = str(req_token or "").strip()
    token_items = _load_auth_tokens()
    if not token_items:
        return {"ok": bool(state.AUTH_FAIL_OPEN), "principal": "anonymous", "role": "admin" if state.AUTH_FAIL_OPEN else "viewer", "reason": "auth_material_missing"}
    if not req_token:
        return {"ok": False, "principal": "anonymous", "role": "viewer", "reason": "missing_token"}
    for item in token_items:
        if req_token == str(item.get("token") or ""):
            return {"ok": True, "principal": str(item.get("principal") or "unknown"), "role": _normalize_role(str(item.get("role") or "viewer")), "reason": "ok"}
    return {"ok": False, "principal": "anonymous", "role": "viewer", "reason": "token_mismatch"}


def _authorize_mtls(required_role: str) -> Dict[str, Any]:
    state = _state()
    if not state.AUTH_MTLS_REQUIRED:
        return {"ok": True, "reason": "mtls_not_required"}
    if state._ROLE_RANK.get(_normalize_role(required_role), 0) < state._ROLE_RANK["operator"]:
        return {"ok": True, "reason": "mtls_not_required_for_viewer"}
    observed = str(request.headers.get(state.AUTH_MTLS_HEADER) or "").strip().lower()
    if not observed:
        return {"ok": False, "reason": "mtls_header_missing"}
    allowlist = _load_mtls_allowlist()
    if not allowlist:
        return {"ok": False, "reason": "mtls_allowlist_empty"}
    if observed not in allowlist:
        return {"ok": False, "reason": "mtls_fingerprint_mismatch"}
    return {"ok": True, "reason": "ok"}


def _audit_authz_event(
    *,
    allowed: bool,
    required_role: str,
    principal: str,
    role: str,
    reason: str,
) -> None:
    state = _state()
    try:
        state._append_jsonl(
            state.AUTHZ_AUDIT_LOG,
            {
                "ts": time.time(),
                "trace_id": state._request_trace_id(),
                "endpoint": str(request.path or ""),
                "method": str(request.method or ""),
                "requested_action": state._request_action_hint(),
                "required_role": _normalize_role(required_role),
                "principal": str(principal or "anonymous"),
                "role": _normalize_role(role),
                "allowed": bool(allowed),
                "reason": str(reason or ""),
                "remote_addr": str(request.remote_addr or ""),
            },
        )
    except Exception as e:
        state.app.logger.warning(f"authz audit logging failed: {e}")


def _unauthorized_response(*, ok_payload: Optional[bool] = False, status_code: int = 403):
    if ok_payload is None:
        payload: Dict[str, Any] = {"error": "Unauthorized"}
    else:
        payload = {"ok": bool(ok_payload), "error": "Unauthorized"}
    return jsonify(payload), int(status_code)


def require_token(
    *,
    ok_payload: Optional[bool] = False,
    status_code: int = 403,
    min_role: str = "viewer",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Endpoint decorator that centralizes token verification responses."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            state = _state()
            required_role = _normalize_role(min_role, default="viewer")
            auth = _authenticate_request()
            role = _normalize_role(str(auth.get("role") or "viewer"))
            principal = str(auth.get("principal") or "anonymous")
            if not bool(auth.get("ok")):
                _audit_authz_event(
                    allowed=False,
                    required_role=required_role,
                    principal=principal,
                    role=role,
                    reason=str(auth.get("reason") or "auth_failed"),
                )
                if state.AUTH_FAIL_OPEN:
                    state.app.logger.warning("AUTH_FAIL_OPEN active: allowing request despite auth failure")
                else:
                    return _unauthorized_response(ok_payload=ok_payload, status_code=status_code)
            mtls = _authorize_mtls(required_role)
            if not bool(mtls.get("ok")):
                _audit_authz_event(
                    allowed=False,
                    required_role=required_role,
                    principal=principal,
                    role=role,
                    reason=str(mtls.get("reason") or "mtls_failed"),
                )
                return _unauthorized_response(ok_payload=ok_payload, status_code=status_code)
            if not _role_allows(role, required_role):
                _audit_authz_event(
                    allowed=False,
                    required_role=required_role,
                    principal=principal,
                    role=role,
                    reason="insufficient_role",
                )
                return _unauthorized_response(ok_payload=ok_payload, status_code=status_code)
            g.auth_principal = principal
            g.auth_role = role
            g.auth_required_role = required_role
            _audit_authz_event(
                allowed=True,
                required_role=required_role,
                principal=principal,
                role=role,
                reason=str(auth.get("reason") or "ok"),
            )
            return func(*args, **kwargs)

        return wrapped

    return decorator
