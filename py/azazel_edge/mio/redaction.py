"""Sensitive-text masking for operator-facing M.I.O. text (#389).

Used where free text must reach a human (the no-model handoff). The durable
trace audit does not rely on this: it keeps no free text at all. Masking is
pattern-based and deliberately over-broad; it is a defence-in-depth layer for
credentials/tokens/PII-like strings that leaked into frame facts or model
output, not an anonymisation claim. IP addresses and hostnames are kept
because the operator needs them to act (see docs/architecture/mio-reasoning-trace.md).
"""
from __future__ import annotations

import re

_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)),
    ("auth_header", re.compile(r"\b(?:authorization|proxy-authorization)\s*[:=]\s*\S+(?:\s+\S+)?", re.I)),
    ("bearer", re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{6,}", re.I)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("url_userinfo", re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)")),
    ("secret_kv", re.compile(r"\b(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|session(?:id)?|cookie|set-cookie|auth)\b\s*[:=]\s*\S+", re.I)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("long_token", re.compile(r"\b[A-Za-z0-9+/_-]{32,}={0,2}")),
)


def redact_text(value: str) -> str:
    text = value
    for label, pattern in _RULES:
        text = pattern.sub(f"[redacted:{label}]", text)
    return text


def contains_sensitive(value: str) -> bool:
    return any(p.search(value) for _, p in _RULES)


_TOKEN_RULES = frozenset({"private_key", "bearer", "jwt", "aws_key", "url_userinfo", "email", "long_token"})


def contains_token_like(value: str) -> bool:
    """Credential/PII shapes only, without the ``key=value`` rule, so that
    structured identifiers such as ``ev:auth:1`` are not misclassified."""
    return any(p.search(value) for label, p in _RULES if label in _TOKEN_RULES)
