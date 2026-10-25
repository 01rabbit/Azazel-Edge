"""Sensitive-text masking for operator-facing M.I.O. text (#389).

Used where free text must reach a human (the no-model handoff). The durable
trace audit does not rely on this: it keeps no free text at all.

This is a best-effort pattern list, not a guarantee. It covers common
credential/token/PII shapes (see ``_RULES``) and is defence in depth for
secrets that leaked into frame facts or model output. Unknown formats can still
pass. IP addresses and hostnames are kept because the operator needs them to
act (see docs/architecture/mio-reasoning-trace.md).

Matching runs on a normalised copy (zero-width/soft-hyphen removed, NFKC,
common Cyrillic/Greek confusables mapped to Latin) and the matching span of
the *original* text is replaced, so fullwidth, homoglyph and zero-width
variants are caught without rewriting unrelated text.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Callable, Optional

_ZERO_WIDTH = frozenset("​‌‍⁠﻿­᠎")
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ү": "Y", "І": "I", "Ѕ": "S", "Ј": "J",
    "ο": "o", "α": "a", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Κ": "K", "Μ": "M", "Ν": "N", "Ρ": "P", "Τ": "T", "Χ": "X",
}


def _normalise(text: str) -> tuple[str, list[int]]:
    """Normalised copy plus, for each normalised char, its original index."""
    out: list[str] = []
    index: list[int] = []
    for i, ch in enumerate(text):
        if ch in _ZERO_WIDTH:
            continue
        for n in unicodedata.normalize("NFKC", ch):
            out.append(_CONFUSABLES.get(n, n))
            index.append(i)
    return "".join(out), index


_PW = r"pass(?:word|wd|w0rd|phrase)?|pwd|pw|パスワード|暗証番号|パスフレーズ"
_LABEL_PW = r"(?P<label>" + _PW + r")"
_LABEL_ANY = (
    r"(?P<label>" + _PW + r"|secret|client[_-]?secret|(?:access|refresh|auth|api|session|bearer)?[_-]?token|"
    r"api[_-]?key|apikey|access[_-]?key|private[_-]?key|session(?:[_-]?id)?|set-cookie|cookie|credentials?|auth|pin|"
    r"秘密鍵|トークン|認証情報|アクセスキー)"
)
# Left boundary: not inside a word or a structured ref (``ev:auth:1``); an
# optional ``x-``/``my_`` style prefix is consumed so the result stays coherent.
_LEFT = r"(?<![A-Za-z0-9:/._-])(?:[A-Za-z0-9]+[-_])*"
_RIGHT = r"(?![A-Za-z0-9])"
# Quoted value to its closing quote; otherwise to the end of the field.
# Closing brackets end an unquoted value so "(pw: x)" keeps its ")".
_VALUE = r"""(?P<value>"[^"\r\n]*"?|'[^'\r\n]*'?|「[^」\r\n]*」?|[^\r\n,;&)\]}>]+)"""

# Short labels that also occur in ordinary SOC prose ("auth: failed for admin",
# "pin: 3 hosts", "token: expired"). For these, a status word or a count
# followed by words is not treated as a secret value. Strong labels
# (password, api_key, ...) are always masked.
_WEAK_LABELS = frozenset({"auth", "pin", "pass", "pw", "secret", "token"})
_STATUS_WORDS = frozenset({
    "failed", "fail", "failure", "failures", "none", "null", "nil", "n/a", "na", "empty", "unset", "missing",
    "expired", "expiring", "rejected", "denied", "refused", "blocked", "revoked", "invalid", "valid", "ok",
    "success", "succeeded", "successful", "passed", "granted", "required", "optional", "disabled", "enabled",
    "true", "false", "yes", "no", "unknown", "leaked", "exposed", "compromised", "rotated", "reused", "reuse",
    "error", "errors", "timeout", "pending", "locked", "unlocked", "changed", "reset", "redacted", "detected",
})


def _keep_ordinary_value(norm: str, m: "re.Match[str]") -> bool:
    label = m.group("label").lower().lstrip("_-")
    if label not in _WEAK_LABELS:
        return False
    value = m.group("value").strip().strip("\"'「」").strip()
    parts = value.split(None, 1)
    if not parts:
        return False
    first = parts[0].lower().rstrip(".!:")
    if first in _STATUS_WORDS:
        return True
    return first.isdigit() and len(parts) > 1 and parts[1][:1].isalpha()

_HEX_DIGEST = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", re.I)
_REF_WORD = re.compile(r"[A-Za-z][A-Za-z0-9._-]*:[A-Za-z0-9._:/#-]+")
_PREFIXED = r"(?:sk-|sk_live_|sk_test_|rk_live_|xox[abprs]-|gh[pousr]_|github_pat_|glpat-|AKIA|ASIA|AIza)"


def _keep_long_token(norm: str, m: "re.Match[str]") -> bool:
    tok = m.group(0)
    if _HEX_DIGEST.fullmatch(tok) or tok.isdigit():
        return True
    # Inside a structured ref such as ``ev:flow:<id>``: keep, unless the token
    # itself has a known secret prefix.
    start = m.start()
    while start > 0 and not norm[start - 1].isspace():
        start -= 1
    end = m.end()
    while end < len(norm) and not norm[end].isspace():
        end += 1
    word = norm[start:end].rstrip(".,;)")
    return bool(_REF_WORD.fullmatch(word)) and not re.match(_PREFIXED, tok)


_Keep = Optional[Callable[[str, "re.Match[str]"], bool]]
_RULES: tuple[tuple[str, "re.Pattern[str]", _Keep], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), None),
    ("url_userinfo", re.compile(r"(?<=://)[^\s/?#]+(?=@[^\s@/?#]+)"), None),
    # Password with spaces: "ftp://user:pa ss@host/".
    ("url_userinfo", re.compile(r"(?<=://)[^\s/?#:@]+:[^\r\n/?#]*(?=@[A-Za-z0-9.-]+(?:[:/?#\s]|$))"), None),
    # Scheme-less "user:pass@host". A plain email has no ":" before "@".
    ("url_userinfo", re.compile(r"(?<![A-Za-z0-9._:/@-])(?!mailto:)[A-Za-z0-9._-]+:(?!//)[^\s@/:]+(?=@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)", re.I), None),
    ("auth_header", re.compile(r"(?<![A-Za-z0-9])(?:proxy-)?authorization\s*[:=][^\r\n,;]*", re.I), None),
    ("bearer", re.compile(r"(?<![A-Za-z0-9])bearer(?:\s*[:=]\s*|\s+)(?!tokens?\b)[^\s,;)\]}>]+", re.I), None),
    ("bearer", re.compile(r"(?<![A-Za-z0-9])basic\s+[A-Za-z0-9+/]{8,}={0,2}", re.I), None),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), None),
    ("api_key", re.compile(r"(?<![A-Za-z0-9])" + _PREFIXED + r"[A-Za-z0-9_-]{6,}"), None),
    ("secret_kv", re.compile(_LEFT + _LABEL_ANY + _RIGHT + r"\s*[:=]\s*" + _VALUE, re.I), _keep_ordinary_value),
    ("secret_kv", re.compile(_LEFT + _LABEL_PW + r"(?:\s+(?:is|was)\s+|\s*は\s*)" + _VALUE, re.I), _keep_ordinary_value),
    # Japanese label then a space: "暗証番号 1234".
    ("secret_kv", re.compile(r"(?:パスワード|暗証番号|パスフレーズ|秘密鍵)\s+[A-Za-z0-9][^\s,;)\]}>]*"), None),
    ("email", re.compile(r"(?:(?<=[Mm][Aa][Ii][Ll][Tt][Oo]:)|(?<![:/A-Za-z0-9._%+-]))[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), None),
    ("long_token", re.compile(r"(?<![A-Za-z0-9_+=-])[A-Za-z0-9_+=-]{32,}"), _keep_long_token),
)
_TOKEN_RULES = frozenset({"private_key", "url_userinfo", "bearer", "jwt", "api_key", "email", "long_token"})


def _spans(text: str, labels: frozenset[str] | None = None) -> list[tuple[int, int, str]]:
    norm, index = _normalise(text)
    spans: list[tuple[int, int, str]] = []
    for label, pattern, keep in _RULES:
        if labels is not None and label not in labels:
            continue
        for m in pattern.finditer(norm):
            if m.end() == m.start() or (keep is not None and keep(norm, m)):
                continue
            spans.append((index[m.start()], index[m.end() - 1] + 1, label))
    spans.sort()
    merged: list[tuple[int, int, str]] = []
    for s, e, label in spans:
        if merged and s <= merged[-1][1]:
            ps, pe, pl = merged[-1]
            merged[-1] = (ps, max(pe, e), pl)
        else:
            merged.append((s, e, label))
    return merged


def redact_text(value: str) -> str:
    out, last = [], 0
    for s, e, label in _spans(value):
        out.append(value[last:s])
        out.append(f"[redacted:{label}]")
        last = e
    out.append(value[last:])
    return "".join(out)


def contains_sensitive(value: str) -> bool:
    return bool(_spans(value))


def contains_token_like(value: str) -> bool:
    """Credential/PII shapes only, without the ``label=value`` rules, so that
    structured identifiers such as ``ev:auth:1`` are not misclassified."""
    return bool(_spans(value, _TOKEN_RULES))
