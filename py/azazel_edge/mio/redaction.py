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

import ipaddress
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
# Any URL-encoded character (%XX: "&", CR LF, "|", space, quote, ...) also
# counts as a left boundary, so "user%3Dbob%26password%3Dx" is found. A dot
# or slash before the label ("db.password: x", "/password%3Dx") is a key path
# and counts too; ":" does not, so a structured ref ("ev:auth:1") stays.
_LEFT = r"(?:(?<![A-Za-z0-9:_-])|(?<=%[0-9A-Fa-f]{2}))(?:[A-Za-z0-9]+[-_])*"
_RIGHT = r"(?![A-Za-z0-9])"
# Quoted value to its closing quote; otherwise to the end of the field.
# Unquoted values run to the field end, closing brackets included; a closing
# bracket only ends the value when its opening bracket precedes the label
# ("(pw: x)"), see ``_bracket_end``. ``_kv_end`` may extend the value over
# the following fields.
# A backslash escapes the next character inside quotes ("a\"b,c" is one
# value); the alternatives are disjoint, so matching stays linear.
_VALUE = r"""(?P<value>"(?:[^"\\\r\n]|\\.)*"?|'(?:[^'\\\r\n]|\\.)*'?|「[^」\r\n]*」?|[^\r\n,;&]+)"""
# Between label and value: an optional closing quote of a JSON/dict key
# ("password": x, 'password': x), then ":" or "=", also URL-encoded (%3A, %3D).
# The key's closing quote may be escaped (\" in a JSON string inside a log
# line) or URL-encoded (%22, %27).
_KV_SEP = r"""(?:\\?["']|%2[27])?\s*(?:[:=]|%3[AD])\s*"""

# Short labels that also occur in ordinary SOC prose ("auth: failed for admin",
# "pin: 3 hosts", "token: expired"). For these the value is kept only when the
# *whole* value is an ordinary phrase: it starts with a status word or a count,
# every word is a status word, an allowed ordinary word, or a short count
# followed by a unit word. Anything else (any unknown word, digits+letters,
# a bare digit run) is masked. If unsure, mask. Strong labels (password,
# api_key, ...) are always masked.
_WEAK_LABELS = frozenset({"auth", "pin", "pass", "pw", "secret", "token"})
_STATUS_WORDS = frozenset({
    "failed", "fail", "failure", "failures", "none", "null", "nil", "n/a", "na", "empty", "unset", "missing",
    "expired", "expiring", "rejected", "denied", "refused", "blocked", "revoked", "invalid", "valid", "ok",
    "success", "succeeded", "successful", "passed", "granted", "required", "optional", "disabled", "enabled",
    "true", "false", "yes", "no", "unknown", "leaked", "exposed", "compromised", "rotated", "reused", "reuse",
    "error", "errors", "timeout", "pending", "locked", "unlocked", "changed", "reset", "redacted", "detected",
})
_ORDINARY_WORDS = frozenset({
    "for", "in", "on", "at", "to", "from", "by", "of", "via", "with", "after", "before", "and", "or", "the", "a", "an",
    "admin", "root", "user", "users", "account", "accounts", "login", "logins", "repo", "repository", "host", "hosts",
    "device", "devices", "session", "sessions", "retry", "later", "again", "across", "attempt", "attempts",
})
# Network context the operator needs (IP addresses are kept, see the module
# docstring): after the first word, these words and IPv4/IPv6 addresses (with
# an optional port) count as ordinary, so "auth: failed, src 10.0.0.5" stays.
# Hostnames are not recognised here: a weak-label value with one is masked.
_CONTEXT_WORDS = frozenset({
    "src", "dst", "source", "destination", "ip", "addr", "address", "port", "peer", "client", "server", "remote", "local",
})
_PORT_SUFFIX = re.compile(r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:.]+\]):(?P<port>\d{1,5})")


def _is_address(word: str) -> bool:
    """A real IPv4/IPv6 address (``ipaddress`` parses it), with an optional
    port ("10.0.0.5:22", "[fe80::1]:22"). The unspecified addresses ("::",
    "0.0.0.0") are not: they carry nothing an operator needs and "::" is
    also a shape secrets can take."""
    if "]:" in word and not word.startswith("["):
        word = "[" + word  # the word strip removed the opening bracket
    m = _PORT_SUFFIX.fullmatch(word)
    if m is not None:
        if int(m.group("port")) > 65535:
            return False
        word = m.group("host").strip("[]")
    try:
        address = ipaddress.ip_address(word)
    except ValueError:
        return False
    return not address.is_unspecified
# Unit words that may follow a count. PIN gets a smaller list: a digit run
# after "pin:" is a PIN unless a unit word follows.
_UNIT_WORDS = frozenset({"host", "hosts", "attempt", "attempts", "device", "devices", "user", "users", "times", "sessions", "failures", "fail", "failed", "errors", "accounts"})
_PIN_UNIT_WORDS = frozenset({"host", "hosts", "attempt", "attempts", "device", "devices", "users", "times", "failures"})
_PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">"}
_OPENERS = {v: k for k, v in _PAIRS.items()}
_WORD_STRIP = ".,!?:\"'「」()[]{}<>"
_SEPARATORS = ",;&"
# One further field of a value; and a field that starts its own "key:"/"key=".
_SEGMENT = re.compile(r"[^\r\n,;&]*")
# A key starts with a letter or "_": "4821:9937:1102" is a value, not a field.
_NEW_FIELD = re.compile(r"\s*[A-Za-z_][A-Za-z0-9_.\-]*\s*[:=]")


def _ordinary_phrase(value: str, label: str, continuation: bool = False) -> bool:
    """Whether a weak label's value is ordinary prose. ``continuation`` is a
    further comma/semicolon segment of the same value: it may start with an
    ordinary word ("auth: failed, admin") and may be empty."""
    raw_words = value.split()
    words = [w.lower().strip(_WORD_STRIP) for w in raw_words]
    # A word made only of ":" and punctuation ("::") is not prose: mask.
    if any(not w and ":" in raw for w, raw in zip(words, raw_words)):
        return False
    words = [w for w in words if w]
    if not words:
        return continuation
    units = _PIN_UNIT_WORDS if label == "pin" else _UNIT_WORDS
    for i, w in enumerate(words):
        later = i > 0 or continuation
        if w in _STATUS_WORDS or (later and (w in _ORDINARY_WORDS or w in _CONTEXT_WORDS or _is_address(w))):
            continue
        # "port 22": a port number after the word "port". Not for PIN, whose
        # secret is a digit run ("pin: failed, port 4821" is masked).
        if label != "pin" and later and w.isdigit() and len(w) <= 5 and int(w) <= 65535 and i > 0 and words[i - 1] == "port":
            continue
        if w.isdigit() and len(w) <= 3:
            nxt = words[i + 1] if i + 1 < len(words) else ""
            # "12 fail" (count + unit) or "fail: 3" (counter after a status word)
            if nxt in units or (label != "pin" and i > 0 and words[i - 1] in _STATUS_WORDS and value.split()[i - 1].endswith(":")):
                continue
        return False
    return True


class _Scan:
    """Per-pattern scan state for the ``label: value`` rules.

    ``finditer`` yields matches left to right, so the bracket depth before each
    label is computed incrementally (each character is visited once), and
    ``limit`` is the start of the next match of the same pattern: a value's
    continuation never runs past it. Both keep masking linear in the text
    length (a per-match rescan from the line start was quadratic).
    """

    def __init__(self, norm: str):
        self.norm = norm
        self.limit = len(norm)
        # Where the next search starts when the value ended inside the match.
        self.resume = 0
        self.budget = 2 * len(norm) + 65536
        self._pos = 0
        self._depth: list[str] = []

    def closer_before(self, pos: int) -> str:
        """Closer of the innermost bracket opened before ``pos`` on its line."""
        depth = self._depth
        for ch in self.norm[self._pos:pos]:
            if ch == "\n":
                depth.clear()
            elif ch in _PAIRS:
                depth.append(_PAIRS[ch])
            elif depth and ch == depth[-1]:
                depth.pop()
        self._pos = max(self._pos, pos)
        return depth[-1] if depth else ""


def _bracket_end(norm: str, start: int, end: int, closer: str) -> Optional[int]:
    """Where a value inside ``(...)`` ends within ``norm[start:end]``, or None.

    The first closer followed by whitespace, end of text or field punctuation
    ends it ("(pw: x) next"), unless a later closer in the field has no opener
    of its own: then the secret itself held a closer ("(pw: p) ss)") and the
    value runs to the last such unmatched closer. If unsure, mask more.
    """
    opener = _OPENERS[closer]
    first = norm.find(closer, start, end)
    while first >= 0:
        nxt = norm[first + 1:first + 2]
        if not nxt or nxt.isspace() or nxt in ",;.!?&":
            break
        first = norm.find(closer, first + 1, end)
    if first < 0:
        return None
    last, balance = first, 0
    for i in range(first + 1, end):
        ch = norm[i]
        if ch == opener:
            balance += 1
        elif ch == closer:
            if balance:
                balance -= 1
            else:
                last = i
    return last


def _kv_end(norm: str, m: "re.Match[str]", scan: _Scan) -> Optional[int]:
    """End of a ``label: value`` mask, or None to keep an ordinary weak value.

    An unquoted value runs to the field end (``,``, ``;``, ``&``, line end)
    and then on through the following fields until one starts with its own
    ``key:``/``key=`` or the next label match begins: ``token: expired,
    abc123`` and ``password: a,b`` are one value, not a status word followed
    by an unrelated field. Inside brackets a closer ends it (``_bracket_end``).
    """
    vs, ve = m.span("value")
    label = m.group("label").lower().lstrip("_-")
    closer = scan.closer_before(m.start())
    parts: list[tuple[int, int]] = []
    end = ve
    if norm[vs:vs + 1] in "\"'「":
        parts.append((vs, ve))
    else:
        cut = _bracket_end(norm, vs, ve, closer) if closer else None
        parts.append((vs, ve if cut is None else cut))
        if cut is not None:
            scan.resume = cut
        end = parts[0][1]
        pos = ve
        while cut is None and pos < scan.limit and norm[pos] in _SEPARATORS:
            seg = _SEGMENT.match(norm, pos + 1, scan.limit)
            s, e = seg.span()
            if _NEW_FIELD.match(norm, s, e):
                break
            cut = _bracket_end(norm, s, e, closer) if closer else None
            if cut is not None:
                e = cut
            if norm[s:e].strip():
                parts.append((s, e))
                end = e
            pos = e
    if label in _WEAK_LABELS and _ordinary_phrase(norm[parts[0][0]:parts[0][1]], label) and all(
        _ordinary_phrase(norm[s:e], label, continuation=True) for s, e in parts[1:]
    ):
        return None
    return end


def _bearer_end(norm: str, m: "re.Match[str]", scan: _Scan) -> Optional[int]:
    """``bearer token <x>``: skip only the word "token", then examine x."""
    if m.group("skip") or m.group("bval").lower() in ("token", "tokens"):
        bval = m.group("bval").lower().strip(".,!?")
        if bval in ("token", "tokens") or bval in _ORDINARY_WORDS or bval in _STATUS_WORDS:
            return None
    return m.end()

_HEX_DIGEST = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", re.I)
_REF_WORD = re.compile(r"[A-Za-z][A-Za-z0-9._-]*:[A-Za-z0-9._:/#-]+")
_PREFIXED = r"(?:sk-|sk_live_|sk_test_|rk_live_|xox[abprs]-|gh[pousr]_|github_pat_|glpat-|AKIA|ASIA|AIza)"


def _long_token_end(norm: str, m: "re.Match[str]", scan: _Scan) -> Optional[int]:
    return None if _keep_long_token(norm, m) else m.end()


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


# A rule's optional callback returns the match end to mask, or None to skip.
_Keep = Optional[Callable[[str, "re.Match[str]", _Scan], Optional[int]]]
_RULES: tuple[tuple[str, "re.Pattern[str]", _Keep], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), None),
    ("url_userinfo", re.compile(r"(?<=://)[^\s/?#]+(?=@[^\s@/?#]+)"), None),
    # Password with spaces: "ftp://user:pa ss@host/".
    ("url_userinfo", re.compile(r"(?<=://)[^\s/?#:@]+:[^\r\n/?#]*(?=@[A-Za-z0-9.-]+(?:[:/?#\s]|$))"), None),
    # Scheme-less "user:pass@host". A plain email has no ":" before "@".
    ("url_userinfo", re.compile(r"(?<![A-Za-z0-9._:/@-])(?!mailto:)[A-Za-z0-9._-]+:(?!//)[^\s@/:]+(?=@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)", re.I), None),
    ("auth_header", re.compile(r"(?<![A-Za-z0-9])(?:proxy-)?authorization\s*[:=][^\r\n,;]*", re.I), None),
    ("bearer", re.compile(r"(?<![A-Za-z0-9])bearer(?:\s*[:=]\s*|\s+)(?P<skip>tokens?\s+)?(?P<bval>[^\s,;]+)", re.I), _bearer_end),
    ("bearer", re.compile(r"(?<![A-Za-z0-9])basic\s+[A-Za-z0-9+/]{8,}={0,2}", re.I), None),
    # Left boundary: without it every "eyJ" inside one long run starts a
    # new scan of the rest of the run (quadratic).
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), None),
    ("api_key", re.compile(r"(?<![A-Za-z0-9])" + _PREFIXED + r"[A-Za-z0-9_-]{6,}"), None),
    ("secret_kv", re.compile(_LEFT + _LABEL_ANY + _RIGHT + _KV_SEP + _VALUE, re.I), _kv_end),
    ("secret_kv", re.compile(_LEFT + _LABEL_PW + r"(?:\s+(?:is|was)\s+|\s*は\s*)" + _VALUE, re.I), _kv_end),
    # Japanese label then a space: "暗証番号 1234".
    ("secret_kv", re.compile(r"(?:パスワード|暗証番号|パスフレーズ|秘密鍵)\s+[A-Za-z0-9][^\s,;]*"), None),
    ("email", re.compile(r"(?:(?<=[Mm][Aa][Ii][Ll][Tt][Oo]:)|(?<![:/A-Za-z0-9._%+-]))[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), None),
    ("long_token", re.compile(r"(?<![A-Za-z0-9_+=-])[A-Za-z0-9_+=-]{32,}"), _long_token_end),
)
_TOKEN_RULES = frozenset({"private_key", "url_userinfo", "bearer", "jwt", "api_key", "email", "long_token"})


def _spans(text: str, labels: frozenset[str] | None = None) -> list[tuple[int, int, str]]:
    norm, index = _normalise(text)
    spans: list[tuple[int, int, str]] = []
    for label, pattern, keep in _RULES:
        if labels is not None and label not in labels:
            continue
        scan = _Scan(norm)
        m = pattern.search(norm)
        while m is not None:
            following = pattern.search(norm, max(m.end(), m.start() + 1))
            scan.limit = len(norm) if following is None else following.start()
            scan.resume = m.end()
            end = m.end() if keep is None else keep(norm, m, scan)
            if end is not None and end > m.start():
                spans.append((index[m.start()], index[end - 1] + 1, label))
            if scan.resume < m.end():
                # The value ended inside the match (a closing bracket), so the
                # rest of the match may hold another label ("[token: expired]
                # [token: x]"): search it again. Rescans share a budget of a
                # few times the text; past it the rest is masked instead, so
                # the work stays linear and the fallback is the safe side.
                rest = m.end() - scan.resume
                if rest <= scan.budget:
                    scan.budget -= rest
                    m = pattern.search(norm, scan.resume)
                    continue
                spans.append((index[scan.resume], index[m.end() - 1] + 1, label))
            m = following
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
