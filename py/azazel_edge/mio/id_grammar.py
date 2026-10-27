"""Closed identifier grammar shared by the M.I.O. surfaces (#384, #385, #386).

One module defines what a valid M.I.O. identifier looks like. Three surfaces
use it, and each keeps its own policy for a value that does not match:

* the model output parser (``contracts.model_id_ok`` / ``safe_model_id``):
  the value becomes ``invalid-model-id`` and the cycle is rejected,
* the no-model handoff (``handoff.build_no_model_handoff``): the value
  becomes a fixed placeholder,
* the Capability Broker audit projection (``broker._audit_id``): the value
  becomes a keyed digest.

Each identifier kind is defined exactly once in ``ID_KINDS``. A surface field
accepts a fixed tuple of kinds (``MODEL_ID_GRAMMAR`` in contracts,
``HANDOFF_ID_KINDS`` in handoff, ``AUDIT_ID_KINDS`` here). Every kind is an
exact-match allowlist built from the shapes the repository produces; a shape
not listed is refused, it is not guessed at.

Every kind also has to pass one second layer (``second_layer_ok``): the
SituationFrame opaque-ID address checks (``opaque_id``: IPv4 quads, also
dashed or with a port, MAC-like runs, IPv6, at most 128 characters) and the
secret checks (a secret word, or an M.I.O. redaction token shape such as an
API key, bearer token, JWT, e-mail or long token).

Non-string values are refused, never stringified. Nothing here grants
authority; it only decides whether an identifier may be shown verbatim.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, Mapping

from .redaction import contains_token_like

# --- second layer: address shapes ---------------------------------------------
_OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
# Address-shaped substrings refused anywhere inside an opaque ID: dotted or
# dashed quads (with or without :port) and MAC-like runs. IPv6-like runs are
# checked separately (_has_ipv6_like_run) so ordinary IDs such as ev:12:34:56
# still pass.
_ADDRESS_LIKE_RES = (
    re.compile(r"(?<![0-9])\d{1,3}(?:[.\-_]\d{1,3}){3}(?![0-9])"),
    re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{2}(?:[:.\-_][0-9a-f]{2}){5}(?![0-9a-f])"),
    re.compile(r"(?i)[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"),
)
_HEX_COLON_RUN_RE = re.compile(r"(?i)[0-9a-f:]*:[0-9a-f:]*")


def _has_ipv6_like_run(value: str) -> bool:
    """A run of hex digits and colons with five or more groups, or one that
    parses as an IPv6 address (e.g. fe80::1, ::1). Shorter runs such as
    12:34:56 are ordinary ID segments."""
    for run in _HEX_COLON_RUN_RE.findall(value):
        if run.strip(":").count(":") >= 4:
            return True
        for candidate in (run, run.strip(":")):
            if "::" in candidate or candidate.count(":") == 7:
                try:
                    ipaddress.IPv6Address(candidate)
                except ValueError:
                    continue
                return True
    return False


def opaque_id(value: Any) -> str:
    """Return an opaque identifier or "" if the value is not one. IP and MAC
    addresses are personal data, not identifiers, and are refused. The
    SituationFrame uses this for every nested identifier."""
    if not isinstance(value, str) or not _OPAQUE_ID_RE.match(value):
        return ""
    if any(pattern.search(value) for pattern in _ADDRESS_LIKE_RES) or _has_ipv6_like_run(value):
        return ""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    return ""


# --- second layer: secret shapes ----------------------------------------------
SECRET_WORD_RE = re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|token|bearer)")


def has_secret_shape(value: str) -> bool:
    """A secret word, or a credential/PII shape from the M.I.O. redaction
    token rules (``contains_token_like``)."""
    return bool(SECRET_WORD_RE.search(value)) or contains_token_like(value)


def second_layer_ok(value: str) -> bool:
    """No address shape and no secret shape. Every kind must pass this."""
    return opaque_id(value) == value and not has_secret_shape(value)


# --- identifier kinds (each defined once) -------------------------------------
# Kinds after ``ev:`` that structured evidence refs use (fixtures, capability
# results): the intersection of the kinds the model output parser and the
# no-model handoff accepted before their grammars were merged.
EVIDENCE_REF_KINDS = ("alert", "auth", "dns", "flow", "http", "ssh", "tls")

# Trace / frame ids from the frame builder callers (bin/azazel-mio-shadow-replay,
# mio/evaluation.py, fixtures). Words come from fixed lists, never from input.
# Six-digit counters leave room for a run counter while staying far below the
# ten digits an IPv4 address needs in decimal.
_TRACE_HEAD = r"(?:trace|mio|evaluation|incident|replay)"
_TRACE_WORDS = r"(?:-(?:golden|fixture|shadow|auth|scan|trace|frame))*"
_TRACE_TAIL = r"(?:-v?[0-9]{1,6})?"
_TRACE_SHAPE = _TRACE_HEAD + _TRACE_WORDS + _TRACE_TAIL

# Words allowed in cycle / request ids (and the other ids the broker audits),
# joined by ``:``, ``-`` or ``_`` with short ordinals.
ID_WORDS = frozenset(
    {
        # structure
        "ev", "evidence", "trace", "cycle", "req", "frame", "mio", "fixture", "replay", "evaluation",
        "golden", "shadow", "scenario", "demo", "test", "sample", "hypothesis", "gap",
        # evidence sources and kinds
        "auth", "flow", "sys", "noc", "soc", "ssh", "alert", "alerts", "dns", "tls", "icmp", "iface",
        "probe", "plane", "activity",
        # defensive states
        "observe", "notify", "throttle", "redirect", "isolate",
        # evaluation / replay scenario words
        "contradictory", "role", "cross", "fabricated", "ref", "empty", "recommendation", "captured",
        "malformed", "model", "output", "timeout", "no", "llm", "unavailable", "prompt", "injection",
        "directive", "recorded", "qwen", "accepted", "stale", "arp", "spoof", "benign", "beacon",
        "cred", "harvest", "exfil", "phishing", "port", "scan", "recon", "bruteforce", "ambiguity",
    }
)
_CORE_TRACE_RE = re.compile(r"trace-0x[0-9a-f]{1,16}(?=:|\Z)")
_COMPOSITE_RE = re.compile(r"[a-z0-9]+(?:[:_-][a-z0-9]+)*\Z")
_ORDINAL_SEGMENT_RE = re.compile(r"[a-z]{0,2}[0-9]{1,6}[a-z]{0,2}\Z")
_DIGITS_RE = re.compile(r"[0-9]+\Z")
_ID_SEPARATORS_RE = re.compile(r"[:_-]")


def _composite_id_ok(value: str) -> bool:
    """Cycle / request ids: an optional Edge core trace id ``trace-0x<hex>``
    (calc_trace_id) followed by lifecycle / loop suffixes (``:e1:c3:req:2``),
    or ids made of ``ID_WORDS`` and short ordinals (``ev:auth:0001``,
    ``replay:g5-golden-replay-v1:req:1``, ``c1:req:1``). No more than two
    numeric segments in a row, so dotted, dashed or colon-separated quads
    cannot pass."""
    rest = value
    core = _CORE_TRACE_RE.match(value)
    if core is not None:
        rest = value[core.end():].lstrip(":")
        if not rest:
            return True
    if not _COMPOSITE_RE.match(rest):
        return False
    digit_run = 0
    for segment in _ID_SEPARATORS_RE.split(rest):
        if segment in ID_WORDS:
            digit_run = 0
            continue
        if not _ORDINAL_SEGMENT_RE.match(segment):
            return False
        digit_run = digit_run + 1 if _DIGITS_RE.match(segment) else 0
        if digit_run > 2:
            return False
    return True


def _shape(pattern: str) -> Callable[[str], bool]:
    compiled = re.compile(pattern)
    return lambda value: compiled.fullmatch(value) is not None


ID_KINDS: Mapping[str, Callable[[str], bool]] = {
    # Evidence Plane event ids (evidence_plane.schema.make_event_id).
    "event_id": _shape(r"sha256:[0-9a-f]{64}"),
    # Structured refs ev:<kind>:<n>.
    "structured_ref": _shape(r"ev:(?:" + "|".join(EVIDENCE_REF_KINDS) + r"):[0-9]{1,6}"),
    # Suricata adapter refs (sids fit 8 digits). flow:<flow_id> is deliberately
    # absent: a 64-bit EVE flow id looks the same as a decimal-encoded MAC or
    # IPv4-mapped IPv6 integer.
    "suricata_ref": _shape(r"suricata_sid:[0-9]{1,8}"),
    # ATT&CK knowledge refs.
    "knowledge_ref": _shape(r"kn:attack:T[0-9]{4}(?:\.[0-9]{3})?"),
    # Offline replay fixture refs.
    "fixture_ref": _shape(r"sha256:fixture-[a-z]{1,16}(?:-[a-z]{1,16})?-[0-9]{1,3}"),
    # MioHypothesis ids (the prompt schema asks for h<n>).
    "hypothesis_id": _shape(r"h[0-9]{1,3}"),
    # MioEvidenceGap ids (g<n>).
    "gap_id": _shape(r"g[0-9]{1,3}"),
    "trace_id": _shape(_TRACE_SHAPE),
    "frame_id": _shape(rf"(?:frame{_TRACE_TAIL}|{_TRACE_SHAPE}(?::frame)?)"),
    "cycle_request_id": _composite_id_ok,
    # Broker capability name grammar; registration is checked separately.
    "capability": _shape(r"[a-z][a-z0-9_]{2,63}"),
}

# The capability name grammar for registration / playbook checks (no second
# layer there: those names come from reviewed code and data).
CAPABILITY_NAME_RE = re.compile(r"[a-z][a-z0-9_]{2,63}\Z")

# Evidence refs Edge and its adapters produce (frames, capability results).
EVIDENCE_REF = ("event_id", "structured_ref", "suricata_ref")
# The broker audit keeps an id verbatim when it is an event id or fits the
# cycle / request id grammar (which also covers the hypothesis, gap and
# structured-ref ids the audit sees).
AUDIT_ID_KINDS = ("event_id", "cycle_request_id")


# A model-chosen capability name can pass the name grammar and still be any
# word (a person's name, say). Errors and gap-score explanations show it only
# when the broker registry knows it; otherwise they show this fixed
# placeholder, which cannot match the capability grammar.
UNREGISTERED_CAPABILITY = "unregistered-capability"


def capability_label(capability: Any, registered_capabilities: Any = ()) -> str:
    """``capability`` if it is a registered capability name that passes the
    capability kind, else ``UNREGISTERED_CAPABILITY``."""
    registered = {item for item in registered_capabilities if type(item) is str}
    if type(capability) is str and capability in registered and id_ok(capability, ("capability",)):
        return capability
    return UNREGISTERED_CAPABILITY


def id_ok(value: Any, kinds: tuple[str, ...]) -> bool:
    """True when ``value`` is a str that matches one of ``kinds`` and passes
    the second layer. An unknown kind matches nothing."""
    if type(value) is not str:
        return False
    try:
        return any(ID_KINDS[k](value) for k in kinds if k in ID_KINDS) and second_layer_ok(value)
    except Exception:
        return False
