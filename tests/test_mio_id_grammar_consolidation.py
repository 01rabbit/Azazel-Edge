"""One closed id grammar for M.I.O. (#384, #385, #386 follow-up).

The model output parser, the no-model handoff and the broker audit projection
used to carry three separate grammars. They now share ``mio/id_grammar.py``.
This test keeps the three pre-consolidation functions as frozen references
and runs a large corpus (every fixture / test literal plus hostile shapes)
through old and new: for every surface and field the new accept set must be
the old one or narrower, and every value that is now refused must fall in one
of the narrowings listed below (and in the PR).
"""
from __future__ import annotations

import ast
import ipaddress
import itertools
import json
import re
from pathlib import Path

import pytest

from azazel_edge.mio import broker as broker_module
from azazel_edge.mio import contracts, handoff, id_grammar
from azazel_edge.mio.redaction import contains_token_like

ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Frozen references: the grammars as merged by #507, #508 and #509. Do not
# edit; they are what "not wider than before" is measured against.
# ---------------------------------------------------------------------------

_OLD_OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OLD_ADDRESS_LIKE_RES = (
    re.compile(r"(?<![0-9])\d{1,3}(?:[.\-_]\d{1,3}){3}(?![0-9])"),
    re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{2}(?:[:.\-_][0-9a-f]{2}){5}(?![0-9a-f])"),
    re.compile(r"(?i)[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"),
)
_OLD_HEX_COLON_RUN_RE = re.compile(r"(?i)[0-9a-f:]*:[0-9a-f:]*")


def _old_has_ipv6_like_run(value):
    for run in _OLD_HEX_COLON_RUN_RE.findall(value):
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


def old_opaque_id(value):
    if not isinstance(value, str) or not _OLD_OPAQUE_ID_RE.match(value):
        return ""
    if any(p.search(value) for p in _OLD_ADDRESS_LIKE_RES) or _old_has_ipv6_like_run(value):
        return ""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    return ""


# contracts.py (#386 / #509)
_OLD_EVIDENCE_REF_KINDS = ("alert", "auth", "deception", "dns", "flow", "host", "http", "noc", "soc", "ssh", "sys", "tls")
_OLD_MODEL_ID_GRAMMAR = {
    "evidence_ref": re.compile(
        r"(?:sha256:[0-9a-f]{64}"
        r"|ev:(?:" + "|".join(_OLD_EVIDENCE_REF_KINDS) + r"):\d{1,6}"
        r"|suricata_sid:\d{1,8}"
        r"|kn:attack:T\d{4}(?:\.\d{3})?"
        r"|sha256:fixture-[a-z]{1,16}(?:-[a-z]{1,16})?-\d{1,3})\Z"
    ),
    "hypothesis_id": re.compile(r"h\d{1,3}\Z"),
    "gap_id": re.compile(r"g\d{1,3}\Z"),
    "capability": re.compile(r"[a-z][a-z0-9_]{2,63}\Z"),
}
_OLD_SECRET_SHAPE_RE = re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|token|bearer)")


def old_model_id_ok(value, kind):
    pattern = _OLD_MODEL_ID_GRAMMAR.get(kind)
    if pattern is None or type(value) is not str or not pattern.match(value):
        return False
    if kind == "capability":
        return not _OLD_SECRET_SHAPE_RE.search(value)
    return bool(old_opaque_id(value)) and not _OLD_SECRET_SHAPE_RE.search(value)


# handoff.py (#385 / #508)
_OLD_TRACE_HEAD = r"(?:trace|mio|evaluation|incident|replay)"
_OLD_TRACE_WORDS = r"(?:-(?:golden|fixture|shadow|auth|scan|trace|frame))*"
_OLD_TRACE_TAIL = r"(?:-v?[0-9]{1,6})?"
_OLD_TRACE_SHAPE = _OLD_TRACE_HEAD + _OLD_TRACE_WORDS + _OLD_TRACE_TAIL
_OLD_EV_KINDS = "|".join(sorted({"auth", "alert", "anomaly", "drop", "flow", "netflow", "dns", "http", "tls", "ssh", "smtp", "ftp", "smb", "dhcp"}))
_OLD_CLOSED_ID_SHAPES = {
    "trace_id": re.compile(rf"{_OLD_TRACE_SHAPE}"),
    "frame_id": re.compile(rf"(?:frame{_OLD_TRACE_TAIL}|{_OLD_TRACE_SHAPE}(?::frame)?)"),
    "evidence_ref": re.compile(rf"sha256:[0-9a-f]{{64}}|suricata_sid:[0-9]{{1,8}}|ev:(?:{_OLD_EV_KINDS})(?::[0-9]{{1,6}})?"),
    "hypothesis_id": re.compile(r"h[0-9]{1,3}"),
}


def old_handoff_ok(value, kind):
    return type(value) is str and _OLD_CLOSED_ID_SHAPES[kind].fullmatch(value) is not None


# broker.py (#384 / #507)
_OLD_IDENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._@#+=-]{0,127}\Z")
_OLD_AUDIT_ID_VOCABULARY = frozenset(
    {
        "ev", "evidence", "trace", "cycle", "req", "frame", "mio", "fixture", "replay", "evaluation",
        "golden", "shadow", "scenario", "demo", "test", "sample", "hypothesis", "gap",
        "auth", "flow", "sys", "noc", "soc", "ssh", "alert", "alerts", "dns", "tls", "icmp", "iface",
        "probe", "plane", "activity",
        "observe", "notify", "throttle", "redirect", "isolate",
        "contradictory", "role", "cross", "fabricated", "ref", "empty", "recommendation", "captured",
        "malformed", "model", "output", "timeout", "no", "llm", "unavailable", "prompt", "injection",
        "directive", "recorded", "qwen", "accepted", "stale", "arp", "spoof", "benign", "beacon",
        "cred", "harvest", "exfil", "phishing", "port", "scan", "recon", "bruteforce", "ambiguity",
    }
)
_OLD_SHA256_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OLD_CORE_TRACE_RE = re.compile(r"trace-0x[0-9a-f]{1,16}(?=:|\Z)")
_OLD_ORDINAL_SEGMENT_RE = re.compile(r"[a-z]{0,2}[0-9]{1,6}[a-z]{0,2}\Z")
_OLD_DIGITS_RE = re.compile(r"[0-9]+\Z")
_OLD_ID_SEPARATORS_RE = re.compile(r"[:_-]")


def _old_audit_id_in_schema(value):
    if _OLD_SHA256_ID_RE.match(value):
        return True
    rest = value
    core = _OLD_CORE_TRACE_RE.match(value)
    if core is not None:
        rest = value[core.end():].lstrip(":")
        if not rest:
            return True
    if not re.fullmatch(r"[a-z0-9]+(?:[:_-][a-z0-9]+)*", rest):
        return False
    digit_run = 0
    for segment in _OLD_ID_SEPARATORS_RE.split(rest):
        if segment in _OLD_AUDIT_ID_VOCABULARY:
            digit_run = 0
            continue
        if not _OLD_ORDINAL_SEGMENT_RE.match(segment):
            return False
        digit_run = digit_run + 1 if _OLD_DIGITS_RE.match(segment) else 0
        if digit_run > 2:
            return False
    return True


def old_audit_safe(value):
    if type(value) is not str or not _OLD_IDENT_RE.match(value):
        return False
    try:
        return _old_audit_id_in_schema(value) and old_opaque_id(value) == value and not contains_token_like(value)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# New functions, one per surface and field.
# ---------------------------------------------------------------------------

def new_model_id_ok(value, kind):
    return contracts.model_id_ok(value, kind)


def new_handoff_ok(value, kind):
    sentinel = object()
    return handoff._safe_id(kind, value, sentinel) is not sentinel


def new_audit_safe(value):
    return broker_module._audit_safe(value)


SURFACES = (
    [("model", kind, old_model_id_ok, new_model_id_ok) for kind in ("evidence_ref", "hypothesis_id", "gap_id", "capability")]
    + [("handoff", kind, old_handoff_ok, new_handoff_ok) for kind in ("trace_id", "frame_id", "evidence_ref", "hypothesis_id")]
    + [("audit", "any", lambda v, _k: old_audit_safe(v), lambda v, _k: new_audit_safe(v))]
)

# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


def _json_strings(node, out):
    if isinstance(node, str):
        out.add(node)
    elif isinstance(node, dict):
        for k, v in node.items():
            out.add(k)
            _json_strings(v, out)
    elif isinstance(node, list):
        for v in node:
            _json_strings(v, out)


def _repo_values():
    out: set[str] = set()
    for path in sorted((ROOT / "tests" / "fixtures" / "mio").rglob("*.json")):
        _json_strings(json.loads(path.read_text(encoding="utf-8")), out)
    for path in sorted((ROOT / "tests").glob("test_mio*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                out.add(node.value)
    return {v for v in out if len(v) <= 300}


def _hostile_values():
    out: set[str] = set()
    ipv4 = ["10.0.0.5", "192.168.1.5", "127.0.0.1", "0.0.0.0", "255.255.255.255", "10.0.0", "192.168.1", "10.1",
            "0x0a000005", "0x0A000005", "0xc0a80105", "c0a80105", "167772165", "3232235777", "2130706433",
            "0300.0250.0.1", "012.0.0.1", "0300-0250-0-1", "10-0-0-5", "10_0_0_5", "10:0:0:5", "192:168:1:5",
            "1:2:3:4", "10x0x0x1", "10.0.0.5:8080", "10-0-0-5-8080"]
    mac = ["00:11:22:33:44:55", "00-11-22-33-44-55", "00.11.22.33.44.55", "00_11_22_33_44_55", "001122334455",
           "aabbccddeeff", "AA:BB:CC:DD:EE:FF", "0011.2233.4455", "aabb-ccdd-eeff", "a1b2c3d4e5f6", "aa_bb_cc_dd_ee_ff"]
    ipv6 = ["fe80::1", "::1", "2001:db8::1", "2001:db8:0:0:1:2:3:4", "::ffff:10.0.0.5", "fe80:0:0:0:0:0:0:1"]
    hosts = ["evil.example.com", "host.lan", "alice-laptop", "alice-laptop.corp", "db01.internal", "localhost", "router"]
    people = ["john", "john_smith", "user_john_smith", "alice", "bob_jones", "mary-ann", "taro_yamada"]
    secrets = ["sk-abcdefghijklmnopqrstuvwxyz123456", "sk_live_abcdefghijklmnop", "ghp_ABCDEFGHIJKLMNOPQRST",
               "github_pat_ABCDEFGHIJKLMNOP", "AKIAIOSFODNN7EXAMPLE", "AIzaSyABCDEFGHIJKLMNOP",
               "eyJhbGciOiJIUzI1NiJ9", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc", "password-hunter2",
               "password", "passwd1", "pwd1", "secret", "api_key_abc", "apikey", "token", "token_abc", "bearer_abc",
               "Bearer_abcdefghijklmnop1234", "x" * 40, "a1" * 20, "abc_" * 9, "user@example.com"]
    sha = ["sha256:", "sha256:zzzz", "sha256:" + "a" * 63, "sha256:" + "a" * 65, "sha256:" + "A" * 64,
           "sha256:" + "a" * 200, "sha256:" + "0" * 64, "sha256:" + "ab" * 32, "sha256:fixture-ssh-1",
           "sha256:fixture-ssh-1234", "sha256:fixture-alert-summary-1", "sha256:fixture-a-b-c-1", "sha256:fixture-SSH-1"]
    flow = ["flow:1", "flow:" + "1" * 12, "flow:" + "9" * 19, "flow:18446744073709551615", "flow:281474976710655",
            "ev:flow:" + "1" * 7, "ev:flow:" + "1" * 12]
    words = ipv4 + mac + ipv6 + hosts + people + secrets
    prefixes = ["", "ev:", "ev:auth:", "ev:flow:", "ev:noc:", "kn:", "kn:attack:", "trace-", "trace-golden-", "mio-",
                "frame-", "h", "g", "suricata_sid:", "replay:", "evaluation:", "trace-0x1f:", "c1:req:"]
    for prefix, word in itertools.product(prefixes, words):
        out.add(prefix + word)
    out.update(sha + flow)
    return out


def _positive_values():
    out: set[str] = set()
    kinds = set(_OLD_EVIDENCE_REF_KINDS) | set(_OLD_EV_KINDS.split("|")) | {"other", "invented", "pii", "late", "new"}
    for kind in kinds:
        out.add(f"ev:{kind}")
        for n in ("0", "1", "0001", "42", "123456", "1234567"):
            out.add(f"ev:{kind}:{n}")
    for n in ("1", "12", "123", "1234", "12345678", "123456789"):
        out.update({f"h{n}", f"g{n}", f"H{n}", f"G{n}", f"suricata_sid:{n}", f"r{n}", f"t{n}", f"c{n}:req:1"})
    out.update({"h", "g", "h-1", "h 1", "h1\n", "kn:attack:T1110", "kn:attack:T1110.001", "kn:attack:T11", "kn:attack:t1110"})
    heads = ["trace", "mio", "evaluation", "incident", "replay", "frame", "other"]
    tails = ["", "-1", "-v1", "-v2", "-123456", "-1234567", "-x"]
    words = ["", "-golden", "-fixture", "-shadow-auth", "-scan-trace-frame", "-golden-fixture-shadow-auth-scan-trace-frame"]
    for head, mid, tail in itertools.product(heads, words, tails):
        base = head + mid + tail
        out.update({base, base + ":frame", base + ":cycle", base + ":cycle:req:1"})
    core = ["trace-0x1f", "trace-0x2d46936d1d47a084", "trace-0x" + "f" * 17]
    for c in core:
        out.update({c, c + ":e1:c3", c + ":e1:c3:req:2", c + ":alice", c + ":1:2:3"})
    out.update({"replay:g5-golden-replay-v1:req:1", "evaluation:recorded-qwen-2b-accepted:req:1", "evaluation:stale-evidence:req:2",
                "mio-fixture-auth-1:cycle:req:1", "query_flow_summary", "query_recent_alerts", "lookup_behavior_pattern",
                "get_host_health", "get_deception_state", "request_trace", "isolate_client", "get_token_list",
                "q", "query-flow", "Query_Flow", "x" * 64, "x" * 65, "a" * 31, "a" * 32, "query_" + "a" * 40,
                "invalid-model-id", "existing-or-short-id", "empty-recommendation-captured-381"})
    return out


CORPUS = sorted(_repo_values() | _hostile_values() | _positive_values())
NON_STRINGS = [None, 1, 0, 1.0, True, b"h1", ["h1"], {"h": 1}, ("h1",)]


def test_corpus_is_large_and_covers_the_repo_and_review_shapes():
    assert len(CORPUS) > 3000
    for must in ("sha256:" + "ab" * 32, "ev:auth:0001", "trace-golden-v2", "mio-fixture-auth-1:frame", "h1",
                 "10.0.0.5", "001122334455", "fe80::1", "sk-abcdefghijklmnopqrstuvwxyz123456", "flow:18446744073709551615"):
        assert must in CORPUS, must


# ---------------------------------------------------------------------------
# Narrowings (listed in the PR). Anything refused now but accepted before must
# match one of these, so an accidental behaviour change fails the test.
# ---------------------------------------------------------------------------

_DROPPED_MODEL_EV_KINDS = {"deception", "host", "noc", "soc", "sys"}
_DROPPED_HANDOFF_EV_KINDS = {"anomaly", "dhcp", "drop", "ftp", "netflow", "smb", "smtp"}


def _second_layer_hit(value):
    return old_opaque_id(value) != value or bool(_OLD_SECRET_SHAPE_RE.search(value)) or contains_token_like(value)


def _documented_narrowing(surface, kind, value):
    if surface == "model":
        if kind == "evidence_ref" and re.fullmatch(r"ev:(\w+):[0-9]{1,6}", value) and value.split(":")[1] in _DROPPED_MODEL_EV_KINDS:
            return "ev kind not shared with the handoff"
        # new second layer for model ids: redaction token shapes; for
        # capability names also the address shapes.
        if contains_token_like(value) or (kind == "capability" and old_opaque_id(value) != value):
            return "second layer now also applies redaction token shapes (and address shapes to capability names)"
        return None
    if surface == "handoff":
        if kind == "evidence_ref":
            m = re.fullmatch(r"ev:([a-z]+)(?::[0-9]{1,6})?", value)
            if m and (m.group(1) in _DROPPED_HANDOFF_EV_KINDS or ":" not in value[3:]):
                return "ev kind not shared with the model parser, or ev ref without an ordinal"
        if _second_layer_hit(value):
            return "the handoff now applies the shared second layer"
        return None
    if surface == "audit":
        if _OLD_SECRET_SHAPE_RE.search(value):
            return "the audit now also refuses secret words"
        return None
    return None


@pytest.mark.parametrize("surface,kind,old,new", SURFACES, ids=[f"{s}-{k}" for s, k, _o, _n in SURFACES])
def test_new_accept_set_is_old_or_narrower(surface, kind, old, new):
    widened = [v for v in CORPUS if new(v, kind) and not old(v, kind)]
    assert widened == [], widened[:20]
    narrowed = [v for v in CORPUS if old(v, kind) and not new(v, kind)]
    unexplained = [v for v in narrowed if _documented_narrowing(surface, kind, v) is None]
    assert unexplained == [], unexplained[:20]
    for value in NON_STRINGS:
        assert not new(value, kind)


# Every id the repository produces or its fixtures carry keeps the verdict it
# had before, on every surface.
REPO_IDS = [
    "sha256:" + "ab" * 32, "suricata_sid:2001219", "ev:auth:0001", "ev:ssh:1", "ev:flow:123456", "ev:alert:1",
    "kn:attack:T1110", "kn:attack:T1110.001", "sha256:fixture-ssh-1", "sha256:fixture-alert-summary-1",
    "h1", "h12", "h999", "g1", "g42", "g999", "trace-1", "trace-test-1", "trace-golden-v2", "trace-golden-activity-1",
    "mio-fixture-auth-1", "mio-fixture-auth-1:frame", "frame-1", "frame-golden-v1", "mio-shadow",
    "trace-0x2d46936d1d47a084", "trace-0x2d46936d1d47a084:e1:c3:req:2", "replay:g5-golden-replay-v1:req:1",
    "evaluation:recorded-qwen-2b-accepted:req:1", "c1:req:1", "ev:noc:0001", "ev:soc:0001", "ev:sys:0001",
    "query_flow_summary", "query_recent_alerts", "lookup_behavior_pattern", "get_host_health", "get_deception_state", "request_trace",
]


@pytest.mark.parametrize("surface,kind,old,new", SURFACES, ids=[f"{s}-{k}" for s, k, _o, _n in SURFACES])
def test_repo_ids_keep_their_verdict(surface, kind, old, new):
    changed = [v for v in REPO_IDS if old(v, kind) != new(v, kind)]
    allowed = {("model", "evidence_ref", v) for v in ("ev:noc:0001", "ev:soc:0001", "ev:sys:0001")}
    assert [v for v in changed if (surface, kind, v) not in allowed] == []


def test_listed_narrowings_are_real():
    # model parser: ev kinds the handoff never accepted
    assert old_model_id_ok("ev:noc:0001", "evidence_ref") and not new_model_id_ok("ev:noc:0001", "evidence_ref")
    # handoff: ev kinds the model parser never accepted, and ev refs without an ordinal
    assert old_handoff_ok("ev:netflow:1", "evidence_ref") and not new_handoff_ok("ev:netflow:1", "evidence_ref")
    assert old_handoff_ok("ev:auth", "evidence_ref") and not new_handoff_ok("ev:auth", "evidence_ref")
    # capability names: address shapes and long-token shapes
    assert old_model_id_ok("aa_bb_cc_dd_ee_ff", "capability") and not new_model_id_ok("aa_bb_cc_dd_ee_ff", "capability")
    assert old_model_id_ok("query_" + "a" * 40, "capability") and not new_model_id_ok("query_" + "a" * 40, "capability")
    # the audit still keeps ev:noc:0001 (cycle / request id grammar)
    assert old_audit_safe("ev:noc:0001") and new_audit_safe("ev:noc:0001")


def test_each_kind_is_defined_once_and_the_surfaces_only_select_kinds():
    assert set(id_grammar.ID_KINDS) >= {"event_id", "structured_ref", "suricata_ref", "knowledge_ref", "fixture_ref",
                                        "hypothesis_id", "gap_id", "trace_id", "frame_id", "cycle_request_id", "capability"}
    for kinds in list(contracts.MODEL_ID_GRAMMAR.values()) + list(handoff.HANDOFF_ID_KINDS.values()) + [id_grammar.AUDIT_ID_KINDS]:
        assert kinds and set(kinds) <= set(id_grammar.ID_KINDS)
    assert broker_module._NAME_RE is id_grammar.CAPABILITY_NAME_RE
    assert contracts._opaque_id is id_grammar.opaque_id
    for path in ("broker.py", "handoff.py", "contracts.py"):
        text = (ROOT / "py" / "azazel_edge" / "mio" / path).read_text(encoding="utf-8")
        for stale in ("CLOSED_ID_SHAPES", "_audit_id_in_schema", "_SECRET_SHAPE_RE", "_ADDRESS_LIKE_RES", "sha256:[0-9a-f]{64}"):
            assert stale not in text, (path, stale)


def test_opaque_id_is_unchanged_for_the_frame():
    for value in CORPUS:
        assert id_grammar.opaque_id(value) == old_opaque_id(value), value


# ---------------------------------------------------------------------------
# #509 NIT: a grammar-valid capability name that the playbook does not allow
# is echoed in errors only when the broker registry knows it.
# ---------------------------------------------------------------------------

from azazel_edge.mio import GroundingValidator, MioEvidenceGap, MioHypothesis, MioSituationFrame  # noqa: E402
from azazel_edge.mio.grounding import UNREGISTERED_CAPABILITY, capability_label  # noqa: E402


def _gap_with(capability):
    return MioEvidenceGap.from_mapping({"gap_id": "g1", "question": "q", "discriminates_hypothesis_ids": ["h1"], "capability": capability}, ordinal=1)


def _validator():
    frame = MioSituationFrame.build(frame_id="frame-1", trace_id="trace-1", created_at="2026-01-01T00:00:00Z", mission="m",
                                    current_defensive_state="OBSERVE", threat_level="LOW", evidence_refs=["ev:ssh:1"])
    return GroundingValidator(frame)


@pytest.mark.parametrize("name", ["john_smith", "alice_laptop", "taro_yamada", "isolate_client"])
def test_unregistered_capability_name_is_not_echoed(name):
    gap = _gap_with(name)
    assert gap.capability == name  # it passes the name grammar
    result = _validator().validate_evidence_gaps(
        [gap], hypotheses=[MioHypothesis.from_mapping({"hypothesis_id": "h1", "statement": "s"}, ordinal=1)],
        allowed_capabilities=["query_recent_alerts"], registered_capabilities=["query_recent_alerts", "query_flow_summary"],
    )
    assert not result.ok
    assert f"capability_not_allowed_by_playbook:{UNREGISTERED_CAPABILITY}" in result.errors
    assert name not in json.dumps(result.errors)


def test_registered_capability_outside_the_playbook_is_still_named():
    result = _validator().validate_evidence_gaps(
        [_gap_with("query_flow_summary")], hypotheses=[MioHypothesis.from_mapping({"hypothesis_id": "h1", "statement": "s"}, ordinal=1)],
        allowed_capabilities=["query_recent_alerts"], registered_capabilities=["query_recent_alerts", "query_flow_summary"],
    )
    assert "capability_not_allowed_by_playbook:query_flow_summary" in result.errors


def test_without_a_registry_the_placeholder_is_used():
    result = _validator().validate_evidence_gaps(
        [_gap_with("query_flow_summary")], hypotheses=[MioHypothesis.from_mapping({"hypothesis_id": "h1", "statement": "s"}, ordinal=1)],
        allowed_capabilities=["query_recent_alerts"],
    )
    assert f"capability_not_allowed_by_playbook:{UNREGISTERED_CAPABILITY}" in result.errors
    assert capability_label(7, ["7"]) == UNREGISTERED_CAPABILITY
    assert not id_grammar.ID_KINDS["capability"](UNREGISTERED_CAPABILITY)  # cannot collide with a real name


def test_every_capability_the_repo_names_still_passes_the_model_grammar():
    from azazel_edge.mio import DEFAULT_PLAYBOOKS, GENERIC_PLAYBOOK
    from azazel_edge.mio.evidence_gap_scoring import CAPABILITY_COST_CLASS

    names = set(CAPABILITY_COST_CLASS) | set(GENERIC_PLAYBOOK.allowed_capabilities)
    for playbook in DEFAULT_PLAYBOOKS.values():
        names |= set(playbook.allowed_capabilities)
    assert names
    for name in names:
        assert contracts.model_id_ok(name, "capability"), name
