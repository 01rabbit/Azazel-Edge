"""SYNTHETIC provider records with genuine PUBLIC TEST signatures, never CI capture."""

from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from azazel_edge.outcome.input_auth import (
    SourceVerifier,
    TrustPolicy,
    SOURCE_DOMAIN,
    public_hex,
)
from azazel_edge.outcome.journal import _json
from safety_observation_data import KEYS, digest, wire
from recorded_nft_restoration_data import make_restoration_case
from real_systemd.provider_restoration import build_projection

POSITIVE = "sampled_fixed_chain_returned_to_baseline"


def fixture(tmp_path):
    value = make_restoration_case(
        tmp_path, native_mutator=lambda e: e["normalized"].update(sid=900001)
    )
    source = value["source_inputs"]["source_raw"]
    policy = value["source"]["trust"]
    prefix = b"".join(source.splitlines(keepends=True)[:2])
    enrollment = {
        name: deepcopy(value["plan"][name])
        for name in (
            "kernel_boot_id",
            "netns_inode",
            "query_window",
            "source_identity",
            "nft_binary_sha256",
            "receipts",
        )
    }
    enrollment["scope_interval"] = json.loads(value["source_inputs"]["contract_raw"])[
        "scope"
    ]["interval"]
    return dict(
        original_policy_raw=_json(dict(policy.data)),
        source_prefix_raw=prefix,
        source_raw=source,
        receipts=deepcopy(value["receipts"]),
        prefix_checkpoint=SourceVerifier(policy).verify(prefix),
        final_checkpoint=SourceVerifier(policy).verify(source),
        enrollment=enrollment,
        observer_public_key=public_hex(KEYS[0]),
    )


def build(value):
    return build_projection(
        value["original_policy_raw"],
        value["source_prefix_raw"],
        value["source_raw"],
        value["receipts"],
        **{
            name: value[name]
            for name in (
                "prefix_checkpoint",
                "final_checkpoint",
                "enrollment",
                "observer_public_key",
            )
        },
    )


def resign(rows):
    previous = "0" * 64
    raw = b""
    for seq, row in enumerate(rows, 1):
        row = deepcopy(row)
        row.pop("signature", None)
        row.update(seq=seq, prev=previous)
        row["signature"] = KEYS[1].sign(SOURCE_DOMAIN + _json(row)).hex()
        previous = digest(_json(row))
        raw += wire(row)
    return raw


def replace_source(value, rows):
    value["source_raw"] = resign(rows)
    policy = TrustPolicy(json.loads(value["original_policy_raw"]))
    value["final_checkpoint"] = SourceVerifier(policy).verify(value["source_raw"])


def receipt(value, phase, mutate):
    r = json.loads(value["receipts"][phase])
    mutate(r)
    value["receipts"][phase] = json.dumps(r, indent=2).encode()
    value["enrollment"]["receipts"][phase]["sha256"] = digest(value["receipts"][phase])


def test_original_no_lf_and_derived_lf_policy_are_distinct_preserved(tmp_path):
    value = fixture(tmp_path)
    before = deepcopy(value)
    built = build(value)
    assert built["result"]["status"] == POSITIVE
    assert value == before
    original = value["original_policy_raw"]
    derived = original + b"\n"
    assert digest(original) != digest(derived)
    assert (
        TrustPolicy(json.loads(original)).digest
        == TrustPolicy(json.loads(derived)).digest
    )
    assert original in built["files"].values() and derived in built["files"].values()
    provenance = json.loads(built["files"]["provenance.json"])
    assert provenance["original_policy_sha256"] == digest(original)
    assert provenance["derived_policy_sha256"] == digest(derived)
    assert provenance["policy_digest"] == TrustPolicy(json.loads(original)).digest
    assert (
        provenance["derived_policy_label"]
        == "DERIVED_canonical_policy_plus_LF_not_original_capture"
    )
    assert provenance["safety_observations_generated"] is False
    assert provenance["source_prefix_sha256"] == digest(value["source_prefix_raw"])
    assert provenance["source_final_sha256"] == digest(value["source_raw"])
    assert built["arguments"]["source_inputs"]["trust_raw"] == derived
    assert built["arguments"]["source_inputs"]["source_raw"] == value["source_raw"]
    assert built["arguments"]["receipts"] == value["receipts"]
    contract = json.loads(built["arguments"]["source_inputs"]["contract_raw"])
    assert all(
        not opportunities for opportunities in contract["opportunities"].values()
    )
    result = built["result"]
    assert result["source_owner_bound"] is True
    assert (
        result["network_mechanism_restored"] is result["qualified_safety_count"] is None
    )
    assert (
        result["execution_fact_verified"] is result["independently_measured"] is False
    )
    selected = value["source_raw"].splitlines(keepends=True)[2]
    plan = json.loads(built["arguments"]["plan_raw"])
    assert plan["source_event_seq"] == 3 and plan["source_event_sha256"] == digest(
        selected
    )


@pytest.mark.parametrize("kind", ["pretty", "lf", "duplicate", "partial"])
def test_noncanonical_or_duplicate_original_policy_is_refused(tmp_path, kind):
    value = fixture(tmp_path)
    raw = value["original_policy_raw"]
    if kind == "pretty":
        raw = json.dumps(json.loads(raw), indent=2).encode()
    elif kind == "lf":
        raw += b"\n"
    elif kind == "duplicate":
        raw = raw.replace(
            b'"schema_version":', b'"schema_version":"duplicate","schema_version":'
        )
    else:
        raw = raw[:-1]
    value["original_policy_raw"] = raw
    with pytest.raises(ValueError):
        build(value)


@pytest.mark.parametrize(
    "kind", ["ambiguous", "open", "multiple_sessions", "wrong_sid"]
)
def test_original_registered_source_requires_unique_selected_closed_session(
    tmp_path, kind
):
    value = fixture(tmp_path)
    rows = [json.loads(row) for row in value["source_raw"].splitlines()]
    if kind == "ambiguous":
        extra = deepcopy(rows[2])
        extra["event"]["capture_origin"]["seq"] = 3
        rows[-1]["event"]["capture_origin"]["seq"] = 4
        rows.insert(3, extra)
    elif kind == "open":
        rows.pop()
    elif kind == "multiple_sessions":
        extra = deepcopy([rows[0], rows[1], rows[-1]])
        for index, row in enumerate(extra):
            row["event"]["capture_origin"].update(session_ref="a" * 32, seq=index)
        rows.extend(extra)
    else:
        rows[2]["event"]["normalized"]["sid"] = 900002
    replace_source(value, rows)
    with pytest.raises(ValueError):
        build(value)


@pytest.mark.parametrize(
    "kind", ["prefix_hash", "final_hash", "prefix_bytes", "boot", "source_suffix"]
)
def test_root_retained_prefix_final_and_context_pins_cannot_be_repaired(tmp_path, kind):
    value = fixture(tmp_path)
    if kind == "prefix_hash":
        value["prefix_checkpoint"]["sha256"] = "e" * 64
    elif kind == "final_hash":
        value["final_checkpoint"]["sha256"] = "e" * 64
    elif kind == "prefix_bytes":
        value["source_prefix_raw"] = value["source_prefix_raw"][:-1]
    elif kind == "boot":
        value["enrollment"]["kernel_boot_id"] = "00000000-0000-4000-8000-000000000002"
    else:
        value["source_raw"] += b'{"bad":'
    with pytest.raises(ValueError):
        build(value)


@pytest.mark.parametrize(
    "kind", ["missing", "pin", "pid", "namespace", "order", "counter"]
)
def test_original_receipt_failures_never_return_restoration(tmp_path, kind):
    value = fixture(tmp_path)
    if kind == "missing":
        value["receipts"]["released"] = None
        value["enrollment"]["receipts"]["released"] = None
    elif kind == "pin":
        value["enrollment"]["receipts"]["applied"]["sha256"] = "e" * 64
    elif kind == "pid":
        receipt(value, "applied", lambda r: r.update(root_pid=9999))
    elif kind == "namespace":
        receipt(value, "applied", lambda r: r.update(netns_inode=9999))
    elif kind == "order":
        receipt(
            value,
            "applied",
            lambda r: r.update(query_started_at="2026-11-13T00:00:00+00:00"),
        )
    else:

        def change(r):
            snapshot = json.loads(r["stdout"])
            snapshot["nftables"][2]["rule"]["expr"][0]["counter"]["packets"] += 1
            r["stdout"] = json.dumps(snapshot)

        receipt(value, "released", change)
    built = build(value)
    assert built["result"]["status"] != POSITIVE
    assert built["arguments"]["receipts"] == value["receipts"]


def test_pure_builder_has_no_io_or_mutation_and_preserves_raw_hashes(tmp_path):
    value = fixture(tmp_path)
    before = deepcopy(value)
    with (
        patch("builtins.open", side_effect=AssertionError("I/O")),
        patch("os.open", side_effect=AssertionError("I/O")),
        patch("socket.socket", side_effect=AssertionError("network")),
        patch("subprocess.Popen", side_effect=AssertionError("command")),
    ):
        result = build(value)
    assert result["result"]["status"] == POSITIVE
    assert value == before
    # Recorder saves originals before the pure builder; they remain unchanged in
    # its arguments rather than being regenerated into a translated receipt.
    assert result["arguments"]["receipts"] == value["receipts"]
    enrolled = json.loads(result["arguments"]["plan_raw"])["receipts"]
    assert all(
        enrolled[phase]["sha256"] == digest(raw)
        for phase, raw in value["receipts"].items()
    )


def test_frozen_builder_cases_keep_actual_provider_route_separate():
    cases = json.loads(
        (
            Path(__file__).parent
            / "fixtures/recorded-provider-restoration/v1/cases.json"
        ).read_bytes()
    )["cases"]
    assert len(cases) == 11
    assert cases[-1] == "actual-existing-provider-apparmor-route"


def test_synthetic_recorder_constructor_uses_keyword_only_protected_reads(
    monkeypatch, tmp_path
):
    from types import SimpleNamespace
    from real_systemd import provider_restoration as recorder

    value = fixture(tmp_path)
    calls, guards, mkdirs, saved = [], [], [], {}
    base = Path("/synthetic-provider-root")
    g = SimpleNamespace(
        BASE=base,
        BUNDLE=base / "public-bundle",
        guard=lambda: guards.append("guard"),
        source=lambda: value["source_prefix_raw"],
    )

    # Exact existing API signature: positional owner/max_bytes would fail here,
    # before any synthetic save or query can pretend the constructor succeeded.
    def read_regular(path, *, owner, max_bytes, mode=None, missing=False):
        path = Path(path)
        calls.append((path, owner, max_bytes, mode, missing))
        assert owner == 0 and missing is False
        if path == g.BUNDLE / "trust.json":
            assert max_bytes == 32768 and mode == 0o644
            return value["original_policy_raw"], SimpleNamespace()
        if path.name == "SOURCE_REVISION":
            assert mode == 0o644 and max_bytes == 41
            return b"a" * 40 + b"\n", SimpleNamespace()
        if path == Path("/usr/sbin/nft"):
            assert mode == 0o755 and max_bytes == 64 * 1024 * 1024
            return b"SYNTHETIC pinned nft binary", SimpleNamespace()
        if path.name in ("provider_restoration.py", "provider.py"):
            assert max_bytes == 1024 * 1024
            return (
                b"SYNTHETIC protected helper source " + path.name.encode(),
                SimpleNamespace(),
            )
        pytest.fail("unexpected protected read: " + str(path))

    def save(path, raw):
        assert path not in saved, "exclusive save overwritten"
        saved[path] = raw

    def stat(path):
        assert str(path) == "/run/netns/edge400-provider-edge"
        return SimpleNamespace(st_dev=4, st_ino=12345)

    monkeypatch.setattr(recorder, "read_regular", read_regular)
    monkeypatch.setattr(recorder, "_save", save)
    monkeypatch.setattr(recorder, "os", SimpleNamespace(stat=stat))
    monkeypatch.setattr(recorder, "time", SimpleNamespace(monotonic_ns=lambda: 123456))
    monkeypatch.setattr(Path, "mkdir", lambda path, **kw: mkdirs.append((path, kw)))
    actual = recorder.Recorder(g, "edge400-provider-edge", value["observer_public_key"])
    assert guards == ["guard"]
    assert mkdirs == [(base / "provider-restoration", dict(mode=0o700))]
    assert actual.prefix == value["source_prefix_raw"]
    assert actual.prefix_checkpoint == value["prefix_checkpoint"]
    assert actual.original == value["original_policy_raw"]
    assert (
        actual.policy.digest
        == TrustPolicy(json.loads(value["original_policy_raw"])).digest
    )
    assert actual.start_ns == 123456
    assert actual.receipts == actual.bindings == {}
    assert {path.name for path in saved} == {
        "original-policy.json",
        "derived-policy.json",
        "source-prefix.jsonl",
        "prefix-checkpoint.json",
    }
    assert saved[actual.output / "original-policy.json"] == value["original_policy_raw"]
    assert (
        saved[actual.output / "derived-policy.json"]
        == value["original_policy_raw"] + b"\n"
    )
    assert saved[actual.output / "source-prefix.jsonl"] == value["source_prefix_raw"]
    assert (
        json.loads(saved[actual.output / "prefix-checkpoint.json"])
        == value["prefix_checkpoint"]
    )
    assert len(calls) == 5
    assert not any("key" in path.name for path in saved)


def test_synthetic_query_child_wrong_path_fails_before_binary_read_or_command(
    monkeypatch,
):
    from types import SimpleNamespace
    from real_systemd import provider_restoration as recorder
    from azazel_edge.outcome import postcondition

    guards = []
    monkeypatch.setitem(
        __import__("sys").modules,
        "provider",
        SimpleNamespace(g=SimpleNamespace(guard=lambda: guards.append("guard"))),
    )
    monkeypatch.setattr(
        recorder, "sys", SimpleNamespace(argv=["fixed-helper", "--root-readonly-nft"])
    )
    monkeypatch.setattr(
        recorder,
        "shutil",
        SimpleNamespace(which=lambda command: "/synthetic/wrong/nft"),
    )

    def forbidden(*args, **kwargs):
        pytest.fail("binary read or query before fixed PATH identity guard")

    monkeypatch.setattr(recorder, "read_regular", forbidden)
    monkeypatch.setattr(postcondition, "SubprocessReadOnlyRunner", forbidden)
    with pytest.raises(
        recorder.ProviderRestorationEvidenceError, match="executable differs"
    ):
        recorder.query_child()
    assert guards == ["guard"]


def test_isolated_query_child_imports_provider_before_fixed_argument_refusal(tmp_path):
    import subprocess
    import sys

    helper = Path(__file__).parent / "real_systemd/provider_restoration.py"
    done = subprocess.run(
        [sys.executable, "-I", str(helper.resolve()), "--invalid-shape"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=tmp_path,
        timeout=8,
        check=False,
    )
    assert done.returncode != 0
    assert done.stdout == ""
    assert done.stderr.rstrip().endswith(
        "ProviderRestorationEvidenceError: fixed Root NFT query child only"
    )
    assert "ModuleNotFoundError" not in done.stderr
    assert "AssertionError" not in done.stderr and "g.guard()" not in done.stderr
