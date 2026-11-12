"""Historical PUBLIC actual ZIP replay; every changed ZIP is explicitly SYNTHETIC.

No fresh capture, extraction, new Source/signature generation or custody claim.
"""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
from unittest.mock import patch
import warnings
import zipfile

import pytest
from azazel_edge.benchmark import provider_restoration_archive as audit
from azazel_edge.outcome.journal import _json

ROOT = Path(__file__).parent / "fixtures/provider-restoration-archive/v1"
FROZEN = json.loads((ROOT / "cases.json").read_bytes())
PIN = FROZEN["actual_fixture"]["sha256"]
RAW = (ROOT / "actual-ci-43301280827.zip").read_bytes()
assert len(RAW) == 20449 and hashlib.sha256(RAW).hexdigest() == PIN
with zipfile.ZipFile(io.BytesIO(RAW)) as archive:
    ORIGINAL = {item.filename: archive.read(item) for item in archive.infolist()}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return _json(value) + b"\n"


def replay(raw, *, pin=None):
    # For SYNTHETIC mutations, this is a new explicitly enrolled byte hash; never
    # reuse it as the historical external checkpoint or rewrite ORIGINAL/RAW.
    return audit.evaluate_provider_restoration_archive(
        raw, expected_archive_sha256=sha(raw) if pin is None else pin
    )


def packed(files=None, *, info_mutator=None, comment=b"", duplicate=False):
    files = deepcopy(ORIGINAL) if files is None else files
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                info = zipfile.ZipInfo(name, (2026, 11, 13, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                if info_mutator:
                    info_mutator(info)
                archive.writestr(info, data)
            if duplicate:
                archive.writestr("result.json", files["result.json"])
            archive.comment = comment
    return output.getvalue()


def updated(files, name, mutate):
    value = json.loads(files[name])
    mutate(value)
    files[name] = wire(value)


def refresh_manifest(files):
    value = json.loads(files["collection-hashes.json"])
    value["files"] = {
        name: dict(sha256=sha(raw), bytes=len(raw))
        for name, raw in files.items()
        if name != "collection-hashes.json"
    }
    files["collection-hashes.json"] = wire(value)


def central_positions(raw):
    eocd = len(raw) - 22
    offset = struct.unpack_from("<I", raw, eocd + 16)[0]
    positions = []
    for _ in range(25):
        assert raw[offset : offset + 4] == b"PK\x01\x02"
        positions.append(offset)
        names, extra, comment = struct.unpack_from("<HHH", raw, offset + 28)
        offset += 46 + names + extra + comment
    return positions


def test_original_historical_actual_archive_matches_frozen_external_identity():
    assert len(RAW) == 20449 and sha(RAW) == PIN
    assert FROZEN["actual_fixture"] == dict(
        run=43301280827,
        artifact=13980483923,
        sha256=PIN,
        kind="historical_offline_not_fresh_capture",
    )
    result = replay(RAW, pin=PIN)
    assert result["schema_version"] == "edge-provider-restoration-archive-audit/v1"
    assert result["archive_sha256"] == PIN
    assert result["archive_integrity_verified"] is True
    assert result["archive_origin_authenticated"] is False
    assert result["replay_matches_published"] is True
    assert result["replayed_diagnostic"] == json.loads(ORIGINAL["result.json"])
    assert (
        result["network_mechanism_restored"] is result["qualified_safety_count"] is None
    )
    assert (
        result["execution_fact_verified"] is result["independently_measured"] is False
    )
    for key in (
        "authorizes_transition",
        "resume_authorized",
        "experiment",
        "measurement_completed",
        "production_admission",
    ):
        assert result[key] is False


def test_synthetic_repack_is_valid_but_has_new_explicit_archive_identity():
    raw = packed()
    assert raw != RAW and sha(raw) != PIN
    assert replay(raw)["replay_matches_published"] is True
    with pytest.raises(audit.ProviderRestorationArchiveError):
        replay(raw, pin=PIN)


@pytest.mark.parametrize(
    "kind",
    [
        "pin",
        "count",
        "disk",
        "disk_count",
        "central_size",
        "central_offset",
        "zip64_count",
        "zip64_size",
        "comment_length",
        "truncated",
        "trailing",
    ],
)
def test_bounded_eocd_and_external_digest_refuse_before_zipfile_allocation(kind):
    raw = bytearray(RAW)
    end = len(raw) - 22
    pin = None
    if kind == "pin":
        pin = "e" * 64
    elif kind == "count":
        struct.pack_into("<HH", raw, end + 8, 65534, 65534)
    elif kind == "disk":
        struct.pack_into("<H", raw, end + 4, 1)
    elif kind == "disk_count":
        struct.pack_into("<H", raw, end + 8, 24)
    elif kind == "central_size":
        struct.pack_into("<I", raw, end + 12, len(raw) + 1)
    elif kind == "central_offset":
        struct.pack_into("<I", raw, end + 16, len(raw) + 1)
    elif kind == "zip64_count":
        struct.pack_into("<HH", raw, end + 8, 65535, 65535)
    elif kind == "zip64_size":
        struct.pack_into("<I", raw, end + 12, 0xFFFFFFFF)
    elif kind == "comment_length":
        struct.pack_into("<H", raw, end + 20, 1)
    elif kind == "truncated":
        raw = raw[:-1]
    else:
        raw += b"x"
    with patch.object(
        zipfile,
        "ZipFile",
        side_effect=AssertionError("ZipFile constructed before bounded preflight"),
    ):
        with pytest.raises(audit.ProviderRestorationArchiveError):
            replay(bytes(raw), pin=pin)


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "extra",
        "duplicate",
        "traversal",
        "absolute",
        "nonascii",
        "directory",
        "link",
        "zip64_extra",
        "entry_comment",
        "archive_comment",
    ],
)
def test_inventory_links_paths_and_unsupported_zip_metadata(kind):
    files = deepcopy(ORIGINAL)
    kwargs = {}
    if kind == "missing":
        files.pop("result.json")
    elif kind == "extra":
        files["unexpected.txt"] = b"not an approved artifact"
    elif kind == "duplicate":
        kwargs["duplicate"] = True
    elif kind in ("traversal", "absolute", "nonascii", "directory"):
        name = {
            "traversal": "../result.json",
            "absolute": "/result.json",
            "nonascii": "r\u00e9sult.json",
            "directory": "result.json/",
        }[kind]
        files[name] = files.pop("result.json")
    elif kind == "link":
        kwargs["info_mutator"] = (
            lambda i: setattr(i, "external_attr", (stat.S_IFLNK | 0o777) << 16)
            if i.filename == "result.json"
            else None
        )
    elif kind == "zip64_extra":
        kwargs["info_mutator"] = lambda i: setattr(i, "extra", b"\x01\x00\x00\x00")
    elif kind == "entry_comment":
        kwargs["info_mutator"] = lambda i: setattr(i, "comment", b"x")
    else:
        kwargs["comment"] = b"x"
    with pytest.raises(audit.ProviderRestorationArchiveError):
        replay(packed(files, **kwargs))


@pytest.mark.parametrize(
    "kind", ["encryption", "compression", "crc", "file_size", "total_size"]
)
def test_declared_sizes_crc_and_compression_fail_closed(kind):
    raw = bytearray(RAW)
    positions = central_positions(raw)
    for position in positions[:3] if kind == "total_size" else positions[:1]:
        local = struct.unpack_from("<I", raw, position + 42)[0]
        if kind == "encryption":
            struct.pack_into("<H", raw, position + 8, 1)
            struct.pack_into("<H", raw, local + 6, 1)
        elif kind == "compression":
            struct.pack_into("<H", raw, position + 10, 99)
            struct.pack_into("<H", raw, local + 8, 99)
        elif kind == "crc":
            struct.pack_into("<I", raw, position + 16, 0)
        else:
            struct.pack_into(
                "<I",
                raw,
                position + 24,
                33 * 1024 * 1024 if kind == "file_size" else 23 * 1024 * 1024,
            )
    with pytest.raises(audit.ProviderRestorationArchiveError):
        replay(bytes(raw))


@pytest.mark.parametrize(
    "kind",
    [
        "errors",
        "hash",
        "bool_size",
        "float_size",
        "missing",
        "extra",
        "duplicate",
        "deep",
    ],
)
def test_manifest_cannot_self_authenticate_or_conflate_types(kind):
    files = deepcopy(ORIGINAL)
    manifest = json.loads(files["collection-hashes.json"])
    if kind == "errors":
        manifest["errors"] = [dict(name="source-final.jsonl", error="missing")]
    elif kind == "hash":
        manifest["files"]["source-final.jsonl"]["sha256"] = "e" * 64
    elif kind == "bool_size":
        manifest["files"]["baseline-child-stderr.raw"]["bytes"] = False
    elif kind == "float_size":
        manifest["files"]["source-final.jsonl"]["bytes"] = float(
            manifest["files"]["source-final.jsonl"]["bytes"]
        )
    elif kind == "missing":
        manifest["files"].pop("source-final.jsonl")
    elif kind == "extra":
        manifest["files"]["unknown"] = dict(sha256="e" * 64, bytes=0)
    if kind == "duplicate":
        files["collection-hashes.json"] = b'{"files":{},"files":{},"errors":[]}'
    elif kind == "deep":
        files["collection-hashes.json"] = b"[" * 1001 + b"0" + b"]" * 1001 + b"\n"
    else:
        files["collection-hashes.json"] = wire(manifest)
    with pytest.raises(audit.ProviderRestorationArchiveError):
        replay(packed(files))


@pytest.mark.parametrize(
    "kind",
    [
        "policy_pretty",
        "policy_duplicate",
        "derived",
        "policy_digest",
        "derived_label",
        "observer_key",
        "observer_role",
        "prefix_bytes",
        "prefix_checkpoint",
        "final_checkpoint",
        "selected_seq",
        "selected_hash",
        "source_plan",
        "source_signature",
        "source_suffix",
        "child_stdout",
        "child_extra",
        "launch_pid",
        "launch_argv",
        "launch_namespace",
        "stderr",
        "receipt_counter",
        "result_status",
        "result_type",
        "authority",
    ],
)
def test_synthetic_semantic_tampering_reenrolls_manifest_but_never_source_signature(
    kind,
):
    files = deepcopy(ORIGINAL)
    if kind == "policy_pretty":
        files["original-policy.json"] = json.dumps(
            json.loads(files["original-policy.json"]), indent=2
        ).encode()
    elif kind == "policy_duplicate":
        files["original-policy.json"] = files["original-policy.json"].replace(
            b'"schema_version":', b'"schema_version":"bad","schema_version":'
        )
    elif kind == "derived":
        files["derived-policy.json"] += b"\n"
    elif kind == "policy_digest":
        updated(files, "provenance.json", lambda p: p.update(policy_digest="e" * 64))
    elif kind == "derived_label":
        updated(
            files,
            "provenance.json",
            lambda p: p.update(derived_policy_label="ORIGINAL"),
        )
    elif kind == "observer_key":
        updated(
            files, "provenance.json", lambda p: p.update(observer_public_key="e" * 64)
        )
    elif kind == "observer_role":
        updated(
            files,
            "provenance.json",
            lambda p: p.update(observer_key_role="actual_independent_sensor"),
        )
    elif kind == "prefix_bytes":
        files["source-prefix.jsonl"] = files["source-prefix.jsonl"][:-1]
    elif kind == "prefix_checkpoint":
        updated(files, "prefix-checkpoint.json", lambda p: p.update(head="e" * 64))
    elif kind == "final_checkpoint":
        updated(files, "final-checkpoint.json", lambda p: p.update(sha256="e" * 64))
    elif kind == "selected_seq":
        updated(
            files, "provenance.json", lambda p: p.update(selected_original_source_seq=4)
        )
    elif kind == "selected_hash":
        updated(
            files,
            "provenance.json",
            lambda p: p.update(selected_original_source_sha256="e" * 64),
        )
    elif kind == "source_plan":
        updated(
            files,
            "source-plan.json",
            lambda p: p["context"].update(session_ref="a" * 32),
        )
    elif kind == "source_signature":
        rows = files["source-final.jsonl"].splitlines(keepends=True)
        row = json.loads(rows[2])
        row["signature"] = "0" * 128
        rows[2] = wire(row)
        files["source-final.jsonl"] = b"".join(rows)
    elif kind == "source_suffix":
        files["source-final.jsonl"] += b'{"bad":'
    elif kind == "child_stdout":
        updated(files, "applied-child.raw", lambda p: p.update(stdout="{}"))
    elif kind == "child_extra":
        updated(files, "applied-child.raw", lambda p: p.update(extra="unbound"))
    elif kind == "launch_pid":
        updated(files, "applied-launch.json", lambda p: p.update(root_pid=9999))
    elif kind == "launch_argv":
        updated(
            files,
            "applied-launch.json",
            lambda p: p["actual_child_argv"].append("extra"),
        )
    elif kind == "launch_namespace":
        updated(
            files, "applied-launch.json", lambda p: p.update(expected_netns_inode=9999)
        )
    elif kind == "stderr":
        files["applied-child-stderr.raw"] = b"error"
    elif kind == "receipt_counter":

        def change(p):
            snapshot = json.loads(p["stdout"])
            rule = next(row["rule"] for row in snapshot["nftables"] if "rule" in row)
            rule["expr"].insert(0, dict(counter=dict(packets=1, bytes=64)))
            p["stdout"] = json.dumps(snapshot)

        updated(files, "released-receipt.json", change)
    elif kind == "result_status":
        updated(files, "result.json", lambda p: p.update(status="unknown"))
    elif kind == "result_type":
        updated(
            files,
            "result.json",
            lambda p: p["phases"]["applied"].update(owner_rule_count=True),
        )
    else:
        updated(files, "result.json", lambda p: p.update(production_admission=True))
    refresh_manifest(files)
    with pytest.raises(audit.ProviderRestorationArchiveError):
        replay(packed(files))


def test_historical_replay_is_pure_no_extraction_writes_queries_or_network():
    before = RAW
    with (
        patch("builtins.open", side_effect=AssertionError("I/O")),
        patch("os.open", side_effect=AssertionError("I/O")),
        patch("subprocess.Popen", side_effect=AssertionError("query")),
        patch("socket.socket", side_effect=AssertionError("network")),
        patch.object(zipfile.ZipFile, "extract", side_effect=AssertionError("extract")),
        patch.object(
            zipfile.ZipFile, "extractall", side_effect=AssertionError("extract")
        ),
    ):
        result = replay(RAW, pin=PIN)
    assert result["replay_matches_published"] is True
    assert RAW == before and sha(RAW) == PIN


@pytest.mark.parametrize("value", [None, True, False, 1, "scalar", []])
@pytest.mark.parametrize(
    "artifact",
    [
        "baseline-receipt.json",
        "applied-child.raw",
        "released-launch.json",
        "provenance.json",
    ],
)
def test_reenrolled_nonobject_artifact_raises_public_archive_error(artifact, value):
    files = deepcopy(ORIGINAL)
    files[artifact] = wire(value)
    refresh_manifest(files)
    with pytest.raises(audit.ProviderRestorationArchiveError):
        replay(packed(files))


def test_source_policy_record_budget_refuses_before_per_line_authentication():
    files = deepcopy(ORIGINAL)
    policy = json.loads(files["original-policy.json"])
    files["source-final.jsonl"] = files["source-prefix.jsonl"] + b"{}\n" * (
        policy["input_max_records"] + 1
    )
    refresh_manifest(files)
    with pytest.raises(
        audit.ProviderRestorationArchiveError, match="Source policy byte/record bound"
    ):
        replay(packed(files))


def test_bare_carriage_returns_refuse_before_source_splitlines_allocation():
    files = deepcopy(ORIGINAL)
    policy = json.loads(files["original-policy.json"])
    prefix = files["source-prefix.jsonl"]
    count = min(100_000, policy["input_max_bytes"] - len(prefix) - 1)
    assert count > 0
    files["source-final.jsonl"] = prefix + b"\r" * count + b"\n"
    assert len(files["source-final.jsonl"]) <= policy["input_max_bytes"]
    assert files["source-final.jsonl"].count(b"\n") <= policy["input_max_records"]
    refresh_manifest(files)
    with pytest.raises(
        audit.ProviderRestorationArchiveError, match="Source policy byte/record bound"
    ):
        replay(packed(files))
