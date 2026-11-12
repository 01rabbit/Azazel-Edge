"""Bounded pure audit of externally pinned historical provider ZIP bytes.

Integrity is not GitHub/Root origin authentication, execution truth or freshness.
No extraction, files, commands, signing or runtime authorization is performed.
"""

import hashlib
import io
import stat
import struct
import zipfile
import zlib

from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.journal import _json
from azazel_edge.outcome.nft_flow_evidence import parse_readback
from . import safety_observations as safety
from .safety_proofs import _source
from .recorded_nft_restoration import evaluate_recorded_nft_restoration

PHASES = ("baseline", "applied", "released")
PUBLIC_FILES = frozenset(
    (
        "original-policy.json",
        "derived-policy.json",
        "source-prefix.jsonl",
        "source-final.jsonl",
        "prefix-checkpoint.json",
        "final-checkpoint.json",
        "enrollment.json",
        "contract.json",
        "source-plan.json",
        "restoration-plan.json",
        "provenance.json",
        "result.json",
    )
    + tuple(
        phase + suffix
        for phase in PHASES
        for suffix in (
            "-launch.json",
            "-child.raw",
            "-child-stderr.raw",
            "-receipt.json",
        )
    )
)
INVENTORY = PUBLIC_FILES | {"collection-hashes.json"}


class ProviderRestorationArchiveError(ValueError):
    """Invalid enrollment or inconsistent archive; no new audit result."""


def _need(condition, message):
    if not condition:
        raise ProviderRestorationArchiveError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _same(left, right):
    return _json(left) == _json(right)


def _extra(raw):
    offset = 0
    while offset < len(raw):
        _need(offset + 4 <= len(raw), "truncated ZIP extra field")
        kind, size = struct.unpack_from("<HH", raw, offset)
        _need(kind != 1 and offset + 4 + size <= len(raw), "ZIP64/invalid extra field")
        offset += 4 + size


def _zip_preflight(raw):
    # EOCD is fixed-size because this v1 forbids comments and multiple disks.
    _need(len(raw) >= 22 and raw[-22:-18] == b"PK\x05\x06", "normal ZIP EOCD required")
    _, disk, central_disk, on_disk, total, size, start, comment = struct.unpack_from(
        "<4s4H2IH", raw, len(raw) - 22
    )
    _need(
        disk == central_disk == comment == 0
        and on_disk == total == 25
        and start != 0xFFFFFFFF
        and size != 0xFFFFFFFF
        and start + size == len(raw) - 22
        and 25 * 46 <= size <= 65536,
        "bounded single-disk 25-entry central directory required",
    )
    records, offset, total_size = {}, start, 0
    for _ in range(25):
        _need(offset + 46 <= start + size, "central directory truncated")
        fields = struct.unpack_from("<4s6H3I5H2I", raw, offset)
        (
            sig,
            made,
            needed,
            flags,
            method,
            mt,
            md,
            crc,
            compressed,
            expanded,
            nl,
            xl,
            cl,
            disk_start,
            _,
            attrs,
            local,
        ) = fields
        end = offset + 46 + nl + xl + cl
        _need(
            sig == b"PK\x01\x02" and end <= start + size and disk_start == cl == 0,
            "invalid/multi-disk/commented central record",
        )
        _need(
            needed <= 20 and method in (0, 8) and flags & ~(8 | 0x800) == 0,
            "unsupported/encrypted ZIP member",
        )
        _need(
            nl <= 64
            and compressed <= 32 * 1024 * 1024
            and expanded <= 32 * 1024 * 1024
            and local < start,
            "ZIP member bound",
        )
        name_raw = raw[offset + 46 : offset + 46 + nl]
        name = name_raw.decode("ascii")
        _need(
            name in INVENTORY
            and name not in records
            and not attrs & 0x10
            and stat.S_IFMT(attrs >> 16) in (0, stat.S_IFREG),
            "unknown/duplicate/path/link ZIP member",
        )
        _extra(raw[offset + 46 + nl : offset + 46 + nl + xl])
        total_size += expanded
        _need(total_size <= 64 * 1024 * 1024, "ZIP uncompressed total bound")
        records[name] = dict(
            flags=flags,
            method=method,
            crc=crc,
            compressed=compressed,
            expanded=expanded,
            local=local,
            needed=needed,
            name_raw=name_raw,
        )
        offset = end
    _need(
        offset == start + size and set(records) == INVENTORY,
        "exact ZIP inventory required",
    )
    spans = []
    for row in records.values():
        local = row["local"]
        _need(local + 30 <= start, "local header truncated")
        sig, needed, flags, method, _, _, crc, compressed, expanded, nl, xl = (
            struct.unpack_from("<4s5H3I2H", raw, local)
        )
        data_start = local + 30 + nl + xl
        _need(
            sig == b"PK\x03\x04"
            and needed == row["needed"]
            and flags == row["flags"]
            and method == row["method"]
            and data_start <= start
            and raw[local + 30 : local + 30 + nl] == row["name_raw"],
            "local/central ZIP header differs",
        )
        _extra(raw[local + 30 + nl : data_start])
        end = data_start + row["compressed"]
        _need(end <= start, "ZIP compressed member outside data region")
        if flags & 8:
            _need(
                all(
                    a in (0, b)
                    for a, b in (
                        (crc, row["crc"]),
                        (compressed, row["compressed"]),
                        (expanded, row["expanded"]),
                    )
                ),
                "local descriptor placeholders differ",
            )
            if raw[end : end + 4] == b"PK\x07\x08":
                end += 4
            _need(
                end + 12 <= start
                and struct.unpack_from("<3I", raw, end)
                == (row["crc"], row["compressed"], row["expanded"]),
                "ZIP data descriptor differs",
            )
            end += 12
        else:
            _need(
                (crc, compressed, expanded)
                == (row["crc"], row["compressed"], row["expanded"]),
                "local ZIP sizes/CRC differ",
            )
        row["data_start"] = data_start
        spans.append((local, end))
    position = 0
    for a, b in sorted(spans):
        _need(a == position, "overlapping/gapped/prefixed ZIP members")
        position = b
    _need(position == start, "unexpected ZIP data trailer")
    return records


def _unpack(raw):
    records = _zip_preflight(raw)  # MUST run before ZipFile allocates its index.
    files = {}
    with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
        _need(
            len(archive.infolist()) == 25 and archive.comment == b"",
            "ZIP index differs",
        )
        for info in archive.infolist():
            _need(
                info.filename in records and info.filename not in files,
                "ZIP index inventory differs",
            )
            row = records[info.filename]
            _need(
                (
                    info.header_offset,
                    info.file_size,
                    info.compress_size,
                    info.compress_type,
                    info.CRC,
                    info.flag_bits,
                )
                == (
                    row["local"],
                    row["expanded"],
                    row["compressed"],
                    row["method"],
                    row["crc"],
                    row["flags"],
                ),
                "ZIP index metadata differs",
            )
            # ZipFile checks CRC. Independent bounded inflation also rejects a
            # stream whose declared size hides additional output or unused data.
            with archive.open(info, "r") as member:
                value = member.read(row["expanded"] + 1)
            _need(len(value) == row["expanded"], "ZIP declared/read size differs")
            packed = raw[row["data_start"] : row["data_start"] + row["compressed"]]
            if row["method"] == 8:
                decoder = zlib.decompressobj(-15)
                decoded = decoder.decompress(packed, row["expanded"] + 1)
                _need(
                    decoder.eof
                    and not decoder.unused_data
                    and not decoder.unconsumed_tail
                    and decoded == value,
                    "ZIP deflate stream/expanded bound differs",
                )
            else:
                _need(packed == value, "stored ZIP size differs")
            _need(zlib.crc32(value) & 0xFFFFFFFF == row["crc"], "ZIP CRC differs")
            files[info.filename] = value
    return files


def _tree(value, depth=0):
    _need(depth <= 12, "JSON depth bound")
    if type(value) is dict:
        for item in value.values():
            _tree(item, depth + 1)
    elif type(value) is list:
        _need(len(value) <= 4096, "JSON array bound")
        for item in value:
            _tree(item, depth + 1)


def _load(raw, maximum=32768, canonical=False):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, "JSON byte bound")
    value = parse_readback(raw)
    _need(type(value) is dict, "artifact JSON object required")
    _tree(value)
    if canonical:
        _need(_json(value) + b"\n" == raw, "canonical JSON+LF required")
    return value


def _audit(files):
    manifest = _load(files["collection-hashes.json"])
    safety._fields(manifest, "schema_version files errors")
    _need(
        manifest["schema_version"] == "edge-provider-artifact-copy/v1"
        and _same(manifest["errors"], []),
        "artifact manifest errors/schema",
    )
    safety._fields(manifest["files"], " ".join(PUBLIC_FILES))
    for name in PUBLIC_FILES:
        row = manifest["files"][name]
        safety._fields(row, "sha256 bytes")
        safety._hex(row["sha256"])
        safety._int(row["bytes"], 0, 32 * 1024 * 1024)
        _need(
            row["sha256"] == _sha(files[name]) and row["bytes"] == len(files[name]),
            "artifact manifest pin differs",
        )
    original, derived = files["original-policy.json"], files["derived-policy.json"]
    parsed = _load(original)
    _need(
        _json(parsed) == original and derived == original + b"\n",
        "original/DERIVED policy serialization differs",
    )
    policy = TrustPolicy(parsed)
    _need(
        TrustPolicy(_load(derived, canonical=True)).digest == policy.digest,
        "policy semantic digest differs",
    )
    contract = _load(files["contract.json"], 128 * 1024, True)
    pins = contract["keypins"]
    safety._fields(
        pins, "observer_public_key source_producer_public_key source_witness_public_key"
    )
    for key in pins.values():
        safety._hex(key)
    _need(len(set(pins.values())) == 3, "contract key roles overlap")
    safety._contract(contract, pins)
    _need(
        all(_same(v, []) for v in contract["opportunities"].values()),
        "evidence-only contract has opportunities",
    )
    source_plan = _load(files["source-plan.json"], canonical=True)
    plan = _load(files["restoration-plan.json"], canonical=True)
    prefix, source = files["source-prefix.jsonl"], files["source-final.jsonl"]
    _need(source.startswith(prefix) and bool(prefix), "original Source prefix differs")
    for raw in (prefix, source):
        # Enforce the already validated policy before allocating a line index.
        _need(
            len(raw) <= policy.data["input_max_bytes"]
            and raw.endswith(b"\n")
            and b"\r" not in raw
            and 0 < raw.count(b"\n") <= policy.data["input_max_records"],
            "Source policy byte/record bound",
        )
        for line in raw.splitlines(keepends=True):
            _load(line, 128 * 1024, True)
    for phase, field in (
        ("prefix", "prefix_checkpoint"),
        ("final", "final_checkpoint"),
    ):
        _need(
            _same(
                _load(files[phase + "-checkpoint.json"], canonical=True),
                source_plan[field],
            ),
            "Source checkpoint differs",
        )
    verified = _source(
        files["contract.json"],
        files["source-plan.json"],
        _sha(files["source-plan.json"]),
        derived,
        source,
    )
    _need(
        verified["authenticated_prefix"] is True
        and verified["authenticated_full_source"] is True
        and verified["normal_terminal_verified"] is True,
        "original Source authentication incomplete",
    )
    _need(
        verified["prefix_tip"]["size"] == len(prefix)
        and verified["prefix_tip"]["sha256"] == _sha(prefix),
        "Source prefix bytes differ",
    )
    selected = []
    for line in source.splitlines(keepends=True):
        row = _load(line, 128 * 1024, True)
        event = row["event"]
        if (
            event["capture_origin"]["kind"] == "decision_execution"
            and type(event.get("normalized", {}).get("sid")) is int
            and event["normalized"]["sid"] == 900001
        ):
            selected.append((line, row))
    _need(len(selected) == 1, "one original selected Source frame required")
    selected_raw, selected_row = selected[0]
    _need(
        type(plan["source_event_seq"]) is int
        and plan["source_event_seq"] == selected_row["seq"]
        and plan["source_event_sha256"] == _sha(selected_raw),
        "selected original Source frame pin differs",
    )
    provenance = _load(files["provenance.json"], canonical=True)
    expected_provenance = dict(
        schema_version="edge-provider-restoration-provenance/v1",
        original_policy_sha256=_sha(original),
        derived_policy_sha256=_sha(derived),
        policy_digest=policy.digest,
        derived_policy_label="DERIVED_canonical_policy_plus_LF_not_original_capture",
        observer_public_key=contract["keypins"]["observer_public_key"],
        observer_key_role="unused_schema_key_no_observations",
        source_prefix_sha256=_sha(prefix),
        source_final_sha256=_sha(source),
        selected_original_source_seq=selected_row["seq"],
        selected_original_source_sha256=_sha(selected_raw),
        Root_interval_role="actual_root_monotonic_bracket_no_opportunities_or_coverage_claim",
        Source_provenance="original_registered_signed_native_Source_not_synthetic_wrapping",
        query_provenance="original_child_query_plus_parent_actual_launch_fields",
        safety_observations_generated=False,
        **safety.FLAGS,
    )
    _need(
        _same(provenance, expected_provenance),
        "policy/Source/provenance binding differs",
    )
    enrollment = _load(files["enrollment.json"], canonical=True)
    safety._fields(
        enrollment,
        "kernel_boot_id netns_inode query_window source_identity nft_binary_sha256 receipts scope_interval",
    )
    for key in (
        "kernel_boot_id",
        "netns_inode",
        "query_window",
        "source_identity",
        "nft_binary_sha256",
        "receipts",
    ):
        _need(_same(enrollment[key], plan[key]), "original enrollment/plan differs")
    _need(
        _same(enrollment["scope_interval"], contract["scope"]["interval"]),
        "Root context interval differs",
    )
    receipts = {}
    for phase in PHASES:
        raw = files[phase + "-receipt.json"]
        receipt = _load(raw, 8 * 1024 * 1024, True)
        child = _load(files[phase + "-child.raw"], 8 * 1024 * 1024)
        _need(
            files[phase + "-child-stderr.raw"] == b"", "original child stderr not empty"
        )
        _need(
            _same(
                child,
                {
                    k: v
                    for k, v in receipt.items()
                    if k not in ("actual_child_argv", "source", "capture_boundary")
                },
            ),
            "original child/receipt differs",
        )
        launch = _load(files[phase + "-launch.json"], canonical=True)
        safety._fields(launch, "actual_child_argv root_pid expected_netns_inode")
        _need(
            _same(launch["actual_child_argv"], receipt["actual_child_argv"])
            and _same(launch["root_pid"], receipt["root_pid"])
            and _same(launch["expected_netns_inode"], receipt["netns_inode"]),
            "actual parent launch/receipt differs",
        )
        descriptor = plan["receipts"][phase]
        _need(
            _same(
                descriptor,
                dict(
                    sha256=_sha(raw),
                    root_pid=launch["root_pid"],
                    actual_child_argv=launch["actual_child_argv"],
                ),
            ),
            "parent launch/plan differs",
        )
        receipts[phase] = raw
    replayed = evaluate_recorded_nft_restoration(
        files["restoration-plan.json"],
        expected_plan_sha256=_sha(files["restoration-plan.json"]),
        source_inputs=dict(
            contract_raw=files["contract.json"],
            source_plan_raw=files["source-plan.json"],
            trust_raw=derived,
            source_raw=source,
        ),
        receipts=receipts,
    )
    published = _load(files["result.json"], 32768, True)
    _need(
        _same(published, replayed),
        "published diagnostic differs from original-byte replay",
    )
    return published


def evaluate_provider_restoration_archive(archive_raw, *, expected_archive_sha256):
    """Audit enrolled historical bytes only; no origin/freshness/custody promotion."""
    try:
        safety._hex(expected_archive_sha256)
        _need(
            type(archive_raw) is bytes and 0 < len(archive_raw) <= 32 * 1024 * 1024,
            "archive byte bound",
        )
        _need(
            _sha(archive_raw) == expected_archive_sha256, "external archive pin differs"
        )
        diagnostic = _audit(_unpack(archive_raw))
        return dict(
            schema_version="edge-provider-restoration-archive-audit/v1",
            archive_sha256=expected_archive_sha256,
            archive_integrity_verified=True,
            archive_origin_authenticated=False,
            replay_matches_published=True,
            replayed_diagnostic=diagnostic,
            network_mechanism_restored=None,
            qualified_safety_count=None,
            execution_fact_verified=False,
            independently_measured=False,
            **safety.FLAGS,
        )
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
        struct.error,
        zipfile.BadZipFile,
        zlib.error,
    ) as exc:
        if isinstance(exc, ProviderRestorationArchiveError):
            raise
        raise ProviderRestorationArchiveError(
            "invalid provider restoration archive: " + str(exc)
        ) from exc
