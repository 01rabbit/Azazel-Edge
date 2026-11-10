"""Prepare public enrollment candidates offline; never provision keys or roles."""

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

from .input_auth import TrustPolicy, read_regular
from .input_origin import MAX_IMAGE, ORIGIN_SCHEMA
from .journal import OutcomeJournalError, _json


def prepare(policy, binary, raw_path, raw_uid):
    """Witness/operator-only public candidate, for a new empty evidence scope.

    Output is not registration until the operator installs these exact public
    bytes under protected ownership. No file is changed by this API.
    """
    d = policy.data
    if (
        os.geteuid() != d["witness_uid"]
        or d["schema_version"] != "outcome-input-trust/v1"
    ):
        raise OutcomeJournalError("new-scope witness enrollment required")
    source, _ = read_regular(
        d["source_path"], owner=d["producer_uid"], max_bytes=d["input_max_bytes"]
    )
    if source:
        raise OutcomeJournalError("enrollment requires new empty evidence scope")
    for k in ("journal_directory", "anchor_directory"):
        if next(Path(d[k]).iterdir(), None) is not None:
            raise OutcomeJournalError("enrollment requires new empty evidence scope")
    image, info = read_regular(binary, owner=d["witness_uid"], max_bytes=MAX_IMAGE)
    if (
        not image.startswith(b"\x7fELF")
        or not info.st_mode & 0o111
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        raise OutcomeJournalError("unsafe enrollment binary")
    if type(raw_uid) is not int or raw_uid not in (0, d["witness_uid"]):
        raise OutcomeJournalError("independent raw ingress owner required")
    raw, raw_info = read_regular(
        raw_path, owner=raw_uid, max_bytes=d["input_max_bytes"]
    )
    if (raw and not raw.endswith(b"\n")) or raw.count(b"\n") > d["input_max_records"]:
        raise OutcomeJournalError("incomplete or oversized raw source")
    registration = dict(
        schema_version=ORIGIN_SCHEMA,
        mode="readonly-core",
        **{
            k: d[k]
            for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")
        },
        binary_path=str(binary),
        binary_sha256=hashlib.sha256(image).hexdigest(),
        raw_path=str(raw_path),
        raw_uid=raw_uid,
        raw_device=raw_info.st_dev,
        raw_inode=raw_info.st_ino
    )
    digest = hashlib.sha256(_json(registration)).hexdigest()
    upgraded = TrustPolicy(
        {
            **dict(d),
            "schema_version": "outcome-input-trust/v2",
            "origin_registration_sha256": digest,
        }
    )
    return {"registration": registration, "trust_policy": dict(upgraded.data)}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Prepare public new-scope origin enrollment; writes no files"
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--raw-input", type=Path, required=True)
    parser.add_argument("--raw-owner-uid", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        p = TrustPolicy.from_file(args.policy, role="witness")
        result = prepare(p, args.binary, args.raw_input, args.raw_owner_uid)
        print(_json(result).decode())
        return 0
    except (OSError, ValueError):
        print("origin enrollment refused; existing evidence unchanged", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
