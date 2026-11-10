"""Prepare public new-scope live-origin candidates; no writes or private keys."""

import argparse
import hashlib
import os
import stat
from pathlib import Path
import sys

from .input_auth import TrustPolicy, read_regular
from .input_live import SCHEMA, validate_registration
from .input_origin import MAX_IMAGE
from .journal import OutcomeJournalError, _json, _parse


def prepare(
    policy,
    binary,
    environment,
    *,
    ai_socket_uid=None,
    capture_apparmor_profile=None,
    native_apparmor_profile=None,
):
    if (
        policy.data["witness_uid"] != 0
        or os.geteuid() != 0
        or policy.data["schema_version"] != "outcome-input-trust/v1"
    ):
        raise OutcomeJournalError("new-scope root-owned live enrollment required")
    d = policy.data
    source, _ = read_regular(
        d["source_path"], owner=d["producer_uid"], max_bytes=d["input_max_bytes"]
    )
    if source or any(
        next(Path(d[k]).iterdir(), None) is not None
        for k in ("journal_directory", "anchor_directory")
    ):
        raise OutcomeJournalError("live enrollment requires new empty evidence scope")
    if (
        type(environment) is not dict
        or type(environment.get("AZAZEL_EVE_PATH")) is not str
    ):
        raise OutcomeJournalError("explicit registered environment required")
    image, info = read_regular(binary, owner=0, max_bytes=MAX_IMAGE)
    if (
        not image.startswith(b"\x7fELF")
        or not info.st_mode & 0o111
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        raise OutcomeJournalError("unsafe live enrollment image")
    existing = {
        **dict(d),
        "binary_path": str(binary),
        "binary_sha256": hashlib.sha256(image).hexdigest(),
    }
    r = dict(
        schema_version=SCHEMA,
        mode="live-core",
        **{
            k: existing[k]
            for k in (
                "scope_ref",
                "producer_ref",
                "stream_ref",
                "producer_public_key",
                "binary_path",
                "binary_sha256",
            )
        },
        launcher_uid=0,
        environment=environment,
    )
    if ai_socket_uid is not None:
        r["schema_version"] = "outcome-live-origin-registration/v2"
        r["ai_socket_uid"] = ai_socket_uid
    if capture_apparmor_profile is not None:
        r.update(
            schema_version="outcome-live-origin-registration/v3",
            ai_socket_uid=ai_socket_uid if ai_socket_uid is not None else 0,
            capture_apparmor_profile=capture_apparmor_profile,
        )
    if native_apparmor_profile is not None:
        if capture_apparmor_profile is None:
            raise OutcomeJournalError(
                "native confinement requires registered capture confinement"
            )
        r.update(
            schema_version="outcome-live-origin-registration/v4",
            native_apparmor_profile=native_apparmor_profile,
        )
    p = TrustPolicy(
        {
            **dict(policy.data),
            "schema_version": "outcome-input-trust/v3",
            "origin_registration_sha256": hashlib.sha256(_json(r)).hexdigest(),
        }
    )
    validate_registration(p, r)
    return dict(registration=r, trust_policy=dict(p.data))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Prepare public live-origin enrollment; no writes or private keys"
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--ai-socket-uid", type=int)
    parser.add_argument("--capture-apparmor-profile")
    parser.add_argument("--native-apparmor-profile")
    args = parser.parse_args(argv)
    try:
        p = TrustPolicy.from_file(args.policy, role="witness")
        raw, _ = read_regular(args.environment, owner=0, max_bytes=8192)
        print(
            _json(
                prepare(
                    p,
                    args.binary,
                    _parse(raw),
                    ai_socket_uid=args.ai_socket_uid,
                    capture_apparmor_profile=args.capture_apparmor_profile,
                    native_apparmor_profile=args.native_apparmor_profile,
                )
            ).decode()
        )
        return 0
    except (OSError, ValueError):
        print("live enrollment refused; existing evidence unchanged", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
