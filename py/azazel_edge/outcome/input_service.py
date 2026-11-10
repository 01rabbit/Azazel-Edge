"""Offline root-only import into a new, quarantined service capture bundle.

Never generates/replaces keys, resets evidence, grants users/capabilities or
starts services. A partially provisioned destination is preserved, not repaired.
"""

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

from .input_auth import (
    TrustPolicy,
    read_regular,
    open_parent,
    crypto,
    public_hex,
    SourceVerifier,
)
from .input_live import registration, validate_registration, SCHEMA
from .input_origin import MAX_IMAGE
from .journal import OutcomeJournalError, _json, _parse

POLICY = "trust.json"
REGISTRATION = "origin.json"
RECEIPT = "provisioned.json"
PRODUCER_KEY = "producer/key.raw"
WITNESS_KEY = "witness/key.raw"


def require_root():
    if os.geteuid() != 0:
        raise OutcomeJournalError("trusted root provisioning required")


def layout(root, p):
    expected = dict(
        source_path=str(root / "input"),
        journal_directory=str(root / "observer"),
        anchor_directory=str(root / "witness/anchors"),
        socket_path=str(root / "socket/witness.sock"),
    )
    if (
        any(p.data[k] != v for k, v in expected.items())
        or p.data["witness_uid"] != 0
        or p.data["schema_version"] != "outcome-input-trust/v3"
    ):
        raise OutcomeJournalError(
            "new live service bundle requires exact protected layout"
        )
    return expected


def public_receipt(root, p, r):
    return dict(
        schema_version="outcome-service-bundle/v1",
        bundle=str(root),
        trust_sha256=p.digest,
        registration_sha256=hashlib.sha256(_json(r)).hexdigest(),
        producer_public_key=p.data["producer_public_key"],
        witness_public_key=p.data["witness_public_key"],
    )


def key_bytes(path, owner, expected):
    raw, _ = read_regular(path, owner=owner, max_bytes=32, mode=0o600)
    Private, *_ = crypto()
    if len(raw) != 32 or public_hex(Private.from_private_bytes(raw)) != expected:
        raise OutcomeJournalError("imported key does not match registered public role")
    return raw


def check_directory(path, owner, mode):
    fd, name = open_parent(path, trusted_owner=owner)
    try:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner
            or stat.S_IMODE(info.st_mode) != mode
        ):
            raise OutcomeJournalError("unsafe or incomplete bundle directory")
    finally:
        os.close(fd)


def verify(root):
    require_root()
    root = Path(root)
    check_directory(root, 0, 0o755)
    p = TrustPolicy.from_file(root / POLICY, role="witness")
    layout(root, p)
    r = registration(p, root / REGISTRATION)
    for relative, uid in (
        ("producer", p.data["producer_uid"]),
        ("observer", p.data["observer_uid"]),
        ("witness", 0),
        ("witness/anchors", 0),
    ):
        check_directory(root / relative, uid, 0o700)
    check_directory(root / "socket", 0, 0o755)
    key_bytes(
        root / PRODUCER_KEY, p.data["producer_uid"], p.data["producer_public_key"]
    )
    key_bytes(root / WITNESS_KEY, 0, p.data["witness_public_key"])
    receipt, _ = read_regular(root / RECEIPT, owner=0, max_bytes=4096, mode=0o644)
    if _parse(receipt) != public_receipt(root, p, r):
        raise OutcomeJournalError("bundle completion receipt mismatch")
    source, _ = read_regular(
        root / "input",
        owner=p.data["producer_uid"],
        max_bytes=p.data["input_max_bytes"],
        mode=0o644,
    )
    SourceVerifier(p).verify(source)  # No source/journal/anchor recreation or repair.
    return p, r


def _write(path, data, owner, mode):
    parent, name = open_parent(path, trusted_owner=owner)
    fd = None
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        os.fchown(fd, owner, owner)
        # Never expose a private key outside 0600, including its first byte.
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OutcomeJournalError("provision short write")
            view = view[n:]
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.fsync(parent)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def prepare(root, template_path, binary, environment_path, *, ai_socket_uid=None):
    require_root()
    root = Path(root)
    template = TrustPolicy.from_file(template_path, role="witness")
    if (
        template.data["schema_version"] != "outcome-input-trust/v1"
        or template.data["witness_uid"] != 0
    ):
        raise OutcomeJournalError("explicit new-scope public template required")
    parent, name = open_parent(root, trusted_owner=0)
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise OutcomeJournalError("candidate destination must not exist")
    finally:
        os.close(parent)
    image, info = read_regular(binary, owner=0, max_bytes=MAX_IMAGE)
    if (
        not image.startswith(b"\x7fELF")
        or not info.st_mode & 0o111
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        raise OutcomeJournalError("unsafe service candidate image")
    raw, _ = read_regular(environment_path, owner=0, max_bytes=8192)
    r = dict(
        schema_version=SCHEMA,
        mode="live-core",
        **{
            k: template.data[k]
            for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")
        },
        binary_path=str(binary),
        binary_sha256=hashlib.sha256(image).hexdigest(),
        launcher_uid=0,
        environment=_parse(raw)
    )
    if ai_socket_uid is not None:
        r.update(
            schema_version="outcome-live-origin-registration/v2",
            ai_socket_uid=ai_socket_uid,
        )
    d = dict(template.data)
    d.update(
        schema_version="outcome-input-trust/v3",
        source_path=str(root / "input"),
        journal_directory=str(root / "observer"),
        anchor_directory=str(root / "witness/anchors"),
        socket_path=str(root / "socket/witness.sock"),
        origin_registration_sha256=hashlib.sha256(_json(r)).hexdigest(),
    )
    policy = TrustPolicy(d)
    layout(root, policy)
    validate_registration(policy, r)
    return dict(trust_policy=dict(policy.data), registration=r)


def provision(root, policy_path, registration_path, producer_key, witness_key):
    require_root()
    root = Path(root)
    p = TrustPolicy.from_file(policy_path, role="witness")
    layout(root, p)
    r = registration(p, registration_path)
    raw_registration, _ = read_regular(registration_path, owner=0, max_bytes=16384)
    # Exact bytes are pinned; candidate serialization is deliberately required.
    if raw_registration != _json(r):
        raise OutcomeJournalError("canonical exact enrollment bytes required")
    pk = key_bytes(producer_key, 0, p.data["producer_public_key"])
    wk = key_bytes(witness_key, 0, p.data["witness_public_key"])
    parent, name = open_parent(root, trusted_owner=0)
    created = False
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            existing, reg = verify(root)
            if existing.digest != p.digest or reg != r:
                raise OutcomeJournalError("existing bundle differs; no replacement")
            return public_receipt(root, p, r)
        # Root-only quarantine prevents any role using partial material.
        for relative, uid, mode in (
            ("producer", p.data["producer_uid"], 0o700),
            ("observer", p.data["observer_uid"], 0o700),
            ("witness", 0, 0o700),
            ("witness/anchors", 0, 0o700),
            ("socket", 0, 0o755),
        ):
            directory = root / relative
            directory.mkdir(mode=0o700)
            os.chown(directory, uid, uid)
            directory.chmod(mode)
        _write(root / PRODUCER_KEY, pk, p.data["producer_uid"], 0o600)
        _write(root / WITNESS_KEY, wk, 0, 0o600)
        _write(root / "input", b"", p.data["producer_uid"], 0o644)
        _write(root / REGISTRATION, raw_registration, 0, 0o644)
        _write(root / POLICY, _json(dict(p.data)), 0, 0o644)
        for relative in (
            "producer",
            "observer",
            "witness/anchors",
            "witness",
            "socket",
            ".",
        ):
            fd = os.open(root / relative, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        receipt = public_receipt(root, p, r)
        _write(root / RECEIPT, _json(receipt), 0, 0o644)
        os.chmod(root, 0o755)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
        verify(root)
        return receipt
    except BaseException:
        if created:
            try:
                os.chmod(root, 0o700)
            except OSError:
                pass
        raise
    finally:
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline key import/new capture bundle; never starts services"
    )
    parser.add_argument("operation", choices=("prepare", "provision", "verify"))
    parser.add_argument("--bundle", type=Path, required=True)
    for flag in ("policy", "registration", "producer-key", "witness-key"):
        parser.add_argument("--" + flag, type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--ai-socket-uid", type=int)
    args = parser.parse_args(argv)
    try:
        if args.operation == "prepare":
            if (
                args.policy is None
                or args.binary is None
                or args.environment is None
                or args.producer_key is not None
                or args.witness_key is not None
            ):
                raise OutcomeJournalError(
                    "public template/image/environment only for preparation"
                )
            result = prepare(
                args.bundle,
                args.policy,
                args.binary,
                args.environment,
                ai_socket_uid=args.ai_socket_uid,
            )
        elif args.operation == "verify":
            p, r = verify(args.bundle)
            result = public_receipt(args.bundle, p, r)
        else:
            if any(
                getattr(args, k) is None
                for k in ("policy", "registration", "producer_key", "witness_key")
            ):
                raise OutcomeJournalError(
                    "explicit public candidates and private input files required"
                )
            result = provision(
                args.bundle,
                args.policy,
                args.registration,
                args.producer_key,
                args.witness_key,
            )
        print(_json(result).decode())
        return 0
    except (OSError, ValueError):
        print(
            "service key provisioning refused; preserve existing/partial evidence; no activation",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
