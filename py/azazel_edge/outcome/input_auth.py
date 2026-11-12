"""Opt-in Ed25519 capture provenance. No executor, key in consumer, or IP I/O."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from types import MappingProxyType
from pathlib import Path
import stat

from .live_protocol import LiveState, signed_live_event
from .journal import OutcomeJournalError, _json, _parse, _ref, ZERO_HASH

SOURCE_SCHEMA = "outcome-signed-input/v1"
SOURCE_DOMAIN = b"azazel-edge:input-capture:v1\x00"
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


def crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature

        return Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature
    except ImportError as exc:
        raise OutcomeJournalError(
            "input authentication requires the preprovisioned optional profile"
        ) from exc


def hex_bytes(value, size):
    if (
        type(value) is not str
        or len(value) != size * 2
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise OutcomeJournalError("invalid bounded authentication value")
    return bytes.fromhex(value)


def verify_signature(public, signature, domain, body):
    _, Public, _, Invalid = crypto()
    try:
        Public.from_public_bytes(hex_bytes(public, 32)).verify(
            hex_bytes(signature, 64), domain + _json(body)
        )
    except (ValueError, Invalid) as exc:
        raise OutcomeJournalError("authentication signature invalid") from exc


def sign(private, domain, body):
    return private.sign(domain + _json(body)).hex()


def public_hex(private):
    _, _, serialization, _ = crypto()
    return (
        private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def open_parent(path, *, trusted_owner=None):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or not path.name:
        raise OutcomeJournalError("physical absolute authentication path required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def trusted(fd):
        if trusted_owner is None:
            return
        info = os.fstat(fd)
        if info.st_uid not in (0, trusted_owner) or (
            info.st_mode & 0o022
            and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
        ):
            raise OutcomeJournalError(
                "authentication ancestor is writable by another role"
                f" (uid={info.st_uid}, trusted={trusted_owner}, mode={info.st_mode:o})"
            )

    try:
        trusted(fd)
        for part in path.parts[1:-1]:
            new = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = new
            trusted(fd)
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def read_regular(path, *, owner, max_bytes, mode=None, missing=False):
    parent, name = open_parent(path, trusted_owner=owner)
    fd = None
    try:
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            if missing:
                return b"", None
            raise
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != owner
            or info.st_mode & 0o022
            or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
            or info.st_size > max_bytes
        ):
            raise OutcomeJournalError(
                "unsafe or oversized authentication file"
                f" (uid={info.st_uid}, owner={owner}, mode={info.st_mode:o},"
                f" requested_mode={mode}, links={info.st_nlink},"
                f" size={info.st_size}, limit={max_bytes})"
            )
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent,
        )
        pinned = os.fstat(fd)
        if (pinned.st_dev, pinned.st_ino, pinned.st_uid) != (
            info.st_dev,
            info.st_ino,
            owner,
        ):
            raise OutcomeJournalError("authentication file identity changed")
        data = bytearray()
        while len(data) <= max_bytes:
            part = os.read(fd, min(65536, max_bytes + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            len(data) > max_bytes
            or (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino)
            or not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or after.st_uid != owner
            or after.st_mode & 0o022
            or (mode is not None and stat.S_IMODE(after.st_mode) != mode)
        ):
            raise OutcomeJournalError("authentication file changed")
        return bytes(data), info
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def private_key(path, expected_public):
    raw, _ = read_regular(path, owner=os.geteuid(), max_bytes=32, mode=0o600)
    Private, _, _, _ = crypto()
    if len(raw) != 32:
        raise OutcomeJournalError("invalid private key file")
    value = Private.from_private_bytes(raw)
    if public_hex(value) != expected_public:
        raise OutcomeJournalError("private key does not match configured role")
    return value


@dataclass(frozen=True)
class TrustPolicy:
    data: dict

    def __post_init__(self):
        fields = {
            "schema_version",
            "scope_ref",
            "producer_ref",
            "stream_ref",
            "producer_public_key",
            "witness_ref",
            "witness_public_key",
            "producer_uid",
            "witness_uid",
            "observer_uid",
            "source_path",
            "journal_directory",
            "socket_path",
            "anchor_directory",
            "input_max_bytes",
            "input_max_records",
            "journal_max_bytes",
            "anchor_max_bytes",
            "anchor_max_records",
        }
        d = self.data
        if type(d) is dict and d.get("schema_version") == "outcome-input-trust/v4":
            fields.add("witness_transport")
        if type(d) is dict and d.get("schema_version") in (
            "outcome-input-trust/v2",
            "outcome-input-trust/v3",
            "outcome-input-trust/v4",
        ):
            fields.add("origin_registration_sha256")
            hex_bytes(d.get("origin_registration_sha256"), 32)
        if (
            type(d) is not dict
            or set(d) != fields
            or d["schema_version"]
            not in (
                "outcome-input-trust/v1",
                "outcome-input-trust/v2",
                "outcome-input-trust/v3",
                "outcome-input-trust/v4",
            )
        ):
            raise OutcomeJournalError("invalid input trust policy")
        for key in ("scope_ref", "producer_ref", "stream_ref", "witness_ref"):
            _ref(d[key])
        for key in ("producer_public_key", "witness_public_key"):
            hex_bytes(d[key], 32)
        if d["producer_public_key"] == d["witness_public_key"]:
            raise OutcomeJournalError("separate producer and witness keys required")
        for key in ("producer_uid", "witness_uid", "observer_uid"):
            if type(d[key]) is not int or not 0 <= d[key] < 2**31:
                raise OutcomeJournalError("invalid authentication role uid")
        if d["producer_uid"] == 0 or d["observer_uid"] == 0:
            raise OutcomeJournalError("capture producer and observer must be non-root")
        if len({d["producer_uid"], d["witness_uid"], d["observer_uid"]}) != 3:
            raise OutcomeJournalError(
                "three distinct producer, observer and witness uids required"
            )
        for key in (
            "source_path",
            "journal_directory",
            "socket_path",
            "anchor_directory",
        ):
            if type(d[key]) is not str or "\x00" in d[key]:
                raise OutcomeJournalError("invalid authentication path")
            value = Path(d[key])
            if not value.is_absolute() or ".." in value.parts or len(d[key]) > 1024:
                raise OutcomeJournalError("invalid authentication path")
        if len(d["socket_path"].encode()) > 100:
            raise OutcomeJournalError("Unix witness socket path too long")
        for key, lo, hi in (
            ("input_max_bytes", 65536, 64 * 1024 * 1024),
            ("input_max_records", 1, 32768),
            ("journal_max_bytes", 131072, 64 * 1024 * 1024),
            ("anchor_max_bytes", 131072, 64 * 1024 * 1024),
            ("anchor_max_records", 2, 131072),
        ):
            if type(d[key]) is not int or not lo <= d[key] <= hi:
                raise OutcomeJournalError("invalid authentication budget")
        paths = [
            d["source_path"],
            str(Path(d["journal_directory"]) / "observations.journal"),
            d["socket_path"],
            str(Path(d["anchor_directory"]) / "anchors.journal"),
        ]
        if len(set(paths)) != 4:
            raise OutcomeJournalError("authentication paths must be separate")

        values = dict(d)
        if d["schema_version"] == "outcome-input-trust/v4":
            from .input_transport import validate_transport

            values["witness_transport"] = validate_transport(
                d["scope_ref"], d["witness_transport"]
            )
        object.__setattr__(self, "data", MappingProxyType(values))

    @property
    def digest(self):
        return hashlib.sha256(_json(dict(self.data))).hexdigest()

    @classmethod
    def from_file(cls, path, *, role):
        # Owner is checked again against the declared witness UID after strict parsing.
        parent, name = open_parent(path)
        try:
            owner = os.stat(name, dir_fd=parent, follow_symlinks=False).st_uid
        finally:
            os.close(parent)
        raw, _ = read_regular(path, owner=owner, max_bytes=8192)
        p = cls(_parse(raw))
        if (
            owner != p.data["witness_uid"]
            or role not in ("observer", "witness", "producer")
            or os.geteuid() != p.data[role + "_uid"]
        ):
            raise OutcomeJournalError("trust policy ownership/role mismatch")
        crypto()  # No fallback when the requested profile is unavailable.
        return p

    def binding(self):
        return dict(schema_version="outcome-input-auth/v1", trust_sha256=self.digest)


def validate_readonly_origin_event(event):
    """An enrolled read-only calculation can never claim live application."""
    if type(event) is not dict:
        raise OutcomeJournalError("invalid read-only origin event")
    enforcement = event.get("enforcement")
    status = event.get("enforcement_status")
    if (
        type(event.get("normalized")) is not dict
        or type(event.get("defense")) is not dict
        or event.get("pipeline") != "rust_event_engine_v1"
        or event.get("source") != "suricata_eve"
        or type(enforcement) is not dict
        or type(status) is not dict
    ):
        raise OutcomeJournalError("invalid read-only origin event")
    if (
        enforcement.get("mode") != "dry_run"
        or enforcement.get("result") != "dry_run"
        or type(enforcement.get("executed_count")) is not int
        or enforcement["executed_count"] != 0
        or type(enforcement.get("failed_count")) is not int
        or enforcement["failed_count"] != 0
        or enforcement.get("command_plan") != []
        or enforcement.get("rollback_plan") != []
        or enforcement.get("errors") != []
        or enforcement.get("metadata") != {"capture_only": True}
        or status.get("enforce_enabled") is not False
        or status.get("dry_run") is not True
        or status.get("high_impact_auto") is not False
        or status.get("enforce_level") != "advisory"
        or status.get("allowed_actions") != []
    ):
        raise OutcomeJournalError("read-only origin cannot assert execution authority")


class SourceVerifier:
    def __init__(self, policy):
        self.policy = policy
        self.raw = b""
        self.seq = 0
        self.head = ZERO_HASH
        self.origin_offset = 0
        self.live_state = LiveState()

    def verify(self, data):
        p = self.policy.data
        if (
            len(data) > p["input_max_bytes"]
            or data.count(b"\n") > p["input_max_records"]
            or (data and not data.endswith(b"\n"))
        ):
            raise OutcomeJournalError("invalid bounded signed source")
        if not data.startswith(self.raw):
            raise OutcomeJournalError("signed input rewound or changed")
        seq = self.seq
        head = self.head
        origin_offset = self.origin_offset
        live_state = self.live_state
        for line in data[len(self.raw) :].splitlines(keepends=True):
            if len(line) > 65536:
                raise OutcomeJournalError("signed input frame too large")
            wire = _parse(line)
            fields = {
                "schema_version",
                "scope_ref",
                "producer_ref",
                "stream_ref",
                "boot_ref",
                "seq",
                "prev",
                "event",
                "signature",
            }
            if (
                type(wire) is not dict
                or set(wire) != fields
                or _json(wire) + b"\n" != line
            ):
                raise OutcomeJournalError("noncanonical signed input frame")
            core = {k: v for k, v in wire.items() if k != "signature"}
            if (
                wire["schema_version"] != SOURCE_SCHEMA
                or type(wire["seq"]) is not int
                or wire["seq"] != seq + 1
                or wire["prev"] != head
                or any(
                    wire[k] != p[k] for k in ("scope_ref", "producer_ref", "stream_ref")
                )
                or type(wire["event"]) is not dict
            ):
                raise OutcomeJournalError("signed input identity/sequence mismatch")
            _ref(wire["boot_ref"])
            registration = p.get("origin_registration_sha256")
            if p["schema_version"] in (
                "outcome-input-trust/v3",
                "outcome-input-trust/v4",
            ):
                live_state = signed_live_event(wire["event"], registration, live_state)
            elif registration is not None:
                validate_readonly_origin_event(wire["event"])
                origin = wire["event"].get("capture_origin")
                if (
                    type(origin) is not dict
                    or set(origin)
                    != {"schema_version", "registration_sha256", "mode", "raw_cursor"}
                    or origin["schema_version"] != "outcome-registered-origin/v1"
                    or origin["registration_sha256"] != registration
                    or origin["mode"] != "readonly-core"
                ):
                    raise OutcomeJournalError(
                        "registered input origin missing or mismatched"
                    )
                cursor = origin["raw_cursor"]
                if (
                    type(cursor) is not dict
                    or set(cursor) != {"offset", "prefix_sha256"}
                    or type(cursor["offset"]) is not int
                    or not origin_offset < cursor["offset"] <= p["input_max_bytes"]
                ):
                    raise OutcomeJournalError("registered raw input position invalid")
                hex_bytes(cursor["prefix_sha256"], 32)
                origin_offset = cursor["offset"]
            verify_signature(
                p["producer_public_key"], wire["signature"], SOURCE_DOMAIN, core
            )
            seq += 1
            head = hashlib.sha256(_json(wire)).hexdigest()
        self.raw = data
        self.seq = seq
        self.head = head
        self.origin_offset = origin_offset
        self.live_state = live_state
        return self.tip()

    def tip(self):
        return dict(
            seq=self.seq,
            head=self.head,
            size=len(self.raw),
            sha256=hashlib.sha256(self.raw).hexdigest(),
        )

    @staticmethod
    def unwrap(line):
        return _json(_parse(line)["event"]) + b"\n"


class SignedCaptureWriter:
    """Explicit trusted-capture producer API; never called by the consumer.

    Authenticity identifies this capture key, not the truth of a Rust action.
    Caller emits origin events; no automatic re-signing/tailing untrusted logs.
    """

    def __init__(self, policy, key_path, *, boot_ref):
        if os.geteuid() != policy.data["producer_uid"]:
            raise OutcomeJournalError("producer uid required")
        self.policy = policy
        self.key = private_key(key_path, policy.data["producer_public_key"])
        self.boot_ref = _ref(boot_ref)
        self.verifier = SourceVerifier(policy)
        self.fd = None
        import fcntl

        parent, name = open_parent(policy.data["source_path"])
        try:
            # Source is precreated; never initialize/recreate silently.
            raw, info = read_regular(
                policy.data["source_path"],
                owner=policy.data["producer_uid"],
                max_bytes=policy.data["input_max_bytes"],
            )
            self.fd = os.open(
                name,
                os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            pinned = os.fstat(self.fd)
            if (pinned.st_dev, pinned.st_ino) != (info.st_dev, info.st_ino):
                raise OutcomeJournalError("producer path changed")
            self.verifier.verify(raw)
        except BaseException:
            self.close()
            raise
        finally:
            os.close(parent)
        self.poisoned = False

    def append(self, event):
        if self.fd is None or self.poisoned:
            raise OutcomeJournalError("capture writer unavailable")
        p = self.policy.data
        v = self.verifier
        core = dict(
            schema_version=SOURCE_SCHEMA,
            **{k: p[k] for k in ("scope_ref", "producer_ref", "stream_ref")},
            boot_ref=self.boot_ref,
            seq=v.seq + 1,
            prev=v.head,
            event=event,
        )
        line = _json({**core, "signature": sign(self.key, SOURCE_DOMAIN, core)}) + b"\n"
        if (
            type(event) is not dict
            or len(line) > 65536
            or len(v.raw) + len(line) > p["input_max_bytes"]
            or v.seq >= p["input_max_records"]
        ):
            raise OutcomeJournalError("capture writer capacity/type refused")
        # Reject registration/semantic/sequence faults before mutating source.
        checked = SourceVerifier(self.policy)
        checked.raw, checked.seq, checked.head = v.raw, v.seq, v.head
        checked.origin_offset = v.origin_offset
        checked.live_state = v.live_state
        checked.verify(v.raw + line)
        try:
            raw, info = read_regular(
                p["source_path"],
                owner=p["producer_uid"],
                max_bytes=p["input_max_bytes"],
            )
            if raw != v.raw or (info.st_dev, info.st_ino) != (
                os.fstat(self.fd).st_dev,
                os.fstat(self.fd).st_ino,
            ):
                raise OutcomeJournalError("capture source changed outside writer")
            view = memoryview(line)
            while view:
                n = os.write(self.fd, view)
                if n <= 0:
                    raise OutcomeJournalError("capture short write")
                view = view[n:]
            os.fsync(self.fd)
            self.verifier = checked
        except BaseException:
            self.poisoned = True
            raise
        return self.verifier.tip()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
