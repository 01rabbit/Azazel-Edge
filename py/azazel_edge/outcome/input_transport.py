"""Explicit Linux abstract witness address; no discovery, transition or fallback."""

import errno
import hashlib
import socket
import sys
import uuid

from .journal import OutcomeJournalError

SCHEMA = "outcome-input-trust/v4"
KIND = "unix-abstract/v1"


class _FrozenDict(dict):
    """JSON-compatible immutable public policy values, including nested namespace."""

    def __new__(cls, *args, **kwargs):
        value = super().__new__(cls)
        dict.__init__(value, *args, **kwargs)
        return value

    def __init__(self, *args, **kwargs):
        pass  # Populate only the fresh object; reinitialization cannot mutate it.

    def _immutable(self, *args, **kwargs):
        raise TypeError("immutable witness transport")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = (
        __ior__
    ) = _immutable


def transport(scope_ref, namespace):
    """Derive one public address; caller explicitly supplies owned namespace facts."""
    if (
        type(scope_ref) is not str
        or not scope_ref
        or type(namespace) not in (dict, _FrozenDict)
        or set(namespace) != {"cookie", "kernel_boot_id"}
        or type(namespace["cookie"]) is not int
        or not 0 < namespace["cookie"] < 2**64
        or not _canonical_boot(namespace["kernel_boot_id"])
    ):
        raise OutcomeJournalError("invalid witness network namespace")
    return _FrozenDict(
        kind=KIND,
        name="azazel-edge-witness-v1-" + hashlib.sha256(scope_ref.encode()).hexdigest(),
        network_namespace=_FrozenDict(namespace),
    )


def validate_transport(scope_ref, value):
    if type(value) not in (dict, _FrozenDict) or set(value) != {
        "kind",
        "name",
        "network_namespace",
    }:
        raise OutcomeJournalError("invalid abstract witness transport")
    expected = transport(scope_ref, value["network_namespace"])
    if value != expected:
        raise OutcomeJournalError("noncanonical abstract witness transport")
    return expected


def _canonical_boot(value):
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def socket_namespace(sock):
    """Kernel socket namespace, not a procfs namespace inode or caller guess."""
    if sys.platform != "linux":
        raise OutcomeJournalError("Linux abstract witness transport required")
    if (
        sock.family != socket.AF_UNIX
        or sock.type != socket.SOCK_STREAM
        or sock.getsockname() not in ("", b"")
    ):
        raise OutcomeJournalError("unbound Unix stream witness socket required")
    try:
        sock.getpeername()
    except OSError as exc:
        if exc.errno != errno.ENOTCONN:
            raise OutcomeJournalError(
                "witness socket connection state unavailable"
            ) from exc
    else:
        raise OutcomeJournalError("unconnected witness socket required")
    try:
        raw = sock.getsockopt(
            socket.SOL_SOCKET, getattr(socket, "SO_NETNS_COOKIE", 71), 8
        )
        if type(raw) is not bytes or len(raw) != 8:
            raise OutcomeJournalError("invalid witness namespace cookie size")
        cookie = int.from_bytes(raw, sys.byteorder)
        with open("/proc/sys/kernel/random/boot_id", "rb") as stream:
            boot_raw = stream.read(38)
        if len(boot_raw) != 37 or not boot_raw.endswith(b"\n"):
            raise OutcomeJournalError("invalid kernel boot identity")
        namespace = dict(cookie=cookie, kernel_boot_id=boot_raw[:-1].decode("ascii"))
        transport("namespace-validation", namespace)
        return namespace
    except (OSError, UnicodeError) as exc:
        raise OutcomeJournalError("witness socket namespace unavailable") from exc


def abstract_address(policy, sock):
    """Check this unbound socket BEFORE bind/connect, private key or store use."""
    if policy.data["schema_version"] != SCHEMA:
        raise OutcomeJournalError("explicit v4 abstract witness policy required")
    value = validate_transport(
        policy.data["scope_ref"], policy.data["witness_transport"]
    )
    if socket_namespace(sock) != value["network_namespace"]:
        raise OutcomeJournalError("witness network namespace mismatch")
    return b"\x00" + value["name"].encode("ascii")
