"""Explicit Linux abstract witness address; no discovery, transition or fallback."""

import hashlib
import os
import sys

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
        or set(namespace) != {"device", "inode"}
        or any(type(v) is not int or not 0 < v < 2**64 for v in namespace.values())
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


def abstract_address(policy):
    """Check this process's namespace BEFORE creating either endpoint socket."""
    if policy.data["schema_version"] != SCHEMA:
        raise OutcomeJournalError("explicit v4 abstract witness policy required")
    value = validate_transport(
        policy.data["scope_ref"], policy.data["witness_transport"]
    )
    if sys.platform != "linux":
        raise OutcomeJournalError("Linux abstract witness transport required")
    try:
        info = os.stat("/proc/self/ns/net")
    except OSError as exc:
        raise OutcomeJournalError("witness network namespace unavailable") from exc
    if {"device": info.st_dev, "inode": info.st_ino} != value["network_namespace"]:
        raise OutcomeJournalError("witness network namespace mismatch")
    return b"\x00" + value["name"].encode("ascii")
