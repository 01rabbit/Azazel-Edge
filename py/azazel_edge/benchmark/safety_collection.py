"""Read-only intake of Root-enrolled sealed safety artifacts, never qualification.

Root enrollment and sensor truth remain external assumptions. Metadata fences are
not an atomic snapshot against Root; repeated intake is not a new measurement.
"""

import hashlib
import os
from pathlib import PurePosixPath
import stat
import uuid

from . import safety_observations as evaluator

_BOOT_PATH = "/proc/sys/kernel/random/boot_id"
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_DIR_FLAGS = _FILE_FLAGS | os.O_DIRECTORY
_META = (
    "st_dev",
    "st_ino",
    "st_uid",
    "st_gid",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


class SafetyCollectionError(ValueError):
    """No collection result exists for unsafe, missing or changed enrollment."""


def _require(condition, message):
    if not condition:
        raise SafetyCollectionError(message)


def _metadata(info):
    return tuple(getattr(info, field) for field in _META)


def _physical_path(value):
    path = os.fspath(value)
    _require(
        type(path) is str and 0 < len(path.encode("utf-8")) <= 256,
        "invalid physical path",
    )
    parts = path.split("/")
    _require(
        path.startswith("/")
        and len(parts) <= 33
        and all(part not in ("", ".", "..") for part in parts[1:])
        and str(PurePosixPath(path)) == path,
        "normalized absolute path required",
    )
    return path, parts[1:]


def _directory(info):
    _require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
        "unsafe Root ancestor",
    )


def _regular(info, maximum):
    _require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) == 0o444
        and info.st_nlink == 1
        and 0 <= info.st_size <= maximum,
        "unsafe or oversized enrolled artifact",
    )


class _HeldFiles:
    """Hold every original directory/file FD until evaluation and final checks."""

    def __init__(self):
        self.nodes = []

    def _hold(self, fd, parent, name, directory):
        # Record FD immediately so even a failed fstat gets independent cleanup.
        node = dict(fd=fd, parent=parent, name=name, directory=directory, metadata=None)
        self.nodes.append(node)
        info = os.fstat(fd)
        if directory:
            _directory(info)
        node["metadata"] = _metadata(info)
        return node, info

    def read(self, path, maximum):
        path, parts = _physical_path(path)
        root, _ = self._hold(os.open("/", _DIR_FLAGS), None, "/", True)
        parent = root["fd"]
        for part in parts[:-1]:
            node, _ = self._hold(
                os.open(part, _DIR_FLAGS, dir_fd=parent), parent, part, True
            )
            parent = node["fd"]
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        _regular(before, maximum)
        node, pinned = self._hold(
            os.open(parts[-1], _FILE_FLAGS, dir_fd=parent), parent, parts[-1], False
        )
        _regular(pinned, maximum)
        _require(_metadata(before) == _metadata(pinned), "artifact changed before open")
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(node["fd"], min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        _require(
            len(raw) == before.st_size and len(raw) <= maximum,
            "artifact size changed during read",
        )
        self.verify()
        return bytes(raw)

    def verify(self):
        for node in self.nodes:
            descriptor = os.fstat(node["fd"])
            named = os.stat(node["name"], dir_fd=node["parent"], follow_symlinks=False)
            if node["directory"]:
                _directory(descriptor)
                _directory(named)
            _require(
                node["metadata"] is not None
                and _metadata(descriptor) == node["metadata"] == _metadata(named),
                "artifact or ancestor metadata changed",
            )

    def close(self):
        errors = []
        for node in reversed(self.nodes):
            try:
                os.close(node["fd"])
            except BaseException as exc:
                errors.append(type(exc).__name__)
        self.nodes.clear()
        return errors


def _kernel_boot_id():
    """Fixed proc reader: proc's reported file size may be zero, unlike artifacts."""
    fd = os.open(_BOOT_PATH, _FILE_FLAGS)
    try:
        before = os.fstat(fd)
        _regular(before, 4096)
        raw = bytearray()
        while len(raw) <= 37:
            block = os.read(fd, 38 - len(raw))
            if not block:
                break
            raw.extend(block)
        _require(
            _metadata(os.fstat(fd)) == _metadata(before), "kernel boot file changed"
        )
        _require(
            len(raw) == 37 and raw.endswith(b"\n"), "bounded kernel boot ID required"
        )
        text = bytes(raw[:-1]).decode("ascii")
        _require(str(uuid.UUID(text)) == text, "canonical kernel boot ID required")
        return text
    finally:
        os.close(fd)


def _registration(enrollment, contract, effective_uid):
    evaluator._fields(
        enrollment, "schema_version contract_sha256 scope observer_uid paths"
    )
    _require(
        enrollment["schema_version"] == "edge-safety-enrollment/v1", "enrollment schema"
    )
    evaluator._hex(enrollment["contract_sha256"])
    evaluator._fields(enrollment["paths"], "contract observations checkpoint")
    evaluator._fields(
        contract.get("keypins"),
        "observer_public_key source_producer_public_key source_witness_public_key",
    )
    keys = contract["keypins"]
    for value in keys.values():
        evaluator._hex(value)
    _require(len(set(keys.values())) == 3, "registered key roles overlap")
    evaluator._contract(contract, keys)
    _require(
        evaluator._same(enrollment["scope"], contract["scope"]),
        "enrollment scope differs",
    )
    uid = enrollment["observer_uid"]
    _require(
        type(uid) is int
        and uid > 0
        and uid == effective_uid == contract["scope"]["owner"]["observer_uid"]
        and uid != contract["scope"]["owner"]["producer_uid"],
        "registered nonroot reader UID required",
    )
    return keys


def _checkpoint(value, enrollment, contract):
    evaluator._fields(
        value, "schema_version contract_sha256 scope capture_ids stream_heads"
    )
    _require(
        value["schema_version"] == "edge-safety-checkpoint/v1"
        and value["contract_sha256"] == enrollment["contract_sha256"]
        and evaluator._same(value["scope"], contract["scope"]),
        "checkpoint registration differs",
    )
    evaluator._fields(value["capture_ids"], " ".join(evaluator.CATEGORIES))
    evaluator._fields(value["stream_heads"], " ".join(evaluator.CATEGORIES))
    for category in evaluator.CATEGORIES:
        _require(
            value["capture_ids"][category]
            == contract["channels"][category]["capture_id"],
            "checkpoint capture differs",
        )
        if value["stream_heads"][category] is not None:
            evaluator._hex(value["stream_heads"][category])
    return value["stream_heads"]


def collect_registered_safety(
    enrollment_path, *, expected_enrollment_sha256, expected_checkpoint_sha256
):
    """Intake frozen registered artifacts; no writes, signing, execution or recovery."""
    held = _HeldFiles()
    failure = None
    result = None
    try:
        evaluator._hex(expected_enrollment_sha256)
        evaluator._hex(expected_checkpoint_sha256)
        effective_uid = os.geteuid()
        _require(
            type(effective_uid) is int and effective_uid > 0, "nonroot reader required"
        )
        boot = _kernel_boot_id()
        enrollment_path, _ = _physical_path(enrollment_path)
        enrollment_raw = held.read(enrollment_path, 32 * 1024)
        _require(
            hashlib.sha256(enrollment_raw).hexdigest() == expected_enrollment_sha256,
            "enrollment external digest differs",
        )
        enrollment = evaluator._wire(enrollment_raw, 32 * 1024)
        evaluator._fields(
            enrollment, "schema_version contract_sha256 scope observer_uid paths"
        )
        _require(
            enrollment["schema_version"] == "edge-safety-enrollment/v1",
            "enrollment schema",
        )
        evaluator._fields(enrollment["paths"], "contract observations checkpoint")
        paths = {
            key: _physical_path(value)[0] for key, value in enrollment["paths"].items()
        }
        _require(
            len(set([enrollment_path, *paths.values()])) == 4,
            "registered paths must be distinct",
        )
        contract_raw = held.read(paths["contract"], 128 * 1024)
        _require(
            hashlib.sha256(contract_raw).hexdigest() == enrollment["contract_sha256"],
            "registered contract digest differs",
        )
        contract = evaluator._wire(contract_raw, 128 * 1024)
        keys = _registration(enrollment, contract, effective_uid)
        _require(boot == contract["scope"]["kernel_boot_id"], "registered boot differs")
        checkpoint_raw = held.read(paths["checkpoint"], 32 * 1024)
        _require(
            hashlib.sha256(checkpoint_raw).hexdigest() == expected_checkpoint_sha256,
            "checkpoint external digest differs",
        )
        checkpoint = evaluator._wire(checkpoint_raw, 32 * 1024)
        heads = _checkpoint(checkpoint, enrollment, contract)
        observations_raw = held.read(paths["observations"], 2 * 1024 * 1024)
        held.verify()
        evaluation = evaluator.evaluate_safety_observations(
            contract_raw,
            observations_raw,
            expected_contract_sha256=enrollment["contract_sha256"],
            expected_stream_heads=heads,
            **keys,
        )
        _require(
            os.geteuid() == effective_uid and _kernel_boot_id() == boot,
            "reader UID or boot changed",
        )
        held.verify()
        result = dict(
            schema_version="edge-safety-collection-result/v1",
            status="unqualified_collection",
            provenance=dict(
                enrollment_sha256=expected_enrollment_sha256,
                checkpoint_sha256=expected_checkpoint_sha256,
                contract_sha256=enrollment["contract_sha256"],
                observations_sha256=hashlib.sha256(observations_raw).hexdigest(),
                observer_uid=effective_uid,
                kernel_boot_id=boot,
            ),
            evaluation=evaluation,
            independently_measured=False,
            qualified_safety_count=None,
        )
    except BaseException as exc:
        failure = exc
    finally:
        close_errors = held.close()
    if failure is not None or close_errors:
        message = "registered safety collection failed"
        if failure is not None:
            message += f": {type(failure).__name__}: {failure}"
        if close_errors:
            message += "; independent FD close failure: " + ",".join(close_errors)
        raise SafetyCollectionError(message) from failure
    return result
