"""Read-only bounded observation of an already-sealed enrolled capture FD."""

import fcntl
import hashlib
import os
from pathlib import Path
import stat
import time

SCHEMA = "edge-capture-close-collector/v1"
MAXIMUM = 1048576
REQUIRED_SEALS = 15


def process_identity():
    value = dict(
        pid=os.getpid(),
        uid=os.geteuid(),
        process_start_ticks=None,
        boot_id=None,
        clock_domain=dict(
            time_namespace_device=None,
            time_namespace_inode=None,
            timens_offsets=None,
            established=False,
        ),
    )
    raw = Path("/proc/self/stat").read_text()
    value["process_start_ticks"] = int(raw[raw.rfind(")") + 2 :].split()[19])
    value["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    namespace = os.stat("/proc/self/ns/time")
    offsets = []
    for line in Path("/proc/self/timens_offsets").read_text().splitlines():
        clock, seconds, nanos = line.split()
        offsets.append(dict(clock=clock, seconds=int(seconds), nanoseconds=int(nanos)))
    value["clock_domain"].update(
        time_namespace_device=namespace.st_dev,
        time_namespace_inode=namespace.st_ino,
        timens_offsets=offsets,
        established=(
            {r["clock"] for r in offsets} == {"monotonic", "boottime"}
            and all(r["seconds"] == r["nanoseconds"] == 0 for r in offsets)
        ),
    )
    return value


def _object(info):
    return dict(
        device=info.st_dev,
        inode=info.st_ino,
        owner_uid=info.st_uid,
        mode=info.st_mode,
        nlink=info.st_nlink,
        size=info.st_size,
    )


def collect_sealed_fd(fd, *, expected_identity, maximum=MAXIMUM):
    """Never closes, seeks, writes or seals the target; partial bytes survive faults.

    This observes a finite test object. Same-UID/kernel custody is a premise,
    never independent production authentication or all-event completeness.
    """
    if (
        type(fd) is not int
        or fd < 0
        or type(maximum) is not int
        or not 1 <= maximum <= MAXIMUM
        or type(expected_identity) is not dict
        or set(expected_identity) != {"device", "inode", "owner_uid"}
        or any(
            type(v) is not int or not 0 <= v < 2**64 for v in expected_identity.values()
        )
    ):
        raise ValueError("invalid sealed-FD enrollment or byte bound")
    errors = []
    receipt = dict(
        schema_version=SCHEMA,
        collector_identity=None,
        object_before=None,
        object_after=None,
        access_mode=None,
        seals_before=None,
        seals_after=None,
        read_started_ns=None,
        read_finished_ns=None,
        bytes_read=0,
        sha256=hashlib.sha256(b"").hexdigest(),
        complete=False,
        errors=errors,
    )
    raw = bytearray()
    try:
        receipt["read_started_ns"] = time.monotonic_ns()
    except Exception:
        errors.append("read_start_clock_unavailable")
    try:
        receipt["collector_identity"] = process_identity()
    except Exception:
        errors.append("collector_identity_unavailable")
    ready = True
    try:
        before = _object(os.fstat(fd))
        receipt["object_before"] = before
        if (
            not stat.S_ISREG(before["mode"])
            or before["nlink"] != 0
            or any(before[key] != value for key, value in expected_identity.items())
        ):
            errors.append("enrolled_object_identity_or_type_mismatch")
            ready = False
        if not 0 <= before["size"] <= maximum:
            errors.append("capture_size_overbound")
            ready = False
    except Exception:
        errors.append("initial_fstat_unavailable")
        ready = False
    try:
        receipt["access_mode"] = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
        if receipt["access_mode"] != os.O_RDONLY:
            errors.append("capture_descriptor_not_read_only")
            ready = False
    except Exception:
        errors.append("access_mode_unavailable")
        ready = False
    seal_command = getattr(fcntl, "F_GET_SEALS", None)
    try:
        if seal_command is None:
            raise ValueError("unsupported seal observation")
        receipt["seals_before"] = fcntl.fcntl(fd, seal_command)
        if receipt["seals_before"] != REQUIRED_SEALS:
            errors.append("required_initial_seals_unavailable")
            ready = False
    except Exception:
        errors.append("initial_seal_observation_unavailable")
        ready = False
    if ready:
        try:
            size = receipt["object_before"]["size"]
            while len(raw) < size:
                chunk = os.pread(fd, min(65536, size - len(raw)), len(raw))
                if type(chunk) is not bytes or not chunk:
                    raise OSError("capture ended before enrolled size")
                if len(chunk) > min(65536, size - len(raw)):
                    raise OSError("capture read exceeded requested bound")
                raw.extend(chunk)
            if os.pread(fd, 1, size) != b"":
                errors.append("capture_has_bytes_after_initial_size")
        except Exception:
            errors.append("capture_read_incomplete")
    try:
        receipt["object_after"] = _object(os.fstat(fd))
        if receipt["object_before"] != receipt["object_after"]:
            errors.append("capture_object_changed")
    except Exception:
        errors.append("final_fstat_unavailable")
    try:
        if seal_command is None:
            raise ValueError("unsupported seal observation")
        receipt["seals_after"] = fcntl.fcntl(fd, seal_command)
        if receipt["seals_after"] != REQUIRED_SEALS:
            errors.append("required_final_seals_unavailable")
    except Exception:
        errors.append("final_seal_observation_unavailable")
    try:
        receipt["read_finished_ns"] = time.monotonic_ns()
    except Exception:
        errors.append("read_end_clock_unavailable")
    data = bytes(raw)
    receipt.update(
        bytes_read=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        complete=not errors,
    )
    return dict(raw=data, receipt=receipt)
