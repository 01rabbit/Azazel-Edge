"""Read-only bounded observation of an enrolled original regular Source FD."""

import fcntl
import hashlib
import os
from pathlib import Path
import stat
import time

SCHEMA = "edge-real-source-close-read/v1"
MAXIMUM = 1048576


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
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
    )


def collect_regular_source_fd(fd, *, expected_identity, maximum=MAXIMUM):
    """Never mutate/close/seek the Source; a stable read is not immutability.

    The collector has no Source key, witness RPC or journal writes. Fixed own
    process reads do not authenticate native launch or actual defensive action.
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
        raise ValueError("invalid regular-Source enrollment or byte bound")
    errors = []
    receipt = dict(
        schema_version=SCHEMA,
        collector_identity=None,
        source_before=None,
        source_after=None,
        access_mode=None,
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
        receipt["source_before"] = before
        if (
            not stat.S_ISREG(before["mode"])
            or before["nlink"] != 1
            or before["mode"] & 0o022
            or any(before[key] != value for key, value in expected_identity.items())
        ):
            errors.append("source_identity_type_or_mode_mismatch")
            ready = False
        if not 0 <= before["size"] <= maximum:
            errors.append("capture_size_overbound")
            ready = False
    except Exception:
        errors.append("initial_source_fstat_unavailable")
        ready = False
    try:
        receipt["access_mode"] = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
        if receipt["access_mode"] != os.O_RDONLY:
            errors.append("capture_descriptor_not_read_only")
            ready = False
    except Exception:
        errors.append("access_mode_unavailable")
        ready = False
    if ready:
        try:
            size = receipt["source_before"]["size"]
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
        receipt["source_after"] = _object(os.fstat(fd))
        if receipt["source_before"] != receipt["source_after"]:
            errors.append("regular_source_changed")
    except Exception:
        errors.append("final_fstat_unavailable")
    try:
        receipt["read_finished_ns"] = time.monotonic_ns()
    except Exception:
        errors.append("read_end_clock_unavailable")
    identity = receipt["collector_identity"]
    if (
        type(identity) is not dict
        or type(identity.get("clock_domain")) is not dict
        or identity["clock_domain"].get("established") is not True
    ):
        errors.append("collector_clock_domain_unestablished")
    begin, end = receipt["read_started_ns"], receipt["read_finished_ns"]
    if not (type(begin) is int and type(end) is int and 0 <= begin <= end < 2**64):
        errors.append("actual_read_clock_bracket_unavailable")
    data = bytes(raw)
    receipt.update(
        bytes_read=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        complete=not errors,
    )
    return dict(raw=data, receipt=receipt)
