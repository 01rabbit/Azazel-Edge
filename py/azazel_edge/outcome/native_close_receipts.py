"""Bounded opt-in diagnostics; never Source, witness or recovery authority."""

import base64
import os
import select
import sys
import time

from .journal import OutcomeJournalError, _json

NATIVE_LIMIT = 1024
NATIVE_INGRESS_LIMIT = 4096
RECEIVER_LIMIT = 4096
RECEIVER_REPORT_LIMIT = 3072
ROOT_LIMIT = 16384


def enabled(registration):
    env = registration["environment"]
    if "AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS" not in env:
        return False
    if (
        env["AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS"] != "v1"
        or env.get("AZAZEL_LIVE_ORIGIN_ACCOUNTING") != "v1"
        or env.get("AZAZEL_EVENT_STDOUT") != "off"
        or registration.get("schema_version") != "outcome-live-origin-registration/v4"
    ):
        raise OutcomeJournalError("invalid registered native close receipt profile")
    return True


def ingress_enabled(registration):
    env = registration["environment"]
    if "AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING" not in env:
        return False
    if env["AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING"] != "v1" or not enabled(
        registration
    ):
        raise OutcomeJournalError("invalid registered ingress accounting profile")
    return True


def load_cost_enabled(registration):
    env = registration["environment"]
    if "AZAZEL_LIVE_ORIGIN_LOAD_COST" not in env:
        return False
    if env["AZAZEL_LIVE_ORIGIN_LOAD_COST"] != "v1" or not ingress_enabled(registration):
        raise OutcomeJournalError("invalid registered load cost profile")
    return True


def emit(value, limit):
    try:
        raw = _json(value) + b"\n"
        if len(raw) > limit:
            return False
        sys.stdout.write(raw.decode("ascii"))
        sys.stdout.flush()
        return True
    except (OSError, ValueError, UnicodeError):
        return False


def emit_pipe(value):
    """One nonblocking atomic-sized attempt; failed publication is diagnostic loss."""
    try:
        raw = _json(value) + b"\n"
        if len(raw) > RECEIVER_REPORT_LIMIT:
            return False
        os.set_blocking(1, False)
        return os.write(1, raw) == len(raw)
    except (OSError, ValueError):
        return False


def stdout_object():
    try:
        info = os.fstat(1)
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
    except OSError:
        return None


def first_line(pipe, *, timeout=10, limit=1025):
    """No buffered read-ahead: retain precisely the bytes actually received."""
    raw = bytearray()
    deadline = time.monotonic() + timeout
    os.set_blocking(pipe.fileno(), False)
    while len(raw) < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([pipe], [], [], remaining)[0]:
            break
        try:
            part = os.read(pipe.fileno(), 1)
        except BlockingIOError:
            continue
        if not part:
            break
        raw.extend(part)
        if part == b"\n":
            break
    return bytes(raw)


def stream(pipe, *, initial=b"", limit, exited, timeout=0.25):
    raw = bytearray(initial[:limit])
    over = len(initial) > limit
    eof = False
    if pipe is not None and exited and not over:
        deadline = time.monotonic() + timeout
        try:
            os.set_blocking(pipe.fileno(), False)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([pipe], [], [], remaining)[0]:
                    break
                try:
                    part = os.read(pipe.fileno(), limit + 1 - len(raw))
                except BlockingIOError:
                    continue
                if not part:
                    eof = True
                    break
                raw.extend(part)
                if len(raw) > limit:
                    over = True
                    del raw[limit:]
                    break
        except (OSError, ValueError):
            pass
    return dict(raw_b64=base64.b64encode(raw).decode("ascii"), eof=eof, over_limit=over)
