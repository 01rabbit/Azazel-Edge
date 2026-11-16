"""Pinned test-only original callback clock recording, never a replacement clock gate."""

from contextlib import contextmanager
import hashlib
import os

from signed_network_phase_recording import _identity, canonical
from signed_network_recording import _clock_anchor, record_collector

SCHEMA = "edge-load-clock-context/v1"
MAX_CONTEXT_BYTES = 16 * 1024
MAX_CONTEXT_ROWS = 2


class ClockContext:
    """Two immutable context rows; an interrupted observer never gains an end row."""

    def __init__(self, path, *, metadata):
        self.fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL
                          | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.seq = self.size = 0
        self.previous = "0" * 64
        self.closed = False
        try:
            self.append("begin", dict(metadata=dict(metadata), identity=_identity(),
                                      anchor=_clock_anchor()))
        except BaseException:
            self.close()
            raise

    def append(self, kind, data):
        if self.closed or self.seq >= MAX_CONTEXT_ROWS:
            raise ValueError("clock context closed or full")
        raw = canonical(dict(schema_version=SCHEMA, seq=self.seq + 1, prev=self.previous,
                             kind=kind, data=data))
        if self.size + len(raw) > MAX_CONTEXT_BYTES:
            raise ValueError("clock context byte bound")
        view = memoryview(raw)
        while view:
            count = os.write(self.fd, view)
            if count <= 0:
                raise OSError("clock context write made no progress")
            view = view[count:]
        self.size += len(raw)
        self.seq += 1
        self.previous = hashlib.sha256(raw).hexdigest()

    def close(self):
        if not self.closed:
            self.closed = True
            os.close(self.fd)


@contextmanager
def record_observer_clock(calls_path, context_path, *, metadata, policy, policy_source_ref):
    """Use original call recorder once; genuine normal return alone records end."""
    context = ClockContext(context_path, metadata=metadata)
    try:
        with record_collector(calls_path, policy=policy, policy_source_ref=policy_source_ref):
            yield
        # Neither exceptions nor default SIGTERM/SIGKILL can execute this row.
        context.append("end", dict(anchor=_clock_anchor(), normal_return=True))
    finally:
        context.close()
