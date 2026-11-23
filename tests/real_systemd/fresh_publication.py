"""V2 TEST-only bounded measurement writer; no product durability changes."""

from collections import deque
import hashlib
import os
import threading
import time

from azazel_edge.outcome.journal import _json

ZERO = "0" * 64
EMPTY = hashlib.sha256(b"").hexdigest()
LIMITS = dict(
    queue_rows=1156,
    queue_bytes=8 * 1024 * 1024,
    stream_rows=dict(calls=900, input_calls=256),
    stream_bytes=dict(calls=4 * 1024 * 1024, input_calls=4 * 1024 * 1024),
    publication_rows=4096,
    publication_bytes=1024 * 1024,
    batch_bytes=65536,
    batch_ns=100_000_000,
    close_ns=5_000_000_000,
)

V3_LIMITS = dict(
    LIMITS,
    queue_rows=5254,
    queue_bytes=12599296,
    stream_rows=dict(calls=900, input_calls=256, phase=4096, context=2),
    stream_bytes=dict(calls=4194304, input_calls=4194304, phase=4194304, context=16384),
)


def canonical(value):
    return _json(value) + b"\n"


def clocks():
    return dict(
        start_ns=time.monotonic_ns(),
        process_cpu_start_ns=time.process_time_ns(),
        thread_cpu_start_ns=time.thread_time_ns(),
    )


def finish(start):
    thread = time.thread_time_ns()
    process = time.process_time_ns()
    end = time.monotonic_ns()
    return dict(start, end_ns=end, process_cpu_end_ns=process, thread_cpu_end_ns=thread)


def watermark():
    return dict(rows=0, last_seq=None, bytes=0, sha256=EMPTY)


def write_all(fd, raw):
    view = memoryview(raw)
    while view:
        try:
            count = os.write(fd, view)
        except InterruptedError:
            continue
        if count <= 0:
            raise OSError("measurement write made no progress")
        view = view[count:]


class Publisher:
    def __init__(self, paths, publication_path, *, metadata, identity, version=2):
        if type(version) is not int or version not in (2, 3):
            raise ValueError("explicit publisher profile required")
        self.limits = LIMITS if version == 2 else V3_LIMITS
        self.schema = f"edge-observer-publication/v{version - 1}"
        if (
            set(paths) != set(self.limits["stream_rows"])
            or len(set(map(str, paths.values()))) != len(self.limits["stream_rows"])
            or str(publication_path) in set(map(str, paths.values()))
        ):
            raise ValueError("exact distinct measurement paths required")
        self.paths = dict(paths)
        self.publication_path = publication_path
        self.metadata = dict(metadata)
        self.identity = dict(identity)
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.ready = threading.Event()
        self.queue = deque()
        self.pending_bytes = 0
        self.accepting = True
        self.closing = False
        self.incomplete = False
        self.error = None
        self.closed = False
        self.result = None
        self.on_call = None
        self.enqueued = {s: watermark() for s in paths}
        self.hashes = {s: hashlib.sha256() for s in paths}
        self.close_start = None
        self.normal_return = False
        self.thread = threading.Thread(
            target=self._worker, name="fresh-measurement-writer", daemon=True
        )
        self.thread.start()
        if not self.ready.wait(5):
            self.fail(TimeoutError("measurement worker initialization timeout"))
            raise TimeoutError("measurement worker initialization timeout")
        if self.error is not None:
            raise RuntimeError(self.error["message"])

    def fail(self, error):
        with self.lock:
            self.incomplete = True
            if self.error is None:
                self.error = dict(type=type(error).__name__, message=str(error)[:4096])

    def submit(self, stream, raw, seq):
        # Queue locks and canonicalization cost CPU; this is not a realtime claim.
        try:
            if (
                stream not in self.paths
                or type(raw) is not bytes
                or not raw.endswith(b"\n")
                or type(seq) is not int
            ):
                raise ValueError("invalid measurement row")
            with self.lock:
                if not self.accepting or self.incomplete:
                    return False
                old = self.enqueued[stream]
                expected = (
                    (0 if stream == "calls" else 1)
                    if old["rows"] == 0
                    else old["last_seq"] + 1
                )
                if (
                    seq != expected
                    or old["rows"] >= self.limits["stream_rows"][stream]
                    or old["bytes"] + len(raw) > self.limits["stream_bytes"][stream]
                    or len(self.queue) >= self.limits["queue_rows"]
                    or self.pending_bytes + len(raw) > self.limits["queue_bytes"]
                ):
                    raise ValueError("measurement queue/stream capacity or sequence")
                self.hashes[stream].update(raw)
                self.enqueued[stream] = dict(
                    rows=old["rows"] + 1,
                    last_seq=seq,
                    bytes=old["bytes"] + len(raw),
                    sha256=self.hashes[stream].hexdigest(),
                )
                self.queue.append((stream, raw, seq))
                self.pending_bytes += len(raw)
                if self.pending_bytes >= self.limits["batch_bytes"]:
                    self.wake.set()
            return True
        except BaseException as error:
            self.fail(error)
            return False

    def call_sink(self, path, *, metadata):
        if str(path) != str(self.paths["calls"]):
            raise ValueError("call sink path differs")
        return CallSink(self, metadata)

    def close(self, *, normal_return):
        if self.result is not None:
            return dict(self.result)
        joined = False
        owner_close = None
        try:
            with self.lock:
                if not self.closing:
                    self.close_start = clocks()
                    self.normal_return = normal_return
                    self.accepting = False
                    self.closing = True
            self.wake.set()
            remaining = max(
                0,
                (
                    self.close_start["start_ns"]
                    + self.limits["close_ns"]
                    - time.monotonic_ns()
                )
                / 1e9,
            )
            self.thread.join(remaining)
            joined = not self.thread.is_alive()
            # Main-thread CPU endpoints must stay on the same main thread.
            owner_close = finish(self.close_start)
            if (
                not joined
                or owner_close["end_ns"] - owner_close["start_ns"]
                > self.limits["close_ns"]
            ):
                self.fail(
                    TimeoutError("measurement worker close timeout or late observation")
                )
        except BaseException as error:
            self.fail(error)
            # Cleanup is measurement only; never replace an original exception.
            with self.lock:
                self.accepting = False
                self.closing = True
            self.wake.set()
        self.closed = joined
        self.result = dict(
            joined=joined,
            complete=joined
            and owner_close is not None
            and not self.incomplete
            and self.normal_return,
            incomplete=self.incomplete or not joined,
            error=self.error,
            owner_close=owner_close,
        )
        return dict(self.result)

    def _worker(self):
        fds = {}
        publication = None
        seq = 0
        previous = ZERO
        size = 0
        written = {s: watermark() for s in self.paths}
        fsynced = {s: watermark() for s in self.paths}
        hashes = {s: hashlib.sha256() for s in self.paths}
        worker_close_start = None

        def publish(kind, data):
            nonlocal seq, previous, size
            row = canonical(
                dict(
                    schema_version=self.schema,
                    seq=seq + 1,
                    prev=previous,
                    kind=kind,
                    data=data,
                )
            )
            if (
                seq >= self.limits["publication_rows"]
                or size + len(row) > self.limits["publication_bytes"]
            ):
                raise ValueError("publication capacity")
            write_all(publication, row)
            os.fsync(publication)
            seq += 1
            size += len(row)
            previous = hashlib.sha256(row).hexdigest()

        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            for s, path in self.paths.items():
                fds[s] = os.open(path, flags, 0o600)
            publication = os.open(self.publication_path, flags, 0o600)
            publish(
                "header",
                dict(
                    metadata=self.metadata, identity=self.identity, limits=self.limits
                ),
            )
            self.ready.set()
            while True:
                self.wake.wait(self.limits["batch_ns"] / 1e9)
                self.wake.clear()
                with self.lock:
                    batch = list(self.queue)
                    self.queue.clear()
                    self.pending_bytes = 0
                    closing = self.closing
                if closing and worker_close_start is None:
                    worker_close_start = clocks()
                for stream in self.paths:
                    items = [item for item in batch if item[0] == stream]
                    if not items:
                        continue
                    start = clocks()
                    for _, raw, row_seq in items:
                        write_all(fds[stream], raw)
                        hashes[stream].update(raw)
                        old = written[stream]
                        written[stream] = dict(
                            rows=old["rows"] + 1,
                            last_seq=row_seq,
                            bytes=old["bytes"] + len(raw),
                            sha256=hashes[stream].hexdigest(),
                        )
                    write = finish(start)
                    start = clocks()
                    os.fsync(fds[stream])
                    sync = finish(start)
                    fsynced[stream] = dict(written[stream])
                    info = os.fstat(fds[stream])
                    publish(
                        "commit",
                        dict(
                            stream=stream,
                            first_seq=items[0][2],
                            last_seq=items[-1][2],
                            **{
                                k: written[stream][k]
                                for k in ("rows", "bytes", "sha256")
                            },
                            object=dict(
                                device=info.st_dev,
                                inode=info.st_ino,
                                owner_uid=info.st_uid,
                                mode=info.st_mode,
                                link_count=info.st_nlink,
                            ),
                            worker_native_tid=threading.get_native_id(),
                            write=write,
                            fsync=sync,
                        ),
                    )
                if closing:
                    break
            for fd in fds.values():
                os.close(fd)
            fds.clear()
            with self.lock:
                streams = {
                    s: dict(
                        enqueued=dict(self.enqueued[s]),
                        written=dict(written[s]),
                        fsynced=dict(fsynced[s]),
                    )
                    for s in self.paths
                }
                complete = (
                    self.normal_return
                    and not self.incomplete
                    and all(
                        v["enqueued"] == v["written"] == v["fsynced"]
                        for v in streams.values()
                    )
                )
                data = dict(
                    normal_return=self.normal_return,
                    complete=complete,
                    incomplete=self.incomplete,
                    error=self.error,
                    streams=streams,
                    close=finish(worker_close_start),
                )
            publish("end", data)
        except BaseException as error:
            self.fail(error)
        finally:
            for fd in fds.values():
                try:
                    os.close(fd)
                except BaseException as error:
                    self.fail(error)
            if publication is not None:
                try:
                    os.close(publication)
                except BaseException as error:
                    self.fail(error)
            self.ready.set()


class CallSink:
    """Original wrapper-compatible sink; completion is enqueue, never fsync ACK."""

    def __init__(self, publisher, metadata):
        self.publisher = publisher
        self.count = 0
        self.previous = ZERO
        self.closed = False
        self.append("begin", metadata)

    @property
    def poisoned(self):
        return self.publisher.incomplete

    def append(self, kind, data):
        try:
            row = dict(seq=self.count, prev=self.previous, kind=kind, data=data)
            row["sha256"] = hashlib.sha256(_json(row)).hexdigest()
            raw = canonical(row)
            if self.publisher.submit("calls", raw, self.count):
                self.previous = row["sha256"]
                self.count += 1
                if self.publisher.on_call is not None:
                    self.publisher.on_call(self, kind, data)
        except BaseException as error:
            self.publisher.fail(error)

    def close(self, *, complete):
        if not self.closed:
            if complete and not self.poisoned:
                self.append("end", {})
            self.closed = True
