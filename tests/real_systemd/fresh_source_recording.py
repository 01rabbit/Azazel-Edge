"""Fresh-only actual input/callback context; never admission or Source authority."""

from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import os
import time

from azazel_edge.outcome import input_resume
from azazel_edge.outcome.journal import _json
import signed_network_recording as original_recording

SCHEMA = "edge-fresh-input-record/v1"
MAX_ROWS = 256
MAX_BYTES = 4 * 1024 * 1024


def canonical(value):
    return _json(value) + b"\n"


class InputRecording:
    def __init__(self, path, *, metadata, identity, binding):
        self.fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        self.count = self.size = self.inputs = self.completed = self.callbacks = 0
        self.previous = "0" * 64
        self.pending = []
        self.incomplete = self.closed = False
        self.active = None
        self.final_cursor = None
        self._buffer(
            "begin",
            dict(
                metadata=metadata,
                identity=identity,
                binding=binding,
                limits=dict(max_rows=MAX_ROWS, max_bytes=MAX_BYTES),
            ),
        )
        self._flush()

    def _buffer(self, kind, data):
        if self.incomplete or self.closed:
            return
        try:
            raw = canonical(
                dict(
                    schema_version=SCHEMA,
                    seq=self.count + 1,
                    prev=self.previous,
                    kind=kind,
                    data=data,
                )
            )
            if self.count >= MAX_ROWS or self.size + len(raw) > MAX_BYTES:
                raise ValueError("fresh input recording capacity")
            self.pending.append(raw)
            self.count += 1
            self.size += len(raw)
            self.previous = hashlib.sha256(raw).hexdigest()
        except BaseException:
            self.incomplete = True

    def _flush(self):
        if self.incomplete or self.closed:
            return
        try:
            for raw in self.pending:
                view = memoryview(raw)
                while view:
                    count = os.write(self.fd, view)
                    if count <= 0:
                        raise OSError("fresh input short write")
                    view = view[count:]
            self.pending.clear()
        except BaseException:
            self.incomplete = True
            self.pending.clear()

    def input(self, original, line, journal, collector, *, live_floor, now):
        if self.active is not None:
            self.incomplete = True
        self.inputs += 1
        state = dict(input_id=self.inputs, callbacks=[], activity=None, invocations=0)
        self.active = state
        try:
            self._buffer(
                "input_intent",
                dict(
                    input_id=self.inputs,
                    decoded_event_sha256=hashlib.sha256(line.raw).hexdigest(),
                    position=dict(line.position),
                    cursor_before=dict(journal.input_position()),
                    live_floor=live_floor,
                    supplied_now=now,
                    start_ns=time.monotonic_ns(),
                ),
            )
        except BaseException:
            self.incomplete = True
        try:
            result = original(line, journal, collector, live_floor=live_floor, now=now)
        except BaseException as error:
            try:
                self._buffer(
                    "input_raise",
                    dict(
                        input_id=state["input_id"],
                        end_ns=time.monotonic_ns(),
                        exception_type=type(error).__name__,
                        cursor_after=dict(journal.input_position()),
                        callbacks=state["callbacks"],
                    ),
                )
            except BaseException:
                self.incomplete = True
            self._flush()
            self.incomplete = True
            raise
        else:
            try:
                cursor = dict(journal.input_position())
                if len(state["callbacks"]) != state["invocations"]:
                    self.incomplete = True
                self._buffer(
                    "input_return",
                    dict(
                        input_id=state["input_id"],
                        end_ns=time.monotonic_ns(),
                        handler_result=result,
                        cursor_after=cursor,
                        callbacks=state["callbacks"],
                    ),
                )
                self.final_cursor = cursor
                self.completed += 1
                self.callbacks += len(state["callbacks"])
            except BaseException:
                self.incomplete = True
            self._flush()
            return result
        finally:
            self.active = None

    def close(self, *, normal_return):
        if self.closed:
            return
        try:
            if normal_return and not self.incomplete and self.active is None:
                self._flush()
                self._buffer(
                    "end",
                    dict(
                        completed_inputs=self.completed,
                        completed_callbacks=self.callbacks,
                        final_cursor=self.final_cursor,
                        normal_return=True,
                        incomplete=False,
                    ),
                )
                self._flush()
                os.fsync(self.fd)
        except BaseException:
            self.incomplete = True
        finally:
            try:
                os.close(self.fd)
            except BaseException:
                self.incomplete = True
            self.closed = True
            self.fd = None


@contextmanager
def record_inputs(path, *, metadata, identity, binding):
    """Inside original record_collector: preserve every original method and exception."""
    sink = InputRecording(path, metadata=metadata, identity=identity, binding=binding)
    original_input = input_resume.observe_input
    recorded_collector = input_resume.OutcomeTelemetryCollector
    original_append = original_recording.CallRecording.append

    class Collector(recorded_collector):
        def observe_event(self, *args, **kwargs):
            if sink.active is not None:
                sink.active["invocations"] += 1
            return super().observe_event(*args, **kwargs)

        def _record_activity(self, *args, **kwargs):
            result = super()._record_activity(*args, **kwargs)
            if sink.active is not None:
                try:
                    sink.active["activity"] = (
                        asdict(result) if result is not None else None
                    )
                except BaseException:
                    sink.incomplete = True
            return result

    def append(recording, kind, data):
        result = original_append(recording, kind, data)
        if kind == "event" and sink.active is not None:
            try:
                if len(sink.active["callbacks"]) >= 1:
                    raise ValueError("multiple callbacks for one input handler")
                sink.active["callbacks"].append(
                    dict(
                        call_seq=recording.count - 1,
                        event_sha256=hashlib.sha256(
                            canonical(data["event"])
                        ).hexdigest(),
                        return_value=data["accepted"],
                        observed_epoch=data["epoch"],
                        activity=sink.active["activity"],
                    )
                )
                sink.active["activity"] = None
            except BaseException:
                sink.incomplete = True
        return result

    def observe(line, journal, collector, *, live_floor, now):
        return sink.input(
            original_input, line, journal, collector, live_floor=live_floor, now=now
        )

    input_resume.OutcomeTelemetryCollector = Collector
    input_resume.observe_input = observe
    original_recording.CallRecording.append = append
    complete = False
    try:
        yield sink
        complete = True
    finally:
        input_resume.observe_input = original_input
        input_resume.OutcomeTelemetryCollector = recorded_collector
        original_recording.CallRecording.append = original_append
        sink.close(normal_return=complete)
