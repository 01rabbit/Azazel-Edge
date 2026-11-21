"""Bounded opt-in in-memory clocks; original operations always run exactly once."""

import time

PHASES = (
    "receive_wait",
    "frame_validation",
    "source_append",
    "source_sign",
    "source_verify",
    "source_fsync",
)
MAXIMUM = 2**63 - 1


class Meter:
    def __init__(self):
        self.reason = None
        self.phases = dict.fromkeys(PHASES)

    def _before(self):
        if self.reason is not None:
            return None
        try:
            return (time.monotonic_ns(), time.process_time_ns(), time.thread_time_ns())
        except BaseException:
            self.reason = "clock_error"
            return None

    def _after(self, phase, start):
        if self.reason is not None:
            return
        try:
            thread = time.thread_time_ns()
            process = time.process_time_ns()
            wall = time.monotonic_ns()
            values = (wall, process, thread)
            if start is None or any(
                type(n) is not int or n < 0 for n in (*start, *values)
            ):
                raise ValueError("clock_error")
            delta = tuple(end - begin for begin, end in zip(start, values))
            if any(n < 0 for n in delta):
                raise ValueError("clock_error")
            old = self.phases[phase] or dict(
                count=0, wall_ns=0, process_cpu_ns=0, thread_cpu_ns=0, max_wall_ns=0
            )
            value = dict(
                count=old["count"] + 1,
                wall_ns=old["wall_ns"] + delta[0],
                process_cpu_ns=old["process_cpu_ns"] + delta[1],
                thread_cpu_ns=old["thread_cpu_ns"] + delta[2],
                max_wall_ns=max(old["max_wall_ns"], delta[0]),
            )
            if any(n > MAXIMUM for n in value.values()):
                self.reason = "counter_overflow"
                return
            self.phases[phase] = value
        except BaseException:
            self.reason = "clock_error"

    def call(self, phase, function, *args, **kwargs):
        start = self._before()
        try:
            return function(*args, **kwargs)
        finally:
            self._after(phase, start)

    def snapshot(self):
        return dict(
            schema_version="azazel-edge/phase-cost/v1",
            complete=self.reason is None,
            invalid_reason=self.reason,
            phases={k: None if v is None else v.copy() for k, v in self.phases.items()},
        )
