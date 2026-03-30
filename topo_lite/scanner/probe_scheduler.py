from __future__ import annotations

import fcntl
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from configuration import TopoLiteConfig
from db.repository import TopoLiteRepository
from logging_utils import TopoLiteLoggers, append_audit_record, log_event
from scanner.probe import probe_hosts


@dataclass(slots=True)
class ProbeSchedulerResult:
    status: str
    runs_completed: int
    failures: int
    last_scan_run_id: int | None


class ProbeSchedulerLockError(RuntimeError):
    """Raised when another probe scheduler instance already holds the lock."""


class ProbeScheduler:
    def __init__(
        self,
        *,
        config: TopoLiteConfig,
        repository: TopoLiteRepository,
        loggers: TopoLiteLoggers,
        lock_path: str | Path = "run/probe_scheduler.lock",
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.repository = repository
        self.loggers = loggers
        self.lock_path = Path(lock_path)
        self.sleep_fn = sleep_fn
        self._stop_requested = False
        self._lock_file = None

    def request_stop(self) -> None:
        self._stop_requested = True

    def install_signal_handlers(self) -> None:
        def _handle_signal(_signum, _frame) -> None:
            self.request_stop()

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

    def run_forever(self, *, max_runs: int | None = None) -> ProbeSchedulerResult:
        self._acquire_lock()
        failures = 0
        runs_completed = 0
        last_scan_run_id: int | None = None

        try:
            append_audit_record(
                self.loggers.audit,
                "probe_scheduler_started",
                actor="system",
                interval_seconds=self.config.scan_intervals.probe_seconds,
            )
            log_event(
                self.loggers.scanner,
                "probe_scheduler_started",
                "probe scheduler started",
                interval_seconds=self.config.scan_intervals.probe_seconds,
            )

            while not self._stop_requested:
                result = probe_hosts(
                    config=self.config,
                    repository=self.repository,
                    loggers=self.loggers,
                )
                last_scan_run_id = int(result["scan_run_id"])
                runs_completed += 1

                if result["status"] == "failed":
                    failures += 1
                    log_event(
                        self.loggers.scanner,
                        "probe_scheduler_iteration_failed",
                        "probe scheduler iteration failed",
                        scan_run_id=last_scan_run_id,
                        failures=failures,
                    )
                else:
                    failures = 0

                if max_runs is not None and runs_completed >= max_runs:
                    break
                self.sleep_fn(self.config.scan_intervals.probe_seconds)

            append_audit_record(
                self.loggers.audit,
                "probe_scheduler_stopped",
                actor="system",
                runs_completed=runs_completed,
                last_scan_run_id=last_scan_run_id,
            )
            return ProbeSchedulerResult(
                status="stopped",
                runs_completed=runs_completed,
                failures=failures,
                last_scan_run_id=last_scan_run_id,
            )
        finally:
            self._release_lock()

    def _acquire_lock(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.lock_path, "w", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            handle.close()
            raise ProbeSchedulerLockError(f"probe scheduler already running: {self.lock_path}") from error
        handle.write(str(os.getpid()))
        handle.flush()
        self._lock_file = handle

    def _release_lock(self) -> None:
        if self._lock_file is None:
            return
        fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
        self._lock_file.close()
        self._lock_file = None
