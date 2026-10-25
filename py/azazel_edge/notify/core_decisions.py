"""Rust core decisions -> core decision chain, for the P0 alert path.

Owner decision on Edge#412: the Rust ``azazel-edge-core`` is the
authoritative decision and enforcement path. It writes every decision event
to its normalized event log and forwards it to the AI agent's socket without
waiting. The AI agent service builds one :class:`CoreDecisionRecorder` when
it starts; the recorder writes each P0 core decision as an ``action_decision``
record to the core decision chain, and the P0 relay (``p0_alert``) attached to
that chain enqueues the alert (Edge#414 SO-03).

* **What is P0** -- the owner's rule (``p0_alert.classify_p0``) applied to what the
  core actually does: the record's ``action`` is the core's
  ``enforcement.selected_action`` (after the redirect policy's fallbacks;
  computed in every enforcement mode, dry run included). A redirect that falls
  back to notify is not P0; one that falls back to isolate is. The core's own
  ``decide_defense`` action is kept as ``decided_action``.
* **Never waits, never drops silently** -- :meth:`submit` (called on the
  agent's connection threads) only classifies and puts the record on a
  bounded queue; one writer thread does the fsynced chain writes. A full
  queue is counted, and the count is written to the P0 queue as a
  ``relay_status`` record.
* **One record per core event** -- the event key is built from the core
  event's own fields (EVE timestamp, sid, source and destination address,
  destination port, protocol, decided action). An event already in the chain
  (the same EVE line delivered twice, or replayed at start) is not recorded
  again.
* **Startup reconcile** -- before taking live events, the writer reads the
  tail of the core's normalized event log (bounded) and records the P0
  decisions the chain does not have: decisions the core took while this
  agent was down, or that it could not forward. What could not be
  reconciled (the log missing or unreadable, lines that do not parse, records
  older than the chain window, more than the bound, a log that no longer
  holds the chain's newest decision) is counted in a ``relay_status`` record.
* **Stale decisions are alerted as past decisions** (Edge#462 item 5, option
  (b)) -- a reconciled decision older than ``reconcile_max_age_s`` (300 s, the
  core's default lease), or whose time cannot be read, is no longer a current
  alert, but an isolate the core applied while the agent was down must still
  reach the operator. It is recorded with ``reconcile_stale: true`` (and its
  age); its alert entries carry ``stale: true`` and
  ``presentation: historical``, are shown with the 「過去の判定」 prefix and the
  event's time, and are not spoken as an urgent alert (see
  ``p0_alert.build_p0_alerts``). Counted as ``core_reconcile_stale`` (found)
  and ``core_reconciled_stale`` (recorded). Stale and fresh decisions share
  the one ``max_reconcile`` bound (256, the newest kept), so a long outage
  cannot flood the queue; what is over it is ``core_reconcile_skipped``. A
  stale decision is recorded in the chain under its core event key like any
  other, so the next start does not record or alert it again.

Observation and notification only: nothing here decides, enforces, or feeds
anything back to the core.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue as _queue_mod
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from . import p0_alert as _p0

_LOG = logging.getLogger(__name__)

CORE_EVENT_SOURCE = "suricata_eve"
CORE_EVENT_PIPELINE = "rust_event_engine_v1"
CORE_DECISION_SOURCE = "azazel-edge-core"
RECORDED_LIVE = "live"
RECORDED_RECONCILE = "startup_reconcile"

DEFAULT_MAX_PENDING = 1024
# Startup reconcile bounds: the newest bytes of the core's normalized log, the
# newest bytes of the chain the keys are read from, and the newest P0
# decisions recorded.
DEFAULT_RECONCILE_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_CHAIN_KEY_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_RECONCILE = 256
# A decision older than this (EVE timestamp, else the core's ingest stamp,
# against the current time) is no longer a current alert: the reconcile
# records it marked ``reconcile_stale`` and its alert is presented as a past
# decision, never as a current one (Edge#462 item 5). 300 s is the core's
# default enforcement lease (AZAZEL_DEFENSE_ACTION_TTL_SEC in
# systemd/azazel-edge-core.service): by then the action the decision bore has
# been released. Stale decisions count against DEFAULT_MAX_RECONCILE like
# fresh ones.
DEFAULT_RECONCILE_MAX_AGE_S = _p0.STALE_AFTER_S
# How long stopping the recorder waits for the writer to drain.
DEFAULT_STOP_DRAIN_S = 5.0
_SEEN_MAX = 65536


def _int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _num(value: Any) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def core_event_key(event: Mapping[str, Any]) -> str:
    """Identity of one core decision event, from the core event's own fields."""

    normalized = event.get("normalized") if isinstance(event.get("normalized"), Mapping) else {}
    defense = event.get("defense") if isinstance(event.get("defense"), Mapping) else {}
    parts = [
        normalized.get("ts"), normalized.get("sid"), normalized.get("src_ip"), normalized.get("dst_ip"),
        normalized.get("target_port"), normalized.get("protocol"), defense.get("action"),
    ]
    return hashlib.sha256(json.dumps(parts, ensure_ascii=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def core_decision_payload(event: Mapping[str, Any]) -> Optional[Tuple[str, Dict[str, Any]]]:
    """(trace id, action_decision payload) for one core decision event, or None.

    Copies what the core decided and did; nothing is re-decided here.
    """

    if not isinstance(event, Mapping):
        return None
    if event.get("source") != CORE_EVENT_SOURCE or event.get("pipeline") != CORE_EVENT_PIPELINE:
        return None
    defense = event.get("defense")
    enforcement = event.get("enforcement")
    if not isinstance(defense, Mapping) or not isinstance(enforcement, Mapping):
        return None
    decided = defense.get("action")
    effective = enforcement.get("selected_action")
    if not (isinstance(decided, str) and decided and isinstance(effective, str) and effective):
        return None
    normalized = event.get("normalized") if isinstance(event.get("normalized"), Mapping) else {}
    status = event.get("enforcement_status") if isinstance(event.get("enforcement_status"), Mapping) else {}
    key = core_event_key(event)
    payload: Dict[str, Any] = {
        "action": effective,
        "decided_action": decided,
        "effective_action": effective,
        "reason": str(defense.get("reason") or ""),
        "policy_reason": str(enforcement.get("policy_reason") or defense.get("policy_reason") or ""),
        "target": str(enforcement.get("target") or defense.get("target") or ""),
        "enforcement_mode": str(enforcement.get("mode") or ""),
        "enforcement_result": str(enforcement.get("result") or ""),
        "enforcement_executed_count": _int(enforcement.get("executed_count")),
        "enforcement_failed_count": _int(enforcement.get("failed_count")),
        "enforce_enabled": status.get("enforce_enabled") is True,
        "enforce_dry_run": status.get("dry_run") is True,
        "enforce_level": str(status.get("enforce_level") or ""),
        "core_pipeline": CORE_EVENT_PIPELINE,
        "core_event_key": key,
        "core_trace_id": str(enforcement.get("trace_id") or ""),
        "core_ingest_epoch": _num(normalized.get("ingest_epoch")),
        "sid": _int(normalized.get("sid")),
        "severity": _int(normalized.get("severity")),
        "target_port": _int(normalized.get("target_port")),
        "event_ts": str(normalized.get("ts") or ""),
    }
    return f"core-{key[:32]}", payload


def _event_epoch(payload: Mapping[str, Any]) -> Optional[float]:
    """When the core's event happened: the EVE timestamp, else the core's
    ingest stamp. None if neither can be read."""

    epoch = _p0.event_ts_epoch(payload.get("event_ts"))
    return epoch if epoch is not None else _num(payload.get("core_ingest_epoch"))


def is_p0(payload: Mapping[str, Any]) -> bool:
    return bool(_p0.classify_p0(dict(payload, kind="action_decision")))


def _tail_lines(path: Path, max_bytes: int) -> Tuple[List[bytes], bool, int]:
    """Complete lines of the newest ``max_bytes`` of ``path``: (lines,
    truncated, file size). A first line cut by the window and a last line
    without its newline are left out."""

    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        start = max(0, size - max_bytes)
        fh.seek(start)
        data = fh.read(size - start)
    lines = data.split(b"\n")
    lines = lines[:-1]  # the part after the last newline is not a complete line
    if start > 0 and lines:
        lines = lines[1:]
    return lines, start > 0, size


class CoreDecisionRecorder:
    """Writes the core's P0 decisions to the core decision chain (see module doc)."""

    def __init__(
        self,
        audit_logger: Any,
        relay: Any = None,
        normalized_log_path: Optional[str | Path] = None,
        *,
        max_pending: int = DEFAULT_MAX_PENDING,
        reconcile_max_bytes: int = DEFAULT_RECONCILE_MAX_BYTES,
        chain_key_max_bytes: int = DEFAULT_CHAIN_KEY_MAX_BYTES,
        max_reconcile: int = DEFAULT_MAX_RECONCILE,
        reconcile_max_age_s: float = DEFAULT_RECONCILE_MAX_AGE_S,
    ):
        self.audit = audit_logger
        self.relay = relay
        self.normalized_log_path = Path(normalized_log_path) if normalized_log_path else None
        self.reconcile_max_bytes = int(reconcile_max_bytes)
        self.chain_key_max_bytes = int(chain_key_max_bytes)
        self.max_reconcile = int(max_reconcile)
        self.reconcile_max_age_s = float(reconcile_max_age_s)
        self._stopped = False
        self._pending: _queue_mod.Queue = _queue_mod.Queue(maxsize=max(1, int(max_pending)))
        self._lock = threading.Lock()
        self.handoff_dropped_total = 0
        self.record_failed_total = 0
        self.duplicate_total = 0
        self.recorded_total = 0
        self.reconciled_total = 0
        self.reconciled_stale_total = 0
        self._outstanding = 0
        self._reported: Tuple[int, int] = (0, 0)
        self._forward_seen: Tuple[int, int] = (0, 0)
        self._seen: "OrderedDict[str, None]" = OrderedDict()
        self._stop = threading.Event()
        self.ready = threading.Event()
        self.last_reconcile: Dict[str, Any] = {}
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------- intake
    def submit(self, event: Mapping[str, Any]) -> None:
        """Hand one core event to the writer. Never blocks, never raises."""

        try:
            built = core_decision_payload(event)
            if built is None:
                return
            trace_id, payload = built
            if not is_p0(payload):
                return
            payload["agent_received_monotonic_ns"] = time.monotonic_ns()
            payload["agent_received_epoch"] = time.time()
            payload["recorded_by"] = RECORDED_LIVE
            with self._lock:
                self._outstanding += 1
            try:
                self._pending.put_nowait((trace_id, payload))
            except _queue_mod.Full:
                with self._lock:
                    self._outstanding -= 1
                    self.handoff_dropped_total += 1
                _LOG.error("core decision hand-off full; P0 decision %s not recorded now", trace_id)
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.error("core decision not handed to the recorder: %s", exc)

    def note_forward_stats(self, dropped: int, failed: int, since: int) -> None:
        """The core's own count of events it could not hand to the agent.
        Written to the P0 queue when it grows. Never raises."""

        with self._lock:
            if (dropped, failed) == self._forward_seen or not (dropped or failed):
                self._forward_seen = (dropped, failed)
                return
            self._forward_seen = (dropped, failed)
        self._status({
            "event": "core_forward_loss",
            "core_forward_dropped": dropped,
            "core_forward_failed": failed,
            "core_forward_since": since,
            "note": "the core could not forward this many events (any action) since it started; "
                    "the next agent start reconciles P0 decisions among them from the core's normalized event log",
        })

    # ------------------------------------------------------------ writing
    def _remember(self, key: str) -> None:
        self._seen[key] = None
        while len(self._seen) > _SEEN_MAX:
            self._seen.popitem(last=False)

    def _record(self, trace_id: str, payload: Dict[str, Any]) -> bool:
        key = str(payload.get("core_event_key") or "")
        if key and key in self._seen:
            with self._lock:
                self.duplicate_total += 1
            return False
        try:
            self.audit.log_action_decision(trace_id=trace_id, source=CORE_DECISION_SOURCE, **payload)
        except Exception as exc:
            # The chain logger raises AuditDurabilityError after the record
            # was appended (only its fsync failed): it is in the chain.
            appended = type(exc).__name__ == "AuditDurabilityError"
            if appended and key:
                self._remember(key)
            with self._lock:
                self.record_failed_total += 1
            _LOG.error("core decision %s not recorded durably: %s", trace_id, exc)
            return appended
        if key:
            self._remember(key)
        with self._lock:
            self.recorded_total += 1
        return True

    def _status(self, status: Dict[str, Any]) -> None:
        relay = self.relay
        if relay is None:
            _LOG.error("core decision status not written (no P0 relay): %s", status)
            return
        record = dict(status)
        record.update(self.metrics())
        try:
            relay.queue.append_status(record)
        except Exception as exc:
            _LOG.error("core decision status not written to the P0 queue: %s", exc)

    def _report_losses(self) -> None:
        with self._lock:
            now = (self.handoff_dropped_total, self.record_failed_total)
            if now == self._reported:
                return
            self._reported = now
        self._status({"event": "core_record_loss"})

    def metrics(self) -> Dict[str, int]:
        with self._lock:
            return {
                "core_record_handoff_dropped_total": self.handoff_dropped_total,
                "core_record_failed_total": self.record_failed_total,
                "core_record_duplicate_total": self.duplicate_total,
                "core_recorded_total": self.recorded_total,
                "core_reconciled_total": self.reconciled_total,
                "core_reconciled_stale_total": self.reconciled_stale_total,
            }

    # ---------------------------------------------------------- reconcile
    def _chain_keys(self) -> Tuple[bool, Optional[float], str]:
        """Load the chain's core event keys into the seen set: (whole chain
        read, oldest core ingest epoch read, newest key)."""

        path = Path(getattr(self.audit, "path", "") or "")
        try:
            lines, truncated, _ = _tail_lines(path, self.chain_key_max_bytes)
        except FileNotFoundError:
            return True, None, ""
        oldest: Optional[float] = None
        newest = ""
        for line in lines:
            try:
                row = json.loads(line)
            except Exception:
                continue
            key = row.get("core_event_key") if isinstance(row, dict) else None
            if isinstance(key, str) and key:
                self._remember(key)
                newest = key
                epoch = _num(row.get("core_ingest_epoch"))
                if epoch is not None and (oldest is None or epoch < oldest):
                    oldest = epoch
        return not truncated, oldest, newest

    def reconcile(self) -> Dict[str, Any]:
        status: Dict[str, Any] = {
            "event": "core_reconcile", "core_reconcile": "done", "core_reconciled": 0,
            "core_reconcile_skipped": 0, "core_reconcile_out_of_window": 0, "core_reconcile_unparseable": 0,
            "core_reconcile_stale": 0, "core_reconciled_stale": 0, "core_reconcile_max_age_s": self.reconcile_max_age_s,
            "core_reconcile_log_truncated": False, "core_reconcile_newest_chain_decision_in_log": None,
        }
        chain_complete, oldest, newest = self._chain_keys()
        now = time.time()
        if self.normalized_log_path is None:
            status["core_reconcile"] = "no_normalized_log_path"
        else:
            try:
                lines, truncated, size = _tail_lines(self.normalized_log_path, self.reconcile_max_bytes)
            except FileNotFoundError:
                lines, truncated, size = [], False, 0
                status["core_reconcile"] = "normalized_log_missing"
            except OSError as exc:
                lines, truncated, size = [], False, 0
                status["core_reconcile"] = f"normalized_log_unreadable:{exc.errno}"
            status["core_reconcile_log_truncated"] = truncated
            status["core_reconcile_log_bytes"] = size
            candidates: List[Tuple[str, Dict[str, Any]]] = []
            keys_in_log = set()
            for line in lines:
                try:
                    event = json.loads(line)
                except Exception:
                    status["core_reconcile_unparseable"] += 1
                    continue
                built = core_decision_payload(event) if isinstance(event, dict) else None
                if built is None:
                    continue
                trace_id, payload = built
                keys_in_log.add(payload["core_event_key"])
                if not is_p0(payload) or payload["core_event_key"] in self._seen:
                    continue
                epoch = payload.get("core_ingest_epoch")
                if not chain_complete and oldest is not None and (epoch is None or epoch < oldest):
                    # Older than the part of the chain read: whether it is
                    # already recorded cannot be told.
                    status["core_reconcile_out_of_window"] += 1
                    continue
                payload["recorded_by"] = RECORDED_RECONCILE
                happened = _event_epoch(payload)
                if happened is None or now - happened > self.reconcile_max_age_s:
                    # Not a current alert any more (or its time is unknown):
                    # recorded and alerted as a past decision, never as a
                    # current one (Edge#462 item 5).
                    status["core_reconcile_stale"] += 1
                    payload["reconcile_stale"] = True
                    payload["reconcile_event_age_s"] = None if happened is None else round(now - happened, 3)
                candidates.append((trace_id, payload))
            if newest:
                status["core_reconcile_newest_chain_decision_in_log"] = newest in keys_in_log
            skipped = max(0, len(candidates) - self.max_reconcile)
            done = 0
            done_stale = 0
            for trace_id, payload in candidates[skipped:]:
                if self._record(trace_id, payload):
                    done += 1
                    if payload.get("reconcile_stale") is True:
                        done_stale += 1
            status["core_reconcile_skipped"] = skipped
            status["core_reconciled"] = done
            status["core_reconciled_stale"] = done_stale
            with self._lock:
                self.reconciled_total += done
                self.reconciled_stale_total += done_stale
        self.last_reconcile = status
        self._status(status)
        return status

    # -------------------------------------------------------------- thread
    def _run(self) -> None:
        try:
            self.reconcile()
        except Exception as exc:
            _LOG.error("core decision reconcile failed: %s", exc)
        finally:
            self.ready.set()
        while not self._stop.is_set() or not self._pending.empty():
            try:
                trace_id, payload = self._pending.get(timeout=0.2)
            except _queue_mod.Empty:
                self._report_losses()
                continue
            try:
                self._record(trace_id, payload)
            finally:
                with self._lock:
                    self._outstanding -= 1
            self._report_losses()

    def pending(self) -> int:
        with self._lock:
            return self._outstanding

    def wait_idle(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while (self.pending() or not self.ready.is_set()) and time.monotonic() < deadline:
            time.sleep(0.005)
        return not self.pending() and self.ready.is_set()

    def start(self) -> "CoreDecisionRecorder":
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="core-decision-recorder", daemon=True)
            self._thread.start()
        return self

    def stop(self, timeout: float = DEFAULT_STOP_DRAIN_S) -> int:
        """Stop taking work and drain what was handed over, for at most
        ``timeout`` seconds. What is not drained by then is counted in a
        ``relay_status`` record (``core_recorder_stopped``); the next start's
        reconcile records it from the core's log. Returns that count."""

        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
        undrained = self.pending()
        if not self._stopped:
            self._stopped = True
            self._status({"event": "core_recorder_stopped", "core_record_undrained": undrained})
        return undrained
