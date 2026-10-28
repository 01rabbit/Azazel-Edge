"""SO-11 starting point: offer 120% of the declared ingress quota (Edge#414 OF-06).

    python -m azazel_edge.service_objectives.so11_ingress_probe --core-bin PATH --out FILE

This is not an SO-11 measurement; that is ``so11_quota_load`` (the SO-11
harness, ``python -m azazel_edge.service_objectives run --objective SO-11``).
SO-11 asks for the SO-03, SO-04 and SO-07 pass rules to hold at each declared
ingress quota and for the quota to shed at 120% of the highest one. This
probe covers only the second half for the one
quota Edge declares (``config/service_objectives/ingress_quota.json``), a
quota on non-alert lines: it starts the real core (Edge defaults, enforcement
off, AI forward off), writes flow, dns, stats and http records at 120% of the
declared rate together with alerts at ``ALERT_RATE``, and checks from the
core's own output that

* the core recorded shedding (``ingress_shed`` summaries in
  ``ingress-audit.jsonl``, beside the normalized event log),
* nothing it shed was an alert (``alerts_shed`` 0, and every alert written
  was decided once the writer stopped and the backlog drained),
* flow was shed at least as much as dns, dns at least as much as stats,
* the summaries are rate-bounded (at most one per audit interval; the one
  the core writes when it stops, ``interval_end: "shutdown"``, is not counted).

The result is a plain JSON document with verdict ``not_measurable`` and the
gaps that keep it so. It is not a service-objective record, and the
referenced rows are not re-run here (the SO-11 harness does both).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

from .declarations import load_ingress_quotas

INGRESS = "core_eve_reader"
OVERLOAD = 1.2
# Alerts offered alongside the non-alert overload. Alerts are outside the
# quota; this is below the measured alert capacity so the run ends drained.
ALERT_RATE = 1000
NON_ALERT_KINDS = ("flow", "dns", "stats", "http")
# Padding makes each line about this many bytes (closer to real EVE lines).
LINE_BYTES = 600


class _Writer(threading.Thread):
    def __init__(self, path: Path, rate_per_s: float, duration_s: float, alert_rate_per_s: float = ALERT_RATE):
        super().__init__(daemon=True)
        self.path = path
        self.rate = rate_per_s
        self.alert_rate = alert_rate_per_s
        self.duration = duration_s
        self.alerts = 0
        self.non_alerts = 0

    def _line(self, n: int, kind: str) -> str:
        base: Dict[str, Any] = {"timestamp": "2026-01-01T00:00:00.000000+0000", "event_type": kind, "src_ip": f"198.51.100.{n % 250 + 1}", "dest_ip": "192.0.2.10", "dest_port": 22, "proto": "TCP"}
        if kind == "alert":
            base["alert"] = {"signature_id": 3000000 + n % 50, "signature": "so11 probe", "category": "load", "severity": 3}
        else:
            base[kind] = {"n": n}
        raw = json.dumps(base)
        base["pad"] = "x" * max(0, LINE_BYTES - len(raw) - 12)
        return json.dumps(base)

    def run(self) -> None:
        start = time.monotonic()
        n = 0
        a = 0
        with self.path.open("a", encoding="utf-8") as fh:
            while True:
                elapsed = time.monotonic() - start
                if elapsed >= self.duration:
                    break
                lines: List[str] = []
                while n < int(elapsed * self.rate):
                    lines.append(self._line(n, NON_ALERT_KINDS[n % len(NON_ALERT_KINDS)]))
                    self.non_alerts += 1
                    n += 1
                    while a < int(n * self.alert_rate / self.rate):
                        lines.append(self._line(a, "alert"))
                        self.alerts += 1
                        a += 1
                if lines:
                    fh.write("\n".join(lines) + "\n")
                    fh.flush()
                time.sleep(0.01)


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    out = []
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def run(core_bin: Path, duration_s: float = 40.0, drain_timeout_s: float = 120.0) -> Dict[str, Any]:
    decl = load_ingress_quotas()
    quota = decl["quotas"].get(INGRESS)
    result: Dict[str, Any] = {
        "objective_id": "SO-11",
        "kind": "starting-point probe, not a service-objective record",
        "declaration": {"path": decl["path"], "sha256": decl["sha256"], "problems": decl["problems"]},
        "verdict": "not_measurable",
    }
    if quota is None:
        result["checks"] = {"quota_declared": False}
        result["gaps"] = [{"id": "SO11-NO-DECLARED-QUOTA", "summary": "no valid ingress quota declared"}]
        return result
    rate = quota["value"] * OVERLOAD
    with tempfile.TemporaryDirectory(prefix="so11-") as tmp:
        work = Path(tmp)
        eve = work / "eve.json"
        eve.touch()
        normalized = work / "normalized-events.jsonl"
        audit = work / "ingress-audit.jsonl"
        env = {
            "PATH": os.environ.get("PATH", ""),
            "AZAZEL_EVE_PATH": str(eve),
            "AZAZEL_NORMALIZED_EVENT_LOG": str(normalized),
            "AZAZEL_FORWARD_AI": "0",
            "AZAZEL_EVENT_STDOUT": "off",
            "AZAZEL_DEFENSE_RELEASE_LEDGER": str(work / "release-ledger.json"),
            "AZAZEL_EVE_FROM_START": "1",
        }
        writer = _Writer(eve, rate, duration_s)
        with (work / "core.stderr").open("w") as err:
            proc = subprocess.Popen([str(core_bin)], cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=err)
            try:
                time.sleep(0.5)
                t0 = time.monotonic()
                writer.start()
                writer.join()
                written_s = time.monotonic() - t0
                deadline = time.monotonic() + drain_timeout_s
                decided = 0
                while time.monotonic() < deadline:
                    decided = sum(1 for r in _read_jsonl(normalized) if isinstance(r.get("normalized"), dict))
                    if decided >= writer.alerts:
                        break
                    time.sleep(0.5)
                drained_s = time.monotonic() - t0
                time.sleep(1.5)  # let a last summary out
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        records = _read_jsonl(audit)
    shed_records = [r["ingress_shed"] for r in records if isinstance(r.get("ingress_shed"), dict)]
    gaps_between = rate_bound_gaps(shed_records)
    interval_s = quota["audit_interval_ms"] / 1000.0
    by_type: Dict[str, int] = {}
    for r in shed_records:
        for k, v in (r.get("shed_by_type") or {}).items():
            by_type[k] = by_type.get(k, 0) + int(v)
    checks = {
        "quota_declared": True,
        "shedding_recorded": sum(by_type.values()) > 0,
        "alerts_never_shed": all(int(r.get("alerts_shed", 1)) == 0 for r in shed_records) and by_type.get("alert", 0) == 0,
        "every_alert_decided_after_drain": decided == writer.alerts,
        "flow_shed_first_then_dns_then_stats": by_type.get("flow", 0) >= by_type.get("dns", 0) >= by_type.get("stats", 0),
        "summaries_rate_bounded": all(g >= interval_s * 0.95 for g in gaps_between),
    }
    result.update({
        "offered": {
            "non_alert_rate_lines_per_s": rate,
            "alert_rate_lines_per_s": ALERT_RATE,
            "overload": OVERLOAD,
            "duration_s": round(written_s, 3),
            "alerts_written": writer.alerts,
            "non_alerts_written": writer.non_alerts,
            "non_alert_kinds": list(NON_ALERT_KINDS),
            "line_bytes": LINE_BYTES,
        },
        "quota": {k: quota[k] for k in ("value", "unit", "non_alert_burst", "alerts_per_poll", "backlog_bound_bytes", "status", "hardware_class")},
        "observed": {
            "alerts_decided": decided,
            "drained_after_s": round(drained_s, 3),
            "shed_by_type": by_type,
            "shed_summaries": len(shed_records),
            "non_alerts_admitted_in_summarised_intervals": sum(int(r.get("admitted", 0)) - int(r.get("alerts_admitted", 0)) for r in shed_records),
            "shed_by_reason": {k: sum(int((r.get("shed_by_reason") or {}).get(k, 0)) for r in shed_records) for k in ("non_alert_rate", "backlog")},
            "max_shed_level": max((int(r.get("max_shed_level", 0)) for r in shed_records), default=0),
            "max_backlog_bytes": max((int(r.get("max_backlog_bytes", 0)) for r in shed_records), default=0),
            "min_seconds_between_summaries": round(min(gaps_between), 3) if gaps_between else None,
        },
        "checks": checks,
        "gaps": [
            {"id": "SO11-REFERENCED-ROWS-NOT-RERUN", "summary": "this probe does not re-run SO-03, SO-04 and SO-07 at the declared quota or at 120% of it (the SO-11 harness, so11_quota_load, does); only the shedding half of SO-11 is probed."},
            {"id": "SO11-QUOTA-PROVISIONAL", "summary": "the quota is provisional and container-derived (container-aarch64, not hardware); no hardware class is declared."},
            {"id": "SO11-NOT-A-RECORD", "summary": "this probe's output is not a service-objective record; SO-11 records come from the SO-11 harness (so11_quota_load) and are validated by record.py."},
            {"id": "SO11-SINGLE-MIX", "summary": "one traffic mix (flow/dns/stats/http in equal parts at 120% of the quota plus 1000 alerts/s, ~600-byte lines); backlog escalation and unparseable/oversized lines are covered by core unit tests, not here."},
        ],
    })
    if not all(checks.values()):
        result["verdict"] = "fail"
    return result


def rate_bound_gaps(shed_records: List[Dict[str, Any]]) -> List[float]:
    """Seconds between consecutive ``ingress_shed`` summaries, for the rate bound.

    The summary the core writes when it stops closes a shorter interval on
    purpose (``interval_end: "shutdown"``), so it is left out; every other
    summary, with or without the field, is kept.
    """
    emitted = sorted(float(r.get("emitted_epoch", 0)) for r in shed_records if r.get("interval_end") != "shutdown")
    return [b - a for a, b in zip(emitted, emitted[1:])]


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--core-bin", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=float, default=40.0)
    args = ap.parse_args(argv)
    result = run(Path(args.core_bin), duration_s=args.duration)
    Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"verdict": result["verdict"], "checks": result.get("checks"), "observed": result.get("observed")}, sort_keys=True))
    return 0 if result["verdict"] in ("not_measurable",) and all(result.get("checks", {}).values()) else 1


if __name__ == "__main__":
    sys.exit(main())
