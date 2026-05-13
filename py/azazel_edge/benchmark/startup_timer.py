from __future__ import annotations

import argparse
import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

REQUIRED_SERVICES = [
    "azazel-edge-web",
    "azazel-edge-control-daemon",
    "azazel-edge-suricata",
    "azazel-edge-opencanary",
]

API_HEALTH_URL = "http://127.0.0.1:8080/api/state"
POLL_INTERVAL_SEC = 1.0
TIMEOUT_SEC = 1200


@dataclass
class StartupTimingResult:
    service_active_at_sec: Dict[str, float] = field(default_factory=dict)
    api_responsive_at_sec: Optional[float] = None
    total_elapsed_sec: Optional[float] = None
    timed_out: bool = False

    def summary(self) -> dict:
        return {
            "services": self.service_active_at_sec,
            "api_responsive_at_sec": self.api_responsive_at_sec,
            "total_elapsed_sec": self.total_elapsed_sec,
            "timed_out": self.timed_out,
            "last_service_at_sec": max(self.service_active_at_sec.values()) if self.service_active_at_sec else None,
            "operational_definition": "all 4 core services active + /api/state HTTP 200",
        }


class StartupTimer:
    def __init__(self, timeout_sec: int = TIMEOUT_SEC):
        self.timeout_sec = timeout_sec

    def _is_service_active(self, service: str) -> bool:
        try:
            r = subprocess.run(["systemctl", "is-active", "--quiet", service], timeout=3)
            return r.returncode == 0
        except Exception:
            return False

    def _is_api_responsive(self) -> bool:
        try:
            import urllib.request
            with urllib.request.urlopen(API_HEALTH_URL, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def measure(self) -> StartupTimingResult:
        result = StartupTimingResult()
        remaining = set(REQUIRED_SERVICES)
        t_start = time.monotonic()

        while True:
            elapsed = time.monotonic() - t_start
            if elapsed > self.timeout_sec:
                result.timed_out = True
                result.total_elapsed_sec = round(elapsed, 2)
                return result

            for svc in list(remaining):
                if self._is_service_active(svc):
                    result.service_active_at_sec[svc] = round(elapsed, 2)
                    remaining.discard(svc)

            if not remaining and result.api_responsive_at_sec is None and self._is_api_responsive():
                result.api_responsive_at_sec = round(elapsed, 2)
                result.total_elapsed_sec = round(elapsed, 2)
                return result

            time.sleep(POLL_INTERVAL_SEC)


def main() -> None:
    ap = argparse.ArgumentParser(description="Measure service activation time")
    ap.add_argument("--timeout-sec", type=int, default=TIMEOUT_SEC)
    args = ap.parse_args()
    summary = StartupTimer(timeout_sec=args.timeout_sec).measure().summary()
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
