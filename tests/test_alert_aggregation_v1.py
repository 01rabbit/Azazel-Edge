from __future__ import annotations

import time
import unittest

import azazel_edge_web.app as webapp


class AlertAggregationV1Tests(unittest.TestCase):
    def _alert(self, *, ts: float, src: str, dst: str, sid: int, risk: int, risk_level: str = "MEDIUM", attack: str = "scan") -> dict:
        return {
            "ts": ts,
            "ts_iso": webapp._iso_from_epoch(ts),
            "src_ip": src,
            "dst_ip": dst,
            "sid": sid,
            "risk_score": risk,
            "risk_level": risk_level,
            "attack_type": attack,
            "recommendation": "observe",
            "severity": 3,
        }

    def test_duplicate_burst_is_grouped_and_suppressed(self) -> None:
        now = time.time()
        rows = [
            self._alert(ts=now - 10, src="10.0.0.2", dst="10.0.0.1", sid=1001, risk=55),
            self._alert(ts=now - 8, src="10.0.0.2", dst="10.0.0.1", sid=1001, risk=55),
            self._alert(ts=now - 5, src="10.0.0.2", dst="10.0.0.1", sid=1001, risk=55),
        ]
        payload = webapp._dashboard_alert_aggregation_payload(rows)
        self.assertEqual(payload["group_count"], 1)
        self.assertEqual(payload["suppressed_total"], 2)
        self.assertEqual(payload["groups"][0]["count"], 3)

    def test_worsening_severity_escalates_by_risk(self) -> None:
        now = time.time()
        rows = [
            self._alert(ts=now - 12, src="10.0.0.5", dst="10.0.0.1", sid=2100, risk=45, risk_level="LOW"),
            self._alert(ts=now - 7, src="10.0.0.5", dst="10.0.0.1", sid=2100, risk=95, risk_level="CRITICAL"),
        ]
        payload = webapp._dashboard_alert_aggregation_payload(rows)
        self.assertTrue(payload["escalation_queue"])
        self.assertEqual(payload["escalation_queue"][0]["risk_score_max"], 95)

    def test_multi_source_creates_distinct_groups(self) -> None:
        now = time.time()
        rows = [
            self._alert(ts=now - 10, src="10.0.0.10", dst="10.0.0.1", sid=333, risk=60),
            self._alert(ts=now - 9, src="10.0.0.11", dst="10.0.0.1", sid=333, risk=60),
        ]
        payload = webapp._dashboard_alert_aggregation_payload(rows)
        self.assertEqual(payload["group_count"], 2)


if __name__ == "__main__":
    unittest.main()

