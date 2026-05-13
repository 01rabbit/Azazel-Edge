import unittest
from unittest.mock import patch
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.benchmark.startup_timer import REQUIRED_SERVICES, StartupTimer


class StartupTimerLogicTests(unittest.TestCase):
    def test_returns_result_when_all_active_immediately(self):
        timer = StartupTimer(timeout_sec=60)
        with patch.object(timer, "_is_service_active", return_value=True), patch.object(timer, "_is_api_responsive", return_value=True):
            result = timer.measure()
        self.assertFalse(result.timed_out)
        self.assertIsNotNone(result.total_elapsed_sec)
        self.assertEqual(set(result.service_active_at_sec.keys()), set(REQUIRED_SERVICES))

    def test_all_required_services_are_checked(self):
        timer = StartupTimer(timeout_sec=5)
        checked = []

        def fake_active(svc):
            checked.append(svc)
            return True

        with patch.object(timer, "_is_service_active", side_effect=fake_active), patch.object(timer, "_is_api_responsive", return_value=True):
            timer.measure()
        for svc in REQUIRED_SERVICES:
            self.assertIn(svc, checked)

    def test_timeout_is_respected(self):
        timer = StartupTimer(timeout_sec=2)
        with patch.object(timer, "_is_service_active", return_value=False), patch.object(timer, "_is_api_responsive", return_value=False):
            result = timer.measure()
        self.assertTrue(result.timed_out)

    def test_summary_contains_operational_definition(self):
        timer = StartupTimer(timeout_sec=5)
        with patch.object(timer, "_is_service_active", return_value=True), patch.object(timer, "_is_api_responsive", return_value=True):
            summary = timer.measure().summary()
        self.assertIn("operational_definition", summary)


if __name__ == "__main__":
    unittest.main()
