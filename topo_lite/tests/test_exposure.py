from __future__ import annotations

import unittest

from configuration import ExposureConfig
from exposure import evaluate_remote_access


class ExposureTests(unittest.TestCase):
    def test_local_only_mode_rejects_non_loopback(self) -> None:
        exposure = ExposureConfig(local_only=True)

        denied = evaluate_remote_access("192.168.40.55", exposure)
        allowed = evaluate_remote_access("127.0.0.1", exposure)

        self.assertEqual(denied.allowed, False)
        self.assertEqual(denied.reason, "local_only")
        self.assertEqual(allowed.allowed, True)

    def test_allowed_cidrs_gate_remote_access(self) -> None:
        exposure = ExposureConfig(
            backend_bind_host="0.0.0.0",
            frontend_bind_host="0.0.0.0",
            local_only=False,
            allowed_cidrs=["192.168.40.0/24"],
        )

        allowed = evaluate_remote_access("192.168.40.89", exposure)
        denied = evaluate_remote_access("10.10.10.10", exposure)

        self.assertEqual(allowed.allowed, True)
        self.assertTrue(allowed.reason.startswith("allowed_cidr:"))
        self.assertEqual(denied.allowed, False)
        self.assertEqual(denied.reason, "outside_allowed_cidrs")


if __name__ == "__main__":
    unittest.main()
