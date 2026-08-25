from __future__ import annotations

import math
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from azazel_edge.outcome import ReadOnlyCommandRejected, SubprocessReadOnlyRunner


class TrustedRunnerPathTests(unittest.TestCase):
    def _run_with_mocks(self, *, stdout: str = "[]", timeout_seconds: float = 1.0):
        runner = SubprocessReadOnlyRunner()
        completed = SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        with (
            patch.dict(
                os.environ,
                {
                    "PATH": "/tmp/attacker",
                    "LD_PRELOAD": "/tmp/attacker.so",
                    "LD_LIBRARY_PATH": "/tmp/attacker-lib",
                },
            ),
            patch(
                "azazel_edge.outcome.postcondition.shutil.which",
                return_value="/usr/sbin/tc",
            ) as which_mock,
            patch(
                "azazel_edge.outcome.postcondition.subprocess.run",
                return_value=completed,
            ) as run_mock,
        ):
            result = runner.run(
                ("tc", "-j", "qdisc", "show", "dev", "br0"),
                timeout_seconds=timeout_seconds,
            )
        return result, which_mock, run_mock

    def test_allowed_probe_ignores_untrusted_process_environment(self) -> None:
        result, which_mock, run_mock = self._run_with_mocks()

        which_mock.assert_called_once_with(
            "tc",
            path="/usr/sbin:/usr/bin:/sbin:/bin",
        )
        argv = run_mock.call_args.args[0]
        kwargs = run_mock.call_args.kwargs
        self.assertEqual(argv[0], "/usr/sbin/tc")
        self.assertNotIn("/tmp/attacker", argv)
        self.assertFalse(kwargs["shell"])
        self.assertEqual(
            kwargs["env"],
            {
                "LC_ALL": "C",
                "LANG": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
        self.assertNotIn("LD_PRELOAD", kwargs["env"])
        self.assertNotIn("LD_LIBRARY_PATH", kwargs["env"])
        self.assertEqual(result.argv, ("tc", "-j", "qdisc", "show", "dev", "br0"))

    def test_probe_timeout_is_capped(self) -> None:
        _result, _which_mock, run_mock = self._run_with_mocks(timeout_seconds=999.0)
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 5.0)

    def test_non_finite_timeout_is_rejected_before_subprocess(self) -> None:
        runner = SubprocessReadOnlyRunner()
        with self.assertRaises(ReadOnlyCommandRejected):
            runner.run(
                ("tc", "-j", "qdisc", "show", "dev", "br0"),
                timeout_seconds=math.inf,
            )

    def test_oversized_probe_output_is_rejected(self) -> None:
        runner = SubprocessReadOnlyRunner()
        completed = SimpleNamespace(returncode=0, stdout="x" * (1024 * 1024 + 1), stderr="")
        with (
            patch(
                "azazel_edge.outcome.postcondition.shutil.which",
                return_value="/usr/sbin/tc",
            ),
            patch(
                "azazel_edge.outcome.postcondition.subprocess.run",
                return_value=completed,
            ),
        ):
            with self.assertRaises(OSError):
                runner.run(
                    ("tc", "-j", "qdisc", "show", "dev", "br0"),
                    timeout_seconds=1.0,
                )


if __name__ == "__main__":
    unittest.main()
