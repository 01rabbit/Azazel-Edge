from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from azazel_edge.outcome import SubprocessReadOnlyRunner


class TrustedRunnerPathTests(unittest.TestCase):
    def test_allowed_probe_ignores_untrusted_process_path(self) -> None:
        runner = SubprocessReadOnlyRunner()
        completed = SimpleNamespace(returncode=0, stdout="[]", stderr="")

        with (
            patch.dict(os.environ, {"PATH": "/tmp/attacker"}),
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
                timeout_seconds=1.0,
            )

        which_mock.assert_called_once_with(
            "tc",
            path="/usr/sbin:/usr/bin:/sbin:/bin",
        )
        argv = run_mock.call_args.args[0]
        kwargs = run_mock.call_args.kwargs
        self.assertEqual(argv[0], "/usr/sbin/tc")
        self.assertNotIn("/tmp/attacker", argv)
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["env"]["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")
        self.assertEqual(result.argv, ("tc", "-j", "qdisc", "show", "dev", "br0"))


if __name__ == "__main__":
    unittest.main()
