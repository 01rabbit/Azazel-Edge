"""Exercise the opt-in harness preflight without services or elevated privileges."""
import os
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch


HARNESS = Path(__file__).resolve().parents[1] / "tools/verification/mio_real_process.py"
MIO_PIN = "6cd015351979ba69e18517d71f79c0c347bb2722"


class RealProcessPreflightTests(unittest.TestCase):
    def test_root_refused_before_environment_writes_or_subprocesses(self):
        with patch.object(os, "geteuid", return_value=0), \
             patch.dict(os.environ, {}, clear=True), \
             patch.object(Path, "mkdir") as mkdir, \
             patch.object(Path, "write_text") as write, \
             patch("subprocess.check_output") as check_output, \
             patch("subprocess.Popen") as popen:
            with self.assertRaisesRegex(SystemExit, "Refusing root execution"):
                runpy.run_path(str(HARNESS))
            mkdir.assert_not_called()
            write.assert_not_called()
            check_output.assert_not_called()
            popen.assert_not_called()

    def test_nonroot_reaches_normal_harness_setup(self):
        env = {"MIO_PROCESS_EVIDENCE": "/unused/private-evidence",
               "MIO_EXACT_SOURCE": "/unused/clean-source"}
        with patch.object(os, "geteuid", return_value=1000), \
             patch.dict(os.environ, env, clear=True), \
             patch.object(Path, "mkdir") as mkdir, \
             patch.object(Path, "write_text") as write, \
             patch("subprocess.check_output", side_effect=[MIO_PIN + "\n", ""]) as check_output, \
             patch("subprocess.Popen") as popen:
            namespace = runpy.run_path(str(HARNESS))
            mkdir.assert_called_once_with(mode=0o700)
            write.assert_called_once_with("")
            self.assertEqual(check_output.call_count, 2)
            self.assertTrue(callable(namespace["run"]))
            self.assertEqual(namespace["BASE"]["AZAZEL_MIO_MODEL_ENABLED"], "1")
            popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
