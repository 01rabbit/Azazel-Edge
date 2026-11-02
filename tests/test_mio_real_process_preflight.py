"""Exercise the opt-in harness preflight without services or elevated privileges."""
import ast
import os
import re
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch


HARNESS = Path(__file__).resolve().parents[1] / "tools/verification/mio_real_process.py"
MIO_PIN = "a8b1bee1775f483a7b2d7d33538896c9446a9b0c"
PIN_LINE = f"azazel-mio @ git+https://github.com/01rabbit/Azazel-MIO.git@{MIO_PIN}"


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

    def test_runtime_pin_parser(self):
        # Load only the pure parser; never initialize the opt-in harness.
        tree = ast.parse(HARNESS.read_text())
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "runtime_mio_pin")
        namespace = {"re": re}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(HARNESS), "exec"), namespace)
        parser = namespace["runtime_mio_pin"]
        with patch.object(Path, "read_text", return_value="# comment\n" + PIN_LINE + "\n"):
            self.assertEqual(parser(Path("unused")), MIO_PIN)
        for content in ("", "# " + PIN_LINE, PIN_LINE + "\n" + PIN_LINE,
                        PIN_LINE.replace(MIO_PIN, "main"),
                        PIN_LINE.replace(MIO_PIN, MIO_PIN[:-1]),
                        PIN_LINE + "#egg=other",
                        PIN_LINE + "; python_version >= '3.11'",
                        PIN_LINE + "\nazazel-mio>=1"):
            with self.subTest(content=content), patch.object(Path, "read_text", return_value=content):
                with self.assertRaises(SystemExit):
                    parser(Path("unused"))
        with patch.object(Path, "read_text", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                parser(Path("missing"))

    def test_invalid_runtime_pin_rejected_before_git_or_services(self):
        env = {"MIO_PROCESS_EVIDENCE": "/unused/private-evidence",
               "MIO_EXACT_SOURCE": "/unused/clean-source"}
        for content in ("", "azazel-mio>=1", PIN_LINE + "\n" + PIN_LINE):
            with self.subTest(content=content), \
                 patch.object(os, "geteuid", return_value=1000), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(Path, "mkdir"), \
                 patch.object(Path, "read_text", return_value=content), \
                 patch.object(Path, "write_text") as write, \
                 patch("subprocess.check_output") as check_output, \
                 patch("subprocess.Popen") as popen:
                with self.assertRaises(SystemExit):
                    runpy.run_path(str(HARNESS), run_name="__main__")
                write.assert_not_called()
                check_output.assert_not_called()
                popen.assert_not_called()

    def test_source_rejected_before_services(self):
        env = {"MIO_PROCESS_EVIDENCE": "/unused/private-evidence",
               "MIO_EXACT_SOURCE": "/unused/clean-source"}
        for outputs, message in ((["0" * 40 + "\n"], "HEAD does not match"),
                                 ([MIO_PIN + "\n", " M dirty.py"], "must be clean")):
            with self.subTest(message=message), \
                 patch.object(os, "geteuid", return_value=1000), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(Path, "mkdir"), \
                 patch.object(Path, "write_text") as write, \
                 patch("subprocess.check_output", side_effect=outputs), \
                 patch("subprocess.Popen") as popen:
                with self.assertRaisesRegex(SystemExit, message):
                    runpy.run_path(str(HARNESS), run_name="__main__")
                write.assert_not_called()
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
