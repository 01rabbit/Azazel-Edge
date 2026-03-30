from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from configuration import LoggingConfig
from logging_utils import append_audit_record, configure_logging, log_event


class LoggingUtilsTests(unittest.TestCase):
    def test_jsonl_loggers_write_parseable_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            logs = configure_logging(
                LoggingConfig(
                    level="INFO",
                    app_log_path=str(Path(tmp_dir) / "app.jsonl"),
                    access_log_path=str(Path(tmp_dir) / "access.jsonl"),
                    audit_log_path=str(Path(tmp_dir) / "audit.jsonl"),
                    scanner_log_path=str(Path(tmp_dir) / "scanner.jsonl"),
                )
            )
            log_event(logs.app, "app_test", "app message", detail="value")
            append_audit_record(logs.audit, "audit_test", actor="tester", action="write")

            app_entry = json.loads((Path(tmp_dir) / "app.jsonl").read_text(encoding="utf-8").strip())
            audit_entry = json.loads((Path(tmp_dir) / "audit.jsonl").read_text(encoding="utf-8").strip())

        self.assertEqual(app_entry["event"], "app_test")
        self.assertEqual(app_entry["detail"], "value")
        self.assertEqual(audit_entry["event"], "audit_test")
        self.assertEqual(audit_entry["actor"], "tester")


if __name__ == "__main__":
    unittest.main()
