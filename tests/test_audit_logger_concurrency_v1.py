from __future__ import annotations

import threading
import tempfile
import unittest
from pathlib import Path

from azazel_edge.audit import P0AuditLogger


class P0AuditLoggerConcurrencyV1Tests(unittest.TestCase):
    @unittest.skip("Phase 3 enables this after P0AuditLogger.log() is locked")
    def test_concurrent_log_appends_preserve_hash_chain(self) -> None:
        thread_count = 8
        writes_per_thread = 25

        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            logger = P0AuditLogger(log_path)

            def write_batch(worker: int) -> None:
                for idx in range(writes_per_thread):
                    logger.log_event_receive(
                        trace_id=f"trace-{worker:02x}-{idx:02x}",
                        source="test",
                        worker=worker,
                        idx=idx,
                    )

            threads = [threading.Thread(target=write_batch, args=(worker,)) for worker in range(thread_count)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            result = P0AuditLogger.verify_chain(log_path)
            self.assertEqual(
                result,
                {"ok": True, "entries": thread_count * writes_per_thread, "error": ""},
            )


if __name__ == "__main__":
    unittest.main()
