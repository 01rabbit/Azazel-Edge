from __future__ import annotations

import threading
import time
import unittest
import socket
from unittest.mock import patch

from azazel_edge.sensors.snmp_poller import SNMPPollError, SNMPPoller


class SNMPPollerV1Tests(unittest.TestCase):
    def test_to_syslog_line_format(self) -> None:
        poller = SNMPPoller(targets=[])
        line = poller.to_syslog_line(
            "192.168.1.1",
            {"sysUpTime": "123", "ifOperStatus": "1", "ifInErrors": "0", "ifOutErrors": "0"},
        )
        self.assertTrue(line.startswith("SNMP_POLL host=192.168.1.1"))
        self.assertIn("sysUpTime=123", line)

    def test_poll_once_timeout_raises(self) -> None:
        class _Sock:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def settimeout(self, _t):
                return None

            def sendto(self, _data, _addr):
                return None

            def recvfrom(self, _size):
                raise socket.timeout("timeout")

        poller = SNMPPoller(targets=[])
        with patch("azazel_edge.sensors.snmp_poller.socket.socket", return_value=_Sock()):
            with self.assertRaises(SNMPPollError):
                poller.poll_once("127.0.0.1", "public", 161)

    def test_run_forever_dispatches_on_success(self) -> None:
        sent: list[str] = []
        poller = SNMPPoller(
            targets=[{"host": "192.168.1.1", "community": "public", "port": 161}],
            poll_interval_sec=1,
            dispatch_fn=lambda line: sent.append(line),
        )
        with patch.object(
            SNMPPoller,
            "poll_once",
            return_value={"sysUpTime": "1", "ifOperStatus": "1", "ifInErrors": "0", "ifOutErrors": "0"},
        ):
            t = threading.Thread(target=poller.run_forever, daemon=True)
            t.start()
            time.sleep(0.05)
            poller.stop()
            t.join(timeout=1)
        self.assertTrue(sent)
        self.assertTrue(sent[0].startswith("SNMP_POLL host=192.168.1.1"))

    def test_run_forever_continues_on_error(self) -> None:
        calls = {"count": 0}
        sent: list[str] = []

        def _poll_once(_host, _community, _port):
            calls["count"] += 1
            if calls["count"] == 1:
                raise SNMPPollError("snmp_timeout")
            return {"sysUpTime": "2", "ifOperStatus": "1", "ifInErrors": "0", "ifOutErrors": "0"}

        poller = SNMPPoller(
            targets=[{"host": "192.168.1.1", "community": "public", "port": 161}],
            poll_interval_sec=1,
            dispatch_fn=lambda line: sent.append(line),
        )
        with patch.object(SNMPPoller, "poll_once", side_effect=_poll_once):
            t = threading.Thread(target=poller.run_forever, daemon=True)
            t.start()
            time.sleep(1.1)
            poller.stop()
            t.join(timeout=2)
        self.assertGreaterEqual(calls["count"], 2)
        self.assertTrue(sent)


if __name__ == "__main__":
    unittest.main()
