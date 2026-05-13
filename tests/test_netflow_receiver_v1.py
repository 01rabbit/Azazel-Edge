from __future__ import annotations

import socket
import struct
import threading
import time
import unittest
from unittest.mock import patch

from azazel_edge.sensors.netflow_receiver import (
    NETFLOW_V5_HEADER,
    NETFLOW_V5_RECORD,
    NetFlowParseError,
    NetFlowV5Receiver,
)


def _ip(a: int, b: int, c: int, d: int) -> bytes:
    return bytes([a, b, c, d])


def _record(src: bytes, dst: bytes, src_port: int, dst_port: int, packets: int, octets: int, proto: int, flags: int = 0) -> bytes:
    return NETFLOW_V5_RECORD.pack(
        src,            # srcaddr
        dst,            # dstaddr
        _ip(0, 0, 0, 0),  # nexthop
        1,              # input
        2,              # output
        packets,        # dPkts
        octets,         # dOctets
        1000,           # First
        2000,           # Last
        src_port,       # srcport
        dst_port,       # dstport
        flags,          # tcp_flags
        proto,          # prot
        0,              # tos
        65000,          # src_as
        65001,          # dst_as
        24,             # src_mask
        24,             # dst_mask
        0,              # pad2
    )


def _packet(flows: list[bytes]) -> bytes:
    header = NETFLOW_V5_HEADER.pack(
        5,              # version
        len(flows),     # count
        10000,          # sys_uptime
        1715580000,     # unix_secs
        0,              # unix_nsecs
        10,             # flow_sequence
        0,              # engine_type
        0,              # engine_id
        0,              # sampling
    )
    return header + b"".join(flows)


class NetFlowReceiverV1Tests(unittest.TestCase):
    def test_parse_packet_valid_v5(self) -> None:
        receiver = NetFlowV5Receiver()
        pkt = _packet(
            [
                _record(_ip(10, 0, 0, 1), _ip(192, 168, 1, 10), 12345, 443, 10, 1000, 6, 0x10),
                _record(_ip(10, 0, 0, 2), _ip(192, 168, 1, 20), 53000, 53, 5, 500, 17, 0),
            ]
        )
        flows = receiver.parse_packet(pkt)
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[0]["src_ip"], "10.0.0.1")
        self.assertEqual(flows[0]["dst_port"], 443)
        self.assertEqual(flows[1]["protocol"], 17)

    def test_parse_packet_wrong_version_raises(self) -> None:
        receiver = NetFlowV5Receiver()
        header = NETFLOW_V5_HEADER.pack(9, 0, 0, 0, 0, 0, 0, 0, 0)
        with self.assertRaises(NetFlowParseError):
            receiver.parse_packet(header)

    def test_to_syslog_lines_format(self) -> None:
        receiver = NetFlowV5Receiver(top_talker_threshold=1000)
        lines = receiver.to_syslog_lines(
            [
                {
                    "src_ip": "10.0.0.1",
                    "dst_ip": "192.168.1.10",
                    "src_port": 1000,
                    "dst_port": 443,
                    "protocol": 6,
                    "packets": 10,
                    "bytes": 5000,
                    "tcp_flags": 16,
                }
            ],
            "172.16.0.1",
        )
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("NETFLOW_FLOW exporter=172.16.0.1"))

    def test_to_syslog_lines_top_talker_flagged(self) -> None:
        receiver = NetFlowV5Receiver(top_talker_threshold=100)
        lines = receiver.to_syslog_lines(
            [
                {
                    "src_ip": "10.0.0.1",
                    "dst_ip": "192.168.1.10",
                    "src_port": 1000,
                    "dst_port": 443,
                    "protocol": 6,
                    "packets": 200,
                    "bytes": 5000,
                    "tcp_flags": 16,
                }
            ],
            "172.16.0.1",
        )
        self.assertTrue(lines[0].startswith("NETFLOW_TOP_TALKER"))

    def test_run_forever_dispatches(self) -> None:
        pkt = _packet([_record(_ip(10, 0, 0, 1), _ip(192, 168, 1, 10), 12345, 443, 10, 1000, 6)])
        sent: list[str] = []

        class _Sock:
            def __init__(self):
                self.sent = False

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def setsockopt(self, *_args):
                return None

            def bind(self, *_args):
                return None

            def settimeout(self, *_args):
                return None

            def recvfrom(self, _size):
                if not self.sent:
                    self.sent = True
                    return pkt, ("127.0.0.1", 9999)
                raise socket.timeout()

        receiver = NetFlowV5Receiver(
            dispatch_fn=lambda line: sent.append(line),
            listen_port=2055,
        )
        with patch("azazel_edge.sensors.netflow_receiver.socket.socket", return_value=_Sock()):
            t = threading.Thread(target=receiver.run_forever, daemon=True)
            t.start()
            time.sleep(0.05)
            receiver.stop()
            t.join(timeout=1)
        self.assertTrue(sent)
        self.assertTrue(sent[0].startswith("NETFLOW_FLOW exporter=127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
