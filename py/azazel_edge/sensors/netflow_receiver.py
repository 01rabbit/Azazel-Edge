from __future__ import annotations

import logging
import socket
import struct
import threading
from typing import Any, Callable, Dict, List

from azazel_edge.evidence_plane import EvidenceBus, EvidencePlaneService


class NetFlowParseError(RuntimeError):
    pass


NETFLOW_V5_HEADER = struct.Struct("!HHIIIIBBH")
NETFLOW_V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHxBBBHHBBH")

_DEFAULT_SERVICE: EvidencePlaneService | None = None


def _default_dispatch_syslog_line(line: str) -> None:
    global _DEFAULT_SERVICE
    if _DEFAULT_SERVICE is None:
        _DEFAULT_SERVICE = EvidencePlaneService(EvidenceBus())
    _DEFAULT_SERVICE.dispatch_syslog_line(line)


def _ipv4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


class NetFlowV5Receiver:
    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 2055,
        dispatch_fn: Callable[[str], None] | None = None,
        top_talker_threshold: int = 1000,
    ):
        self.listen_host = str(listen_host or "0.0.0.0")
        self.listen_port = int(listen_port)
        self.dispatch_fn = dispatch_fn or _default_dispatch_syslog_line
        self.top_talker_threshold = max(1, int(top_talker_threshold))
        self.logger = logging.getLogger(__name__)
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def parse_packet(self, data: bytes) -> List[Dict[str, Any]]:
        if not isinstance(data, (bytes, bytearray)) or len(data) < NETFLOW_V5_HEADER.size:
            raise NetFlowParseError("netflow_packet_too_short")
        header = NETFLOW_V5_HEADER.unpack_from(data, 0)
        version = int(header[0])
        count = int(header[1])
        if version != 5:
            raise NetFlowParseError("netflow_version_unsupported")
        expected = NETFLOW_V5_HEADER.size + (count * NETFLOW_V5_RECORD.size)
        if len(data) < expected:
            raise NetFlowParseError("netflow_packet_truncated")

        flows: List[Dict[str, Any]] = []
        offset = NETFLOW_V5_HEADER.size
        for _ in range(count):
            rec = NETFLOW_V5_RECORD.unpack_from(data, offset)
            offset += NETFLOW_V5_RECORD.size
            flows.append(
                {
                    "src_ip": _ipv4(rec[0]),
                    "dst_ip": _ipv4(rec[1]),
                    "src_port": int(rec[9]),
                    "dst_port": int(rec[10]),
                    "packets": int(rec[5]),
                    "bytes": int(rec[6]),
                    "protocol": int(rec[12]),
                    "tcp_flags": int(rec[11]),
                }
            )
        return flows

    def to_syslog_lines(self, flows: List[Dict[str, Any]], exporter_ip: str) -> List[str]:
        rows: List[str] = []
        exp = str(exporter_ip or "").strip() or "unknown"
        for flow in flows:
            prefix = "NETFLOW_TOP_TALKER" if int(flow.get("packets") or 0) > self.top_talker_threshold else "NETFLOW_FLOW"
            rows.append(
                f"{prefix} exporter={exp} "
                f"src={flow.get('src_ip','-')}:{int(flow.get('src_port') or 0)} "
                f"dst={flow.get('dst_ip','-')}:{int(flow.get('dst_port') or 0)} "
                f"proto={int(flow.get('protocol') or 0)} "
                f"pkts={int(flow.get('packets') or 0)} "
                f"bytes={int(flow.get('bytes') or 0)}"
            )
        return rows

    def run_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.listen_host, self.listen_port))
            sock.settimeout(1.0)
            while not self._stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except Exception as exc:
                    self.logger.warning("netflow receive failure: %s", exc)
                    continue
                try:
                    flows = self.parse_packet(data)
                    lines = self.to_syslog_lines(flows, addr[0] if isinstance(addr, tuple) and addr else "")
                    for line in lines:
                        self.dispatch_fn(line)
                except NetFlowParseError as exc:
                    self.logger.warning("netflow parse error: %s", exc)
                    continue
