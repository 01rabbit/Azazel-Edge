from __future__ import annotations

import logging
import shutil
import socket
import struct
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List

from azazel_edge.evidence_plane import EvidenceBus, EvidencePlaneService


class SNMPPollError(RuntimeError):
    pass


_DEFAULT_SERVICE: EvidencePlaneService | None = None


def _default_dispatch_syslog_line(line: str) -> None:
    global _DEFAULT_SERVICE
    if _DEFAULT_SERVICE is None:
        _DEFAULT_SERVICE = EvidencePlaneService(EvidenceBus())
    _DEFAULT_SERVICE.dispatch_syslog_line(line)


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _ber_tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _ber_int(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    out = []
    val = int(n)
    while val:
        out.append(val & 0xFF)
        val >>= 8
    body = bytes(reversed(out))
    if body[0] & 0x80:
        body = b"\x00" + body
    return body


def _ber_oid(oid: str) -> bytes:
    parts = [int(x) for x in str(oid).split(".")]
    if len(parts) < 2:
        raise ValueError("invalid_oid")
    out = bytes([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        if n < 128:
            out += bytes([n])
            continue
        stack = [n & 0x7F]
        n >>= 7
        while n:
            stack.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(stack))
    return out


def _build_snmp_get(community: str, oids: List[str], request_id: int) -> bytes:
    varbinds = []
    for oid in oids:
        oid_field = _ber_tlv(0x06, _ber_oid(oid))
        value_null = _ber_tlv(0x05, b"")
        varbinds.append(_ber_tlv(0x30, oid_field + value_null))
    varbind_list = _ber_tlv(0x30, b"".join(varbinds))
    pdu = _ber_tlv(
        0xA0,
        _ber_tlv(0x02, _ber_int(request_id))
        + _ber_tlv(0x02, _ber_int(0))
        + _ber_tlv(0x02, _ber_int(0))
        + varbind_list,
    )
    message = _ber_tlv(0x30, _ber_tlv(0x02, _ber_int(1)) + _ber_tlv(0x04, community.encode("utf-8")) + pdu)
    return message


def _decode_len(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    nbytes = first & 0x7F
    if nbytes == 1:
        return data[pos], pos + 1
    if nbytes == 2:
        return (data[pos] << 8) | data[pos + 1], pos + 2
    raise SNMPPollError("unsupported_length")


def _decode_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos >= len(data):
        raise SNMPPollError("tlv_overrun")
    tag = data[pos]
    length, next_pos = _decode_len(data, pos + 1)
    end = next_pos + length
    if end > len(data):
        raise SNMPPollError("tlv_overrun")
    return tag, data[next_pos:end], end


def _decode_oid(body: bytes) -> str:
    if not body:
        return ""
    first = body[0]
    parts = [first // 40, first % 40]
    i = 1
    while i < len(body):
        n = 0
        while i < len(body):
            b = body[i]
            n = (n << 7) | (b & 0x7F)
            i += 1
            if (b & 0x80) == 0:
                break
        parts.append(n)
    return ".".join(str(x) for x in parts)


def _decode_value(tag: int, body: bytes) -> str:
    if tag in (0x02, 0x41, 0x42, 0x43):
        return str(int.from_bytes(body, byteorder="big", signed=(tag == 0x02)))
    if tag == 0x04:
        try:
            return body.decode("utf-8", errors="replace")
        except Exception:
            return body.hex()
    if tag == 0x06:
        return _decode_oid(body)
    if tag == 0x05:
        return "null"
    return body.hex()


def _parse_snmp_response(data: bytes, request_id: int) -> Dict[str, str]:
    tag, top, _ = _decode_tlv(data, 0)
    if tag != 0x30:
        raise SNMPPollError("invalid_top_sequence")
    pos = 0
    _, _, pos = _decode_tlv(top, pos)  # version
    _, _, pos = _decode_tlv(top, pos)  # community
    pdu_tag, pdu, _ = _decode_tlv(top, pos)
    if pdu_tag != 0xA2:
        raise SNMPPollError("not_get_response")
    p = 0
    _, req_body, p = _decode_tlv(pdu, p)
    resp_req_id = int.from_bytes(req_body, byteorder="big", signed=True)
    if resp_req_id != int(request_id):
        raise SNMPPollError("request_id_mismatch")
    _, err_status_body, p = _decode_tlv(pdu, p)
    _, _, p = _decode_tlv(pdu, p)  # err-index
    err_status = int.from_bytes(err_status_body, byteorder="big", signed=False)
    if err_status != 0:
        raise SNMPPollError("snmp_error_status")
    _, varbind_list, _ = _decode_tlv(pdu, p)

    vp = 0
    out: Dict[str, str] = {}
    while vp < len(varbind_list):
        _, vb, vp = _decode_tlv(varbind_list, vp)
        vbp = 0
        oid_tag, oid_body, vbp = _decode_tlv(vb, vbp)
        if oid_tag != 0x06:
            raise SNMPPollError("invalid_varbind_oid")
        value_tag, value_body, _ = _decode_tlv(vb, vbp)
        out[_decode_oid(oid_body)] = _decode_value(value_tag, value_body)
    return out


class SNMPPoller:
    DEFAULT_OIDS = {
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
        "ifOperStatus": "1.3.6.1.2.1.2.2.1.8.1",
        "ifInErrors": "1.3.6.1.2.1.2.2.1.14.1",
        "ifOutErrors": "1.3.6.1.2.1.2.2.1.20.1",
    }

    def __init__(
        self,
        targets: List[Dict[str, Any]],
        poll_interval_sec: int = 60,
        dispatch_fn: Callable[[str], None] | None = None,
    ):
        self.targets = list(targets or [])
        self.poll_interval_sec = max(1, int(poll_interval_sec))
        self.dispatch_fn = dispatch_fn or _default_dispatch_syslog_line
        self.logger = logging.getLogger(__name__)
        self._stop_event = threading.Event()
        self._request_id = int(time.time()) & 0x7FFFFFFF

    def stop(self) -> None:
        self._stop_event.set()

    def poll_once(self, host: str, community: str, port: int) -> Dict[str, Any]:
        self._request_id += 1
        req_id = self._request_id
        packet = _build_snmp_get(str(community or "public"), list(self.DEFAULT_OIDS.values()), req_id)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3.0)
                sock.sendto(packet, (str(host), int(port)))
                data, _addr = sock.recvfrom(8192)
            oid_values = _parse_snmp_response(data, req_id)
            return {
                key: str(oid_values.get(oid, ""))
                for key, oid in self.DEFAULT_OIDS.items()
            }
        except socket.timeout as exc:
            raise SNMPPollError("snmp_timeout") from exc
        except SNMPPollError:
            raise
        except Exception:
            # Fallback to net-snmp CLI if present.
            cli = shutil.which("snmpget")
            if not cli:
                raise SNMPPollError("snmp_poll_failed") from None
            return self._poll_once_cli(cli, host, community, port)

    def _poll_once_cli(self, cli_path: str, host: str, community: str, port: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, oid in self.DEFAULT_OIDS.items():
            cmd = [
                cli_path,
                "-v2c",
                "-c",
                str(community or "public"),
                "-t",
                "3",
                "-r",
                "0",
                f"{host}:{int(port)}",
                oid,
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=6)
            except subprocess.TimeoutExpired as exc:
                raise SNMPPollError("snmp_timeout") from exc
            if proc.returncode != 0:
                raise SNMPPollError("snmp_cli_failed")
            line = str(proc.stdout or "").strip()
            out[key] = line.split("=", 1)[1].strip() if "=" in line else line
        return out

    def to_syslog_line(self, host: str, result: Dict[str, Any]) -> str:
        parts = [f"SNMP_POLL host={host}"]
        for key in sorted(self.DEFAULT_OIDS.keys()):
            value = str(result.get(key, "")).strip().replace(" ", "_")
            parts.append(f"{key}={value}")
        return " ".join(parts)

    def run_forever(self) -> None:
        while not self._stop_event.is_set():
            for target in self.targets:
                if self._stop_event.is_set():
                    break
                host = str(target.get("host") or "").strip()
                if not host:
                    continue
                community = str(target.get("community") or "public")
                port = int(target.get("port") or 161)
                try:
                    result = self.poll_once(host, community, port)
                    self.dispatch_fn(self.to_syslog_line(host, result))
                except SNMPPollError as exc:
                    self.logger.warning("snmp poll failed host=%s error=%s", host, exc)
                    continue
            self._stop_event.wait(float(self.poll_interval_sec))
