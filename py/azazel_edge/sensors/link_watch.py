"""Link-state watch for the NOC monitor (Edge#414 SO-02).

Observation only. A carrier/operstate change on a monitored interface asks
for an immediate NOC re-evaluation of that interface, so the operator surface
shows the change without waiting for the periodic loop. It changes *when* a
state becomes visible, never what is decided from it: no enforcement, no
approval, no unit operation is reachable from here.

Two sources, in order of preference:

* ``netlink`` -- an ``AF_NETLINK``/``NETLINK_ROUTE`` socket subscribed to the
  ``RTMGRP_LINK`` multicast group. The kernel lets any process receive
  rtnetlink multicast (``NL_CFG_F_NONROOT_RECV``); no capability is needed,
  and the socket only listens -- it never sends a request.
* ``sysfs_poll`` -- when the socket cannot be opened (not Linux, a sandbox
  without ``AF_NETLINK``), ``/sys/class/net/<if>/{carrier,operstate}`` is read
  every ``poll_interval_s`` (at most 1 s).

Every trigger goes through :class:`ReevaluationGate`: changes are debounced
(a flapping link becomes one re-evaluation) and re-evaluations are rate
bounded, so link events can never drive the probes harder than once per
``min_interval_s``.
"""

from __future__ import annotations

import logging
import select
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

NETLINK_ROUTE = 0
RTMGRP_LINK = 0x1
RTM_NEWLINK = 16
RTM_DELLINK = 17
NLMSG_HDR = struct.Struct('=IHHII')
IFINFOMSG = struct.Struct('=BxHiII')
RTATTR = struct.Struct('=HH')
IFLA_IFNAME = 3
IFLA_OPERSTATE = 16
IFLA_CARRIER = 33
IFF_LOWER_UP = 0x10000
# RFC 2863 operstates as the kernel numbers them (IF_OPER_*).
OPERSTATES = ('unknown', 'notpresent', 'down', 'lowerlayerdown', 'testing', 'dormant', 'up')

DEFAULT_DEBOUNCE_S = 0.25
DEFAULT_MAX_DELAY_S = 1.0
DEFAULT_MIN_INTERVAL_S = 2.0
MAX_POLL_INTERVAL_S = 1.0

LinkState = Tuple[str, int]  # (operstate, carrier)


def _align4(n: int) -> int:
    return (n + 3) & ~3


def parse_link_messages(data: bytes) -> List[Tuple[str, Optional[LinkState]]]:
    """(ifname, (operstate, carrier)) for each RTM_NEWLINK in ``data``;
    (ifname, None) for RTM_DELLINK. Malformed input yields what parsed."""

    out: List[Tuple[str, Optional[LinkState]]] = []
    offset = 0
    while offset + NLMSG_HDR.size <= len(data):
        length, mtype, _flags, _seq, _pid = NLMSG_HDR.unpack_from(data, offset)
        if length < NLMSG_HDR.size or offset + length > len(data):
            break
        body = offset + NLMSG_HDR.size
        if mtype in (RTM_NEWLINK, RTM_DELLINK) and body + IFINFOMSG.size <= offset + length:
            _family, _type, _index, flags, _change = IFINFOMSG.unpack_from(data, body)
            name, oper, carrier = '', None, None
            attr = body + IFINFOMSG.size
            end = offset + length
            while attr + RTATTR.size <= end:
                alen, atype = RTATTR.unpack_from(data, attr)
                if alen < RTATTR.size or attr + alen > end:
                    break
                payload = data[attr + RTATTR.size:attr + alen]
                if atype == IFLA_IFNAME:
                    name = payload.split(b'\0', 1)[0].decode('utf-8', 'replace')
                elif atype == IFLA_OPERSTATE and payload:
                    oper = payload[0]
                elif atype == IFLA_CARRIER and payload:
                    carrier = payload[0]
                attr += _align4(alen)
            if name:
                if mtype == RTM_DELLINK:
                    out.append((name, None))
                else:
                    if carrier is None:
                        carrier = 1 if flags & IFF_LOWER_UP else 0
                    oper_name = OPERSTATES[oper] if isinstance(oper, int) and 0 <= oper < len(OPERSTATES) else 'unknown'
                    out.append((name, (oper_name, int(carrier))))
        offset += _align4(length)
    return out


def read_sysfs_state(iface: str, root: Path = Path('/sys/class/net')) -> Optional[LinkState]:
    base = root / iface
    try:
        oper = (base / 'operstate').read_text(encoding='utf-8').strip()
    except OSError:
        return None
    try:
        carrier = int((base / 'carrier').read_text(encoding='utf-8').strip() or 0)
    except (OSError, ValueError):
        carrier = 0  # reading carrier of an admin-down link fails with EINVAL
    return (oper, carrier)


class ReevaluationGate:
    """Debounce link changes and bound the rate of re-evaluations.

    ``note(iface)`` records a change. ``due()`` returns the interfaces to
    re-evaluate now -- all pending ones -- once the last change is
    ``debounce_s`` old (or the first is ``max_delay_s`` old, so a link that
    keeps flapping is still reported) and at least ``min_interval_s`` has
    passed since the previous re-evaluation. Pure; the clock is injectable.
    """

    def __init__(
        self,
        *,
        debounce_s: float = DEFAULT_DEBOUNCE_S,
        max_delay_s: float = DEFAULT_MAX_DELAY_S,
        min_interval_s: float = DEFAULT_MIN_INTERVAL_S,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not (0 <= debounce_s <= max_delay_s) or min_interval_s <= 0:
            raise ValueError('invalid_reevaluation_gate')
        self.debounce_s = float(debounce_s)
        self.max_delay_s = float(max_delay_s)
        self.min_interval_s = float(min_interval_s)
        self.clock = clock
        self._first: Dict[str, float] = {}
        self._last: Dict[str, float] = {}
        self._last_fire: Optional[float] = None
        self.fired = 0

    def note(self, iface: str) -> None:
        now = self.clock()
        self._first.setdefault(iface, now)
        self._last[iface] = now

    def pending(self) -> List[str]:
        return sorted(self._first)

    def _ready_at(self) -> Optional[float]:
        if not self._first:
            return None
        settle = min(
            min(self._first.values()) + self.max_delay_s,
            max(self._last.values()) + self.debounce_s,
        )
        if self._last_fire is not None:
            settle = max(settle, self._last_fire + self.min_interval_s)
        return settle

    def wait_s(self) -> Optional[float]:
        """Seconds until ``due()`` may return something; None if nothing is pending."""
        ready = self._ready_at()
        return None if ready is None else max(0.0, ready - self.clock())

    def due(self) -> List[str]:
        ready = self._ready_at()
        now = self.clock()
        if ready is None or now < ready:
            return []
        ifaces = sorted(self._first)
        self._first.clear()
        self._last.clear()
        self._last_fire = now
        self.fired += 1
        return ifaces


class LinkStateWatcher:
    """Watch monitored interfaces and call ``on_change(ifaces)`` through the gate.

    ``interfaces`` returns the currently monitored interface names (it may
    change as the NOC scope changes). ``on_change`` runs in the watcher
    thread; a slow callback delays later triggers but never queues more than
    one re-evaluation.
    """

    def __init__(
        self,
        interfaces: Callable[[], Iterable[str]],
        on_change: Callable[[List[str]], None],
        *,
        gate: Optional[ReevaluationGate] = None,
        sysfs_root: Path = Path('/sys/class/net'),
        poll_interval_s: float = MAX_POLL_INTERVAL_S,
        open_netlink: Optional[Callable[[], socket.socket]] = None,
    ):
        self.interfaces = interfaces
        self.on_change = on_change
        self.gate = gate or ReevaluationGate()
        self.sysfs_root = sysfs_root
        self.poll_interval_s = min(MAX_POLL_INTERVAL_S, max(0.05, float(poll_interval_s)))
        self._open_netlink = open_netlink or self._default_open_netlink
        self.mode = 'stopped'
        self.mode_detail = ''
        self._known: Dict[str, Optional[LinkState]] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _default_open_netlink() -> socket.socket:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | getattr(socket, 'SOCK_CLOEXEC', 0), NETLINK_ROUTE)
        try:
            sock.bind((0, RTMGRP_LINK))
            sock.setblocking(False)
        except OSError:
            sock.close()
            raise
        return sock

    def _monitored(self) -> List[str]:
        try:
            return sorted({str(i).strip() for i in self.interfaces() if str(i).strip()})
        except Exception:
            return []

    def observe(self, iface: str, state: Optional[LinkState]) -> bool:
        """Record ``state`` for ``iface``; True (and noted on the gate) if it changed."""
        if iface not in self._monitored():
            return False
        if iface not in self._known:
            # First sight: the baseline, not a change.
            self._known[iface] = state
            return False
        if self._known[iface] == state:
            return False
        self._known[iface] = state
        self.gate.note(iface)
        return True

    def resync(self) -> None:
        """Re-read every monitored interface from sysfs (start, ENOBUFS, poll)."""
        for iface in self._monitored():
            self.observe(iface, read_sysfs_state(iface, self.sysfs_root))

    def fire_due(self) -> List[str]:
        ifaces = self.gate.due()
        if ifaces:
            try:
                self.on_change(ifaces)
            except Exception as exc:  # observation only: never kill the watcher
                logger.debug(f'link-state re-evaluation failed: {exc}')
        return ifaces

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self.run, name='noc-link-watch', daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        sock: Optional[socket.socket] = None
        try:
            sock = self._open_netlink()
            self.mode, self.mode_detail = 'netlink', 'RTMGRP_LINK multicast'
        except (OSError, AttributeError) as exc:
            self.mode, self.mode_detail = 'sysfs_poll', f'netlink unavailable ({exc}); polling sysfs every {self.poll_interval_s} s'
        logger.info(f'NOC link-state watch: {self.mode} ({self.mode_detail})')
        self.resync()
        try:
            while not self._stop.is_set():
                wait = self.gate.wait_s()
                timeout = self.poll_interval_s if wait is None else min(wait, self.poll_interval_s)
                if sock is not None:
                    try:
                        readable, _, _ = select.select([sock], [], [], timeout)
                    except (OSError, ValueError):
                        readable = []
                    if readable:
                        self._drain(sock)
                    # Interfaces that appear later get their baseline here.
                    for iface in self._monitored():
                        if iface not in self._known:
                            self.observe(iface, read_sysfs_state(iface, self.sysfs_root))
                else:
                    self._stop.wait(timeout)
                    self.resync()
                self.fire_due()
        finally:
            if sock is not None:
                sock.close()
            self.mode = 'stopped'

    def _drain(self, sock: socket.socket) -> None:
        while True:
            try:
                data = sock.recv(65536)
            except BlockingIOError:
                return
            except OSError:
                # ENOBUFS: messages were dropped; re-read the truth from sysfs.
                self.resync()
                return
            if not data:
                return
            for iface, state in parse_link_messages(data):
                self.observe(iface, state)
