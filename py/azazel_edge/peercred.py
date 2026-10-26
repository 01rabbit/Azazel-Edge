"""Who is on the other end of a Unix socket (Edge#471).

``peer_credentials`` reads the peer's uid and pid from the kernel
(``SO_PEERCRED`` on Linux, ``LOCAL_PEERCRED``/``LOCAL_PEERPID`` on macOS for
development). It never trusts anything the peer sends. When the kernel
cannot say, the uid is ``None`` and every caller must refuse (fail closed).

``account_uid`` resolves a fixed account name to its uid; an account that
does not exist (or cannot be resolved) is ``None``, so a table keyed on it
grants nothing.
"""

from __future__ import annotations

import pwd
import socket
import struct
import sys
from typing import Optional, Tuple

# macOS <sys/un.h>: SOL_LOCAL, LOCAL_PEERCRED, LOCAL_PEERPID.
_SOL_LOCAL = 0
_LOCAL_PEERCRED = 0x001
_LOCAL_PEERPID = 0x002
_XUCRED_SIZE = 76  # u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]


def peer_credentials(conn: socket.socket) -> Tuple[Optional[int], Optional[int]]:
    """Return ``(uid, pid)`` of the connected peer, ``(None, None)`` if unknown."""
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is not None:
        try:
            raw = conn.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
            pid, uid, _gid = struct.unpack("3i", raw)
            if uid < 0:
                return None, None
            return uid, (pid if pid > 0 else None)
        except (OSError, struct.error):
            return None, None
    if sys.platform == "darwin":
        try:
            raw = conn.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, _XUCRED_SIZE)
            _version, uid = struct.unpack_from("=II", raw, 0)
        except (OSError, struct.error):
            return None, None
        pid: Optional[int] = None
        try:
            pid = struct.unpack("i", conn.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, 4))[0]
        except (OSError, struct.error):
            pid = None
        return uid, pid
    return None, None


def account_uid(name: str) -> Optional[int]:
    """uid of the fixed account ``name``, or ``None`` when it cannot be resolved."""
    try:
        return int(pwd.getpwnam(name).pw_uid)
    except (KeyError, OSError, ValueError, TypeError):
        return None
