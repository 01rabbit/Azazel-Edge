"""The control daemon's real accept/handle path on a temporary control.sock,
in this process (Edge#471 stage 1 tests). The peer is this test process, so
its uid is the daemon's own and the peer table allows every action."""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT / "py", ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from azazel_edge_control import daemon as control_daemon  # noqa: E402


def short_tmpdir(prefix: str) -> Path:
    """AF_UNIX paths are limited (about 104 bytes on macOS)."""
    base = "/tmp" if os.path.isdir("/tmp") else None
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


class InProcessControlDaemon:
    def __init__(self, sot_path: Path, audit_path: Path):
        self.dir = short_tmpdir("azc")
        self.socket_path = self.dir / "control.sock"
        self.sot_path = sot_path
        self.audit_path = audit_path
        self._saved: dict = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._srv: socket.socket | None = None

    def __enter__(self) -> "InProcessControlDaemon":
        self._saved = {
            "SOT_AUDIT_LOG": control_daemon.SOT_AUDIT_LOG,
            "env": os.environ.get("AZAZEL_SOT_PATH"),
        }
        control_daemon.SOT_AUDIT_LOG = self.audit_path
        os.environ["AZAZEL_SOT_PATH"] = str(self.sot_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(self.socket_path))
        srv.listen(8)
        srv.settimeout(0.2)
        self._srv = srv

        def loop() -> None:
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                threading.Thread(target=control_daemon.handle_client, args=(conn, addr), daemon=True).start()

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(5)
        if self._srv is not None:
            self._srv.close()
        control_daemon.SOT_AUDIT_LOG = self._saved["SOT_AUDIT_LOG"]
        if self._saved["env"] is None:
            os.environ.pop("AZAZEL_SOT_PATH", None)
        else:
            os.environ["AZAZEL_SOT_PATH"] = self._saved["env"]
        shutil.rmtree(self.dir, ignore_errors=True)
