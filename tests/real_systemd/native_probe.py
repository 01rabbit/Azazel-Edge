"""Independent same-root policy controls; never a provider execution probe."""

import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

assert sys.argv[1:] in ([], ["--provider"], ["--tc"])
profile = {"--provider": "edge400-provider", "--tc": "edge400-tc"}.get(
    sys.argv[1] if len(sys.argv) > 1 else "", "edge400-native"
)
lib = ctypes.CDLL("libapparmor.so.1", use_errno=True)
assert lib.aa_change_profile(profile.encode()) == 0
assert (
    Path("/proc/self/attr/apparmor/current").read_text().strip()
    == profile + " (enforce)"
)
denied = []


def expect(name, operation):
    try:
        operation()
    except OSError as exc:
        assert exc.errno in (errno.EACCES, errno.EPERM, errno.EAFNOSUPPORT), (
            name,
            exc.errno,
        )
        denied.append(name)
    else:
        raise AssertionError(name + " unexpectedly allowed")


base = Path("/var/lib/edge400-systemd-lab")
for name in [
    "aa-denied",
    "bundle/producer/key.raw",
    "bundle/witness/key.raw",
    "bundle/input",
    "bundle/observer/observations.journal",
]:
    expect(name, lambda name=name: os.open(base / name, os.O_RDONLY))
expect("unexpected-exec", lambda: subprocess.run(["/usr/bin/true"], check=True))
expect("uid-switch", lambda: os.setuid(61003))
expect(
    "profile-escape",
    lambda: Path("/proc/self/attr/apparmor/current").write_text(
        "changeprofile unconfined"
    ),
)
expect(
    "systemd-control",
    lambda: socket.socket(socket.AF_UNIX).connect("/run/systemd/private"),
)
if profile == "edge400-provider":
    for family, kind in [
        (socket.AF_INET, socket.SOCK_STREAM),
        (socket.AF_NETLINK, socket.SOCK_RAW),
    ]:
        allowed = socket.socket(family, kind)
        allowed.close()
else:
    if profile == "edge400-tc":
        allowed = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW)
        allowed.close()
    expect("inet", lambda: socket.socket(socket.AF_INET))
expect("inet6", lambda: socket.socket(socket.AF_INET6))
print(json.dumps(dict(uid=os.getuid(), profile=profile + " (enforce)", denied=denied)))
