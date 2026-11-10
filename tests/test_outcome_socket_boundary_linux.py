"""Actual non-root kernel socket restriction without parent family filtering."""

import os
import subprocess
import sys
import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0, reason="isolated Linux root needed"
)


def test_signer_filter_blocks_netlink_even_when_the_parent_allows_it():
    script = """
import ctypes,errno,os,socket,threading
from azazel_edge.outcome.input_live import harden_receiver
# Prove unprivileged NETLINK_ROUTE creation works before our restriction.
s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,0);s.close()
ready=threading.Event();go=threading.Event();result=[]
def other_thread():
 s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,0);s.close();ready.set();go.wait()
 try: socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,0)
 except OSError as e: result.append(e.errno)
thread=threading.Thread(target=other_thread);thread.start();ready.wait()
harden_receiver(os.getuid());go.set();thread.join();assert result==[errno.EPERM]
for family,kind in [(socket.AF_NETLINK,socket.SOCK_RAW),(socket.AF_INET,socket.SOCK_STREAM),(socket.AF_INET6,socket.SOCK_STREAM)]:
 try: socket.socket(family,kind,0)
 except OSError as e: assert e.errno==errno.EPERM
 else: raise AssertionError('forbidden socket allowed')
a,b=socket.socketpair();a.sendall(b'ok');assert b.recv(2)==b'ok';a.close();b.close()
assert ctypes.CDLL(None,use_errno=True).syscall(425,0,0)==-1
assert ctypes.get_errno()==errno.EPERM
print('unix-only')
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        user=61001,
        group=61001,
        extra_groups=[],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "unix-only"
