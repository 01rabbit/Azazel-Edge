"""Fixed disposable SCM_RIGHTS credential controls, never observer acquisition.

Root setup only. Every target response is control_only; no actors start on import.
The creator exits before capture and the parent only retains/transfers its own FD.
"""

from contextlib import contextmanager
import array
import ctypes
import os
from pathlib import Path
import socket
import subprocess
import sys

from udp_payload_copy_lab import _COPY_HELPERS
from test_protected_ingress_linux import line

OWNER = 61002
_ALLOWED = {(OWNER, OWNER), (61003, 61003), (61003, OWNER), (OWNER, 61003)}
_CREATOR = r"""
import array,json,os,socket,struct,sys
transport=socket.socket(fileno=int(sys.argv[1]))
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0))
stat=open('/proc/self/stat').read();start=int(stat[stat.rfind(')')+2:].split()[19])
meta=dict(port=s.getsockname()[1],target=dict(pid=os.getpid(),start_ticks=start,uid=os.geteuid(),fd=s.fileno(),
 socket_inode=os.fstat(s.fileno()).st_ino,socket_cookie=struct.unpack('=Q',s.getsockopt(socket.SOL_SOCKET,57,8))[0],
 netns_cookie=struct.unpack('=Q',s.getsockopt(socket.SOL_SOCKET,71,8))[0]))
status={}
for row in open('/proc/self/status'):
 name,sep,value=row.partition(':')
 if sep and name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'):status[name]=value.strip()
if set(status)!={'CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'} or status['NoNewPrivs']!='1' or any(int(status[n],16) for n in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')):
 raise ValueError('creator capability/NNP guard failed')
r,e,saved=os.getresuid()
meta['creator_credentials']=dict(real_uid=r,effective_uid=e,saved_uid=saved,**status)
meta['control_only']=True
print(json.dumps(meta),flush=True)
if transport.sendmsg([b'F'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[s.fileno()]))])!=1:
 raise RuntimeError('short fixed descriptor transfer')
s.close();transport.close()
"""
_RECEIVER = (
    r"""
import array,ctypes,json,os,socket,struct,sys
from udp_copy_credential_lab import _identity, _ALLOWED
# Fixed Root setup executes FIRST; no socket/SCM read until split identities and
# zero capabilities are established. execve would otherwise collapse split UID.
requested=(int(sys.argv[2]),int(sys.argv[3]))
if os.getuid()!=0 or os.geteuid()!=0 or requested not in _ALLOWED:
 raise ValueError('fixed Root credential bootstrap required')
_identity(*requested)()
transport=socket.socket(fileno=int(sys.argv[1]));transport.settimeout(2)
message,anc,flags,peer=transport.recvmsg(1,socket.CMSG_SPACE(array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
fds=[]
for level,kind,data in anc:
 if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS:raise ValueError('unexpected ancillary metadata')
 values=array.array('i');values.frombytes(data);fds.extend(values)
if message!=b'F' or flags&(socket.MSG_CTRUNC|socket.MSG_TRUNC) or len(fds)!=1:
 for fd in fds:os.close(fd)
 raise ValueError('exact one descriptor required')
s=socket.socket(fileno=fds[0]);transport.close()

def credentials():
 fields={}
 for row in open('/proc/self/status'):
  name,sep,value=row.partition(':')
  if sep and name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'):fields[name]=value.strip()
 r,e,saved=os.getresuid()
 if set(fields)!={'CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'}:raise ValueError('capability metadata missing')
 if fields['NoNewPrivs']!='1' or any(int(fields[n],16) for n in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')):
  raise ValueError('receiver must have zero capabilities and NNP')
 return dict(real_uid=r,effective_uid=e,saved_uid=saved,**fields)
def socket_identity():
 return dict(inode=os.fstat(s.fileno()).st_ino,uid=os.fstat(s.fileno()).st_uid,
  cookie=struct.unpack('=Q',s.getsockopt(socket.SOL_SOCKET,57,8))[0],
  netns_cookie=struct.unpack('=Q',s.getsockopt(socket.SOL_SOCKET,71,8))[0])
"""
    + _COPY_HELPERS
    + r"""
try:
 print(json.dumps(dict(control_only=True,port=s.getsockname()[1],socket_identity=socket_identity(),
                       credentials=credentials(),receiver=receiver_context())),flush=True)
 for raw in sys.stdin:
  if len(raw)>1024:raise ValueError('fixed command byte bound')
  a=json.loads(raw)
  if a!={'op':'copy','mode':'iovec'}:raise ValueError('only fixed iovec copy control permitted')
  before=socket_identity();before_creds=credentials()
  result=copy_control('iovec')
  result.update(credentials=credentials(),socket_identity=socket_identity(),
                socket_identity_before=before,credentials_before=before_creds)
  print(json.dumps(result),flush=True)
finally:s.close()
"""
)


class _Header(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _Data(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_uint32) for name in ("effective", "permitted", "inheritable")
    ]


def _identity(real_uid, effective_uid):
    def setup():
        libc = ctypes.CDLL(None, use_errno=True)
        os.setgroups([])
        os.setresgid(real_uid, effective_uid, effective_uid)
        for cap in range(64):
            if libc.prctl(24, cap, 0, 0, 0) != 0 and ctypes.get_errno() != 22:
                raise OSError(ctypes.get_errno(), "target bounding drop")
        os.setresuid(real_uid, effective_uid, effective_uid)
        data = (_Data * 2)()
        if libc.capset(ctypes.byref(_Header(0x20080522, 0)), ctypes.byref(data)) != 0:
            raise OSError(ctypes.get_errno(), "target capset")
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "target NNP")

    return setup


def _launch(code, descriptor, real_uid, effective_uid):
    return subprocess.Popen(
        [sys.executable, "-u", "-c", code, str(descriptor)],
        pass_fds=(descriptor,),
        close_fds=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=_identity(real_uid, effective_uid),
    )


def _close_process(process):
    failure = None
    try:
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    except BaseException as exc:
        failure = exc
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                if stream is not None:
                    stream.close()
            except BaseException as exc:
                failure = failure or exc
    if failure is not None:
        raise failure


def _receive_fd(transport):
    received = []
    try:
        transport.settimeout(2)
        message, ancillary, flags, _ = transport.recvmsg(
            1, socket.CMSG_SPACE(array.array("i").itemsize), socket.MSG_CMSG_CLOEXEC
        )
        for level, kind, raw in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise ValueError("unexpected creator ancillary metadata")
            values = array.array("i")
            values.frombytes(raw)
            received.extend(values)
        if (
            message != b"F"
            or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
            or len(received) != 1
        ):
            raise ValueError("one exact creator FD required")
        result = socket.socket(fileno=received[0])
        received.clear()
        return result
    finally:
        for descriptor in received:
            os.close(descriptor)


class _TransferredSocket:
    def __init__(self, sock, metadata, creator_returncode):
        self._socket = sock
        self.metadata = metadata
        self.creator_reaped = True
        self.creator_returncode = creator_returncode

    @contextmanager
    def receiver(self, real_uid, effective_uid):
        if (
            type(real_uid) is not int
            or type(effective_uid) is not int
            or (real_uid, effective_uid) not in _ALLOWED
        ):
            raise ValueError("only four fixed credential controls are supported")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        process = None
        try:
            # No later exec occurs after the credential change. The fixed child
            # drops setup authority before constructing/reading its SCM socket.
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-u",
                    "-c",
                    _RECEIVER,
                    str(child.fileno()),
                    str(real_uid),
                    str(effective_uid),
                ],
                pass_fds=(child.fileno(),),
                close_fds=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=dict(
                    os.environ,
                    PYTHONPATH=os.pathsep.join(
                        [
                            str(Path(__file__).resolve().parent),
                            os.environ.get("PYTHONPATH", ""),
                        ]
                    ),
                ),
            )
            child.close()
            if (
                parent.sendmsg(
                    [b"F"],
                    [
                        (
                            socket.SOL_SOCKET,
                            socket.SCM_RIGHTS,
                            array.array("i", [self._socket.fileno()]),
                        )
                    ],
                )
                != 1
            ):
                raise RuntimeError("short receiver FD transfer")
            parent.close()
            ready = line(process)
            expected = self.metadata["target"]
            identity = ready["socket_identity"]
            if (
                identity
                != dict(
                    inode=expected["socket_inode"],
                    cookie=expected["socket_cookie"],
                    netns_cookie=expected["netns_cookie"],
                    uid=OWNER,
                )
                or ready["credentials"]["real_uid"] != real_uid
                or ready["credentials"]["effective_uid"] != effective_uid
                or ready["credentials"]["saved_uid"] != effective_uid
                or ready["receiver"]["pid"] == expected["pid"]
            ):
                raise RuntimeError(
                    "actual transferred identity/credentials differ: " + repr(ready)
                )
            yield process, ready
        finally:
            try:
                if process is not None:
                    _close_process(process)
            finally:
                parent.close()
                child.close()


@contextmanager
def transferred_socket():
    """Create fixed UID61002 socket, reap creator, retain same owned FD only."""
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("isolated Linux Root test setup required")
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    creator = sock = None
    try:
        creator = _launch(_CREATOR, child.fileno(), OWNER, OWNER)
        child.close()
        metadata = line(creator)
        sock = _receive_fd(parent)
        parent.close()
        creator.wait(timeout=2)
        if creator.returncode != 0:
            raise RuntimeError("original creator failed")
        _close_process(creator)
        creator = None
        yield _TransferredSocket(sock, metadata, 0)
    finally:
        try:
            if creator is not None:
                _close_process(creator)
        finally:
            if sock is not None:
                sock.close()
            parent.close()
            child.close()
