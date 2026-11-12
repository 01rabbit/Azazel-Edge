"""Target-owned socket reads and buffer controls, NEVER observer memory access.

No process starts at import. These reports are target-claimed control facts, not
BPF evidence or application receipt. The legacy queue target protocol stays intact.
"""

from test_udp_queue_linux import TARGET_WORKER as _QUEUE_TARGET_WORKER

_COPY_HELPERS = r"""
import errno,threading

def receiver_context():
 p=os.stat('/proc/self/ns/pid');n=os.stat('/proc/self/ns/net')
 return dict(pid=os.getpid(),tid=threading.get_native_id(),ruid=os.getuid(),euid=os.geteuid(),
             pid_namespace=dict(device=p.st_dev,inode=p.st_ino),
             network_namespace=dict(device=n.st_dev,inode=n.st_ino))

def copy_control(mode):
 allowed={'python','iovec','ubuf','peek','short','trunc','copyfault','namefault'}
 if mode not in allowed:raise ValueError('unknown fixed target operation')
 context=receiver_context()
 if mode=='python':
  try:
   data,anc,flags,peer=s.recvmsg(64,0,socket.MSG_DONTWAIT)
   return dict(control_only=True,mode=mode,receiver=context,ret=len(data),errno=0,
               payload_hex=data.hex(),flags=flags,peer=list(peer))
  except OSError as exc:
   return dict(control_only=True,mode=mode,receiver=context,ret=-1,errno=exc.errno,payload_hex='')
 if not sys.platform.startswith('linux') or ctypes.sizeof(ctypes.c_void_p)!=8:
  return dict(control_only=True,mode=mode,receiver=context,unavailable='linux64-msghdr-ABI-required')
 class IOVec(ctypes.Structure):
  _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
 class MsgHdr(ctypes.Structure):
  _fields_=[('name',ctypes.c_void_p),('namelen',ctypes.c_uint),
            ('iov',ctypes.POINTER(IOVec)),('iovlen',ctypes.c_size_t),
            ('control',ctypes.c_void_p),('controllen',ctypes.c_size_t),('flags',ctypes.c_int)]
 if (ctypes.sizeof(IOVec),ctypes.sizeof(MsgHdr),MsgHdr.iov.offset,MsgHdr.flags.offset)!=(16,56,16,48):
  return dict(control_only=True,mode=mode,receiver=context,unavailable='unsupported-msghdr-layout')
 libc=ctypes.CDLL(None,use_errno=True)
 libc.recvfrom.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
 libc.recvfrom.restype=ctypes.c_ssize_t
 libc.recvmsg.argtypes=[ctypes.c_int,ctypes.POINTER(MsgHdr),ctypes.c_int]
 libc.recvmsg.restype=ctypes.c_ssize_t
 size=8 if mode in {'short','trunc'} else 64
 buf=ctypes.create_string_buffer(size);flags=socket.MSG_DONTWAIT
 if mode=='peek':flags|=socket.MSG_PEEK
 if mode=='trunc':flags|=socket.MSG_TRUNC
 ctypes.set_errno(0)
 if mode=='ubuf':
  result=libc.recvfrom(s.fileno(),ctypes.addressof(buf),size,flags,None,None);msgflags=0
 else:
  iov=IOVec(1 if mode=='copyfault' else ctypes.addressof(buf),size)
  msg=MsgHdr();msg.iov=ctypes.pointer(iov);msg.iovlen=1
  if mode=='namefault':msg.name=1;msg.namelen=16
  result=libc.recvmsg(s.fileno(),ctypes.byref(msg),flags);msgflags=msg.flags
 error=ctypes.get_errno() if result<0 else 0
 # The receiver examines ONLY its own buffer. Never read ptr1 or another process.
 valid_buffer=mode!='copyfault'
 return dict(control_only=True,mode=mode,receiver=context,ret=result,errno=error,
             payload_hex=bytes(buf.raw).hex() if valid_buffer else None,
             flags=msgflags,buffer_capacity=size)

def inherited_control(mode):
 # Parent retains the original socket/locator. Child has same UID and same socket,
 # but its independently reported receiver PID/TID differs. Nonblocking read only.
 readfd,writefd=os.pipe();child=os.fork()
 if child==0:
  os.close(readfd)
  try:
   result=copy_control(mode)
   raw=json.dumps(result).encode()
   if len(raw)>4096:raise ValueError('bounded target control result')
   if os.write(writefd,raw)!=len(raw):raise OSError('short target pipe write')
  finally:
   os.close(writefd);s.close();os._exit(0)
 os.close(writefd)
 try:
  raw=b''
  while True:
   part=os.read(readfd,4097-len(raw))
   if not part:break
   raw+=part
   if len(raw)>4096:raise ValueError('target control result overflow')
 finally:
  os.close(readfd);waited,status=os.waitpid(child,0)
 if waited!=child or status!=0:raise RuntimeError('owned receiver child failed')
 return dict(control_only=True,inherited_socket=True,locator_pid=os.getpid(),
             receiver_child_pid=child,receiver_child_reaped=True,result=json.loads(raw))
"""

_COPY_COMMANDS = r"""
 elif a['op']=='copy':
  print(json.dumps(copy_control(a['mode'])),flush=True)
 elif a['op']=='inherit_receive':
  print(json.dumps(inherited_control(a.get('mode','iovec'))),flush=True)
"""

_READY = "\nprint(json.dumps(metadata()),flush=True)\n"
_REPLACE = " elif a['op']=='replace':"
if _QUEUE_TARGET_WORKER.count(_READY) != 1 or _QUEUE_TARGET_WORKER.count(_REPLACE) != 1:
    raise RuntimeError("legacy target worker shape changed: review fixed copy harness")
COPY_TARGET_WORKER = _QUEUE_TARGET_WORKER.replace(
    _READY, _COPY_HELPERS + _READY
).replace(_REPLACE, _COPY_COMMANDS + _REPLACE)
