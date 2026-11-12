"""Fixed actual owned-link FD fault worker; no sensor truth is synthesized.

Only the disposable worker's libbpf wrapper injects one close, selected by actual
owned stats. Clock, native events, signatures, identity and cleanup stay original.
No actor starts on import. fault_state is exclusively control_only harness data.
"""

WORKER = r"""
import ctypes,json,os,sys,time
from types import SimpleNamespace
from azazel_edge.benchmark.udp_payload_copy import capture_udp_payload_copy,UDPPayloadCopyError
from azazel_edge.benchmark import udp_payload_copy_bpf as p
from udp_payload_copy_data import KEY
class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
a=json.loads(sys.stdin.read());fault=a.pop('fault')
if fault not in {'before_first','entry','consume','exit','reuse'}:raise ValueError('unknown fixed owned-link fault')
libc=ctypes.CDLL(None,use_errno=True)
for cap in range(64):
 if cap in (38,39):continue
 if libc.prctl(24,cap,0,0,0)!=0 and ctypes.get_errno()!=22:raise OSError(ctypes.get_errno(),'bounding set')
h=Header(0x20080522,0);data=(Data*2)();data[1].effective=data[1].permitted=(1<<6|1<<7)
if libc.capset(ctypes.byref(h),ctypes.byref(data))!=0:raise OSError(ctypes.get_errno(),'capset')
if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'NNP')
# Assert the ACTUAL unchanged product role before installing any test wrapper.
p._role()
names=('copy_entry','copy_consume','copy_exit')
selected={'before_first':'copy_entry','entry':'copy_entry','consume':'copy_consume','exit':'copy_exit','reuse':'copy_entry'}[fault]
state=dict(control_only=True,fault_applied=False,attach_calls=0,link=selected,
 trigger='before_first' if fault=='before_first' else 'accepted_at_least_one',
 accepted_at_fault=None,fd_reused=False,replacement_alive=None,
 original_link_fds={},destroy_calls=dict.fromkeys(names,0),disconnect_calls=dict.fromkeys(names,0))
cache={};pointers={};replacement=None;replacement_identity=None;backend=None
original_factory=p._Libbpf;original_time=p.time;real_sleep=time.sleep

def identity(fd):
 s=os.fstat(fd)
 return (s.st_dev,s.st_ino,s.st_mode,s.st_rdev)

class Library:
 def __init__(self,original):self.original=original
 def __getattr__(self,name):return getattr(self.original,name)
 def bpf_map__fd(self,value):
  fd=self.original.bpf_map__fd(value)
  if fd>=0:cache[self.original.bpf_map__name(value).decode('ascii')]=fd
  return fd
 def bpf_program__attach(self,program):
  pointer=self.original.bpf_program__attach(program)
  if pointer and self.original.libbpf_get_error(pointer)==0:
   name=self.original.bpf_program__name(program).decode('ascii')
   if name not in names or name in state['original_link_fds']:raise RuntimeError('unexpected original attachment')
   fd=self.original.bpf_link__fd(pointer)
   if fd<0:raise RuntimeError('owned link FD unavailable')
   cache[name]=fd;pointers[pointer]=name
   state['original_link_fds'][name]=fd;state['attach_calls']+=1
  return pointer
 def bpf_link__disconnect(self,pointer):
  if pointer not in pointers:raise RuntimeError('unowned disconnect pointer')
  state['disconnect_calls'][pointers[pointer]]+=1
  return self.original.bpf_link__disconnect(pointer)
 def bpf_link__destroy(self,pointer):
  if pointer not in pointers:raise RuntimeError('unowned destroy pointer')
  state['destroy_calls'][pointers[pointer]]+=1
  # Do not suppress or simulate native cleanup, including native error returns.
  return self.original.bpf_link__destroy(pointer)

def factory():
 global backend
 if backend is not None:raise RuntimeError('unexpected observer reload')
 backend=original_factory();backend.lib=Library(backend.lib);return backend

def fault_sleep(seconds):
 global replacement,replacement_identity
 if not state['fault_applied'] and state['attach_calls']==3 and 'stats' in cache:
  count=p.Counters();zero=ctypes.c_uint32(0)
  code=backend.lib.bpf_map_lookup_elem(cache['stats'],ctypes.byref(zero),ctypes.byref(count))
  if code!=0:raise RuntimeError('own stats fault-trigger lookup failed')
  if fault=='before_first' or count.accepted>=1:
   if fault=='before_first' and count.accepted!=0:raise RuntimeError('unexpected positive before first fault')
   fd=cache[selected]
   # Close only our OWN actual FD. The libbpf pointer remains owned and alive.
   os.close(fd);state['fault_applied']=True;state['accepted_at_fault']=count.accepted
   if fault=='reuse':
    replacement=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC)
    if replacement!=fd:
     try:os.dup2(replacement,fd,inheritable=False)
     finally:os.close(replacement)
     replacement=fd
    replacement_identity=identity(replacement);state['fd_reused']=True
 real_sleep(seconds)

p._Libbpf=factory
p.time=SimpleNamespace(monotonic_ns=time.monotonic_ns,sleep=fault_sleep)
try:
 report=capture_udp_payload_copy(a.pop('contract').encode(),a.pop('plan').encode(),observer_private_key=KEY,**a)
 if not state['fault_applied'] or state['attach_calls']!=3:raise RuntimeError('fixed fault was not established')
 if replacement is not None:
  try:state['replacement_alive']=identity(replacement)==replacement_identity
  except OSError:state['replacement_alive']=False
  if not state['replacement_alive']:raise RuntimeError('owned replacement was closed or changed')
 print(json.dumps(dict(report=report.decode(),fault_state=state)),flush=True)
except (UDPPayloadCopyError,RuntimeError,OSError) as exc:
 print(json.dumps(dict(rejected=True,reason=str(exc),fault_state=state)),flush=True)
finally:
 p._Libbpf=original_factory;p.time=original_time
 if replacement is not None:
  # Close ONLY the still-confirmed harness replacement, never an unknown reuse.
  try:
   if identity(replacement)==replacement_identity:os.close(replacement)
  except OSError:pass
"""
