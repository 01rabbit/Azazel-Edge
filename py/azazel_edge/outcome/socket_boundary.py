"""Irreversible Unix-only signer socket creation, independent of parent unit.

Linux little-endian x86_64/aarch64 only; unknown ABI or unavailable filtering
refuses before key/writer access. No policy loading, listener or helper exec.
"""

import ctypes
import errno
import os
import sys
from .journal import OutcomeJournalError


def program(machine):
    # audit arch, socket, socketpair, seccomp syscall. No socketcall ABI admitted.
    abi = {"x86_64": (0xC000003E, 41, 53, 317), "aarch64": (0xC00000B7, 198, 199, 277)}
    if sys.byteorder != "little" or machine not in abi:
        raise OutcomeJournalError("Unix-only signer requires a supported Linux ABI")
    arch, socket_call, pair_call, seccomp_call = abi[machine]
    deny = 0x00050000 | errno.EPERM
    # BPF LD ABS, JEQ/JSET, RET. Offsets are struct seccomp_data nr/arch/args[0].
    rules = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, arch),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
    ]
    if machine == "x86_64":
        rules += [(0x45, 0, 1, 0x40000000), (0x06, 0, 0, deny)]  # no x32 ABI bypass
    # io_uring socket operations must not bypass the socket syscall checks.
    for number in (425, 426, 427):
        rules += [(0x15, 0, 1, number), (0x06, 0, 0, deny)]
    rules += [
        (0x15, 1, 0, socket_call),
        (0x15, 0, 3, pair_call),
        (0x20, 0, 0, 16),
        (0x15, 1, 0, 1),
        (0x06, 0, 0, deny),
        (0x06, 0, 0, 0x7FFF0000),
    ]
    return seccomp_call, rules


def unix_only():
    if sys.platform != "linux":
        raise OutcomeJournalError("Unix-only signer requires Linux")
    call, rules = program(os.uname().machine)

    class Filter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint),
        ]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]

    filters = (Filter * len(rules))(*(Filter(*rule) for rule in rules))
    value = Program(len(rules), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # SECCOMP_SET_MODE_FILTER + TSYNC. Any error/unsynchronized TID refuses.
    result = libc.syscall(
        ctypes.c_long(call), ctypes.c_ulong(1), ctypes.c_ulong(1), ctypes.byref(value)
    )
    if result != 0:
        raise OutcomeJournalError("Unix-only signer filter unavailable")
