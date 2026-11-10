"""ABI and bypass cases for the fixed signer filter; real kernel proof in Linux."""

import errno
import pytest
from azazel_edge.outcome.socket_boundary import program


def evaluate(machine, nr, family=1, arch=None):
    _, rules = program(machine)
    actual = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}[machine]
    data = {0: nr, 4: arch if arch is not None else actual, 16: family & 0xFFFFFFFF}
    pc = accumulator = 0
    while True:
        code, yes, no, value = rules[pc]
        if code == 0x20:
            accumulator = data[value]
        elif code == 0x15:
            pc += yes if accumulator == value else no
        elif code == 0x45:
            pc += yes if accumulator & value else no
        elif code == 0x06:
            return value
        else:
            raise AssertionError("unsupported filter opcode")
        pc += 1


@pytest.mark.parametrize(
    "machine,socket,pair", [("x86_64", 41, 53), ("aarch64", 198, 199)]
)
def test_only_unix_socket_creation_with_no_compat_or_uring_bypass(
    machine, socket, pair
):
    for call in [socket, pair]:
        assert evaluate(machine, call, 1) == 0x7FFF0000
        for family in [0, 2, 10, 16, 17, 40, 0xFFFFFFFF]:
            assert evaluate(machine, call, family) == 0x50000 | errno.EPERM
    for call in [425, 426, 427]:
        assert evaluate(machine, call) == 0x50000 | errno.EPERM
    assert evaluate(machine, socket, arch=0x40000003) == 0x80000000
    assert evaluate(machine, 1) == 0x7FFF0000
    if machine == "x86_64":
        assert evaluate(machine, socket | 0x40000000) == 0x50000 | errno.EPERM


def test_unknown_abi_refuses():
    with pytest.raises(OSError):
        program("unsupported")


@pytest.mark.parametrize("result", [-1, 12345])
def test_filter_installation_error_or_unsynchronized_thread_refuses(result):
    from unittest.mock import patch
    from types import SimpleNamespace
    from azazel_edge.outcome.socket_boundary import unix_only

    with (
        patch("sys.platform", "linux"),
        patch("os.uname", return_value=SimpleNamespace(machine="x86_64")),
        patch("ctypes.CDLL") as library,
    ):
        library.return_value.syscall.return_value = result
        with pytest.raises(OSError, match="filter unavailable"):
            unix_only()
