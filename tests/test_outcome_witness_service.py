"""Readiness is local metadata, emitted only by an explicitly opted-in witness."""

import os
from pathlib import Path
import socket
import tempfile

import pytest

from azazel_edge.outcome.input_witness import SystemdReady


@pytest.mark.parametrize(
    "address", ["", "relative", "vsock:2:1", "/x\nREADY=1", "/" + "x" * 108]
)
def test_notify_requires_an_explicit_bounded_local_address(monkeypatch, address):
    monkeypatch.setenv("NOTIFY_SOCKET", address)
    with pytest.raises(OSError):
        SystemdReady()


def test_readiness_is_one_local_datagram_without_evidence(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="ew-", dir="/tmp") as tmp:
        address = str(Path(tmp) / "notify")
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as listener:
            listener.bind(address)
            listener.settimeout(1)
            monkeypatch.setenv("NOTIFY_SOCKET", address)
            SystemdReady().set()
            assert listener.recv(128) == b"READY=1"


def test_absent_manager_does_not_report_success(monkeypatch):
    monkeypatch.setenv("NOTIFY_SOCKET", "/nonexistent/edge400-notify")
    with pytest.raises(OSError):
        SystemdReady().set()


@pytest.mark.skipif(
    not hasattr(socket, "SO_PEERCRED"), reason="Linux abstract namespace"
)
def test_abstract_manager_address(monkeypatch):
    address = "edge400-notify-" + str(os.getpid())
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as listener:
        listener.bind("\x00" + address)
        listener.settimeout(1)
        monkeypatch.setenv("NOTIFY_SOCKET", "@" + address)
        SystemdReady().set()
        assert listener.recv(128) == b"READY=1"
