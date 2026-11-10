"""Offline Unix witness. Separate UID owns signing key and durable anchor log.

The witness attests append-only byte prefixes, not Outcome truth or authority.
No command, arbitrary request path, IP listener, repair, reset or rotation.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import struct
import threading

from .input_auth import (
    TrustPolicy,
    SourceVerifier,
    hex_bytes,
    private_key,
    sign,
    verify_signature,
    read_regular,
    open_parent,
)
from .journal import OutcomeJournalError, _json, _parse, ZERO_HASH

ANCHOR_DOMAIN = b"azazel-edge:input-witness-anchor:v1\x00"
RESPONSE_DOMAIN = b"azazel-edge:input-witness-response:v1\x00"
STATE_FIELDS = {
    "journal_seq",
    "journal_head",
    "journal_size",
    "journal_sha256",
    "journal_device",
    "journal_inode",
    "source_seq",
    "source_head",
    "source_size",
    "source_sha256",
}
MESSAGE_BYTES = 8192


def digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


def validate_state(state):
    if type(state) is not dict or set(state) != STATE_FIELDS:
        raise OutcomeJournalError("invalid witness state")
    for name, value in state.items():
        if name.endswith(("head", "sha256")):
            hex_bytes(value, 32)
        elif type(value) is not int or not 0 <= value < 2**64:
            raise OutcomeJournalError("invalid witness state bound")
    return dict(state)


class WitnessStore:
    """One explicitly initialized protected log, locked for witness lifetime."""

    def __init__(self, policy, key_path, *, initialize=False):
        p = policy.data
        if os.geteuid() != p["witness_uid"]:
            raise OutcomeJournalError("witness uid required")
        self.policy = policy
        self.key = private_key(key_path, p["witness_public_key"])
        self.source = SourceVerifier(policy)
        self.fd = self.parent = None
        self.counter = 0
        self.head = ZERO_HASH
        self.state = None
        self.size = 0
        self.poisoned = False
        self.anchor_digest = hashlib.sha256()
        try:
            self.parent, _ = open_parent(
                Path(p["anchor_directory"]) / "anchors.journal",
                trusted_owner=p["witness_uid"],
            )
            info = os.fstat(self.parent)
            if info.st_uid != p["witness_uid"] or stat.S_IMODE(info.st_mode) != 0o700:
                raise OutcomeJournalError(
                    "witness anchor directory must be private and owned by witness"
                )
            if initialize and os.listdir(self.parent):
                raise OutcomeJournalError(
                    "witness initialization requires empty anchor directory"
                )
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if initialize:
                flags |= os.O_CREAT | os.O_EXCL
            self.fd = os.open("anchors.journal", flags, 0o600, dir_fd=self.parent)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.inode = os.fstat(self.fd)
            self._namespace()
            if initialize:
                source_data, tip = self._source()
                journal_data, j = self._journal(source_data)
                if source_data or journal_data:
                    raise OutcomeJournalError(
                        "new witness requires empty source and journal"
                    )
                self._append(self._state(tip, j))
                os.fsync(self.parent)
            else:
                self._load()
                os.fsync(self.fd)
                os.fsync(self.parent)
        except BaseException:
            self.close()
            raise

    def _namespace(self):
        check, _ = open_parent(
            Path(self.policy.data["anchor_directory"]) / "anchors.journal",
            trusted_owner=self.policy.data["witness_uid"],
        )
        try:
            current = os.fstat(check)
            pinned = os.fstat(self.parent)
            if (
                (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino)
                or current.st_uid != os.geteuid()
                or stat.S_IMODE(current.st_mode) != 0o700
            ):
                raise OutcomeJournalError(
                    "witness anchor directory identity/permissions changed"
                )
        finally:
            os.close(check)
        a = os.stat("anchors.journal", dir_fd=self.parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(a.st_mode)
            or a.st_uid != os.geteuid()
            or stat.S_IMODE(a.st_mode) != 0o600
            or a.st_nlink != 1
            or (a.st_dev, a.st_ino) != (self.inode.st_dev, self.inode.st_ino)
        ):
            raise OutcomeJournalError("witness anchor namespace unsafe")

    def _load(self):
        p = self.policy.data
        size = os.fstat(self.fd).st_size
        if not 0 < size <= p["anchor_max_bytes"]:
            raise OutcomeJournalError("witness retention invalid")
        raw = bytearray()
        while len(raw) <= p["anchor_max_bytes"]:
            part = os.read(self.fd, min(65536, p["anchor_max_bytes"] + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        if (
            len(raw) != size
            or not raw.endswith(b"\n")
            or raw.count(b"\n") > p["anchor_max_records"]
        ):
            raise OutcomeJournalError("witness incomplete/oversized; no repair")
        for line in raw.splitlines(keepends=True):
            if len(line) > MESSAGE_BYTES:
                raise OutcomeJournalError("witness frame oversized")
            wire = _parse(line)
            if type(wire) is not dict or set(wire) != {
                "schema_version",
                "counter",
                "prev",
                "trust_sha256",
                "state",
                "signature",
            }:
                raise OutcomeJournalError("witness frame invalid")
            core = {k: v for k, v in wire.items() if k != "signature"}
            if (
                wire["schema_version"] != "outcome-input-anchor/v1"
                or type(wire["counter"]) is not int
                or wire["counter"] != self.counter + 1
                or wire["prev"] != self.head
                or wire["trust_sha256"] != self.policy.digest
            ):
                raise OutcomeJournalError("witness chain/context invalid")
            verify_signature(
                p["witness_public_key"], wire["signature"], ANCHOR_DOMAIN, core
            )
            state = validate_state(wire["state"])
            if self.state and (
                state["journal_seq"] != self.state["journal_seq"] + 1
                or state["source_seq"] < self.state["source_seq"]
            ):
                raise OutcomeJournalError("witness progression invalid")
            if self.state is None and (state["journal_seq"] or state["source_seq"]):
                raise OutcomeJournalError("witness genesis invalid")
            self.state = state
            self.counter += 1
            self.head = digest(wire)
        self.size = size
        self.anchor_digest = hashlib.sha256(raw)
        self._namespace()

    def _check_backing(self, *, size=None, expected=None):
        try:
            self._namespace()
            size = self.size if size is None else size
            expected = self.anchor_digest.hexdigest() if expected is None else expected
            if os.fstat(self.fd).st_size != size:
                raise OutcomeJournalError("witness backing length changed")
            h = hashlib.sha256()
            offset = 0
            while offset < size:
                part = os.pread(self.fd, min(65536, size - offset), offset)
                if not part:
                    raise OutcomeJournalError("witness backing truncated")
                h.update(part)
                offset += len(part)
            if h.hexdigest() != expected:
                raise OutcomeJournalError("witness backing integrity changed")
        except BaseException:
            self.poisoned = True
            raise

    def _append(self, state):
        p = self.policy.data
        if self.poisoned or self.counter >= p["anchor_max_records"]:
            raise OutcomeJournalError("witness unavailable/capacity exhausted")
        core = dict(
            schema_version="outcome-input-anchor/v1",
            counter=self.counter + 1,
            prev=self.head,
            trust_sha256=self.policy.digest,
            state=validate_state(state),
        )
        wire = {**core, "signature": sign(self.key, ANCHOR_DOMAIN, core)}
        line = _json(wire) + b"\n"
        if self.size + len(line) > p["anchor_max_bytes"] or len(line) > MESSAGE_BYTES:
            raise OutcomeJournalError("witness byte capacity exhausted")
        try:
            self._check_backing()
            if os.fstat(self.fd).st_size != self.size:
                raise OutcomeJournalError("witness changed outside writer")
            os.lseek(self.fd, 0, os.SEEK_END)
            view = memoryview(line)
            while view:
                n = os.write(self.fd, view)
                if n <= 0:
                    raise OutcomeJournalError("witness short write")
                view = view[n:]
            os.fsync(self.fd)
            next_digest = self.anchor_digest.copy()
            next_digest.update(line)
            self._check_backing(
                size=self.size + len(line), expected=next_digest.hexdigest()
            )
            self.anchor_digest = next_digest
            self.size += len(line)
            self.counter += 1
            self.head = digest(wire)
            self.state = dict(state)
        except BaseException:
            self.poisoned = True
            raise

    def _source(self):
        p = self.policy.data
        data, _ = read_regular(
            p["source_path"], owner=p["producer_uid"], max_bytes=p["input_max_bytes"]
        )
        end = data.rfind(b"\n") + 1
        if len(data) - end > 65536:
            raise OutcomeJournalError("source partial frame oversized")
        data = data[:end]
        tip = self.source.verify(data)
        if self.state:
            n = self.state["source_size"]
            if (
                len(data) < n
                or hashlib.sha256(data[:n]).hexdigest() != self.state["source_sha256"]
                or tip["seq"] < self.state["source_seq"]
            ):
                raise OutcomeJournalError("source behind protected witness")
        return data, tip

    def _journal(self, source_data):
        p = self.policy.data
        data, info = read_regular(
            Path(p["journal_directory"]) / "observations.journal",
            owner=p["observer_uid"],
            max_bytes=p["journal_max_bytes"],
            mode=0o600,
            missing=True,
        )
        if data and not data.endswith(b"\n"):
            raise OutcomeJournalError("journal incomplete; no witness acknowledgement")
        if data.count(b"\n") > 131072:
            raise OutcomeJournalError("journal frame bound exhausted")
        seq = 0
        head = ZERO_HASH
        for line in data.splitlines(keepends=True):
            if len(line) > 65536:
                raise OutcomeJournalError("journal frame oversized")
            frame = _parse(line)
            if type(frame) is not dict or set(frame) != {
                "seq",
                "prev",
                "kind",
                "data",
                "sha256",
            }:
                raise OutcomeJournalError("journal frame invalid")
            core = {k: v for k, v in frame.items() if k != "sha256"}
            if (
                type(frame["seq"]) is not int
                or frame["seq"] != seq + 1
                or frame["prev"] != head
                or digest(core) != frame["sha256"]
            ):
                raise OutcomeJournalError("journal chain invalid")
            if frame["kind"] not in (
                "header",
                "session_open",
                "session_close",
                "session_recovered",
                "begin",
                "lost",
                "commit",
                "cursor",
                "input_ready",
                "seal",
            ):
                raise OutcomeJournalError("unknown witnessed journal transition")
            if seq == 0:
                header = frame["data"]
                if (
                    frame["kind"] != "header"
                    or type(header) is not dict
                    or header.get("schema_version") != "outcome-observation-journal/v3"
                    or header.get("scope_ref") != p["scope_ref"]
                    or header.get("max_bytes") != p["journal_max_bytes"]
                    or header.get("input_config", {}).get("authentication")
                    != self.policy.binding()
                ):
                    raise OutcomeJournalError("journal authentication context mismatch")
            elif frame["kind"] == "header":
                raise OutcomeJournalError("duplicate journal header")
            if frame["kind"] in ("cursor", "input_ready"):
                pos = (
                    frame["data"]["position"]
                    if frame["kind"] == "cursor"
                    else frame["data"]
                )
                if (
                    type(pos) is not dict
                    or set(pos) != {"offset", "sha256"}
                    or type(pos["offset"]) is not int
                    or not 0 <= pos["offset"] <= len(source_data)
                ):
                    raise OutcomeJournalError("witnessed cursor invalid")
                n = pos["offset"]
                if (n and source_data[n - 1 : n] != b"\n") or hashlib.sha256(
                    source_data[:n]
                ).hexdigest() != pos["sha256"]:
                    raise OutcomeJournalError(
                        "witnessed cursor not present in authenticated source"
                    )
            seq += 1
            head = frame["sha256"]
        j = dict(
            seq=seq,
            head=head,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            device=info.st_dev if info else 0,
            inode=info.st_ino if info else 0,
        )
        if self.state:
            s = self.state
            n = s["journal_size"]
            if (
                len(data) < n
                or hashlib.sha256(data[:n]).hexdigest() != s["journal_sha256"]
            ):
                raise OutcomeJournalError("journal rewound or rewritten behind witness")
            if s["journal_seq"] and (j["device"], j["inode"]) != (
                s["journal_device"],
                s["journal_inode"],
            ):
                raise OutcomeJournalError("journal identity differs from witness")
        return data, j

    @staticmethod
    def _state(tip, j):
        return dict(
            journal_seq=j["seq"],
            journal_head=j["head"],
            journal_size=j["size"],
            journal_sha256=j["sha256"],
            journal_device=j["device"],
            journal_inode=j["inode"],
            source_seq=tip["seq"],
            source_head=tip["head"],
            source_size=tip["size"],
            source_sha256=tip["sha256"],
        )

    def request(self, request):
        if self.poisoned:
            raise OutcomeJournalError("witness poisoned")
        self._check_backing()
        if (
            type(request) is not dict
            or set(request) != {"op", "nonce", "counter", "anchor_head"}
            or request["op"] not in ("read", "advance")
        ):
            raise OutcomeJournalError("invalid witness request")
        hex_bytes(request["nonce"], 32)
        hex_bytes(request["anchor_head"], 32)
        if type(request["counter"]) is not int or request["counter"] < 0:
            raise OutcomeJournalError("invalid witness counter")
        source, tip = self._source()
        _, j = self._journal(source)
        if request["op"] == "read":
            if (j["seq"], j["head"], j["size"]) != (
                self.state["journal_seq"],
                self.state["journal_head"],
                self.state["journal_size"],
            ):
                raise OutcomeJournalError(
                    "journal/witness commit gap; automatic resume refused"
                )
        else:
            if (
                request["counter"] != self.counter
                or request["anchor_head"] != self.head
                or j["seq"] != self.state["journal_seq"] + 1
            ):
                raise OutcomeJournalError("witness compare-and-advance conflict")
            self._append(self._state(tip, j))
        core = dict(
            schema_version="outcome-input-witness-response/v1",
            trust_sha256=self.policy.digest,
            op=request["op"],
            nonce=request["nonce"],
            counter=self.counter,
            anchor_head=self.head,
            state=dict(self.state),
        )
        return {**core, "signature": sign(self.key, RESPONSE_DOMAIN, core)}

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent is not None:
            os.close(self.parent)
            self.parent = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def recv_message(conn):
    def exact(n):
        result = bytearray()
        while len(result) < n:
            part = conn.recv(n - len(result))
            if not part:
                raise OutcomeJournalError("incomplete witness message")
            result.extend(part)
        return bytes(result)

    size = struct.unpack("!I", exact(4))[0]
    if not 0 < size <= MESSAGE_BYTES:
        raise OutcomeJournalError("witness message bound exceeded")
    return _parse(exact(size))


def send_message(conn, value):
    data = _json(value)
    if len(data) > MESSAGE_BYTES:
        raise OutcomeJournalError("witness response bound exceeded")
    conn.sendall(struct.pack("!I", len(data)) + data)


def peer_uid(conn):
    if not hasattr(socket, "SO_PEERCRED"):
        raise OutcomeJournalError("Linux peer credentials required")
    return struct.unpack(
        "3i",
        conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
    )[1]


class WitnessClient:
    def __init__(self, policy):
        if os.geteuid() != policy.data["observer_uid"]:
            raise OutcomeJournalError("observer uid required")
        self.policy = policy
        self.counter = 0
        self.head = ZERO_HASH
        self.state = None

    def accept(self, response, request):
        fields = {
            "schema_version",
            "trust_sha256",
            "op",
            "nonce",
            "counter",
            "anchor_head",
            "state",
            "signature",
        }
        if type(response) is not dict or set(response) != fields:
            raise OutcomeJournalError("invalid witness reply")
        core = {k: v for k, v in response.items() if k != "signature"}
        if (
            response["schema_version"] != "outcome-input-witness-response/v1"
            or response["trust_sha256"] != self.policy.digest
            or response["op"] != request["op"]
            or response["nonce"] != request["nonce"]
            or type(response["counter"]) is not int
            or not 1 <= response["counter"] <= self.policy.data["anchor_max_records"]
        ):
            raise OutcomeJournalError("witness freshness/context mismatch")
        verify_signature(
            self.policy.data["witness_public_key"],
            response["signature"],
            RESPONSE_DOMAIN,
            core,
        )
        state = validate_state(response["state"])
        hex_bytes(response["anchor_head"], 32)
        if request["op"] == "advance" and response["counter"] != self.counter + 1:
            raise OutcomeJournalError("witness acknowledgement out of order")
        if response["counter"] < self.counter:
            raise OutcomeJournalError("witness counter moved backwards")
        self.counter = response["counter"]
        self.head = response["anchor_head"]
        self.state = state
        return state

    def call(self, op):
        p = self.policy.data
        parent, name = open_parent(p["socket_path"], trusted_owner=p["witness_uid"])
        try:
            parent_info = os.fstat(parent)
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                parent_info.st_uid != p["witness_uid"]
                or parent_info.st_mode & 0o022
                or not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != p["witness_uid"]
            ):
                raise OutcomeJournalError("witness endpoint ownership unsafe")
        finally:
            os.close(parent)
        req = dict(
            op=op,
            nonce=secrets.token_hex(32),
            counter=self.counter,
            anchor_head=self.head,
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(1.0)
            conn.connect(p["socket_path"])
            if peer_uid(conn) != p["witness_uid"]:
                raise OutcomeJournalError("witness peer uid mismatch")
            send_message(conn, req)
            response = recv_message(conn)
        return self.accept(response, req)

    def preflight(self, seq, head, size):
        state = self.call("read")
        if (state["journal_seq"], state["journal_head"], state["journal_size"]) != (
            seq,
            head,
            size,
        ):
            raise OutcomeJournalError(
                "journal behind protected witness; resume refused"
            )

    def advance(self, seq, head, size):
        state = self.call("advance")
        if (state["journal_seq"], state["journal_head"], state["journal_size"]) != (
            seq,
            head,
            size,
        ):
            raise OutcomeJournalError(
                "witness did not acknowledge the exact journal head"
            )


class InputAuthentication:
    def __init__(self, policy):
        self.policy = policy
        self.verifier = SourceVerifier(policy)
        self.client = WitnessClient(policy)

    def binding(self):
        return self.policy.binding()

    def verify(self, data):
        tip = self.verifier.verify(data)
        state = self.client.state
        if state:
            n = state["source_size"]
            if (
                len(data) < n
                or hashlib.sha256(data[:n]).hexdigest() != state["source_sha256"]
                or tip["seq"] < state["source_seq"]
            ):
                raise OutcomeJournalError("source behind protected witness")

    def unwrap(self, line):
        return SourceVerifier.unwrap(line)

    def preflight(self, seq, head, size):
        self.client.preflight(seq, head, size)
        self.verify(self.verifier.raw)

    def advance(self, seq, head, size):
        self.client.advance(seq, head, size)


def retire_stale_endpoint(policy, parent, name):
    """Only after the protected store is verified and exclusively locked.

    A socket inode can survive process/OS death. Never remove evidence, a live
    endpoint, a non-socket, or another owner's namespace to make startup work.
    """
    try:
        old = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(old.st_mode) or old.st_uid != policy.data["witness_uid"]:
        raise OutcomeJournalError("untrusted witness endpoint; no cleanup")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        try:
            probe.connect(policy.data["socket_path"])
        except OSError as exc:
            if exc.errno != errno.ECONNREFUSED:
                raise OutcomeJournalError(
                    "witness endpoint liveness uncertain"
                ) from exc
        else:
            raise OutcomeJournalError("live witness endpoint; no takeover")
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (old.st_dev, old.st_ino) != (current.st_dev, current.st_ino):
        raise OutcomeJournalError("witness endpoint changed; no cleanup")
    os.unlink(name, dir_fd=parent)
    os.fsync(parent)


class SystemdReady:
    """Explicit local readiness only; no evidence/signing/control authority."""

    def __init__(self):
        address = os.environ.get("NOTIFY_SOCKET", "")
        if (
            not address.startswith(("/", "@"))
            or not 1 < len(address.encode()) <= 107
            or any(c in address for c in ("\x00", "\n", "\r"))
        ):
            raise OutcomeJournalError("explicit local systemd notify socket required")
        self.address = "\x00" + address[1:] if address.startswith("@") else address

    def set(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
            notify.settimeout(1)
            if notify.sendto(b"READY=1", self.address) != 7:
                raise OutcomeJournalError("witness readiness notification failed")


def serve(
    policy, key_path, *, initialize=False, stop=None, ready=None, max_requests=131072
):
    p = policy.data
    if os.geteuid() != p["witness_uid"] or not hasattr(socket, "SO_PEERCRED"):
        raise OutcomeJournalError("separate Linux witness uid required")
    parent, name = open_parent(p["socket_path"], trusted_owner=p["witness_uid"])
    try:
        info = os.fstat(parent)
        if info.st_uid != p["witness_uid"] or info.st_mode & 0o022:
            raise OutcomeJournalError(
                "private witness socket parent ownership required"
            )
        with (
            WitnessStore(policy, key_path, initialize=initialize) as store,
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server,
        ):
            retire_stale_endpoint(policy, parent, name)
            server.bind(p["socket_path"])
            os.chmod(p["socket_path"], 0o666)
            inode = os.stat(name, dir_fd=parent, follow_symlinks=False)
            server.listen(4)
            server.settimeout(0.2)
            try:
                if stop is not None and stop.is_set():
                    return
                if ready is not None:
                    ready.set()
                accepted = 0
                while accepted < max_requests:
                    if stop is not None and stop.is_set():
                        break
                    try:
                        conn, _ = server.accept()
                    except socket.timeout:
                        continue
                    accepted += 1
                    with conn:
                        conn.settimeout(1.0)
                        try:
                            if peer_uid(conn) != p["observer_uid"]:
                                raise OutcomeJournalError("witness caller uid refused")
                            response = store.request(recv_message(conn))
                            send_message(conn, response)
                        except (
                            OSError,
                            ValueError,
                            TypeError,
                            KeyError,
                            RecursionError,
                        ):
                            try:
                                send_message(conn, {"error": "continuity_unavailable"})
                            except OSError:
                                pass
            finally:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (inode.st_dev, inode.st_ino):
                    os.unlink(name, dir_fd=parent)
    finally:
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Explicit foreground offline witness; never installed/enabled automatically"
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--initialize", action="store_true")
    parser.add_argument("--systemd-notify", action="store_true")
    args = parser.parse_args(argv)
    ready = SystemdReady() if args.systemd_notify else None
    stop = threading.Event()
    previous = {}
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, lambda *_: stop.set())
        serve(
            TrustPolicy.from_file(args.policy, role="witness"),
            args.private_key,
            initialize=args.initialize,
            stop=stop,
            ready=ready,
        )
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
