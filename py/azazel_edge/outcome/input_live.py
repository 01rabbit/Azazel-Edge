"""Explicit trusted launcher -> real core -> separate-UID signed capture.

No listening endpoint, arbitrary argv, retry, reattachment or deployment.
"""

import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

from .input_auth import (
    TrustPolicy,
    SignedCaptureWriter,
    read_regular,
    open_parent,
    hex_bytes,
)
from .input_origin import MAX_IMAGE
from .instance import CoreLease
from .journal import OutcomeJournalError, _parse, _ref
from .live_protocol import native_frame

SCHEMA = "outcome-live-origin-registration/v1"
ENV_KEYS = frozenset(
    "EVE_PATH AI_SOCKET NORMALIZED_EVENT_LOG EVE_POLL_MS FORWARD_AI FORWARD_LOG EVENT_STDOUT DEFENSE_ENFORCE DEFENSE_DRY_RUN DEFENSE_ENFORCE_LEVEL DEFENSE_ACTION_TTL_SEC PROTECTED_FLOWS_PATH UNDELIVERED_SPOOL UNDELIVERED_SPOOL_CAP_BYTES DEFENSE_RELEASE_LEDGER DEFENSE_ALLOW_HIGH_IMPACT_AUTO DEFENSE_IFACE DEFENSE_HONEYPOT_PORT REDIRECT_POLICY_PATH EVE_FROM_START".split()
)
REQUIRED_ENV = frozenset(
    "EVE_PATH NORMALIZED_EVENT_LOG FORWARD_AI FORWARD_LOG EVENT_STDOUT DEFENSE_ENFORCE DEFENSE_DRY_RUN DEFENSE_RELEASE_LEDGER REDIRECT_POLICY_PATH PROTECTED_FLOWS_PATH EVE_FROM_START".split()
)


def registration(policy, path):
    d = policy.data
    if d["schema_version"] != "outcome-input-trust/v3" or d["witness_uid"] != 0:
        raise OutcomeJournalError(
            "live origin requires explicit root-owned v3 enrollment"
        )
    raw, _ = read_regular(path, owner=0, max_bytes=16384)
    if hashlib.sha256(raw).hexdigest() != d["origin_registration_sha256"]:
        raise OutcomeJournalError("live origin enrollment digest mismatch")
    return validate_registration(policy, _parse(raw))


def validate_registration(policy, r):
    d = policy.data
    fields = {
        "schema_version",
        "mode",
        "scope_ref",
        "producer_ref",
        "stream_ref",
        "producer_public_key",
        "binary_path",
        "binary_sha256",
        "launcher_uid",
        "environment",
    }
    if type(r) is dict and r.get("schema_version") in (
        "outcome-live-origin-registration/v2",
        "outcome-live-origin-registration/v3",
        "outcome-live-origin-registration/v4",
    ):
        fields.add("ai_socket_uid")
    if type(r) is dict and r.get("schema_version") in (
        "outcome-live-origin-registration/v3",
        "outcome-live-origin-registration/v4",
    ):
        fields.add("capture_apparmor_profile")
    if (
        type(r) is dict
        and r.get("schema_version") == "outcome-live-origin-registration/v4"
    ):
        fields.add("native_apparmor_profile")
    if (
        type(r) is not dict
        or set(r) != fields
        or r["schema_version"]
        not in (
            SCHEMA,
            "outcome-live-origin-registration/v2",
            "outcome-live-origin-registration/v3",
            "outcome-live-origin-registration/v4",
        )
        or r["mode"] != "live-core"
        or type(r["launcher_uid"]) is not int
        or r["launcher_uid"] != 0
    ):
        raise OutcomeJournalError("invalid live origin registration")
    if "capture_apparmor_profile" in r:
        from .confinement import profile_name

        profile_name(r["capture_apparmor_profile"])
    if "native_apparmor_profile" in r:
        profile_name(r["native_apparmor_profile"])
        if r["native_apparmor_profile"] == r["capture_apparmor_profile"]:
            raise OutcomeJournalError("native and signer profiles must be distinct")
    if any(
        r[k] != d[k]
        for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")
    ):
        raise OutcomeJournalError("live origin key/scope mismatch")
    hex_bytes(r["binary_sha256"], 32)
    env = r["environment"]
    if (
        type(env) is not dict
        or not all(
            type(k) is str
            and k.startswith("AZAZEL_")
            and k[7:] in ENV_KEYS
            and type(v) is str
            and len(v) <= 1024
            and "\x00" not in v
            for k, v in env.items()
        )
        or not {"AZAZEL_" + k for k in REQUIRED_ENV} <= set(env)
    ):
        raise OutcomeJournalError(
            "live origin requires a complete bounded registered environment"
        )
    if env["AZAZEL_EVE_FROM_START"] != "0" or env["AZAZEL_EVENT_STDOUT"] != "off":
        raise OutcomeJournalError(
            "live origin cannot replay input or use stdout as evidence"
        )
    ai_uid = r.get("ai_socket_uid", 0)
    if (
        type(ai_uid) is not int
        or not 0 <= ai_uid < 2**31
        or ai_uid in (d["producer_uid"], d["observer_uid"])
    ):
        raise OutcomeJournalError(
            "AI socket role must remain separate from capture and observer"
        )
    for key in ("binary_path",):
        path = r[key]
        if (
            type(path) is not str
            or not Path(path).is_absolute()
            or ".." in Path(path).parts
            or "\x00" in path
        ):
            raise OutcomeJournalError("invalid live origin executable path")
    for key in (
        "EVE_PATH",
        "NORMALIZED_EVENT_LOG",
        "DEFENSE_RELEASE_LEDGER",
        "REDIRECT_POLICY_PATH",
        "PROTECTED_FLOWS_PATH",
        "UNDELIVERED_SPOOL",
        "AI_SOCKET",
    ):
        if "AZAZEL_" + key not in env:
            continue
        value = Path(env["AZAZEL_" + key])
        if not value.is_absolute() or ".." in value.parts:
            raise OutcomeJournalError("physical registered core path required")
        # The producer has no access to private core/AI directories. Its root
        # parent validated these; verify public structure here without grants.
        if os.geteuid() != 0:
            continue
        expected_owner = ai_uid if key == "AI_SOCKET" else 0
        parent, name = open_parent(value, trusted_owner=expected_owner)
        try:
            try:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if key == "EVE_PATH":
                    raise
                continue
            expected_type = (
                stat.S_ISSOCK(info.st_mode)
                if key == "AI_SOCKET"
                else stat.S_ISREG(info.st_mode)
            )
            if (
                info.st_uid != expected_owner
                or info.st_mode & 0o022
                or not expected_type
                or info.st_nlink != 1
            ):
                raise OutcomeJournalError("unsafe registered core path")
        finally:
            os.close(parent)
    # Native core paths may never alias signed evidence, private keys/anchor or
    # journal; even an accidental registered config must not feed a log loop.
    forbidden = {
        d["source_path"],
        str(Path(d["journal_directory"]) / "observations.journal"),
        str(Path(d["anchor_directory"]) / "anchors.journal"),
        d["socket_path"],
    }
    if any(
        v in forbidden
        for k, v in env.items()
        if k.endswith(("PATH", "LOG", "LEDGER", "SOCKET", "SPOOL"))
    ):
        raise OutcomeJournalError("live core path aliases protected evidence")
    return r


def native_arguments(r):
    """Registration, never environment/optional caller flags, requires the gate."""
    return (
        ["--native-apparmor-profile", r["native_apparmor_profile"]]
        if "native_apparmor_profile" in r
        else []
    )


def native_gate(r, image):
    """No key/session preparation until the sealed native gate proves enforcement."""
    if "native_apparmor_profile" not in r:
        return
    result = subprocess.run(
        [f"/proc/self/fd/{image}", "--health", *native_arguments(r)],
        pass_fds=(image,),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=5,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", **r["environment"]},
    )
    if result.returncode not in (0, 1) or len(result.stdout) > 8192:
        raise OutcomeJournalError("native AppArmor preflight refused")
    if _parse(result.stdout).get("native_apparmor") != dict(
        schema_version="azazel-edge-core/native-apparmor/v1",
        sealed_memfd=True,
        early_transition=True,
        enforced_profile=r["native_apparmor_profile"],
    ):
        raise OutcomeJournalError("native AppArmor enforcement not verified")


def sealed_image(r):
    image, info = read_regular(r["binary_path"], owner=0, max_bytes=MAX_IMAGE)
    if (
        not image.startswith(b"\x7fELF")
        or not info.st_mode & 0o111
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or hashlib.sha256(image).hexdigest() != r["binary_sha256"]
    ):
        raise OutcomeJournalError("unregistered live core image")
    fd = os.memfd_create("edge-live-origin", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(image)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OutcomeJournalError("live image short write")
            view = view[n:]
        os.fchmod(fd, 0o500)
        fcntl.fcntl(
            fd,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        return fd
    except BaseException:
        os.close(fd)
        raise


def harden_receiver(uid):
    import ctypes

    if (
        os.getresuid() != (uid, uid, uid)
        or os.getresgid() != (uid, uid, uid)
        or os.getgroups()
    ):
        raise OutcomeJournalError("receiver retained unexpected identities/groups")
    status = Path("/proc/self/status").read_text()
    for key in ("CapEff", "CapPrm", "CapAmb"):
        if int(status.split(key + ":", 1)[1].split()[0], 16):
            raise OutcomeJournalError("receiver retained process capabilities")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # Linux PR_SET_NO_NEW_PRIVS
        raise OutcomeJournalError("receiver no-new-privileges unavailable")


def receive(policy, r, key_path, boot_ref, fd, session):
    if sys.platform != "linux" or os.geteuid() != policy.data["producer_uid"]:
        raise OutcomeJournalError("registered non-root Linux receiver required")
    harden_receiver(policy.data["producer_uid"])
    if "capture_apparmor_profile" in r:
        from .confinement import enforce_capture

        enforce_capture(r["capture_apparmor_profile"])
    with socket.socket(fileno=fd) as channel:
        os.set_inheritable(channel.fileno(), False)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_STREAM:
            raise OutcomeJournalError("private live Unix stream required")
        pid, uid, _ = struct.unpack(
            "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if uid != r["launcher_uid"] or pid != os.getppid():
            raise OutcomeJournalError("live launcher peer/parent mismatch")
        # No payload is read until identity, key, source history and clean
        # previous session closure all verify. Missing stores are not created.
        with SignedCaptureWriter(policy, key_path, boot_ref=boot_ref) as writer:
            if not writer.verifier.live_state.closed:
                raise OutcomeJournalError(
                    "unclean live session; automatic continuation refused"
                )
            prepare = dict(
                pipeline="rust_live_origin_v1",
                source="capture_producer",
                capture_lifecycle=dict(state="prepare"),
                capture_origin=dict(
                    schema_version="outcome-registered-origin/v2",
                    registration_sha256=policy.data["origin_registration_sha256"],
                    mode="live-core",
                    session_ref=session,
                    seq=0,
                    kind="session_prepare",
                ),
            )
            writer.append(prepare)  # Durable uncertainty marker before core launch.
            state = writer.verifier.live_state
            print('{"ready":true}', flush=True)
            buffer = bytearray()
            ended = False
            terminal = None
            while True:
                part = channel.recv(min(8192, 65537 - len(buffer)))
                if not part:
                    if buffer or not ended:
                        raise OutcomeJournalError("live capture truncated or unclosed")
                    writer.append(terminal)  # Only after clean EOF, no extra bytes.
                    return
                buffer.extend(part)
                while b"\n" in buffer:
                    index = buffer.index(b"\n") + 1
                    if index > 65536:
                        raise OutcomeJournalError("live capture frame bound")
                    wire = _parse(buffer[:index])
                    del buffer[:index]
                    if ended:
                        raise OutcomeJournalError("live data after session end")
                    next_state = native_frame(wire, state)
                    event = dict(wire["event"])
                    if "capture_origin" in event:
                        raise OutcomeJournalError("native provenance injection")
                    event["capture_origin"] = dict(
                        schema_version="outcome-registered-origin/v2",
                        registration_sha256=policy.data["origin_registration_sha256"],
                        mode="live-core",
                        **{k: wire[k] for k in ("session_ref", "seq", "kind")},
                    )
                    ended = wire["kind"] == "session_end"
                    if ended:
                        terminal = event  # Withhold clean closure until EOF verifies.
                    else:
                        writer.append(event)
                    state = next_state
                if len(buffer) > 65536:
                    raise OutcomeJournalError("live capture frame bound")


def launch(policy_path, registration_path, key_path, boot_ref):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise OutcomeJournalError("trusted root launcher required")
    _ref(boot_ref)
    p = TrustPolicy.from_file(policy_path, role="witness")
    r = registration(p, registration_path)
    capture_python = sys.executable
    if "capture_apparmor_profile" in r:
        from .confinement import capture_image

        capture_python, _ = capture_image(sys.executable, r["capture_apparmor_profile"])
    lease = CoreLease(r["environment"]["AZAZEL_DEFENSE_RELEASE_LEDGER"])
    try:
        image = sealed_image(r)
    except BaseException:
        lease.close()
        raise
    core_end, signer_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    worker = None
    core = None
    old_handlers = {}
    stopping = False
    session = secrets.token_hex(16)

    def stop(signum, frame):
        nonlocal stopping
        stopping = True
        if core is not None and core.poll() is None:
            core.send_signal(signum)

    try:
        native_gate(r, image)
        # The launcher is trusted root code. Its child receives only this
        # private channel and drops supplementary groups/UID before key use.
        worker = subprocess.Popen(
            [
                str(capture_python),
                "-m",
                "azazel_edge.outcome.input_live",
                "--policy",
                str(policy_path),
                "--registration",
                str(registration_path),
                "--private-key",
                str(key_path),
                "--boot-ref",
                boot_ref,
                "--receive-fd",
                str(signer_end.fileno()),
                "--session-ref",
                session,
            ],
            pass_fds=(signer_end.fileno(),),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            user=p.data["producer_uid"],
            group=p.data["producer_uid"],
            extra_groups=[],
            cwd="/",
            env={
                "PATH": "/nonexistent",
                "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
            },
            close_fds=True,
        )
        signer_end.close()
        if (
            not select.select([worker.stdout], [], [], 10)[0]
            or worker.stdout.readline(1025) != b'{"ready":true}\n'
        ):
            raise OutcomeJournalError(
                "live signer preflight refused; core not launched"
            )
        for sig in (signal.SIGTERM, signal.SIGINT):
            old_handlers[sig] = signal.signal(sig, stop)
        if stopping:
            raise OutcomeJournalError("live launch interrupted")
        core = subprocess.Popen(
            [
                f"/proc/self/fd/{image}",
                "--live-origin-fd",
                str(core_end.fileno()),
                "--live-origin-session",
                session,
                "--core-instance-fd",
                str(lease.fd),
                *native_arguments(r),
            ],
            pass_fds=(image, core_end.fileno(), lease.fd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            cwd="/",
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", **r["environment"]},
            close_fds=True,
        )
        core_end.close()
        os.close(image)
        image = None
        print('{"core_started":true}', flush=True)
        reported = False
        while core.poll() is None:
            if worker.poll() is not None and not reported:
                print(
                    "live signer stopped; no reconnect; core continues",
                    file=sys.stderr,
                    flush=True,
                )
                reported = True
            time.sleep(0.05)
        code = core.returncode
        try:
            signer_code = worker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait()
            signer_code = 1
        return 0 if code == 0 and signer_code == 0 else 1
    finally:
        lease.close()  # A surviving core still owns its inherited lock.
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
        core_end.close()
        signer_end.close()
        if image is not None:
            os.close(image)
        # Never terminate/restart an already launched defense process due to
        # capture failure. Normal SIGTERM/SIGINT above is explicit core stop.
        if worker is not None:
            if core is None and worker.poll() is None:
                worker.kill()
            if core is None:
                worker.wait()
            worker.stdout.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Explicit enrolled live core capture; no activation defaults"
    )
    for k in ("policy", "registration", "private-key"):
        parser.add_argument("--" + k, type=Path, required=True)
    parser.add_argument("--boot-ref", required=True)
    parser.add_argument("--receive-fd", type=int)
    parser.add_argument("--session-ref")
    args = parser.parse_args(argv)
    try:
        if args.receive_fd is None:
            return launch(
                args.policy, args.registration, args.private_key, args.boot_ref
            )
        p = TrustPolicy.from_file(args.policy, role="producer")
        r = registration(p, args.registration)
        receive(
            p, r, args.private_key, args.boot_ref, args.receive_fd, args.session_ref
        )
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print(
            "live input refused; preserve evidence; no fallback or automatic reconnect",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
