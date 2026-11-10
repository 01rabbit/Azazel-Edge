"""Opt-in registered, read-only Rust origin. No attachment to live enforcement.

The trusted operator enrolls an immutable public manifest offline; this module
never generates keys, installs binaries, tails normalized logs or repairs state.
"""

import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import time

from .input_auth import (
    TrustPolicy,
    SignedCaptureWriter,
    read_regular,
    hex_bytes,
    validate_readonly_origin_event,
)
from .journal import OutcomeJournalError, _json, _parse

MAX_IMAGE = 64 * 1024 * 1024
ORIGIN_SCHEMA = "outcome-origin-registration/v1"


class RegisteredOrigin:
    """A sealed executable image plus a pre-enrolled physical raw EVE source."""

    def __init__(self, policy, registration):
        self.policy = policy
        self.fd = None
        self.poisoned = False
        self.bound_writer = None
        if os.geteuid() != policy.data["producer_uid"]:
            raise OutcomeJournalError("registered producer uid required")
        d = policy.data
        if d["schema_version"] != "outcome-input-trust/v2":
            raise OutcomeJournalError(
                "registered origin requires v2 trust; no downgrade"
            )
        raw, _ = read_regular(registration, owner=d["witness_uid"], max_bytes=8192)
        self.digest = hashlib.sha256(raw).hexdigest()
        if self.digest != d["origin_registration_sha256"]:
            raise OutcomeJournalError("origin registration digest mismatch")
        r = _parse(raw)
        fields = {
            "schema_version",
            "scope_ref",
            "producer_ref",
            "stream_ref",
            "producer_public_key",
            "binary_path",
            "binary_sha256",
            "raw_path",
            "raw_uid",
            "raw_device",
            "raw_inode",
            "mode",
        }
        if (
            type(r) is not dict
            or set(r) != fields
            or r["schema_version"] != ORIGIN_SCHEMA
            or r["mode"] != "readonly-core"
        ):
            raise OutcomeJournalError("invalid origin registration")
        if any(
            r[k] != d[k]
            for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")
        ):
            raise OutcomeJournalError("origin key/scope registration mismatch")
        hex_bytes(r["binary_sha256"], 32)
        for k in ("raw_uid", "raw_device", "raw_inode"):
            if type(r[k]) is not int or r[k] < 0:
                raise OutcomeJournalError("invalid raw source identity")
        if r["raw_uid"] not in (0, d["witness_uid"]):
            raise OutcomeJournalError("raw ingress must have independent trusted owner")
        for k in ("raw_path", "binary_path"):
            if (
                type(r[k]) is not str
                or not Path(r[k]).is_absolute()
                or ".." in Path(r[k]).parts
                or "\x00" in r[k]
            ):
                raise OutcomeJournalError("invalid origin path")
        if r["raw_path"] in (
            d["source_path"],
            str(Path(d["journal_directory"]) / "observations.journal"),
        ):
            raise OutcomeJournalError("origin source aliases evidence")
        self.registration = r
        # Pin the binary to a sealed memory image: a hash followed by path-based
        # execution would permit replacement or same-inode mutation in between.
        image, info = read_regular(
            r["binary_path"], owner=d["witness_uid"], max_bytes=MAX_IMAGE
        )
        if (
            not image.startswith(b"\x7fELF")
            or not info.st_mode & 0o111
            or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or hashlib.sha256(image).hexdigest() != r["binary_sha256"]
        ):
            raise OutcomeJournalError("unregistered or unsafe origin binary")
        if sys.platform != "linux" or not hasattr(os, "memfd_create"):
            raise OutcomeJournalError("sealed Linux origin unavailable")
        try:
            self.fd = os.memfd_create(
                "edge-registered-origin", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
            )
            view = memoryview(image)
            while view:
                n = os.write(self.fd, view)
                if n <= 0:
                    raise OutcomeJournalError("origin image short write")
                view = view[n:]
            os.fchmod(self.fd, 0o500)
            fcntl.fcntl(
                self.fd,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_SEAL,
            )
            self.raw, self.info = self.snapshot()
            if self.raw and not self.raw.endswith(b"\n"):
                raise OutcomeJournalError("partial raw input at startup")
            for line in self.raw.splitlines(keepends=True):
                parsed = _parse(line)
                if len(line) > 65536 or type(parsed) is not dict:
                    raise OutcomeJournalError("invalid historical raw input")
                _json(parsed)  # Reject overflow-to-infinity before EOF exclusion.
            self.records = self.raw.count(b"\n")
        except BaseException:
            self.close()
            raise

    def snapshot(self):
        r, d = self.registration, self.policy.data
        raw, info = read_regular(
            r["raw_path"], owner=r["raw_uid"], max_bytes=d["input_max_bytes"]
        )
        if (info.st_dev, info.st_ino) != (r["raw_device"], r["raw_inode"]) or raw.count(
            b"\n"
        ) > d["input_max_records"]:
            raise OutcomeJournalError(
                "registered raw source identity/capacity mismatch"
            )
        return raw, info

    def transform(self, line):
        # Strict Python parsing rejects duplicate keys and nonfinite values
        # before the Rust JSON parser receives any raw source record.
        if (
            len(line) > 65536
            or not line.endswith(b"\n")
            or line.count(b"\n") != 1
            or type(_parse(line)) is not dict
        ):
            raise OutcomeJournalError("raw origin record refused")
        _json(_parse(line))
        if self.fd is None:
            raise OutcomeJournalError("origin closed")
        proc = subprocess.Popen(
            [f"/proc/self/fd/{self.fd}", "--capture-origin-once"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(self.fd,),
            cwd="/",
            env={"PATH": "/nonexistent"},
            close_fds=True,
        )
        output = bytearray()
        pending = memoryview(line)
        deadline = time.monotonic() + 5
        try:
            # Both directions are bounded and nonblocking, including a stalled
            # or unexpected registered executable. Never inherit arbitrary env.
            with selectors.DefaultSelector() as selector:
                os.set_blocking(proc.stdin.fileno(), False)
                os.set_blocking(proc.stdout.fileno(), False)
                selector.register(proc.stdin, selectors.EVENT_WRITE)
                selector.register(proc.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise OutcomeJournalError("origin deadline exceeded")
                    for key, _ in selector.select(remaining):
                        if key.fileobj is proc.stdin:
                            n = os.write(proc.stdin.fileno(), pending)
                            pending = pending[n:]
                            if not pending:
                                selector.unregister(proc.stdin)
                                proc.stdin.close()
                        else:
                            part = os.read(
                                proc.stdout.fileno(), min(8192, 65537 - len(output))
                            )
                            output.extend(part)
                            if len(output) > 65536:
                                raise OutcomeJournalError(
                                    "origin output bound exceeded"
                                )
                            if not part:
                                selector.unregister(proc.stdout)
                if proc.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                    raise OutcomeJournalError("registered origin failed")
            if not output.endswith(b"\n") or output.count(b"\n") != 1:
                raise OutcomeJournalError("origin response framing mismatch")
            event = _parse(output)
            if event is None:
                return None  # Non-alert is not fabricated into an event.
            validate_readonly_origin_event(event)
            return event
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            if not proc.stdin.closed:
                proc.stdin.close()
            proc.stdout.close()

    def bind(self, writer):
        if writer.policy.digest != self.policy.digest:
            raise OutcomeJournalError("origin writer trust mismatch")
        if writer.verifier.raw:
            last = _parse(writer.verifier.raw.splitlines()[-1])["event"][
                "capture_origin"
            ]["raw_cursor"]
            if (
                len(self.raw) < last["offset"]
                or hashlib.sha256(self.raw[: last["offset"]]).hexdigest()
                != last["prefix_sha256"]
            ):
                raise OutcomeJournalError("registered raw history rewound or changed")
        self.bound_writer = writer

    def poll(self, writer):
        if self.poisoned or writer is not self.bound_writer:
            raise OutcomeJournalError("origin unbound or poisoned")
        try:
            self._poll(writer)
        except BaseException:
            self.poisoned = True
            raise

    def _poll(self, writer):
        raw, _ = self.snapshot()
        if not raw.startswith(self.raw):
            raise OutcomeJournalError("raw input rewound or changed")
        suffix = raw[len(self.raw) :]
        end = suffix.rfind(b"\n") + 1
        if len(suffix[end:]) > 65536:
            raise OutcomeJournalError("partial raw origin record too large")
        for line in suffix[:end].splitlines(keepends=True):
            event = self.transform(line)
            prefix = self.raw + line
            latest, _ = self.snapshot()
            if not latest.startswith(prefix):
                raise OutcomeJournalError("raw origin changed during calculation")
            if event is not None:
                event["capture_origin"] = dict(
                    schema_version="outcome-registered-origin/v1",
                    registration_sha256=self.digest,
                    mode="readonly-core",
                    raw_cursor=dict(
                        offset=len(prefix),
                        prefix_sha256=hashlib.sha256(prefix).hexdigest(),
                    ),
                )
                writer.append(event)
            self.raw += line  # No position advance before successful signed fsync.
            self.records += 1
        # Restart deliberately starts at then-current EOF: no downtime backfill.

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Explicit registered read-only Rust capture; no enforcement"
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--boot-ref", required=True)
    args = parser.parse_args(argv)
    origin = None
    try:
        policy = TrustPolicy.from_file(args.policy, role="producer")
        origin = RegisteredOrigin(policy, args.registration)
        with SignedCaptureWriter(
            policy, args.private_key, boot_ref=args.boot_ref
        ) as writer:
            origin.bind(writer)
            while True:
                origin.poll(writer)
                time.sleep(0.2)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("registered input refused; preserve evidence for review", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        if origin is not None:
            origin.close()


if __name__ == "__main__":
    raise SystemExit(main())
