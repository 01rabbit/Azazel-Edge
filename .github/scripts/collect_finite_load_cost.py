"""Export only frozen public finite-load originals from the disposable lab."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

CASES = ("load-off", "load-on", "load-faulted")
NAMES = frozenset(
    "load-controller.json corpus-manifest.json observer-config.json observer-policy.json observer-phase.raw observer-calls.raw observer-context.raw observer-completion.json observer-stdout.raw observer-stderr.raw observer-journal.raw observer-outcomes.raw observer-fault-anchors.raw protocol.json trust.json registration.json close-controller.json root-custody.raw root-custody-object.json actor-fd-custody.json native-close.raw receiver-close.raw launcher-systemd.json unit-exec-start.raw launcher-journal.raw source-before.raw source-after.raw anchors-before.raw anchors-after.raw journal-before.raw journal-after.raw readback-source.raw reader-binding.json witness-boundary.json code-pins.json failure.json evaluation.json ingress-controller.json eve-start.raw eve-after-writer.raw eve-before-mutation.raw eve-held-final.raw eve-path-final.raw normalized-log-before.raw normalized-log-final.raw".split()
)
BASE = Path("/var/lib/edge400-systemd-lab/finite-load-cost-public")
TARGET = Path("finite-load-cost-public")


def metadata(info):
    return tuple(
        getattr(info, k)
        for k in (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def file_limit(name):
    if name.startswith("eve-"):
        return 16 * 1024 * 1024
    if name in ("observer-phase.raw", "observer-calls.raw"):
        return 4 * 1024 * 1024
    if name == "observer-context.raw":
        return 16384
    if name in (
        "observer-stdout.raw",
        "observer-stderr.raw",
        "observer-completion.json",
    ):
        return 65536
    if name in ("load-controller.json", "observer-config.json", "corpus-manifest.json"):
        return 131072
    if name == "launcher-journal.raw":
        return 65536
    if name == "unit-exec-start.raw":
        return 131072
    if name == "root-custody.raw":
        return 32768
    if name in ("native-close.raw", "receiver-close.raw"):
        return 4096
    if name in ("trust.json", "registration.json"):
        return 32768
    if name.endswith(".json"):
        return 131072
    return 8 * 1024 * 1024


def collect():
    cases = CASES
    TARGET.mkdir(mode=0o755)
    files, missing, errors = {}, [], []
    for case in cases:
        (TARGET / case).mkdir(mode=0o755)
        total_eve = 0
        for name in sorted(NAMES):
            relative, fd = case + "/" + name, None
            limit = file_limit(name)
            try:
                path = BASE / relative
                before = path.lstat()
                assert stat.S_ISREG(before.st_mode) and before.st_uid == 0
                assert before.st_nlink == 1 and not before.st_mode & 0o022
                assert 0 <= before.st_size <= limit
                fd = os.open(
                    path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                )
                assert metadata(os.fstat(fd)) == metadata(before)
                chunks, count = [], 0
                while count <= limit:
                    block = os.read(fd, min(65536, limit + 1 - count))
                    if not block:
                        break
                    chunks.append(block)
                    count += len(block)
                raw = b"".join(chunks)
                assert len(raw) == before.st_size
                assert (
                    metadata(os.fstat(fd)) == metadata(path.lstat()) == metadata(before)
                )
                if name.startswith("eve-"):
                    total_eve += len(raw)
                    assert total_eve <= 64 * 1024 * 1024
                with (TARGET / relative).open("xb") as output:
                    output.write(raw)
                (TARGET / relative).chmod(0o644)
                files[relative] = dict(
                    bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()
                )
            except FileNotFoundError:
                missing.append(relative)
            except Exception as error:
                errors.append(dict(path=relative, error=type(error).__name__))
            finally:
                if fd is not None:
                    os.close(fd)
    for name in ("corpus-manifest.json", "comparison.json"):
        try:
            path = BASE / name
            before = path.lstat()
            assert (
                stat.S_ISREG(before.st_mode)
                and before.st_uid == 0
                and before.st_nlink == 1
                and not before.st_mode & 0o022
                and before.st_size <= 131072
            )
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                assert metadata(os.fstat(fd)) == metadata(before)
                raw = os.read(fd, 131073)
                assert len(raw) == before.st_size and metadata(
                    os.fstat(fd)
                ) == metadata(path.lstat()) == metadata(before)
            finally:
                os.close(fd)
            with (TARGET / name).open("xb") as output:
                output.write(raw)
            files[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        except FileNotFoundError:
            missing.append(name)
        except Exception as error:
            errors.append(dict(path=name, error=type(error).__name__))
    manifest = dict(
        schema_version="edge-finite-load-public-inventory/v1",
        flavor="finite-load-cost",
        cases=list(cases),
        files=files,
        missing=missing,
        errors=errors,
        private_keys_exported=False,
    )
    with (TARGET / "manifest.json").open("x") as output:
        json.dump(manifest, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    (TARGET / "manifest.json").chmod(0o644)
    required = {
        case + "/" + name
        for case in cases
        for name in (
            "protocol.json",
            "trust.json",
            "registration.json",
            "close-controller.json",
            "ingress-controller.json",
            "load-controller.json",
            "corpus-manifest.json",
            "source-after.raw",
            "eve-start.raw",
            "eve-held-final.raw",
            "eve-path-final.raw",
            "evaluation.json",
        )
    }
    assert not errors and required <= files.keys(), (
        "finite load originals missing or rejected"
    )


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("fixed finite-load flavor takes no arguments")
    collect()
