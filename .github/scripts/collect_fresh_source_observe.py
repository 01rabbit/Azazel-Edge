"""Export only frozen public finite-load originals from the disposable lab."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

CASES = ("fresh-controls", "fresh-interrupted")
NAMES = frozenset(
    "fresh-controller.json fresh-timestamp-receipts.json observer-input-calls.raw load-controller.json corpus-manifest.json observer-config.json observer-policy.json observer-phase.raw observer-calls.raw observer-context.raw observer-completion.json observer-stdout.raw observer-stderr.raw observer-journal.raw observer-outcomes.raw observer-fault-anchors.raw protocol.json trust.json registration.json close-controller.json root-custody.raw root-custody-object.json actor-fd-custody.json native-close.raw receiver-close.raw launcher-systemd.json unit-exec-start.raw launcher-journal.raw source-before.raw source-after.raw anchors-before.raw anchors-after.raw journal-before.raw journal-after.raw readback-source.raw reader-binding.json witness-boundary.json code-pins.json failure.json evaluation.json ingress-controller.json eve-start.raw eve-after-writer.raw eve-before-mutation.raw eve-held-final.raw eve-path-final.raw normalized-log-before.raw normalized-log-final.raw".split()
)
BASE = Path("/var/lib/edge400-systemd-lab/fresh-source-observe-public")
TARGET = Path("fresh-source-observe-public")


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
    if name == "observer-publication.raw":
        return 1024 * 1024
    if name == "fresh-timestamp-receipts.json":
        return 65536
    if name == "observer-input-calls.raw":
        return 4 * 1024 * 1024
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


def collect(*, version=1):
    assert version in (1, 2, 3)
    names = NAMES | {"observer-publication.raw"} if version >= 2 else NAMES
    source = (
        Path(
            str(BASE).replace(
                "fresh-source-observe-public", f"fresh-source-observe-v{version}-public"
            )
        )
        if version >= 2
        else BASE
    )
    target = (
        Path(
            str(TARGET).replace(
                "fresh-source-observe-public", f"fresh-source-observe-v{version}-public"
            )
        )
        if version >= 2
        else TARGET
    )
    cases = CASES
    target.mkdir(mode=0o755)
    files, missing, errors = {}, [], []
    for case in cases:
        (target / case).mkdir(mode=0o755)
        total_eve = 0
        for name in sorted(names):
            relative, fd = case + "/" + name, None
            limit = file_limit(name)
            try:
                path = source / relative
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
                with (target / relative).open("xb") as output:
                    output.write(raw)
                (target / relative).chmod(0o644)
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
    for name in (
        (
            "recipe-declaration.json",
            "fresh-controls-snapshot.json",
            "fresh-interrupted-snapshot.json",
            "disposition.json",
        )
        if version >= 2
        else ("recipe-declaration.json",)
    ):
        try:
            path = source / name
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
            with (target / name).open("xb") as output:
                output.write(raw)
            files[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        except FileNotFoundError:
            missing.append(name)
        except Exception as error:
            errors.append(dict(path=name, error=type(error).__name__))
    manifest = dict(
        schema_version="edge-finite-load-public-inventory/v1",
        flavor=f"fresh-source-observe-v{version}"
        if version >= 2
        else "fresh-source-observe",
        cases=list(cases),
        files=files,
        missing=missing,
        errors=errors,
        private_keys_exported=False,
    )
    with (target / "manifest.json").open("x") as output:
        json.dump(manifest, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    (target / "manifest.json").chmod(0o644)
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
            "fresh-controller.json",
            "fresh-timestamp-receipts.json",
            "observer-input-calls.raw",
            "source-after.raw",
            "eve-start.raw",
            "eve-held-final.raw",
            "eve-path-final.raw",
            "evaluation.json",
        )
    }
    if version >= 2:
        required |= {case + "/observer-publication.raw" for case in cases}
        required |= {
            "recipe-declaration.json",
            "fresh-controls-snapshot.json",
            "fresh-interrupted-snapshot.json",
            "disposition.json",
        }
    assert not errors and required <= files.keys(), (
        "finite load originals missing or rejected"
    )


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--v2"], ["--v3"]):
        raise SystemExit("fixed fresh-source collector accepts only --v2 or --v3")
    collect(version=int(sys.argv[1][-1]) if sys.argv[1:] else 1)
