#!/usr/bin/env python3
"""Build the per-CPU Edge Core package Azazel-Nexus verifies (Edge#424).

**This has nothing to do with `installer/`.** Nexus does not change network
configuration when it installs anything, so the existing network installer is
neither used nor ported. This tool takes an already-built binary and a fixed
set of configuration files and produces one artifact plus a manifest
describing it. It configures no network, touches no interface, and installs
nothing.

## Deterministic, because Nexus verifies a digest

The same inputs produce byte-identical output. Archive entries are sorted,
every mtime is zero, uid/gid are zero, names are normalised, and the gzip
header carries no timestamp. A packager whose output changed run to run would
give Nexus a digest that means nothing.

## The digest is **not signed**, and the manifest says so

Edge#424 asks for this to be explicit, because Nexus distinguishes "the tag is
signed" from "the digest is signed". Neither is true here: signing-key
operations are out of scope for this artifact.

What an unsigned digest establishes is **integrity against accidental
change** -- a truncated download, a half-written file, the wrong build copied
into place. What it does not establish is integrity against an adversary who
can rewrite the package and the manifest together. The manifest carries
`"signed": false` and the reason, and Nexus is expected to degrade rather than
pretend otherwise.

## One package per CPU, and the CPU is read from the binary

`--architecture` names the CPU being packaged (`x86_64` or `aarch64`, the
Linux `uname -m` spelling Nexus pins by). It is a request, not a label: the
ELF header of the binary actually being packaged (class, byte order and
`e_machine`) is read **before the binary is run**, and the package is refused
unless the header is the one listed for that CPU in `ARCHITECTURES`. The
manifest then records the CPU and the ELF identity that were read, and the
artifact and manifest are named for that CPU. An aarch64 build can no longer
be wrapped under an x86_64 name, which is the deviation the Nexus VM
acceptance record of 2026-10-29 had to write down (its D1).

The packager runs the binary (`--version`, and `--health` for the contract),
so it packages on the CPU it was built for, or under an emulator; it does not
cross-package. CI builds and packages on an x86_64 and an arm64 runner.

## What the package does not establish

That anything is running. The manifest declares how a supervisor should start
the payload and what observe-only means; it does not start it, and accepting
the package is not `edge-baseline-ready`. Nexus decides that from the package,
the version, the digest, the health contract **and** the running state, all
five.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[2]

PACKAGE_NAME = "azazel-edge-core"
#: v2 (2026-10-30): the manifest names the CPU read from the binary and
#: carries `elf`. Bumped, not only extended, so that a consumer that predates
#: per-CPU packages (it compares a fixed `x86_64` name and never looks at the
#: host or the binary) refuses every package of this packager by its
#: contract, instead of accepting an x86_64 package on an aarch64 host.
MANIFEST_CONTRACT = "azazel-edge-core/package-manifest/v2"
HEALTH_CONTRACT = "azazel-edge-core/health/v1"

#: The payload, as (archive path, source path relative to the repository).
#:
#: Listed rather than globbed. A glob picks up whatever happens to be in the
#: tree, and a package whose contents depend on the state of a working copy is
#: a package whose digest means something different on every machine.
PAYLOAD = (
    ("bin/azazel-edge-core", "rust/azazel-edge-core/target/release/azazel-edge-core"),
    ("config/redirect_policy.yaml", "config/redirect_policy.yaml"),
)

#: The environment that makes the payload observe-only. Shipped in the
#: manifest so Nexus can check the posture it is being asked to run, rather
#: than trusting that a default stayed the default.
OBSERVE_ONLY_ENV = {
    "AZAZEL_DEFENSE_ENFORCE": "false",
    "AZAZEL_DEFENSE_DRY_RUN": "true",
    "AZAZEL_DEFENSE_ENFORCE_LEVEL": "advisory",
    "AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO": "false",
}


class BuildRefused(Exception):
    """The package was not built, rather than built from something unknown."""


@dataclass(frozen=True)
class ElfIdentity:
    """The ELF header fields that say which CPU a binary is for.

    Recorded by name in the manifest; the numbers are what the header holds.
    """

    elf_class: str
    data: str
    machine: str

    def as_record(self) -> dict:
        return {"class": self.elf_class, "data": self.data, "machine": self.machine}


#: The CPUs a package can be built for, by the Linux `uname -m` name the
#: artifact, the manifest and the Nexus pin use, and the ELF identity a
#: binary for that CPU carries. Both reviewed CPUs run 64-bit little-endian
#: Linux; a big-endian or 32-bit build of either is not one of them.
ARCHITECTURES = {
    "aarch64": ElfIdentity(elf_class="ELFCLASS64", data="ELFDATA2LSB", machine="EM_AARCH64"),
    "x86_64": ElfIdentity(elf_class="ELFCLASS64", data="ELFDATA2LSB", machine="EM_X86_64"),
}

_ELF_MAGIC = b"\x7fELF"
_ELF_CLASSES = {1: "ELFCLASS32", 2: "ELFCLASS64"}
_ELF_DATA = {1: "ELFDATA2LSB", 2: "ELFDATA2MSB"}
#: `e_machine` values, from the System V ABI. Only names that matter here are
#: listed; any other value is reported by number and refused.
_ELF_MACHINES = {3: "EM_386", 40: "EM_ARM", 62: "EM_X86_64", 183: "EM_AARCH64", 243: "EM_RISCV"}
#: `e_type` values of something that can be executed: an executable or a
#: position-independent executable.
_ELF_EXECUTABLE_TYPES = {2, 3}


def elf_identity(header: bytes) -> ElfIdentity:
    """Read the CPU identity out of the first bytes of an ELF file.

    Reads the header only and runs nothing. Refuses anything that is not a
    well-formed ELF executable header: a wrong magic, a version other than 1,
    a type that cannot be executed, or a header too short to hold `e_machine`.
    """

    if len(header) < 24 or header[:4] != _ELF_MAGIC:
        raise BuildRefused("the payload binary is not an ELF file")
    elf_class = _ELF_CLASSES.get(header[4])
    data = _ELF_DATA.get(header[5])
    if elf_class is None or data is None or header[6] != 1:
        raise BuildRefused(
            f"the payload binary has an ELF header this packager cannot read "
            f"(class {header[4]}, data {header[5]}, version {header[6]})"
        )
    order = "<" if data == "ELFDATA2LSB" else ">"
    e_type, e_machine, e_version = struct.unpack_from(order + "HHI", header, 16)
    if e_version != 1 or e_type not in _ELF_EXECUTABLE_TYPES:
        raise BuildRefused(
            f"the payload binary is not an ELF executable (e_type {e_type}, e_version {e_version})"
        )
    machine = _ELF_MACHINES.get(e_machine, f"e_machine={e_machine}")
    return ElfIdentity(elf_class=elf_class, data=data, machine=machine)


def architecture_of(identity: ElfIdentity) -> str:
    """The `uname -m` name of the CPU an ELF identity is for, or a refusal."""

    for name, expected in ARCHITECTURES.items():
        if identity == expected:
            return name
    raise BuildRefused(
        f"the payload binary is {identity.elf_class}/{identity.data}/{identity.machine}, "
        f"which is none of the CPUs this packager builds for ({sorted(ARCHITECTURES)})"
    )


def binary_architecture(binary: bytes, requested: str) -> ElfIdentity:
    """The ELF identity of the binary's bytes, only when it is the one `requested` names.

    Called before the binary is run: a binary for another CPU is refused by
    what it is, not by whether it happens to execute here (an emulator would
    let it). It takes the bytes, not a path: the bytes checked here are the
    bytes run, hashed and archived (`build`), so nothing can be swapped in
    between.
    """

    if requested not in ARCHITECTURES:
        raise BuildRefused(
            f"--architecture {requested!r} is not one of {sorted(ARCHITECTURES)}"
        )
    identity = elf_identity(binary[:64])
    found = architecture_of(identity)
    if found != requested:
        raise BuildRefused(
            f"asked to package {requested} and the binary's ELF header says {found} "
            f"({identity.machine}); a package is named for the CPU its binary is for, "
            "never for the one requested"
        )
    return identity


@dataclass(frozen=True)
class Component:
    """One file in the package, as the SBOM-equivalent records it."""

    path: str
    digest: str
    size: int

    def as_record(self) -> dict:
        return {"path": self.path, "digest": self.digest, "size": self.size}


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _payload_paths(root: Path) -> list[tuple[str, Path]]:
    resolved: list[tuple[str, Path]] = []
    for archive_path, source in PAYLOAD:
        path = root / source
        if not path.is_file():
            raise BuildRefused(
                f"{source} is not present. Build it first "
                f"(cargo build --release --manifest-path rust/{PACKAGE_NAME}/Cargo.toml); "
                "this tool packages what exists and never builds a stand-in"
            )
        resolved.append((archive_path, path))
    return sorted(resolved, key=lambda pair: pair[0])


def _payload_bytes(root: Path) -> list[tuple[str, bytes]]:
    """Each payload file, read **once**.

    Everything the package says about a file -- the binary's CPU, its
    version, each component's digest and size, the archive member -- is
    derived from these bytes. Reading the tree again later would let a file
    replaced in between be archived under a check made on its predecessor.
    """

    payload: list[tuple[str, bytes]] = []
    for archive_path, path in _payload_paths(root):
        try:
            payload.append((archive_path, path.read_bytes()))
        except OSError as exc:
            raise BuildRefused(f"{path} could not be read: {exc}") from exc
    return payload


def _version(root: Path) -> str:
    """The crate version, read from Cargo.toml rather than restated here.

    A version written in two places is a version that disagrees with itself
    the first time one of them is edited.
    """

    cargo = root / "rust" / PACKAGE_NAME / "Cargo.toml"
    for line in cargo.read_text(encoding="utf-8").splitlines():
        if line.startswith("version") and "=" in line:
            return line.split("=", 1)[1].strip().strip('"')
    raise BuildRefused(f"{cargo} declares no version")


def _binary_reports_bytes(binary: bytes, version: str) -> None:
    """`_binary_reports` on a private copy of exactly these bytes.

    The copy is written to a fresh 0700 directory and removed afterwards, so
    the program run is the one whose header was checked and whose bytes are
    archived, not whatever the build tree holds by then.
    """

    import os
    import tempfile

    with tempfile.TemporaryDirectory(prefix="azazel-nexus-core-") as scratch:
        copy = Path(scratch) / "azazel-edge-core"
        fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, "wb") as stream:
            stream.write(binary)
        _binary_reports(copy, version)


def _binary_reports(binary: Path, version: str) -> None:
    """The packaged binary must agree with the version being packaged.

    Checked by running it, because a binary built from a different checkout
    than the Cargo.toml being read is exactly the mistake a digest cannot
    catch -- both would be internally consistent.
    """

    try:
        reported = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildRefused(f"the payload binary does not answer --version: {exc}") from exc
    if reported != version:
        raise BuildRefused(
            f"Cargo.toml declares {version} and the built binary reports "
            f"{reported}; the tree and the binary are from different builds"
        )


def build(root: Path, out_dir: Path, *, architecture: str) -> tuple[Path, Path]:
    """Write the package and its manifest for `architecture`. Returns both paths.

    `architecture` is required and checked against the binary's ELF header
    before anything runs it.
    """

    version = _version(root)
    payload = _payload_bytes(root)
    binary = dict(payload)["bin/azazel-edge-core"]
    identity = binary_architecture(binary, architecture)
    _binary_reports_bytes(binary, version)

    components = [
        Component(path=archive_path, digest=_digest(data), size=len(data))
        for archive_path, data in payload
    ]

    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / artifact_name(version, architecture)
    _write_archive(archive, payload)

    manifest = manifest_document(
        version=version,
        architecture=architecture,
        elf=identity,
        artifact=archive.name,
        digest=_digest(archive.read_bytes()),
        components=[component.as_record() for component in components],
    )

    manifest_path = out_dir / manifest_name(version, architecture)
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    manifest_path.write_bytes(manifest_bytes)
    (out_dir / f"{manifest_path.name}.sha256").write_text(
        f"{_digest(manifest_bytes)}  {manifest_path.name}\n", encoding="utf-8"
    )
    return archive, manifest_path


def artifact_name(version: str, architecture: str) -> str:
    return f"{PACKAGE_NAME}-{version}-{architecture}.tar.gz"


def manifest_name(version: str, architecture: str) -> str:
    return f"{PACKAGE_NAME}-{version}-{architecture}.manifest.json"


def manifest_document(
    *,
    version: str,
    architecture: str,
    elf: ElfIdentity,
    artifact: str,
    digest: str,
    components: list[dict],
) -> dict:
    """The manifest, as a document, separated from writing it.

    Extracted so the contract export below derives its schema from **this**
    function rather than from a second description of it. A schema written by
    hand is a schema that stops matching the first time a field is added, and
    the consumer that trusted it would be verifying a shape nothing produces.
    """

    return {
        "contract": MANIFEST_CONTRACT,
        "package": PACKAGE_NAME,
        "version": version,
        "architecture": architecture,
        "elf": elf.as_record(),
        "artifact": artifact,
        "digest": digest,
        "signed": False,
        "signed_reason": (
            "signing-key operations are out of scope for this artifact. An "
            "unsigned digest establishes integrity against accidental change "
            "-- a truncated copy, a half-written file, the wrong build put in "
            "place -- and not against an adversary who can rewrite the package "
            "and this manifest together. A consumer must degrade rather than "
            "treat it as authenticity"
        ),
        "components": list(components),
        "health": {
            "contract": HEALTH_CONTRACT,
            "kind": "cli",
            "command": ["bin/azazel-edge-core", "--health"],
            "healthy_when": (
                "the process exits 0 AND stdout parses as JSON AND its "
                "`contract` equals the contract above AND its `status` is "
                "'healthy'. All four, because a truncated or garbled stdout "
                "must not be able to read as healthy"
            ),
            "establishes": (
                "that this binary is present, is this version, and can "
                "evaluate its own posture"
            ),
            "does_not_establish": (
                "that anything is running. A one-shot check says nothing about "
                "a daemon, so a consumer determines the running state "
                "separately"
            ),
        },
        "startup": {
            "command": ["bin/azazel-edge-core"],
            "observe_only_env": dict(sorted(OBSERVE_ONLY_ENV.items())),
            "network_configuration": "none",
            "note": (
                "this package starts nothing. It declares how a supervisor "
                "should start the payload and what observe-only means; "
                "bringing it up is the consumer's service manager's job"
            ),
        },
        "posture": {
            "observe_only": True,
            "enforcement": False,
            "redirect": False,
            "external_device_change": False,
            "network_configuration_change": False,
        },
        "not_established_by_accepting_this_package": [
            "that the payload is running",
            "that the digest is authentic rather than merely consistent",
            "edge-baseline-ready, which needs package, version, digest, health "
            "and running state together",
        ],
    }


def _write_archive(archive: Path, payload: Sequence[tuple[str, bytes]]) -> None:
    """Byte-identical for identical inputs.

    Sorted entries, zeroed mtimes, zeroed ownership, fixed modes, and a gzip
    header with no timestamp. Each of those is a place a timestamp or a
    username would otherwise leak into a digest Nexus is about to compare.
    """

    with gzip.GzipFile(filename="", mode="wb", fileobj=archive.open("wb"), mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for archive_path, data in sorted(payload, key=lambda pair: pair[0]):
                info = tarfile.TarInfo(name=archive_path)
                info.size = len(data)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = 0o755 if archive_path.startswith("bin/") else 0o644
                import io

                tar.addfile(info, io.BytesIO(data))


# -- the contract Nexus pins ------------------------------------------------
#
# Azazel-Nexus#44 verifies this package. It needs to know the *shape* it is
# verifying, and it cannot import this module: the two repositories build and
# test separately, and a consumer that needed the producer's source in its own
# CI would not be verifying a contract, it would be sharing an implementation.
#
# So the shape is exported as three small documents that both repositories
# commit. They contain **no digest and no timestamp**, which is what lets them
# stay byte-identical across rebuilds: a contract that changed every time the
# binary was recompiled would be re-approved so often that nobody would read
# the diff.
#
# The schemas are derived from `manifest_document` and from the binary's own
# `--health` output rather than restated. A hand-written schema is a second
# description, and the first time the two disagree it is the consumer that
# breaks, believing it verified something.

CONTRACT_DIR = Path(__file__).resolve().parent / "contract"

#: What a consumer pins. A version bump has to be written here, which means it
#: shows up in the diff of both repositories rather than only in a filename.
#: v2: one entry per CPU (`architectures`) instead of one `architecture`.
PIN_CONTRACT = "azazel-edge-core/nexus-pin/v2"
SCHEMA_CONTRACT = "azazel-edge-core/contract-schema/v1"

#: Placeholder values for deriving the manifest schema. They are never
#: written into a package; a schema only needs the shape.
_SCHEMA_DIGEST = "sha256:" + "0" * 64


def key_paths(document: object, prefix: str = "") -> list[str]:
    """Every field of a JSON document, as sorted dotted paths.

    A list of objects contributes `name[].field`, because a consumer reading
    `components` cares which fields each entry carries and not how many
    entries a particular build happened to produce.
    """

    found: list[str] = []
    if isinstance(document, dict):
        for key in sorted(document):
            path = f"{prefix}.{key}" if prefix else str(key)
            child = key_paths(document[key], path)
            found.extend(child or [path])
    elif isinstance(document, list):
        merged: set[str] = set()
        for item in document:
            if isinstance(item, (dict, list)):
                merged.update(key_paths(item, f"{prefix}[]"))
        found.extend(sorted(merged))
    return sorted(set(found))


def manifest_schema() -> dict:
    """The manifest's shape, derived from the function that writes manifests."""

    document = manifest_document(
        version="0.0.0",
        architecture="x86_64",
        elf=ARCHITECTURES["x86_64"],
        artifact=artifact_name("0.0.0", "x86_64"),
        digest=_SCHEMA_DIGEST,
        components=[Component(path="bin/placeholder", digest=_SCHEMA_DIGEST, size=0).as_record()],
    )
    return {
        "contract": SCHEMA_CONTRACT,
        "describes": MANIFEST_CONTRACT,
        "keys": key_paths(document),
    }


def health_schema(binary: Path) -> dict:
    """The health report's shape, derived by running the binary twice.

    Twice, because the unhealthy branch has to be observed rather than
    asserted. A contract that documented only the healthy answer would let a
    consumer be written that never tested the case it exists to catch.
    """

    healthy = _run_health(binary, {})
    unhealthy = _run_health(binary, {"AZAZEL_DEFENSE_ENFORCE": "true"})
    if healthy["report"]["status"] != "healthy" or healthy["code"] != 0:
        raise BuildRefused(
            "the binary does not report healthy under its own observe-only "
            "defaults; the contract would document a posture it cannot reach"
        )
    if unhealthy["report"]["status"] != "unhealthy" or unhealthy["code"] == 0:
        raise BuildRefused(
            "enforcement enabled did not produce an unhealthy report and a "
            "non-zero exit; a consumer could then read unhealthy as healthy"
        )
    keys = key_paths(healthy["report"])
    if keys != key_paths(unhealthy["report"]):
        raise BuildRefused(
            "the healthy and unhealthy reports have different shapes; a "
            "consumer parsing one would fail on the other"
        )
    return {
        "contract": SCHEMA_CONTRACT,
        "describes": HEALTH_CONTRACT,
        "keys": keys,
        "checks": sorted(check["name"] for check in healthy["report"]["checks"]),
        "healthy_status": "healthy",
        "unhealthy_status": unhealthy["report"]["status"],
        "healthy_exit_code": 0,
        "healthy_when": [
            "the process exits 0",
            "stdout parses as JSON",
            "the report's contract equals the health contract",
            "the report's status is the healthy status",
        ],
        "does_not_establish": [
            "that the payload is running",
        ],
    }


def _run_health(binary: Path, env_overrides: dict) -> dict:
    import os

    env = dict(os.environ)
    env.update(env_overrides)
    try:
        completed = subprocess.run(
            [str(binary), "--health"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            cwd=str(ROOT),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildRefused(f"the payload binary does not answer --health: {exc}") from exc
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BuildRefused(f"--health did not print JSON: {exc}") from exc
    return {"code": completed.returncode, "report": report}


def pin_document(version: str) -> dict:
    """Exactly what a consumer fixes. Nothing derived, nothing optional.

    One entry per CPU, each naming its artifact, its manifest and the ELF
    identity its binary carries. Still no digest: a digest changes with every
    rebuild, and which build a consumer accepts is the consumer's pin.
    """

    return {
        "contract": PIN_CONTRACT,
        "package": PACKAGE_NAME,
        "version": version,
        "architectures": {
            name: {
                "artifact": artifact_name(version, name),
                "manifest": manifest_name(version, name),
                "elf": identity.as_record(),
            }
            for name, identity in sorted(ARCHITECTURES.items())
        },
        "manifest_contract": MANIFEST_CONTRACT,
        "health_contract": HEALTH_CONTRACT,
        "signed": False,
        "consumer_must": [
            "select the entry for the host's CPU (Linux uname -m) and refuse a "
            "package whose name, manifest architecture or binary ELF header "
            "names another CPU, or whose ELF header is not the one listed for it",
            "re-derive the artifact digest and compare it with the manifest",
            "treat a digest match as integrity against accidental change only, "
            "because nothing here is signed",
            "report package absence, a corrupt manifest, a version mismatch, a "
            "digest mismatch, an unhealthy report and a not-running payload as "
            "six separate findings",
            "not claim edge-baseline-ready from accepting this package",
        ],
    }


def contract_documents(root: Path) -> dict[str, dict]:
    """The three documents, by filename."""

    version = _version(root)
    binary = root / dict(PAYLOAD)["bin/azazel-edge-core"]
    if not binary.is_file():
        raise BuildRefused(
            f"{binary} is not built; the health contract is derived by running "
            "the binary and is never written from memory"
        )
    _binary_reports(binary, version)
    return {
        "pin.json": pin_document(version),
        "manifest-schema.json": manifest_schema(),
        "health-schema.json": health_schema(binary),
    }


def write_contract(root: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, document in sorted(contract_documents(root).items()):
        path = out_dir / name
        path.write_bytes(
            (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
                "utf-8"
            )
        )
        written.append(path)
    return written


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "nexus-core")
    parser.add_argument(
        "--emit-contract",
        action="store_true",
        help=(
            "write the pin and schemas Azazel-Nexus commits, instead of "
            "building a package"
        ),
    )
    parser.add_argument("--contract-dir", type=Path, default=CONTRACT_DIR)
    parser.add_argument(
        "--architecture",
        choices=sorted(ARCHITECTURES),
        help=(
            "the CPU being packaged (required to build). Checked against the "
            "binary's ELF header; a mismatch refuses"
        ),
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.emit_contract:
            for path in write_contract(args.root, args.contract_dir):
                print(path)
            return 0
        if args.architecture is None:
            raise BuildRefused(
                "--architecture is required to build a package; it is checked "
                "against the binary and never assumed"
            )
        archive, manifest = build(args.root, args.out, architecture=args.architecture)
    except BuildRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(archive)
    print(manifest)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
