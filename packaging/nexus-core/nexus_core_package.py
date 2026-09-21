#!/usr/bin/env python3
"""Build the x86_64 Edge Core package Azazel-Nexus verifies (Edge#424).

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
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[2]

PACKAGE_NAME = "azazel-edge-core"
ARCHITECTURE = "x86_64"
MANIFEST_CONTRACT = "azazel-edge-core/package-manifest/v1"
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


def build(root: Path, out_dir: Path) -> tuple[Path, Path]:
    """Write the package and its manifest. Returns both paths."""

    version = _version(root)
    payload = _payload_paths(root)
    binary = dict(payload)["bin/azazel-edge-core"]
    _binary_reports(binary, version)

    components = [
        Component(
            path=archive_path,
            digest=_digest(source.read_bytes()),
            size=source.stat().st_size,
        )
        for archive_path, source in payload
    ]

    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / f"{PACKAGE_NAME}-{version}-{ARCHITECTURE}.tar.gz"
    _write_archive(archive, payload)

    manifest = {
        "contract": MANIFEST_CONTRACT,
        "package": PACKAGE_NAME,
        "version": version,
        "architecture": ARCHITECTURE,
        "artifact": archive.name,
        "digest": _digest(archive.read_bytes()),
        "signed": False,
        "signed_reason": (
            "signing-key operations are out of scope for this artifact. An "
            "unsigned digest establishes integrity against accidental change "
            "-- a truncated copy, a half-written file, the wrong build put in "
            "place -- and not against an adversary who can rewrite the package "
            "and this manifest together. A consumer must degrade rather than "
            "treat it as authenticity"
        ),
        "components": [component.as_record() for component in components],
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

    manifest_path = out_dir / f"{PACKAGE_NAME}-{version}-{ARCHITECTURE}.manifest.json"
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    manifest_path.write_bytes(manifest_bytes)
    (out_dir / f"{manifest_path.name}.sha256").write_text(
        f"{_digest(manifest_bytes)}  {manifest_path.name}\n", encoding="utf-8"
    )
    return archive, manifest_path


def _write_archive(archive: Path, payload: Sequence[tuple[str, Path]]) -> None:
    """Byte-identical for identical inputs.

    Sorted entries, zeroed mtimes, zeroed ownership, fixed modes, and a gzip
    header with no timestamp. Each of those is a place a timestamp or a
    username would otherwise leak into a digest Nexus is about to compare.
    """

    with gzip.GzipFile(filename="", mode="wb", fileobj=archive.open("wb"), mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for archive_path, source in payload:
                info = tarfile.TarInfo(name=archive_path)
                data = source.read_bytes()
                info.size = len(data)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = 0o755 if archive_path.startswith("bin/") else 0o644
                import io

                tar.addfile(info, io.BytesIO(data))


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "nexus-core")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        archive, manifest = build(args.root, args.out)
    except BuildRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(archive)
    print(manifest)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
