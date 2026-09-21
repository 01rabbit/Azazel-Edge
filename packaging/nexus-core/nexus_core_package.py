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

    manifest = manifest_document(
        version=version,
        artifact=archive.name,
        digest=_digest(archive.read_bytes()),
        components=[component.as_record() for component in components],
    )

    manifest_path = out_dir / f"{PACKAGE_NAME}-{version}-{ARCHITECTURE}.manifest.json"
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    manifest_path.write_bytes(manifest_bytes)
    (out_dir / f"{manifest_path.name}.sha256").write_text(
        f"{_digest(manifest_bytes)}  {manifest_path.name}\n", encoding="utf-8"
    )
    return archive, manifest_path


def manifest_document(
    *, version: str, artifact: str, digest: str, components: list[dict]
) -> dict:
    """The manifest, as a document, separated from writing it.

    Extracted so the contract export below derives its schema from **this**
    function rather than from a second description of it. A schema written by
    hand is a schema that stops matching the first time a field is added, and
    the consumer that trusted it would be verifying a shape nothing produces.
    """

    return {
        "contract": MANIFEST_CONTRACT,
        "contract": MANIFEST_CONTRACT,
        "package": PACKAGE_NAME,
        "version": version,
        "architecture": ARCHITECTURE,
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
PIN_CONTRACT = "azazel-edge-core/nexus-pin/v1"
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
        artifact=f"{PACKAGE_NAME}-0.0.0-{ARCHITECTURE}.tar.gz",
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
    """Exactly what a consumer fixes. Nothing derived, nothing optional."""

    return {
        "contract": PIN_CONTRACT,
        "package": PACKAGE_NAME,
        "version": version,
        "architecture": ARCHITECTURE,
        "manifest_contract": MANIFEST_CONTRACT,
        "health_contract": HEALTH_CONTRACT,
        "artifact": f"{PACKAGE_NAME}-{version}-{ARCHITECTURE}.tar.gz",
        "manifest": f"{PACKAGE_NAME}-{version}-{ARCHITECTURE}.manifest.json",
        "signed": False,
        "consumer_must": [
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
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.emit_contract:
            for path in write_contract(args.root, args.contract_dir):
                print(path)
            return 0
        archive, manifest = build(args.root, args.out)
    except BuildRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(archive)
    print(manifest)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
