#!/usr/bin/env python3
"""Read-only, cross-platform inspection of optional Nexus-produced resources.

This is an admission report, not a package installer or a signature verifier.
Nexus is not imported and cannot become an action authority.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def inspect_edge_pin(pin_path: Path, artifact_dir: Path) -> dict:
    try:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"status": "invalid_pin", "error": type(exc).__name__}
    if pin.get("contract") != "azazel-edge-core/nexus-pin/v2":
        return {"status": "unsupported_contract"}
    arch = platform.machine().lower()
    # The pin describes Linux ELF binaries. Do not mistake Apple Silicon
    # for a Linux aarch64 deployment target.
    if platform.system() != "Linux":
        return {"status": "unsupported_platform", "platform": platform.system(),
                "detail": "Linux ELF package is not a macOS runtime"}
    arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(arch, arch)
    entry = pin.get("architectures", {}).get(arch)
    if not isinstance(entry, dict):
        return {"status": "unsupported_architecture", "architecture": arch}
    artifact_name, manifest_name = entry.get("artifact"), entry.get("manifest")
    if not all(isinstance(x, str) and x == Path(x).name for x in (artifact_name, manifest_name)):
        return {"status": "invalid_pin_paths"}
    artifact, manifest = artifact_dir / artifact_name, artifact_dir / manifest_name
    if not artifact.is_file() or not manifest.is_file():
        return {"status": "package_absent", "artifact": artifact_name, "manifest": manifest_name}
    try:
        metadata = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"status": "corrupt_manifest"}
    # Digest field names are contract-specific; do not guess and claim admission.
    return {"status": "present_unverified", "artifact_sha256": sha256(artifact),
            "manifest_sha256": sha256(manifest),
            "detail": "Nexus v2 manifest verifier and ELF validation required before admission"}

def inspect_knowledge(path: Path) -> dict:
    if not path.is_file():
        return {"status": "bundle_absent"}
    return {"status": "present_unverified", "sha256": sha256(path),
            "detail": "Knowledge signature, member digests, anti-rollback and expiry not verified"}

def inspect_resources(pin: Path, artifact_dir: Path, knowledge_bundle: Path) -> dict:
    edge = inspect_edge_pin(pin, artifact_dir)
    knowledge = inspect_knowledge(knowledge_bundle)
    return {"edge_core": edge, "knowledge_lite": knowledge,
            "admitted": False,
            "authority": "Azazel-Edge deterministic Action Arbiter",
            "nexus_runtime_required": False}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--knowledge-bundle", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect_resources(args.pin, args.artifact_dir, args.knowledge_bundle), indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
