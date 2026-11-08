#!/usr/bin/env python3
"""Read-only Nexus v2 Edge Core package verification, portable to macOS.

Validates Linux ELF payload without executing it. A passing integrity check
is NOT a signature or runtime-health attestation.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import struct
import tarfile

ELF = {"aarch64": ("ELFCLASS64", "ELFDATA2LSB", "EM_AARCH64", 183),
       "x86_64": ("ELFCLASS64", "ELFDATA2LSB", "EM_X86_64", 62)}

def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()

def _safe_name(name: str) -> bool:
    p = PurePosixPath(name)
    return bool(name) and not p.is_absolute() and ".." not in p.parts and str(p) == name

def verify(pin_file: Path, manifest_file: Path, artifact_file: Path, architecture: str) -> dict:
    errors = []
    if architecture not in ELF:
        return {"ok": False, "errors": ["unsupported architecture"]}
    try:
        pin = json.loads(pin_file.read_text())
        manifest = json.loads(manifest_file.read_text())
        if not isinstance(pin, dict) or not isinstance(manifest, dict):
            raise ValueError("contracts must be JSON objects")
        artifact = artifact_file.read_bytes()
    except (OSError, ValueError) as exc:
        return {"ok": False, "errors": [f"unreadable input: {type(exc).__name__}"]}
    entry = pin.get("architectures", {}).get(architecture, {})
    if pin.get("contract") != "azazel-edge-core/nexus-pin/v2":
        errors.append("pin contract mismatch")
    if manifest.get("contract") != "azazel-edge-core/package-manifest/v2":
        errors.append("manifest contract mismatch")
    for key, expected in (("package", pin.get("package")), ("version", pin.get("version")),
                          ("architecture", architecture), ("artifact", entry.get("artifact"))):
        if manifest.get(key) != expected:
            errors.append(f"{key} mismatch")
    if manifest_file.name != entry.get("manifest") or artifact_file.name != entry.get("artifact"):
        errors.append("artifact/manifest filename mismatch")
    if pin.get("signed") is not False or manifest.get("signed") is not False:
        errors.append("unsupported signing claim")
    if manifest.get("digest") != digest(artifact):
        errors.append("artifact digest mismatch")
    expected_elf = dict(zip(("class", "data", "machine"), ELF[architecture][:3]))
    if manifest.get("elf") != expected_elf or entry.get("elf") != expected_elf:
        errors.append("ELF contract mismatch")
    components = manifest.get("components")
    if not isinstance(components, list) or not components:
        errors.append("components missing")
        components = []
    declared = {}
    for component in components:
        if not isinstance(component, dict):
            errors.append("malformed component"); continue
        name = component.get("path")
        if not isinstance(name, str) or not _safe_name(name) or name in declared:
            errors.append("invalid or duplicate component path"); continue
        declared[name] = component
    try:
        with tarfile.open(fileobj=io.BytesIO(artifact), mode="r:gz") as tar:
            members = tar.getmembers()
            if len(members) > 64:
                errors.append("too many archive members")
            seen = set()
            for member in members:
                if not _safe_name(member.name) or not member.isfile() or member.name in seen:
                    errors.append("unsafe, non-file or duplicate archive member"); continue
                seen.add(member.name)
                if member.size > 32 * 1024 * 1024:
                    errors.append("oversized archive member"); continue
                stream = tar.extractfile(member)
                if stream is None:
                    errors.append("unreadable archive member"); continue
                data = stream.read(32 * 1024 * 1024 + 1)
                record = declared.get(member.name)
                if not record or record.get("size") != len(data) or record.get("digest") != digest(data):
                    errors.append(f"component mismatch: {member.name}")
                if member.name == "bin/azazel-edge-core":
                    if len(data) < 24 or data[:4] != b"\x7fELF" or data[4:7] != b"\x02\x01\x01":
                        errors.append("invalid ELF header")
                    else:
                        e_type, machine, version = struct.unpack_from("<HHI", data, 16)
                        if e_type not in (2, 3) or machine != ELF[architecture][3] or version != 1:
                            errors.append("ELF architecture/type mismatch")
            if seen != set(declared):
                errors.append("archive component set mismatch")
            if "bin/azazel-edge-core" not in seen:
                errors.append("missing Edge Core binary")
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        errors.append(f"invalid archive: {type(exc).__name__}")
    posture = manifest.get("posture", {})
    if not isinstance(posture, dict) or posture.get("observe_only") is not True:
        errors.append("observe-only posture not established")
    return {"ok": not errors, "errors": errors, "architecture": architecture,
            "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
            "integrity_only": True, "authenticity_verified": False,
            "running_verified": False, "health_verified": False}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pin", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--artifact", type=Path, required=True)
    p.add_argument("--architecture", choices=sorted(ELF), required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = verify(args.pin, args.manifest, args.artifact, args.architecture)
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
    print(output, end="")
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
