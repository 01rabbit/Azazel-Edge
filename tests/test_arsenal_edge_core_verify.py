"""Synthetic contract tests for offline Edge Core integrity verification."""
from __future__ import annotations
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("core_verify", ROOT / "tools/arsenal_edge_core_verify.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def _inputs(tmp_path):
    elf = bytearray(64)
    elf[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", elf, 16, 2, 183, 1)
    binary = bytes(elf)
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        info = tarfile.TarInfo("bin/azazel-edge-core")
        info.size = len(binary)
        tar.addfile(info, io.BytesIO(binary))
    artifact = tmp_path / "azazel-edge-core-0.1.0-aarch64.tar.gz"
    artifact.write_bytes(out.getvalue())
    elf_contract = {"class": "ELFCLASS64", "data": "ELFDATA2LSB", "machine": "EM_AARCH64"}
    manifest = {"contract": "azazel-edge-core/package-manifest/v2", "package": "azazel-edge-core",
                "version": "0.1.0", "architecture": "aarch64", "artifact": artifact.name,
                "digest": mod.digest(out.getvalue()), "signed": False,
                "elf": elf_contract, "posture": {"observe_only": True},
                "components": [{"path": "bin/azazel-edge-core", "digest": mod.digest(binary), "size": len(binary)}]}
    manifest_path = tmp_path / "azazel-edge-core-0.1.0-aarch64.manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    pin = {"contract": "azazel-edge-core/nexus-pin/v2", "package": "azazel-edge-core",
           "version": "0.1.0", "signed": False, "architectures": {
               "aarch64": {"artifact": artifact.name, "manifest": manifest_path.name, "elf": elf_contract}}}
    pin_path = tmp_path / "pin.json"
    pin_path.write_text(json.dumps(pin))
    return pin_path, manifest_path, artifact

def test_valid_unsigned_integrity(tmp_path):
    result = mod.verify(*_inputs(tmp_path), "aarch64")
    assert result["ok"], result
    assert result["authenticity_verified"] is False

def test_tampered_archive_rejected(tmp_path):
    pin, manifest, artifact = _inputs(tmp_path)
    artifact.write_bytes(artifact.read_bytes() + b"tamper")
    assert not mod.verify(pin, manifest, artifact, "aarch64")["ok"]

def test_wrong_architecture_rejected(tmp_path):
    assert not mod.verify(*_inputs(tmp_path), "x86_64")["ok"]

def test_bad_component_digest_rejected(tmp_path):
    pin, manifest, artifact = _inputs(tmp_path)
    payload = json.loads(manifest.read_text())
    payload["components"][0]["digest"] = "sha256:" + "0" * 64
    manifest.write_text(json.dumps(payload))
    assert not mod.verify(pin, manifest, artifact, "aarch64")["ok"]
