#!/usr/bin/env python3
"""Optional Knowledge Lite verification using the producer's own verifier.

No private key, remote service, Nexus runtime, or Arbiter integration.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import tempfile

def verify(bundle: Path, anchors: Path, state: Path, *, fixture_mode: bool = False) -> dict:
    if not all(p.is_file() for p in (bundle, anchors, state)):
        return {"ok": False, "status": "missing_input"}
    if not fixture_mode and "fixture" in str(anchors).lower():
        return {"ok": False, "status": "fixture_anchor_refused"}
    try:
        from azazel_knowledge.bundle.verify import verify_bundle
    except ImportError:
        return {"ok": False, "status": "producer_verifier_unavailable",
                "detail": "Install the pinned Azazel-Knowledge verifier and PyNaCl; no fallback"}
    try:
        with tempfile.TemporaryDirectory(prefix="azazel-knowledge-verify-") as stage:
            verified = verify_bundle(bundle, anchors, state, stage)
            manifest = verified.manifest
            return {"ok": True, "status": "verified_fixture" if fixture_mode else "verified",
                    "bundle_format_version": manifest.get("bundle_format_version", 1),
                    "bundle_version": manifest.get("bundle_version"),
                    "datasets": sorted(verified.file_paths.keys()),
                    "advisory_only": True, "arbiter_unchanged": True,
                    "note": "Signature and payload verified; per-claim expiry must be evaluated at query time"}
    except Exception as exc:
        # The producer documents decoder exceptions in addition to its own
        # BundleVerifyError. Any exception must refuse admission.
        return {"ok": False, "status": "verification_refused",
                "error_type": type(exc).__name__,
                "code": str(getattr(exc, "code", "BUNDLE_VERIFY_FAILED"))}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--anchors", type=Path, required=True)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--fixture-mode", action="store_true",
                   help="Test-only fixture verification; never production admission")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = verify(args.bundle, args.anchors, args.state, fixture_mode=args.fixture_mode)
    body = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body)
    print(body, end="")
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
