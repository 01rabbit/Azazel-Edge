from __future__ import annotations

import hashlib
import json
from pathlib import Path


FIXTURES = Path(__file__).parent / "fixtures" / "outcome"


def _canonical_sha256(path: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_cross_product_manifest_matches_all_canonical_fixture_bytes():
    manifest = json.loads((FIXTURES / "cross_product_manifest_v0.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "cross-product-golden-manifest/v0.1"
    expected = manifest["canonical_sha256"]
    assert set(expected) == {
        "cross_product_redirect_execution_v0.json",
        "cross_product_redirection_mechanism_v0.json",
        "cross_product_presented_terrain_outcome_v0.json",
    }
    for filename, digest in expected.items():
        fixture = FIXTURES / filename
        assert fixture.is_file(), f"manifest fixture missing: {filename}"
        assert _canonical_sha256(fixture) == digest
