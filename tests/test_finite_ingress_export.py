"""Public export allowlist and failure retention; no privileged lab claim."""

import importlib.util
import json
from pathlib import Path

import pytest

from azazel_edge.benchmark.finite_ingress import CASES, FILES

SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/collect_finite_ingress.py"
spec = importlib.util.spec_from_file_location("finite_public_export", SCRIPT)
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


def test_exact_allowlist_matches_frozen_evaluator_and_separate_case_scopes():
    assert export.NAMES == FILES
    assert set(export.MAIN) | set(export.FAULT) == set(CASES)
    assert not set(export.MAIN) & set(export.FAULT)
    with pytest.raises(ValueError, match="fixed finite-ingress flavor"):
        export.collect("../bundle")


def test_export_rejects_symlink_and_retains_missing_inventory(tmp_path, monkeypatch):
    source = tmp_path / "source"
    target = tmp_path / "public"
    source.mkdir()
    case = export.FAULT[0]
    (source / case).mkdir()
    private = tmp_path / "private"
    private.write_bytes(b"must not export")
    (source / case / "protocol.json").symlink_to(private)
    monkeypatch.setattr(export, "BASE", source)
    monkeypatch.setattr(export, "TARGET", target)
    with pytest.raises(AssertionError, match="originals missing or rejected"):
        export.collect("finite-ingress-fault")
    manifest = json.loads((target / "manifest.json").read_bytes())
    assert manifest["files"] == {}
    assert manifest["errors"] == [dict(path=case + "/protocol.json", error="AssertionError")]
    assert case + "/trust.json" in manifest["missing"]
    assert not (target / case / "protocol.json").exists()
    assert manifest["private_keys_exported"] is False
