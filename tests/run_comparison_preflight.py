"""Offline software preflight plus unchanged, explicitly synthetic pilot replay."""

import argparse
import hashlib
import json
from pathlib import Path

from azazel_edge.benchmark.benefit import manifest_digest
from azazel_edge.benchmark.comparison_preflight import (
    evaluate_comparison_preflight,
    INPUT_SCHEMA,
)
from run_measurement_pilot import run as historical_run

ROOT = Path(__file__).parent / "fixtures" / "comparison-preflight" / "v1"
PLAN_PIN = "96388cd451b7340fd0dd4ec45cef1ef5e1fbf854907ca1da873d732c64e23815"
MANIFEST_PIN = "26cbab9603a8774b676b6976ac91f68e9697b7d8e3adcb57ff2ebee3421b4063"


def wire(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )


def run(export=None):
    plan_raw = (ROOT / "plan.json").read_bytes()
    manifest_raw = (ROOT / "manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    inputs_raw = wire(
        dict(
            schema_version=INPUT_SCHEMA,
            manifest_sha256=manifest_digest(manifest),
            records=[],
        )
    )
    preflight = evaluate_comparison_preflight(
        plan_raw,
        manifest_raw,
        inputs_raw,
        expected_plan_sha256=PLAN_PIN,
        expected_manifest_sha256=MANIFEST_PIN,
    )
    output = Path(export) if export is not None else None
    if output is not None:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        for name, raw in dict(
            plan=plan_raw, manifest=manifest_raw, inputs=inputs_raw
        ).items():
            with (output / (name + ".raw")).open("xb") as stream:
                stream.write(raw)
        with (output / "preflight.json").open("xb") as stream:
            stream.write(wire(preflight))
    # The old nine-case regression remains a separate original report group.
    historical = historical_run(
        output / "original-pilot" if output is not None else None
    )
    report = dict(
        schema_version="edge-comparison-preflight-lab/v1",
        evidence_kind="SOFTWARE_PREFLIGHT_AND_SYNTHETIC_REGRESSION",
        preflight=preflight,
        original_synthetic_pilot=historical,
        actual_comparison_started=False,
        comparison_qualified=False,
        qualified_safety_count=None,
        production_admission=False,
        source_provenance="pinned_readonly_checkout_not_independent_measurement_custody",
    )
    if output is not None:
        with (output / "report.json").open("xb") as stream:
            stream.write(wire(report))
        inventory = {
            str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob("*"))
            if p.is_file()
        }
        with (output / "inventory.json").open("xb") as stream:
            stream.write(wire(inventory))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.export), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
