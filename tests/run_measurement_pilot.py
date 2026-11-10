"""Reproduce frozen synthetic pilot; optional new-directory artifact export."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from measurement_pilot_data import ROOT, inputs
from azazel_edge.benchmark.benefit import manifest_digest
from azazel_edge.benchmark.measurement import LIMITS, measure_experiment


def run(export=None):
    protocol=json.loads((ROOT/'protocol.json').read_text());cases=json.loads((ROOT/'cases.json').read_text())
    if manifest_digest(protocol)!=(ROOT/'protocol.sha256').read_text().strip() or manifest_digest(cases)!=protocol['cases_sha256']:
        raise ValueError('frozen pilot digest mismatch')
    if protocol['measurement_limits']!=LIMITS:raise ValueError('frozen resource/quality limits changed')
    if export is not None:export.mkdir(mode=0o700,parents=True,exist_ok=False)
    summaries=[]
    for case in cases:
        manifest,records=inputs(protocol,case)
        for record in records:
            binding=protocol['bindings'][record['assignment_id']]
            if any(binding[k]!=manifest_digest(record[field]) for k,field in [('capture_sha256','capture'),('recording_sha256','edge_recording'),('linkage_sha256','linkage')]):
                raise ValueError('frozen recording/capture/linkage changed')
        measured=dict(manifest_sha256=manifest_digest(manifest),records=records)
        bundle=measure_experiment(manifest,measured)
        if bundle['integrity_rejections'] or bundle['comparison']['measurement_gate']!=case['expected_gate']:
            raise ValueError('frozen expected measurement gate failed')
        if bundle['authorized_actions'] or bundle['canonical_records_mutated'] or any(row['edge_evidence']['causal_support']!='inconclusive' for row in bundle['ledger']):
            raise ValueError('canonical authority/causal boundary failed')
        summaries.append(dict(case_id=case['id'],assigned_runs=bundle['assigned_runs'],expected_gate=case['expected_gate'],
                              actual_gate=bundle['comparison']['measurement_gate'],claim_status=bundle['comparison']['claim_status'],bundle_sha256=manifest_digest(bundle)))
        if export is not None:
            for suffix,body in [('manifest',manifest),('inputs',measured),('bundle',bundle)]:
                with (export/(case['id']+'-'+suffix+'.json')).open('x',encoding='utf-8') as stream:
                    json.dump(body,stream,sort_keys=True,indent=2,allow_nan=False);stream.write('\n')
    report=dict(schema_version='edge-measurement-pilot-report/v2',protocol_sha256=manifest_digest(protocol),
                status='software_pilot_passed',claim_status='mechanical_only',scenarios=len(cases),assigned_runs=sum(c['assigned_runs'] for c in summaries),
                cases=summaries,canonical_causal_promotions=0,authorized_actions=[],
                outstanding=['independently labelled clients and real protected-service captures',
                             'independent preregistration and rerun','live before-window crash journal and device storage budget','G6 hardware/offline/service-cost acceptance'])
    if export is not None:
        with (export/'report.json').open('x',encoding='utf-8') as stream:json.dump(report,stream,sort_keys=True,indent=2);stream.write('\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--export',type=Path);args=parser.parse_args()
    try:report=run(args.export)
    except (ValueError,OSError,TypeError,KeyError) as exc:parser.exit(2,f'pilot did not complete: {exc}\n')
    print(json.dumps(report,sort_keys=True,indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
