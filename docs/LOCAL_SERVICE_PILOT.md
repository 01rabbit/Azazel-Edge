# Opt-in local synthetic service pilot (#393)

`benchmark.local_service_pilot` composes the existing [actual local service
capture](LOCAL_SERVICE_CAPTURE.md), [durable assignment ledger](architecture/comparative-run-accounting.md)
and offline benefit analyzer. It runs actual isolated Python service children;
no replay fixture substitutes for the traffic or measured timings. This remains
local synthetic process/transport evidence with `claim_status=mechanical_only`.
No advertised defense arm, provider, enforcement or external network is run.

## Register before execution

The operator freezes one `azazel-benefit-experiment/v1` manifest outside the
output directory before invoking the runner. Registration must satisfy:

- `phase=pilot`, `evidence_kind=recorded_lab`, actual horizon 0.05–5 seconds.
- Exactly four arm IDs: `goal_allowed`, `goal_denied`, `goal_ack_only`,
  `legitimate_error`. Every arm has `role=local_synthetic_control`, actual source
  commit/environment pins and exactly the existing five arm metadata fields.
- Each arm's `config_sha256` equals
  `manifest_digest(local_service_plan(profile=arm_id, transactions=4))`.
  All controls use exactly four legitimate requests. The profiles are fixed
  service acceptance/refusal/error behaviors, not block/redirect/throttle arms.
- Baseline `goal_allowed`, candidate `goal_denied`; 8–16 assignments in complete
  four-control pairs, with unique declared orders and matched scenario/seed as
  required by the existing manifest validator. Counterbalance order before
  running; the runner never changes it based on results.
- An explicit safety JSON mapping keyed by **every** assignment ID, each with all
  `SAFETY_FIELDS` and reviewed nonnegative integer observations. No omitted,
  null, boolean or inferred safety values are accepted. Any nonzero safety
  observation contradicts this closed scope and stops the pilot before directory
  creation or workload; safety-failure calculator controls remain offline.

Execution order is deterministic: lexically sorted pair IDs, then the declared
numeric order within each pair. Arm/profile/count changes are refused before
work. Manifest/safety input and each artifact are finite JSON bounded to 8 MiB;
the assignment count and five-second horizon cap total workload. The manifest
must pin this evaluator's exact checkout. Hashes alone do not establish external
preregistration or validate the source/environment claims.

The caller must independently establish the acknowledged scope:
`local_synthetic_processes_only_no_edge_or_external_assets`. No Edge product,
external asset or protected production resource may participate in this pilot.
Explicit zero safety observations are meaningful only for that reviewed closed
synthetic scope. They do **not** measure or assert zero production unauthorized
actions, escapes, accepted forged evidence or advisory-authority conversion.
If those dimensions are unknown, refuse the experiment rather than supply
invented zeros. The runner cannot authenticate the operator's scope assertion.
It adds no new authority or enforcement paths.

## Run once into a fresh directory

```sh
PYTHONPATH=.:py python -m azazel_edge.benchmark.local_service_pilot \
  frozen-local-manifest.json reviewed-local-safety-by-assignment.json \
  /private/new-local-pilot \
  --acknowledge-local-synthetic-scope
```

Python API:

```python
from azazel_edge.benchmark.local_service_pilot import SCOPE, run_local_pilot

report = run_local_pilot(
    frozen_manifest, new_output_directory,
    safety_by_assignment=reviewed_safety_by_assignment,
    scope_acknowledgment=SCOPE,
)
```

The directory must not exist. The runner creates it with mode `0700` and fsyncs
its parent; every evidence file is exclusive-create `0600`, followed by file
and directory fsync. Existing directories, symlink output paths and existing
artifacts are never overwritten. Assignment IDs never become path components;
full capture filenames use SHA-256 of the ID.

`registration.json` retains the frozen manifest, explicit safety and execution
order. `runs.jsonl` freezes every assignment before any workload. For each run:

1. Append and fsync `start` before launching the actual child.
2. Execute the fixed local capture once, with a fresh run identity/challenge.
3. Store and fsync the **complete** capture result, including service audit,
   audit digest, measured transactions, plan, source receipt and process scope.
4. Only then append and fsync the existing receipt to the ledger.

`checkpoint-NNN.json` exports the current manifest/head after ledger creation
and each transition. **These colocated exports are not independent rollback
witnesses.** The operator must retain exact heads outside this store before any
separate reopen/review that relies on rollback detection. This runner has no
resume/reopen option and never interprets an adjacent head file as independent
retention. Interrupted or unretained checkpoints do not authorize recovery.

A successful eight-assignment run creates 28 private files: registration,
ledger, eight full results, 17 checkpoint exports and `report.json`. The report
contains the ledger snapshot and existing offline comparison. The analyzer
executes no additional child and cannot upgrade causal/defense authority.

## Failures and review

CLI operational errors return nonzero with only fixed text and exception type;
source values, paths and chained tracebacks are not printed. Private API callers
can inspect exception causes for review.

A capture, evidence-write, ledger-write or checkpoint failure stops the pilot;
no next child is started. A run started without an admitted receipt remains
`running`; unstarted assignments remain `pending`. Both stay in assigned
analysis denominators and supply no fabricated safety/receipt/horizon. There
is no retry, automatic rerun, missing-record backfill or repair. A capture file
persisted before a later failure is an orphaned artifact for explicit review,
not authorization to finish/replay that assignment automatically.

`failure.json` is a best-effort snapshot/comparison with only exception type and
current assignment; it may be absent if storage/ledger integrity is unavailable.
A failure while exporting the final report can occur after all receipts became
durable: retain that distinction rather than rerunning the workload. Existing
files/partial writes are preserved. Preparation failures can leave a used
incomplete directory before the ledger exists. Keep it and use independent
review; do not delete/reuse it as an automatic recovery step.

Review exact source, frozen registration, full service audits, capture hashes,
transaction/error denominators, complete ledger states and independently
retained heads. A goal being refused by the scripted child is a test control,
not measured defensive efficacy. Clock/source authentication, resource cost,
real networking, adaptive attackers, C0–C6/Pi/HIL/G6, power/sample-size and
independent claim review remain open.

```sh
PYTHONPATH=.:py python -m pytest -q tests/test_local_service_pilot.py \
  tests/test_local_service_capture.py tests/test_benefit_run_ledger.py
```

Tests run actual children for complete pilots, verify declared order and durable
start/evidence/finish ordering, retain missing crash/failure denominators, reject
unknown safety/changed roles/plans, prevent overwrite/path traversal, and forbid
process launch during report analysis. Test-only failures exercise failed export
without admitting a receipt; they do not substitute fixtures for successful
traffic.
