# Durable local comparison-run accounting

Owners: Edge #393 and Azazel #67. `benchmark.run_ledger.RunLedger` adds local
experiment accounting around the existing manifest, receipt and analyzer. It
does not generate observations, execute workloads, launch a provider, or enable
production enforcement. All assignments are frozen in the first record.

## Procedure and responsibility

The operator first freezes and independently retains the manifest/registration.
Create one new file in an operator-owned mode-0700 directory:

```python
with RunLedger(path, manifest=frozen_manifest) as ledger:
    retain_checkpoint_elsewhere(ledger.head_sha256)
    ledger.start(assignment_id, run_id)
    retain_checkpoint_elsewhere(ledger.head_sha256)
    # Only now may the separate approved scenario runner start its workload.
    # Retain the complete original capture/audit/plan bundle separately.
    ledger.finish(independently_observed_receipt)
    retain_checkpoint_elsewhere(ledger.head_sha256)
    report = analyze(ledger.manifest, ledger.snapshot()['observations'])
```

`retain_checkpoint_elsewhere` is an operator-owned integration requirement, not
an implementation supplied here. Reopening requires that exact externally
retained head. Merely extracting a head from an untrusted file cannot authorize
resume. A hash chain is neither independent preregistration nor authentication
of service truth. Receipt hashes bind source captures; original artifacts must
remain available for separate verification.

The file is exclusive-create, mode 0600, single-link, non-symlink, finite and
held under an exclusive nonblocking lifetime lock. Every transition is fsynced
before acknowledgement; creation also fsyncs the directory. Unexpected file
identity, link, permission or length changes refuse subsequent mutation. A
write/sync failure poisons the current handle. Partial tails and unmatched heads
refuse reopening; there is no truncate, repair, replay or automatic retry path.

A crash after `start` leaves the assignment visibly running. It cannot be
started again under the same assignment ID. Unstarted and interrupted runs stay
in the assignment denominator and have no completed receipt. The existing
analyzer sees their absent receipts as missing, never successful censoring.
An operator may explicitly record a failed/missing receipt with observed safety
fields and an evidence digest; no safety zeros or full horizon are synthesized.
Any repeat experiment requires a separately registered assignment/manifest,
retaining the original failed run. A receipt may be finalized only once against
its exact started assignment/run identity.

## Limits and acceptance

This is trusted-operator local accounting. It does not defend against malicious
same-UID/root writers, whole-store rollback together with the external checkpoint,
or a forged producer receipt. It adds no signing keys, runtime witness or trusted
clock. Advisory/analysis records cannot change runtime Outcome/effect authority.
Fsync ordering tests are software evidence, not power-cut/SD durability proof.

Tests cover real competing opens, stale checkpoints, edit/truncate/duplicate/
partial-tail refusal, write durability failure, private-file boundaries, crash
denominators, repeat/finalization refusal, immutable exports, existing analyzer
parity and absence of network/subprocess execution. Physical G6 and independent
efficacy/sample-size review remain separate gates.
