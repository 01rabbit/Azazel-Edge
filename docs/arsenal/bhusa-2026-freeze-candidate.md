# BHUSA 2026 Freeze Candidate

This note defines the final freeze rule for the Black Hat USA 2026 booth demo.

## Freeze principle

After the freeze point, prioritize repeatability, documentation accuracy, and
operator-visible explanation over all new capability work.

The freeze candidate exists to protect the accepted session story:

- deterministic edge decision support
- separate NOC/SOC evaluation
- bounded action selection
- structured explanation
- local auditability

## Freeze timing

Recommended freeze window:

- target start: `2026-07-28`
- target end: session day `2026-08-05`

This leaves one week for rehearsal-only validation and narrow blocker fixes.

## Candidate selection rule

Pick the freeze candidate only after these are true on the target booth device:

- `mixed_correlation_demo` replay succeeds
- compact audit review succeeds
- replay-only fallback succeeds with no Internet dependency
- booth view or CLI fallback is stable
- at least one fallback drill has been completed

## Current observed baseline

Current repository baseline at planning time:

- branch: `main`
- observed commit: `dc8b56a`
- observed commit subject: `docs: record subissue creation target safe`

This is a planning reference only. It is not automatically the final freeze
candidate.

## Allowed changes after freeze

Allowed only with narrow justification tied to demo correctness or stability:

- docs wording fixes for the accepted session story
- booth notes and command sheet corrections
- deterministic replay bug fixes for the selected booth scenario
- audit walkthrough fixes
- booth-safe UI text fixes
- packaging or path fixes required to run the known-good booth flow

## Disallowed changes after freeze

Do not merge these after freeze unless the user explicitly reopens scope for a
true demo blocker:

- large refactors
- new integrations
- new AI behavior in the core decision path
- CTI sensorization expansion
- architecture rewrites
- broad UI redesign
- scenario changes away from `mixed_correlation_demo` without a blocker

## Required freeze verification

Run these on the booth device:

```bash
bin/azazel-edge-bhusa-prep candidate-pack --force
bin/azazel-edge-bhusa-freeze-record --force
bin/azazel-edge-bhusa-archive --force
bin/azazel-edge-bhusa-freeze-check
bin/azazel-edge-bhusa-verify
bin/azazel-edge-scenario-replay run mixed_correlation_demo
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --compact
bin/azazel-edge-scenario-replay clear
```

Also confirm:

- README still states Azazel-Edge is not a production SIEM replacement
- booth docs still describe AI as optional operator support
- live boundary docs still keep replay separate from normal live operation
- one offline copy of the booth docs is present on the device
- rehearsal log shows at least 3 recorded full rehearsals

Rehearsal evidence command:

```bash
bin/azazel-edge-bhusa-rehearse summary
bin/azazel-edge-bhusa-prep candidate-pack --force
bin/azazel-edge-bhusa-freeze-check
bin/azazel-edge-bhusa-bundle --force
bin/azazel-edge-bhusa-report --force
bin/azazel-edge-bhusa-archive --force
bin/azazel-edge-bhusa-freeze-record --force
```

## Freeze approval checklist

- [ ] known-good branch/tag/commit identified
- [ ] final booth command sheet archived
- [ ] replay path verified
- [ ] audit walkthrough verified
- [ ] replay-only fallback verified
- [ ] no post-freeze broad feature work pending

## Post-freeze change log rule

Every post-freeze change must record:

- why it is necessary for demo correctness or stability
- which booth path it affects
- what regression check was rerun

If that justification is missing, defer the change until after Vegas.
