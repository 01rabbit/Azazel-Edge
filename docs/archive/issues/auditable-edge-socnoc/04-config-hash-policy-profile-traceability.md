<!--
Register with:
gh issue create \
  --title "[CFP] Config hash / policy profile traceability across outputs" \
  --body-file docs/archive/issues/auditable-edge-socnoc/04-config-hash-policy-profile-traceability.md \
  --label "auditable-edge-socnoc-cfp" --label "audit" --label "documentation"
-->

## Summary

The SOC policy SHA-256 hash and `config_hash` already appear in v2 explanation
records. This issue verifies that every decision-bearing output stream carries
`config_hash` and `policy_profile`, extends the streams where they are missing,
and documents the reproducibility story. It advances the Planned full
config-hash / reproducibility packaging across all outputs.

## Rationale

Reproducibility anchoring is a stated technical differentiator: a recorded
decision should be tied to a known configuration and policy profile.

- The SOC policy SHA-256 is computed at load (`py/azazel_edge/policy.py`); the
  arbiter exposes it as `policy_hash`.
- The v2 explanation record carries `policy_profile` and `config_hash`
  (Implemented).
- Three policy profiles exist under `config/soc_policy_profiles/` selected via
  `AZAZEL_SOC_POLICY_PATH`; config-drift auditing exists
  (`py/azazel_edge/config_drift.py`).

Full packaging across *all* outputs is Planned. This issue narrows that gap by
making the per-stream coverage explicit and consistent, without claiming the
Planned packaging is finished.

## Tasks

- [ ] State explicitly that `config_hash` + `policy_profile` are present in v2
      explanation records (Implemented).
- [ ] Audit each decision-bearing stream (audit-chain action-decision records, the
      OpenCanary redirect records, demo replay outputs, and the tactics-engine
      record) for `config_hash` and `policy_profile`.
- [ ] Extend streams that are missing one or both fields, sourcing the policy hash
      from the loaded policy (`policy_hash`) and the profile from the active
      `AZAZEL_SOC_POLICY_PATH` selection.
- [ ] Confirm demo replay outputs carry `config_hash` / `policy_profile` so the
      reviewer can tie a demo decision to a profile.
- [ ] Document the reproducibility story: what is anchored today, and what full
      cross-output packaging (Planned) would still add. Do not describe the Planned
      packaging as done.
- [ ] Add a test asserting `config_hash` and `policy_profile` presence on each
      stream expected to carry them.

## Acceptance Criteria

- [ ] A per-stream table records `config_hash` / `policy_profile` presence and the
      source of each value.
- [ ] Streams that should carry both fields and previously did not now do.
- [ ] Demo replay outputs carry `config_hash` and `policy_profile`.
- [ ] A documented reproducibility note distinguishes Implemented anchoring from
      the Planned full-packaging work.
- [ ] A test asserts presence of both fields on each expected stream.

## Files Likely Affected

- `py/azazel_edge/policy.py` (policy hash; reference)
- `py/azazel_edge/explanations/decision.py` (reference)
- `py/azazel_edge/opencanary_redirect.py` (likely extended)
- `py/azazel_edge/audit/logger.py` (action-decision records; reference / extended)
- `py/azazel_edge/demo/scenarios.py` (demo output fields)
- `py/azazel_edge/config_drift.py` (reference)
- `docs/architecture/evidence-model.md`, `docs/SOC_POLICY_GUIDE.md`
- `tests/` (field-presence assertions)

## Dependencies

Depends on Issue 02 (stream inventory). Parallel to Issue 03 (same per-stream audit
for a different field set). Advances the Planned reproducibility-packaging item.

## Risk

Medium. Adds metadata fields to decision-recording streams; must not change
decision content or chain integrity, and must not imply the Planned full packaging
is complete.
