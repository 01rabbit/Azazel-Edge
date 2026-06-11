<!--
Register with:
gh issue create \
  --title "[CFP] privacy-sensitive auditable demo scenario auditable_edge_socnoc" \
  --body-file docs/archive/issues/auditable-edge-socnoc/06-europe-demo-auditable-edge-socnoc.md \
  --label "auditable-edge-socnoc-cfp" --label "demo" --label "testing"
-->

## Summary

Add a new deterministic replay scenario with id `auditable_edge_socnoc` to
`DemoScenarioPack`, framed for privacy-sensitive, regulated, local-first
operation, that exercises a decision with rejected alternatives, a release
condition, `config_hash` / `policy_profile` display, and the audit-chain review.
Register it in the concept pack. Do not use any disaster, shelter, or emergency
narrative, and do not rename or delete any existing scenario id.

## Rationale

The CFP draft and paper currently note that a dedicated auditable scenario
`auditable_edge_socnoc` is Planned and does not exist; the concept pack reuses
`mixed_correlation_demo` and `disaster_phishing_demo`. The candidate auditable demo
needs a scenario whose narrative matches the profile (auditable, explainable,
local-first, regulated) rather than a disaster/shelter framing, and that directly
showcases the auditable decision record and the audit-chain walk.

## Tasks

- [ ] Add a new scenario `auditable_edge_socnoc` to `DemoScenarioPack.scenarios()`
      in `py/azazel_edge/demo/scenarios.py`, following the existing structure
      (`description`, `demo` metadata, `events`).
- [ ] Choose events that drive a decision with non-empty rejected alternatives and
      a meaningful release condition (e.g. a bounded-control or redirect path), so
      the explanation walk is substantive.
- [ ] Use neutral, regulated/privacy-sensitive framing in all narrative text. No
      disaster, shelter, evacuation, or emergency wording.
- [ ] Confirm the run reports `execution.mode = deterministic_replay` and
      `ai_used = false` (inherited from the runner) and that the explanation carries
      `config_hash` / `policy_profile`.
- [ ] Register the new id in `demos/concepts/auditable-edge-socnoc.yaml`
      `stage_order` and `scenarios`. Consider replacing the `disaster_phishing_demo`
      reference in this Europe-facing pack with the new scenario, while keeping the
      `disaster_phishing_demo` id intact everywhere else (do not rename or delete it).
- [ ] Update the CFP draft Demo Plan reference to name `auditable_edge_socnoc` once
      it exists (replacing the "Planned / does not exist" note).
- [ ] Add a test in `tests/test_demo_scenario_pack_v1.py` style asserting the
      scenario exists, runs, and produces an explanation with the required auditable
      fields (rejected alternatives, release condition, `config_hash`,
      `policy_profile`).

## Acceptance Criteria

- [ ] `bin/azazel-edge-demo run auditable_edge_socnoc` runs fully offline and
      reports `deterministic_replay` and `ai_used = false`.
- [ ] The scenario's explanation record contains non-empty rejected alternatives
      and a release condition, plus `config_hash` and `policy_profile`.
- [ ] The scenario narrative contains no disaster/shelter/emergency framing.
- [ ] No existing scenario id is renamed or removed; `disaster_phishing_demo`
      remains a valid id.
- [ ] `demos/concepts/auditable-edge-socnoc.yaml` lists `auditable_edge_socnoc` in
      `stage_order` and `scenarios`.
- [ ] A test covers the scenario.

## Files Likely Affected

- `py/azazel_edge/demo/scenarios.py` (new scenario)
- `demos/concepts/auditable-edge-socnoc.yaml` (registration)
- `docs/cfp/auditable-edge-socnoc-cfp-arsenal-auditable-edge-socnoc.md` (Demo Plan reference)
- `tests/test_demo_scenario_pack_v1.py` (new assertions)

## Dependencies

Depends on Issues 01, 02, 04, and 05 (confirmed fields, canonical schema,
config-hash/profile coverage, review command) so the demo walk uses verified,
consistent data.

## Risk

Medium. The scenario must keep deterministic replay stable and must not introduce
disaster framing or rename existing ids (a hard rule in `demos/concepts/README.md`).
Risk is contained because the scenario reuses existing deterministic machinery and
adds only data plus registration.
