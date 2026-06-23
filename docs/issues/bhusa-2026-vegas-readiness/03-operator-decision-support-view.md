# BHUSA 2026: operator decision-support view

Parent roadmap: #283

## Purpose

Improve the operator-facing view so Arsenal visitors can see the deterministic SOC/NOC decision loop in seconds.

This is a decision-support display, not a generic SIEM dashboard and not an AI chat interface.

## Required visible story

The view should make the following sequence obvious:

1. Evidence was ingested.
2. NOC and SOC context were evaluated separately.
3. The Action Arbiter selected one bounded action.
4. Stronger/weaker alternatives were rejected for explicit reasons.
5. Operator-facing explanation and audit context were recorded.

## Tasks

- [ ] Identify the current Web UI route/component that should become the Vegas decision-support view.
- [ ] Display Current Mode or current posture.
- [ ] Display Evidence Summary with evidence IDs.
- [ ] Display separate NOC and SOC evaluator outputs.
- [ ] Display Selected Action from the bounded action set: `observe`, `notify`, `throttle`, `redirect`, `isolate`.
- [ ] Display `why_chosen` in operator-readable wording.
- [ ] Display `why_not_others` for rejected actions.
- [ ] Display policy profile and release condition when available.
- [ ] Display AI Assist status as `not used`, `optional summary`, or equivalent bounded wording.
- [ ] Display audit trace ID and make the audit review command easy to copy.
- [ ] Add a booth-safe compact mode for projected or laptop screen viewing.

## Acceptance criteria

- A booth visitor can identify evidence, decision, action, explanation, and audit trail without reading raw JSON.
- The view reinforces deterministic edge decision support rather than autonomous AI control.
- The view can be populated from deterministic replay output.
- The view does not require optional integrations such as Wazuh, TAXII/STIX, Aggregator fleet view, or external services.
- If Web UI fails, the same story can still be shown through CLI and JSON logs as documented fallback.

## References

- `azazel_edge_web/`
- `docs/API_REFERENCE.md`
- `docs/P0_RUNTIME_ARCHITECTURE.md`
- `docs/ARSENAL_DEMO_PROFILE.md`
- `py/azazel_edge/explanations/decision.py`
