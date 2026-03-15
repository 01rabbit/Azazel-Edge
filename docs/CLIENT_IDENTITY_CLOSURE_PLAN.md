# Client Identity Closure Plan

## Goal

Close the remaining implementation gaps for `Client Identity` so that:

1. Managed endpoints are limited to Azazel-Edge internal clients on `172.16.0.0/24`.
2. `eth0` and `wlan0` clients are visible separately.
3. `ARP-only` candidates are easy to recognize and easy to resolve.
4. Remote peers are not mixed into endpoint identity.
5. SoT edits affect runtime behavior, not just stored metadata.

## Critical Review

### What is already closed

- External `192.168.40.0/24` peers are excluded from `Client Identity`.
- `ETH` / `WLAN` grouping is visible.
- `ARP-only` candidates can be trusted or excluded.
- Remote peers are shown in a separate foldout.
- SoT can store trust, note, allowed networks, expected link, and ignore scope.

### What was still incomplete

- `expected_interface_or_segment` could be saved but did not influence monitoring.
- SoT could be empty, which made `allowed_networks` weak on first use.
- We did not have a clean closure statement separating
  - mandatory implementation work,
  - operational validation work,
  - optional future ideas.

## Final Mandatory Implementation Items

### 1. Expected-link enforcement

If a trusted endpoint has `expected_interface_or_segment=eth0|wlan0` and the observed link differs,
it must become an attention item.

Decision:

- Use the existing `MISMATCH` path rather than inventing a new state family.
- Surface it with a dedicated `LINK DRIFT` badge so operators know why it mismatched.

### 2. Managed-network bootstrap for SoT

When the SoT has no internal network entries yet, seed managed client networks from:

- `AZAZEL_MANAGED_CLIENT_CIDRS`
- default `172.16.0.0/24`

Decision:

- Create deterministic network IDs such as `managed-lan`.
- Derive a default gateway from the first usable IP in the managed CIDR.
- Allow later manual refinement.

## Non-code Closure Items

These are real tasks, but they are not blocked by code anymore.

### A. Live WLAN validation

- Connect one real endpoint to `wlan0`
- Confirm it renders as `WIRELESS`
- Confirm SoT expected-link behavior works for `wlan0`

### B. Field run validation

- Trust one endpoint
- Ignore one ARP-only candidate
- Save one profile with expected link and note
- Confirm the dashboard changes immediately

## Exit Criteria

This topic can be considered implementation-complete when:

1. No external peer appears in `Client Identity`
2. `ARP-only` candidates are actionable
3. SoT edits affect runtime classification
4. `LINK DRIFT` is visible when expected link differs
5. Only live validation remains

## Honest Closure Statement

After the final mandatory items above are implemented, no additional code proposal is required for this topic.

Further changes, if any, are refinements or field feedback, not missing core implementation.
