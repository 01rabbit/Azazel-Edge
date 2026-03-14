# SOC State Rules v1

This document defines deterministic SOC state rules used by `SocEvaluator`.

## Incident Campaign Grouping

- Incident key:
  - `src_ip | dst_ip | dst_port | attack_type_or_category`
  - Incident ID is `inc-` + first 12 hex chars of SHA-256 of the key.
- Event assignment:
  - Suricata events update incident counters, max score, evidence IDs, and implicated entities.
  - Flow events are attached as supporting evidence when `src_ip` and `dst_ip` match an existing incident.
- Lifecycle:
  - `active`: touched in current evaluation call.
  - `cooling`: not touched for 1-2 consecutive evaluation calls.
  - `closed`: not touched for 3 or more consecutive evaluation calls.
  - `recurrence_count`: incremented when an incident returns from `cooling`/`closed` to `active`.
- Bounded memory:
  - Keep at most `max_incidents` incidents, ranked by status, score, event count, and recency.

## Visibility State

- Sources tracked: `suricata_eve`, `flow_min`, `syslog_min`.
- Per-source status:
  - `missing`: no events from source in current batch.
  - `stale`: all source events marked stale by deterministic attributes (`stale`, `collector_stale`, or `collector_age_sec >= 300`).
- TI feed status:
  - `configured`, `empty`, or `unconfigured`.
- Output:
  - `status`, `coverage_score`, `trust_penalty`, `missing_sources`, `stale_sources`, `ti_status`.

## Suppression and Exception State

- Deterministic suppressors:
  - `src_ips`, `dst_ips`, `sid`, `attack_types`, `categories`.
  - `expected_scanners` (source IP list).
  - `lab_segments` or event attribute `lab_traffic=true`.
  - `maintenance_windows` by UTC day/hour, or event attribute `maintenance_window=true`.
- Exception rule:
  - Suppression match still becomes actionable when risk score is `>= 90`.
- Output:
  - `suppressed_count`, `actionable_count`, `exception_count`, reason trace, and evidence references.

## Behavior Sequence State

- Stage inference (keyword based):
  - `recon`, `access`, `lateral`, `command`, `impact`, `unknown`.
- Chain support:
  - Known deterministic chains:
    - `recon -> access -> command`
    - `recon -> access -> lateral -> command`
    - `access -> lateral -> impact`
- Output includes:
  - `stage_sequence`, `chain_hits`, `implicated_entities`, and evidence IDs.

## Triage Priority State

- Deterministic weighted score combines:
  - suspicion, confidence, blast radius, criticality, and exposure.
- Queue buckets:
  - `now` (>=75), `watch` (>=50), `backlog` (<50).
- Output includes:
  - `status`, `now/watch/backlog` entries, and `top_priority_ids`.
