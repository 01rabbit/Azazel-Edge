# Threat Intel Feed Format (`config/ti`)

This directory stores local IOC feeds used by deterministic SOC evaluation.

## Schema

Each file must be YAML with top-level `indicators:` list.

Each indicator entry:
- `type`: `ip` | `domain` | `url`
- `value`: indicator value
- `confidence`: integer `0-100`
- `source`: feed/source name
- `note`: short operator-facing description
- `technique_id`: optional ATT&CK technique id (e.g. `T1566`)
- `tags`: optional list
- `inactive`: optional bool (when true, entry is ignored but kept for audit/history)

## Update Procedure

1. Add new IOCs as new entries.
2. Do not delete historical entries; set `inactive: true` instead.
3. Keep confidence calibrated (`60+` only for credible evidence).
4. Run:
   - `PYTHONPATH=py:. pytest -q tests/test_ti_lookup_v1.py tests/test_ti_feed_disaster_v1.py`

## Recommended Sources

- JPCERT/CC advisories
- CISA KEV and related alerts
- abuse.ch tracking feeds

When importing external indicators, preserve provenance in `source` and add a short `note`.
