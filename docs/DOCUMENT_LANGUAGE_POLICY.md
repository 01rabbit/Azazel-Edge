# Document Language Policy

Last updated: 2026-05-13

## Policy
- English is the default language for repository documentation.
- Japanese is allowed as supplemental text for field operators.
- Documents with high operational depth may be split into dedicated EN/JA versions.

## Classification (Current)
### A. English base with optional Japanese supplement
- `README.md`
- `docs/INDEX.md`
- `docs/P0_RUNTIME_ARCHITECTURE.md`
- `docs/NEXT_DEVELOPMENT_EXECUTION_INDEX_2026Q2.md`
- `docs/FIELD_DEPLOYMENT_GUIDE.md`
- `docs/PHYSICAL_SETUP_GUIDE.md`
- `docs/POWER_PLAYBOOK.md`
- `docs/PRIVACY_AND_LEGAL.md`
- `docs/STATUS_CARD.md`
- `docs/VEHICLE_DEPLOYMENT_GUIDE.md`
- `docs/WAZUH_INTEGRATION_GUIDE.md`
- `docs/HUMANITARIAN_PARTNER_GUIDE.md`
- `docs/MAINTENANCE_CHECKLIST.md`
- `docs/index.html`

### B. Split EN/JA documents
- `docs/AI_OPERATION_GUIDE.md` (EN)
- `docs/AI_OPERATION_GUIDE_JA.md` (JA)
- `docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md` (EN)
- `docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL_JA.md` (JA)
- `docs/MIO_PERSONA_PROFILE.md` (EN)
- `docs/MIO_PERSONA_PROFILE_JA.md` (JA)
- `docs/OPERATOR_GUIDE.md` (EN)
- `docs/OPERATOR_GUIDE_JA.md` (JA)

### C. Governance charter split
- `AGENTS.md`: existing governance charter (current authoritative source)
- `AGENTS_EN.md`: English reference summary

## Maintenance Rules
- When editing a split document pair, update both EN and JA versions in the same PR when behavior changes.
- If only wording is changed and behavior is unchanged, update the edited language version and add a note to backlog for parity check.
