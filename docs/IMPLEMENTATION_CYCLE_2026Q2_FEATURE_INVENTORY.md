# Implementation Cycle Feature Inventory (2026Q2)

Last updated: 2026-05-13
Related epic: #196

This inventory summarizes the implemented features completed in the current execution cycle and links each item to purpose, affected modules, operational impact, and verification commands.

## Feature Inventory

| Issue | Feature | Purpose | Affected modules | Operational impact | Verification |
|---|---|---|---|---|---|
| #197 | Syslog CEF notifier adapter | Add SIEM-friendly outbound notifier format for deterministic decisions | `py/azazel_edge/notify/delivery.py`, `py/azazel_edge/notify/__init__.py`, `tests/test_notification_syslog_cef_v1.py` | Enables forwarding decision notifications in CEF via syslog collectors | `PYTHONPATH=py:. .venv/bin/pytest -q tests/test_notification_syslog_cef_v1.py` |
| #198 | Offline queue notifier + recovery flush | Preserve outbound notifications during temporary network outages | `py/azazel_edge/notify/delivery.py`, `py/azazel_edge/notify/__init__.py`, `tests/test_notification_offline_queue_v1.py` | Fail-closed notification path with queue depth visibility and controlled replay | `PYTHONPATH=py:. .venv/bin/pytest -q tests/test_notification_offline_queue_v1.py` |
| #199 | Summary-only transfer mode in DecisionNotifier | Reduce sensitive transfer payload in degraded transport paths | `py/azazel_edge/notify/delivery.py`, `tests/test_notification_v1.py` | Strips `evidence_ids`, truncates `operator_wording` to 200 chars before adapter send | `PYTHONPATH=py:. .venv/bin/pytest -q tests/test_notification_v1.py` |
| #200 | Vector installer/config/service integration | Standardize local and aggregator log forwarding path | `installer/internal/install_vector.sh`, `security/vector/*`, `systemd/azazel-edge-vector.service`, `installer/internal/install_all.sh` | Operator can provision deterministic log pipeline by installer toggle | `bash -n installer/internal/install_vector.sh` |
| #201 | Wazuh ARM64 installer | Add ARM64-compatible endpoint telemetry integration path | `installer/internal/install_wazuh_agent.sh`, `docs/WAZUH_INTEGRATION_GUIDE.md` | Optional host telemetry integration for field deployments | `bash -n installer/internal/install_wazuh_agent.sh` |
| #202 | Suricata disaster threat rules + ATT&CK mappings | Improve SOC detection coverage for disaster context threats | `security/suricata/azazel-lite.rules`, `config/attack_mapping.yaml` | Increased deterministic SOC signal quality with mapped rationale | `PYTHONPATH=py:. .venv/bin/pytest -q tests/test_soc_evaluator_v*.py` |
| #203 | Disaster phishing / evacuation demo scenarios | Strengthen deterministic demonstration coverage for training | `py/azazel_edge/demo/scenarios.py`, `tests/test_demo_scenario_pack_v1.py` | Operators can replay scenario-specific triage behavior | `PYTHONPATH=py:. .venv/bin/pytest -q tests/test_demo_scenario_pack_v1.py` |
| #204 | Shift handoff summary API | Improve operator continuity during shift rotation | `azazel_edge_web/app.py`, `tests/test_handoff_api_v1.py` | Adds consistent summary endpoint for handoff briefing | `PYTHONPATH=py:. .venv/bin/pytest -q tests/test_handoff_api_v1.py` |
| #205 | Periodic self-test timer | Add routine runtime checks and predictable maintenance rhythm | `bin/azazel-edge-selftest`, `installer/internal/install_selftest_timer.sh`, `systemd/azazel-edge-selftest.{service,timer}` | Better early detection of drift/failure in unattended operation | `bash -n installer/internal/install_selftest_timer.sh` |
| #206 | Encrypted storage default path | Enforce fail-closed secret handling at install baseline | `installer/internal/install_security_stack.sh`, `installer/internal/install_encrypted_storage.sh`, `docs/FIELD_DEPLOYMENT_GUIDE.md` | Secrets are moved under encrypted mount by default | `bash -n installer/internal/install_encrypted_storage.sh installer/internal/install_security_stack.sh` |
| #207 | Captive portal consent + registration API | Add explicit user consent flow and local allowlist registration | `azazel_edge_web/app.py`, `azazel_edge_web/templates/captive_consent.html`, `py/azazel_edge/i18n.py`, `installer/internal/install_captive_portal.sh`, `tests/test_captive_portal_api_v1.py` | Field onboarding flow gains legal notice + consent trace | `PYTHONPATH=py:. .venv/bin/pytest -q tests/test_captive_portal_api_v1.py` |
| #208 | Operations/deployment doc suite | Provide role-specific run and deployment guides | `docs/OPERATOR_GUIDE_JA.md`, `docs/STATUS_CARD.md`, `docs/PHYSICAL_SETUP_GUIDE.md`, `docs/POWER_PLAYBOOK.md`, `docs/FIELD_DEPLOYMENT_GUIDE.md`, `docs/VEHICLE_DEPLOYMENT_GUIDE.md`, `docs/WAZUH_INTEGRATION_GUIDE.md`, `docs/HUMANITARIAN_PARTNER_GUIDE.md`, `docs/PRIVACY_AND_LEGAL.md`, `docs/MAINTENANCE_CHECKLIST.md` | Operational onboarding speed and consistency improved | Link and doc consistency checks + repo test baseline |
| #209 | Docs index/navigation refresh | Align docs discovery with latest runtime and ops content | `docs/INDEX.md`, `docs/index.html` | Public/internal documentation entrypoint reflects current state | Manual link check in `docs/` |

## Cycle Baseline Validation

```bash
PYTHONPATH=py:. .venv/bin/pytest -q
```

Expected baseline at cycle close:
- `305 passed, 62 subtests passed`

