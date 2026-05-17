# AGENTS.md — Azazel-Edge AI Agent Working Charter (Authoritative)

Last updated: 2026-05-17

This file is the authoritative AI agent charter for this repository.
All AI agents must read and follow this file before starting work.

## Core Principles
- Deterministic First: do not move AI ahead of Evidence Plane.
- AI is governed assist only; do not bypass `py/azazel_edge/ai_governance.py`.
- Fail-Closed defaults must be preserved.
- Raspberry Pi resource constraints must be respected.

## Mandatory Practices
- Read relevant architecture/operation docs before code changes.
- Run tests after changes (`PYTHONPATH=. .venv/bin/pytest -q`, and Rust tests when applicable).
- Keep auditability intact (`adopt/fallback` logging, decision explanation required fields).

## Prohibited Without Human Approval
- Changes under `installer/`, `security/`, `systemd/`
- Enabling fail-open auth defaults
- Enabling enforcement paths without dry-run verification and explicit approval

## Language
- Repository docs default to English.
- Japanese is supplemental or provided in dedicated JA versions.
