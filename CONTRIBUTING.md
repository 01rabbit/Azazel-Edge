# Contributing to Azazel-Edge

## Before you start

Read [AGENTS.md](AGENTS.md) first. It defines the design principles, layer rules, and what must not be changed.

## Branch naming

`<type>/<short-description>`

Examples: `feat/decision-trust-capsule`, `fix/epd-help-crash`, `docs/readme-reorganize`

## Commit message format

`<type>(<scope>): <summary>`

- type: `feat` / `fix` / `refactor` / `test` / `docs` / `chore` / `security`
- scope: `arbiter` / `evaluator` / `evidence` / `ai` / `web` / `rust` / `runbook` / `installer` / `notify` / `audit` / `demo` / `mio`

## Pull request rules

- 1 PR = 1 purpose. Do not mix unrelated changes.
- Every PR must include:
  - [ ] `PYTHONPATH=. pytest -q` passes
  - [ ] Related documentation updated in the same PR
  - [ ] Deterministic First principle not violated
  - [ ] Raspberry Pi constraints not broken

## What not to do (requires human review)

See AGENTS.md §3.4 for the full list. The short version:
- Do not touch `installer/`, `systemd/`, or `security/` without explicit approval
- Do not set `AZAZEL_AUTH_FAIL_OPEN=1` or `AZAZEL_DEFENSE_ENFORCE=true`
- Do not disable `requires_approval` on any Runbook

## Testing

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements/runtime.txt
PYTHONPATH=. pytest -q
```
