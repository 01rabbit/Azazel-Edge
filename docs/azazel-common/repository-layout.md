# Azazel-Common: Repository and Package Layout

Status: **Design proposal only. This repository does not exist yet.**

## Proposed repository name

```
01rabbit/Azazel-Common
```

(Not `Azazel-Core` — see `architecture.md` §1 and `design-principles.md`
§4.6 for why.)

## Repository layout

```
Azazel-Common/
├── README.md
├── LICENSE
├── pyproject.toml
├── CHANGELOG.md
├── src/
│   └── azazel_common/
│       ├── __init__.py
│       ├── version.py
│       ├── schema/
│       │   ├── __init__.py
│       │   ├── state.py            # StateSnapshot
│       │   ├── mode.py             # ModeState
│       │   ├── action.py           # ActionIntent, ObservePlan..ReleasePlan (abstract only)
│       │   ├── evidence.py         # EvidenceRef
│       │   ├── decision.py         # DecisionExplanation
│       │   ├── audit.py            # AuditEvent
│       │   └── trust.py            # TrustCapsule
│       ├── cti_contracts/
│       │   ├── __init__.py
│       │   ├── ingest.py           # CtiEventBatch, CtiFlowBatch, CtiReactionBatch
│       │   ├── reactions.py        # (reaction-specific sub-shapes, if they diverge from ingest.py)
│       │   ├── context.py          # CtiContextRequest, CtiContextResponse, IocMatch
│       │   └── advisory.py         # BehavioralCtiBlock, advisory_notice / limitations helpers
│       ├── paths/                  # Phase 5
│       │   ├── __init__.py
│       │   ├── schema.py           # runtime/config/log dir resolution
│       │   └── migration.py        # legacy-path dry-run migration helper
│       ├── audit/                  # Phase 5
│       │   ├── __init__.py
│       │   ├── jsonl.py            # JSONL writer, trace_id generator, config_hash helper
│       │   └── chain.py            # HMAC / chain-of-custody helper (future extension point)
│       ├── api/                    # Phase 5
│       │   ├── __init__.py
│       │   ├── auth.py             # token auth helper (X-AZAZEL-TOKEN / X-Auth-Token)
│       │   ├── roles.py            # viewer/operator/responder/admin
│       │   └── errors.py           # standard JSON error model, fail-closed default
│       ├── notify/                 # Phase 5
│       │   ├── __init__.py
│       │   ├── model.py            # shared notification event schema
│       │   ├── ntfy.py             # thin ntfy send helper
│       │   └── mattermost.py       # thin Mattermost send helper
│       └── testing/
│           ├── __init__.py
│           ├── fixtures.py         # shared pytest fixtures for consumer contract tests
│           └── contract_cases.py   # canonical valid/invalid payload examples per schema
├── tests/
│   ├── test_schema_state.py
│   ├── test_schema_decision.py
│   ├── test_cti_contracts.py
│   ├── test_audit_jsonl.py
│   ├── test_paths.py
│   └── test_api_auth_models.py
└── docs/
    ├── architecture.md
    ├── design-principles.md
    ├── migration-plan.md
    └── contracts.md
```

Notes:

- `docs/` inside `Azazel-Common` mirrors this design task's documents once
  the repository is created, kept in sync with actual implementation as it
  lands (this task's copies, under `Azazel-Edge/docs/azazel-common/`, are
  the design record for how the repository came to be — the in-repo copies
  become the living reference once code exists).
- `azazel_common.paths`, `.audit`, `.api`, `.notify` directories are shown
  now for completeness of the target layout, but per `migration-plan.md`
  Phase 1, only `schema/` and `cti_contracts/` ship in `v0.1.0`. The empty
  Phase-5 directories are **not** scaffolded in `v0.1.0` — they are added
  when their phase starts, so the initial release has no dead code.
- `action.py`'s `ObservePlan`..`ReleasePlan` are abstract, data-only plan
  descriptions (see `architecture.md`'s Action Plan section) — they carry
  no execution logic and no adapter to nft/tc/OpenCanary. Converting a
  plan into an actual firewall rule, traffic-control action, or canary
  deployment remains entirely inside Edge/Gadget adapters.

## `pyproject.toml` shape (illustrative)

```toml
[project]
name = "azazel-common"
version = "0.1.0"
description = "Shared contracts for the Azazel series (schema, CTI advisory contract, audit/path/api/notify helpers)"
requires-python = ">=3.10"
dependencies = [
    "pydantic>=2,<3",
]

[project.optional-dependencies]
flask = ["flask>=2"]
fastapi = ["fastapi>=0.100"]
test = ["pytest>=7"]

[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"
```

Kept intentionally minimal: Pydantic is the only hard runtime dependency,
consistent with the Raspberry Pi weight constraint in
`design-principles.md` §5. Flask/FastAPI adapters are opt-in extras.

## Consumption pattern from a product repository

```toml
# in Azazel-Edge / Azazel-Gadget / Azazel-CTI's own requirements
azazel-common @ git+https://github.com/01rabbit/Azazel-Common.git@v0.1.0
```

Tag-pinned, not branch-pinned, not a submodule (see
`design-principles.md` §6).
