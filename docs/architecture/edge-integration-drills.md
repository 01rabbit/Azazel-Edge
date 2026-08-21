# Edge integration drills (T1–T5)

Runnable, human-readable **drills** that exercise the Edge ⇄ AZ-06 Deception ⇄
Knowledge integration on a live localhost, each printing a `PASS/FAIL` table and
exiting non-zero on any failure. They complement the pytest e2e suites: the
suites assert guarantees in isolation, the drills prove them on a running
system. All are dev harnesses (not collected by CI) and need the four sibling
checkouts importable with Fabric v0.6.0 and the Knowledge `api` extra — see
[edge-integration-functional-test.md](edge-integration-functional-test.md) for
the one-time environment setup.

| Drill | Repo / path | What it proves |
|---|---|---|
| **T1** fault-injection | Azazel-Edge `tools/fault_injection_drill.py` | fail-open (Knowledge absent), fail-closed heartbeat + recovery (AZ-06 killed), auth (wrong key rejected), anti-replay, full-loop recovery |
| **T2** live-Docker lifecycle | Azazel-Deception `scripts/dev/live_docker_drill.py` | a **real** decoy container: materialize → isolation (no host port, non-root, ro-rootfs, caps dropped) → tamper destroyed by terminate+reset → deterministic reset with evidence preserved |
| **T3** incremental relay | Azazel-Edge `tools/incremental_relay_drill.py` | streaming observations via the `observations_since` cursor, advisory accumulation across relays, idempotent landing (no duplicate rows) |
| **T4** forward seam | Azazel-Edge `tools/detection_to_decoy_drill.py` | detection → live `/v1/context` advisory (scored, advisory-only) → posture decision (redirect = deploy-a-decoy) → AZ-06 decoy rehearsal (non-executing); Knowledge advises, Edge decides |
| **T5** multi-env isolation | Azazel-Edge `tools/multi_env_isolation_drill.py` | two environments kept separate: per-env advisories and immutable-store rows, plus AZ-06 reconcile reporting an edge-only divergence vs a consistent match |

## Running

From the Azazel-Edge checkout with the shared venv active (Docker-independent
except T2):

```bash
python tools/fault_injection_drill.py            # T1
python tools/incremental_relay_drill.py          # T3
python tools/detection_to_decoy_drill.py         # T4
python tools/multi_env_isolation_drill.py        # T5
```

T2 starts a real container, so it is opt-in and needs a running Docker daemon
(Docker Desktop). From the Azazel-Deception checkout:

```bash
AZAZEL_DECEPTION_LIVE=1 python scripts/dev/live_docker_drill.py --live
```

Each drill auto-discovers the sibling checkouts as `../Azazel-Deception` and
`../Azazel-Knowledge`; override with `--deception-root` / `--knowledge-root` or
the `DECEPTION_ROOT` / `KNOWLEDGE_ROOT` env vars.

## Doctrine the drills hold the system to

- **Advisory-only / fail-open**: Knowledge absent, slow, or hostile never blocks
  or steers Edge (T1 D1, T4 F4).
- **Fail-closed liveness**: an unreachable AZ-06 degrades to "unhealthy", never a
  crash, and recovers when the node returns (T1 D2).
- **Non-executing by default**: the shadow/replay and forward-seam paths start no
  container and enforce nothing (T1, T4, T5); only the explicitly-gated live path
  runs a real container (T2).
- **Immutable, isolated evidence**: observations land once, per environment, in an
  append-only table; live reset preserves the evidence chain (T2, T3, T5).
- **Authenticated, anti-replay transport** between Edge and AZ-06 (T1 D3/D4).
