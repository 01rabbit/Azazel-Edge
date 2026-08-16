# Edge-driven integrated functional test

`tools/edge_integration_functional_test.py` exercises the two integration
seams **Azazel-Edge owns** against real, locally-running peer systems — with
Edge as the main driver. It uses only Edge's own client modules
(`azazel_edge.deception_shadow_client`, `azazel_edge.deception_effectiveness_client`),
so a green run proves Edge can drive the peers, not just that the peers work in
isolation.

Nothing here starts an attacker-facing container or enforces anything. The
AZ-06 shadow server pins `live_execution=disabled`; every response Edge
accepts is verified `descriptive_only` / `enforcement_applied=False`, and every
advisory is fail-closed-verified `advisory_only` / `executable=false`.

## The two seams

```
SHADOW / REPLAY            Edge ──▶ AZ-06 Azazel-Deception Host
  Az06ShadowClient.run_bootstrap_session
    capabilities ▶ package identity ▶ descriptive plan
    ▶ local shadow evaluation ▶ activation/termination rehearsal
  HeartbeatLoop.wait_until_healthy
    authenticated heartbeat + reconcile against Edge's active set

EFFECTIVENESS (advisory)   AZ-06 ──▶ Edge ──▶ Azazel-Knowledge
  AZ-06 records fact-only InteractionObservations
  KnowledgeIngestClient.submit_observations   (Edge relays the batch)
  Knowledge single-writer worker drains the spool
  EffectivenessAdvisoryReader.get_advisory    (Edge reads, fail-closed verify)
```

## Prerequisites

The four sibling repos checked out next to each other and importable, plus the
Fabric **v0.6.0** contracts and the Knowledge `api` extra
(`fastapi`/`uvicorn`/`pydantic`):

```
Azazel-Edge/        (this repo — the driver)
Azazel-Deception/   (AZ-06 shadow server + fact-only observation authoring)
Azazel-Knowledge/   (advisory API + single-writer worker)
Azazel-Fabric/      (v0.6.0 shared contracts, imported by all three)
```

No single repo's CI installs all three packages together, so this is a **dev
harness, not a CI test**.

## One-command mode (default)

The harness starts the AZ-06 shadow server in-process and the Knowledge API +
worker as subprocesses, drives everything from Edge, and tears them down:

```bash
cd Azazel-Edge
python tools/edge_integration_functional_test.py
# peer checkouts are auto-discovered as ../Azazel-Deception and
# ../Azazel-Knowledge; override with --deception-root / --knowledge-root
# or DECEPTION_ROOT / KNOWLEDGE_ROOT.
```

Run a single seam with `--only shadow` or `--only effectiveness`.

Exit `0` and a printed `EffectivenessAdvisory` mean both seams interlocked.

## Manual mode — start the peers yourself

Use this to drive peers you started by hand (different hosts, long-lived
servers, debugging). Start each peer, then point the harness at them with
`--manual`.

### 1. AZ-06 Azazel-Deception shadow server

There is no shipped `serve` CLI (AZ-06 exposes the server programmatically),
so the repo provides a dev launcher:

```bash
cd Azazel-Deception
PYTHONPATH=src python scripts/dev/serve_shadow.py \
    --host 127.0.0.1 --port 8071 \
    --key dev-shared-key \
    --edge-id edge-func-test \
    --node-id az06-shadow-dev
# prints: [az06-shadow] serving on http://127.0.0.1:8071 ...
#         [az06-shadow] live_execution=disabled (shadow/replay only).
```

- `--key` is the shared HMAC transport secret; it **must** match
  `AZ06_SHADOW_KEY`.
- `--edge-id` is the allow-listed Edge node id; it **must** match the harness's
  Edge node id (`edge-func-test`).
- The launcher injects a deterministic docker-capable capability snapshot so
  the descriptive plan builds identically on any dev host. Pass
  `--real-capabilities` to detect the actual host instead.

### 2. Azazel-Knowledge API + worker

```bash
cd Azazel-Knowledge
export AZAZEL_ROOT=$(mktemp -d)          # ephemeral node state for the dev run
export AZAZEL_CONFIG_DIR=$PWD/config

# provision the node and mint an Edge client token (ingest + read scopes)
python azctl provision --root "$AZAZEL_ROOT" --config-dir "$AZAZEL_CONFIG_DIR"
python azctl client add --root "$AZAZEL_ROOT" --config-dir "$AZAZEL_CONFIG_DIR" \
    --key-id edge1 --scopes ingest,read      # prints an azcti_... token

# serve the advisory API
python -m uvicorn azazel_knowledge.api.app:app \
    --host 127.0.0.1 --port 8072 --log-level warning
```

Knowledge uses a **single-writer worker** to drain the ingest spool into its
immutable observation table — the API never writes. The harness runs the drain
for you (`worker --once`) **only if** you also give it the same
`AZAZEL_ROOT` / `AZAZEL_CONFIG_DIR` / `KNOWLEDGE_ROOT`. Otherwise, drain it
yourself between the relay and the advisory read:

```bash
python -m azazel_knowledge.worker \
    --root "$AZAZEL_ROOT" --config-dir "$AZAZEL_CONFIG_DIR" --once
```

### 3. Drive both from Edge

```bash
cd Azazel-Edge
export AZ06_SHADOW_URL=http://127.0.0.1:8071
export AZ06_SHADOW_KEY=dev-shared-key
export AZ06_NODE_ID=az06-shadow-dev

export AZ_KNOWLEDGE_URL=http://127.0.0.1:8072
export AZ_KNOWLEDGE_TOKEN=azcti_...          # the token printed above

# optional: let the harness run the Knowledge worker drain for you
export KNOWLEDGE_ROOT=/path/to/Azazel-Knowledge
export AZAZEL_ROOT=/the/same/AZAZEL_ROOT
export AZAZEL_CONFIG_DIR=/path/to/Azazel-Knowledge/config

python tools/edge_integration_functional_test.py --manual
```

`python tools/edge_integration_functional_test.py --print-procedures` prints
this same procedure from the harness itself.

## What a pass asserts

- **Shadow:** bootstrap session outcome `shadow_complete`, step order
  `capabilities ▶ package ▶ plan ▶ shadow_activate ▶ shadow_terminate`,
  `enforcement_applied=False`, `container_start_count=0`, capability snapshot
  `descriptive_only`, Edge's local evaluator `would_accept`, simulated
  activation `live_execution=false`; heartbeat reaches healthy with
  `failure_count=0`.
- **Effectiveness:** Edge relay `accepted`, advisory present and
  `authority=advisory_only`, `executable=false`, matching `environment_id`,
  `0.0 ≤ confidence ≤ 1.0`, and non-empty `counter_evidence` (the injected
  `scanner_noise` confounder surfaces as counter-evidence — narrative
  effectiveness is separated from runtime/capacity confounders, and attacker
  belief is never asserted).

## Relationship to the Knowledge-driven harness

`Azazel-Knowledge/tools/virtual_e2e_effectiveness.py` proves the same
effectiveness loop from the **Knowledge** hub's perspective. This harness is
its Edge-driven complement and additionally covers the shadow/replay +
heartbeat seam that only Edge drives.
