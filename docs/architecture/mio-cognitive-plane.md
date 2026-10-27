# M.I.O. Cognitive Plane: Architecture and Authority Matrix

Status: canonical architecture description of what the code does today.
Tracking: #388 (successor of closed #361; Edge reference-core work per #408).
Last updated: 2026-10-27.

This document describes the components that decide, enforce, advise, display
and audit around M.I.O., and who may do which. It is written from the code in
this repository. Where this document and the code disagree, the code is right
and this document is the defect. It creates no decision authority, no
enforcement authority, no approval flag and no bypass. It changes no runtime
behaviour.

The detailed contracts stay in their own documents (section 10). This page is
the entry point that ties them together.

## 1. Two things are called "M.I.O."

| Name used here | What it is | Code | Runs in |
| --- | --- | --- | --- |
| **M.I.O. persona** | The operator-facing wording of the live AI agent: the analyst, ops coach and manual-query prompts, the Mattermost `[M.I.O.]` replies, the triage prefaces. Persona text is not authority ([MIO_PERSONA_PROFILE.md](../MIO_PERSONA_PROFILE.md)). | `py/azazel_edge_ai/agent.py`, `azazel_edge_web/app.py` | `azazel-edge-ai-agent.service` (account `azazel-agent`), `azazel-edge-web.service` (account `azazel-web`) |
| **M.I.O. cognitive core** | The bounded reasoning library: SituationFrame, playbooks, hypotheses, evidence gaps, typed read-only Capability Broker, grounding, lifecycle, no-model handoff, trace audit. | `py/azazel_edge/mio/` | No service. The only callers are the offline tools `bin/azazel-mio-shadow-replay`, `bin/azazel-mio-evaluate` and the read-only `bin/azazel-mio-trace-export`. No systemd unit starts them. |

The cognitive core is therefore a shadow/replay component today. Its output is
not read by any running service. Wiring it into a service is open work
(section 9).

## 2. Components

| Component | Process and account | Code | Role |
| --- | --- | --- | --- |
| Rust core | `azazel-edge-core.service`, root (non-root is #471 stage 3) | `rust/azazel-edge-core/src/main.rs`, `ingress.rs`, `release.rs` | Reads Suricata EVE, selects the action (`decide_defense()`), applies it when the enforcement settings allow (`maybe_enforce()`), releases it when its lease expires (`release.rs`). The only decision and enforcement path ([X86_64_INTEGRATION_BOUNDARY.md](../X86_64_INTEGRATION_BOUNDARY.md), owner decision #412). |
| Python `ActionArbiter` | No process of its own | `py/azazel_edge/arbiter/action.py` | A deterministic decision record over NOC/SOC evaluations, used by scenario replay, benchmarks and the SOC policy dry run. Nothing applies its output to the network. |
| AI agent | `azazel-edge-ai-agent.service`, `azazel-agent` (#471 stage 2) | `py/azazel_edge_ai/agent.py` | Receives the core's decision events after the decision; records P0 decisions in the core-decision audit chain and the P0 alert queue; computes the tactical score and the second-pass SOC evaluation (`DecisionLayers`); asks the local model in the ambiguous band; writes the advisory, the snapshot fields and the v2 decision explanation with its trust capsule (#496, #498). |
| M.I.O. cognitive core | Offline tools only | `py/azazel_edge/mio/` | Advisory reasoning over a SituationFrame. `MioRecommendation.executable` is always `False`. |
| Local model runtime | Ollama, outside this repository | `agent.py` (`AZAZEL_OLLAMA_ENDPOINT`, default `http://127.0.0.1:11434`), `py/azazel_edge/mio/model_adapter.py` | Produces untrusted text that the callers validate. |
| Web UI | `azazel-edge-web.service`, `azazel-web` (#471 stage 1) | `azazel_edge_web/app.py` | Dashboards, Booth Focus, touch console, Mattermost relay, runbook preview and execution, fixed control actions through the control daemon. |
| Control daemon | `azazel-edge-control-daemon.service`, root | `py/azazel_edge_control/daemon.py` | The only writer of the shared `ui_snapshot.json`: it merges the agent's `ai_snapshot.json` fields listed in `AGENT_SNAPSHOT_KEYS` (`user_state`, `recommendation`, `reasons`, `evidence`, `llm`, `ops_coach`, `decision_pipeline`, `second_pass`, `attack` and others, each type-checked) and ages out a stale advisory. The Web UI and the e-paper refresh read that snapshot. It also runs Wi-Fi, legacy mode files, SoT edits, uplink disconnect, shutdown and reboot for the peers its fixed table allows. None of this is decision input: the core never reads the snapshot. |
| Optional peers | Other products | `py/azazel_edge/engagement_advisory_client.py`, `deception_effectiveness_client.py`, `deception_shadow*.py`, `deception_transition.py`, `engagement/candidate.py` | Knowledge (AZ-04) and Deception (AZ-06) through Fabric contracts. Advisory-only on the way in, optional for Edge operation (section 4.2). |

"The arbiter" in integration contracts means the Rust core, and
`ActionArbiter` means the Python class
([X86_64_INTEGRATION_BOUNDARY.md](../X86_64_INTEGRATION_BOUNDARY.md), "What
'arbiter' means"). This document uses the same names.

## 3. Data flow

### 3.1 Live path

```text
Suricata eve.json  (attacker-influenced content)
   |
   v
Rust core: ingress quota (ingress.rs) -> decide_defense() -> maybe_enforce()
   |            nft/tc only if AZAZEL_DEFENSE_ENFORCE=true, level is not
   |            "advisory", the action is in the level's allowlist and
   |            AZAZEL_DEFENSE_DRY_RUN=false (shipped: off, dry run, advisory)
   |
   +--> normalized-events.jsonl          (core's own log)
   +--> ai-bridge.sock  (bounded queue of 1024, drop and count when full;
   |                     one-way: the core never reads anything back)
   v
AI agent  (after the decision; the event already carries "defense" and "enforcement")
   +--> core-decision-audit.jsonl + p0-alert-queue.jsonl   (P0 decisions)
   +--> tactical score + second-pass SOC  -> ai_advisory.json, ai_snapshot.json
   +--> local model (ambiguous band only) -> advisory "llm" / "ops_coach" fields
   +--> decision-explanations.jsonl (v2 explanation + trust capsule)
   v
Web UI reads these files (group azazel-web) ------------------------> operator
   |
   v
control daemon (root): merges AGENT_SNAPSHOT_KEYS of ai_snapshot.json into
   the shared ui_snapshot.json (sole writer; ages out a stale advisory)
   |
   +--> Web UI dashboards, touch console -----------------------------> operator
   +--> e-paper refresh (azazel_edge_epd_mode_refresh.py) ------------> e-paper
```

Nothing in this chain feeds back into the core. The core reads EVE, its
redirect policy, its release ledger, the boot id and its unit environment. No
Python service writes any of these.

### 3.2 Where reasoning starts and ends

- In the live path, AI runs after the core has decided and, if allowed,
  applied the action (`process_value()` decides and enforces before
  `send_to_ai_socket()`). The agent's output is advice and display data.
- The cognitive core runs only offline. One cycle is:

```text
evidence + deterministic NOC/SOC outputs + current Defensive State
  -> MioSituationFrameBuilder (deterministic, no model, no network)
  -> select_playbook (deterministic)
  -> AIGovernance.authorize -> local model: hypotheses
  -> GroundingValidator, lifecycle rules
  -> evidence gaps -> score_evidence_gaps -> CapabilityBroker (typed, read-only)
  -> hypothesis revision -> recommendation (executable=false) + claim audit
  -> or: mio.no_model_handoff.v2 (deterministic)
  -> project_outcome -> mio.trace_audit.v2  (edge_decision_ref supplied by Edge)
```

The cycle ends with an advisory record. There is no consumer that turns it
into a decision. `edge_decision_ref` links an advisory to a decision Edge made;
M.I.O. never mints one ([mio-reasoning-trace.md](mio-reasoning-trace.md)).

## 4. Authority matrix

### 4.1 Edge components

"Yes" means the component holds that authority. Everything else is "No" or a
narrower role, stated in the cell.

| | Rust core | Python `ActionArbiter` | M.I.O. cognitive core | AI agent (incl. M.I.O. persona) | Web UI | Operator |
| --- | --- | --- | --- | --- | --- | --- |
| **Decide** (select the defensive action) | **Yes.** Sole live decider: `decide_defense()`, a fixed severity ladder over the five Defensive State actions; `resolve_redirect_decision()` may then replace `redirect` by the redirect policy's fallback (section 6). | No. Produces a decision record for replay, benchmarks and dry runs; no live caller. | **No.** May recommend one of `OBSERVE/NOTIFY/THROTTLE/REDIRECT/ISOLATE` as advice; `executable` is always `False`; nothing consumes it. | **No.** Its risk score, SOC second pass and model verdict are computed after the core decided and change no decision. | No. | Indirect only: chooses the core's enforcement settings (`AZAZEL_DEFENSE_*` in the unit and `/etc/default/azazel-edge-security`, root on the device). There is no per-decision override and no runtime approval channel. |
| **Enforce** (apply or release `nft`/`tc` defensive rules) | **Yes**, gated by the settings above; the release path (`release.rs`) removes what it applied when the lease expires. An action outside the level's allowlist is recorded as `policy_gated` and not applied. | No. | **No.** No import of arbiter, control, deception transition or outcome modules; no `subprocess`, `socket` or `os.system` (tested). | **No.** Its only child process is a read of `ip -4 route show default` (tested). | **No** defensive action. Its control-daemon actions are a fixed table (Wi-Fi, legacy mode, SoT, uplink disconnect, shutdown, reboot) that contains none of the five actions (tested). Two of them are not defensive actions but do change the network path: `wifi_connect` enables forwarding and adds NAT rules for a USB uplink, and `uplink_disconnect` brings the uplink down (`ip link set ... down`). | Runs the fixed control actions (role `responder`, mode change `admin`) and reviewed runbooks (role `operator`; `controlled_exec` needs review and `approved`). None of these writes the core's `inet azazel_edge` rules. |
| **Advise** | No (reports `policy_reason`). | No. | **Yes**, offline: hypotheses, evidence gaps, recommendation, no-model handoff. | **Yes**: `ai_advisory.json` (tactical recommendation; replaced by the analyst model's `suggested_action` when its confidence is at least 0.60), ops-coach runbook suggestion, manual-query answers. | Relays: Mattermost replies, runbook proposals (`/api/runbooks/propose`). | Decides whether to act on any advice. |
| **Display** | No UI; a summary line on stdout. | No. | **None today.** Operator surfaces are #374; the decision-level trace display (#341) is being implemented in #501 (open). | Writes display data (advisory, snapshot, explanation); renders nothing. | **Yes**: dashboards, Booth Focus, touch console, Mattermost. The control daemon's snapshot also feeds the e-paper display. | Reads. |
| **Audit** | `normalized-events.jsonl`, `ingress-audit.jsonl`, release ledger and its rollback audit. | Decision fields reused by replay explanations. | `ai_assist` records through `AIGovernance.authorize`; broker audit ring; `mio.trace_audit.v2` projection, `TraceAuditSink` and the recorder port (library, off by default; no service writes it yet, #385); read-only `azazel-mio-trace-export`. | Core-decision audit chain (P0), AI audit `ai-audit.jsonl` (scope records with `in_scope=false` for its model calls), v2 explanations with trust capsule, model result logs. | Runbook event log; reads the files above. | Reviews with `azazel-edge-audit-review`. |

Invariants behind the matrix, with the check that pins each one:

| Invariant | Check |
| --- | --- |
| Exactly one unit starts the core, and no other unit or Python module applies a defensive action. | `tests/test_enforcement_boundary_inventory_v1.py` |
| The Defensive State vocabulary is the five actions; M.I.O. validates against it and cannot extend it. | `tests/test_defensive_state_vocabulary.py` |
| No running service imports `azazel_edge.mio`; no unit starts the M.I.O. tools. | `tests/test_mio_cognitive_plane_authority_v1.py` |
| `azazel_edge.mio` imports only the standard library, itself and `azazel_edge.ai_governance`; it does not start processes or open sockets; only `model_adapter.py` uses `urllib`. | `tests/test_mio_cognitive_plane_authority_v1.py` |
| A model-supplied `executable: true` never survives into `MioRecommendation`. | `tests/test_mio_cognitive_plane_authority_v1.py`, `tests/test_mio_cognitive_shadow_core.py` |
| The core reads nothing the agent, the Web UI or M.I.O. writes. | `tests/test_mio_cognitive_plane_authority_v1.py` (static check of the core's non-test source) |
| The agent's only subprocess is the default-route read; the Web UI and control-daemon action tables contain no Defensive State action. | `tests/test_mio_cognitive_plane_authority_v1.py` |
| Deterministic modules do not import the trace audit or redaction. | `tests/test_mio_reasoning_trace_audit.py` |
| Model-built broker requests never reach the arbiter, enforcement, AZ-06 or OpenCanary. | `tests/test_mio_capability_broker_acceptance.py` |

These are static checks of the repository tree. They catch accidental drift,
not code written to evade them (the same limit as the enforcement inventory).

### 4.2 Other products

| Operation | M.I.O. | Edge | Knowledge (AZ-04) | Deception (AZ-06) | Fabric |
| --- | --- | --- | --- | --- | --- |
| Interpret, summarize | advisory | exposes facts | advisory | facts only | schema only |
| Create a hypothesis | yes (offline) | not needed | context only (`knowledge_refs`) | no | no |
| Read evidence | through the broker only | serves local reads | advisory reads (clients verify `authority=advisory_only`, `executable=false`, fail closed) | state reads | describes |
| Select a network action | no | **Rust core** | no | no | no |
| Approve engagement | no | Edge records (`engagement/candidate.py` can only downgrade to the arbiter's action; library, no live caller) | no | no | no |
| Activate or transition AZ-06 | no | produces the signed transition decision (`deception_transition.py`; library, no live caller) | no | executes approved decisions only (in AZ-06) | describes the decision |

Availability of Knowledge and AZ-06 is fail-open for Edge: a timeout, an
outage or a rejected response is "no advisory" and never blocks or changes a
decision (`engagement_advisory_client.py`, `deception_effectiveness_client.py`).
In the SituationFrame, `knowledge_status` and `deception_status` record their
state. Since `mio.situation_frame.v2` the frame can carry AZ-06 facts
(`deception_context`: IDs, lifecycle state, observation refs) and the actions
Edge already selected (`actions`, from Edge's decision audit) as data for
reasoning; neither is an input to any decision
([mio-situation-frame.md](mio-situation-frame.md)).

## 5. Degradation ladder

Edge decides and, if configured, enforces at every rung. Only advice and its
display degrade.

| Condition | What continues | What stops or changes | Where it is visible |
| --- | --- | --- | --- |
| Normal | Core decision and enforcement; agent advisory; model in the ambiguous band | - | dashboard, `ai_metrics.json` |
| Model quality low (`_recompute_policy`: completed, empty or fallback rates out of bounds after 10 requests) | everything | agent switches to `degraded`: model `AZAZEL_LLM_MODEL_DEGRADED` (default `qwen3.5:0.8b`) and a narrower ambiguous band (`AZAZEL_LLM_AMBIG_MIN_DEGRADED`, 70 in the unit) | `ai_runtime_policy.json` |
| Low memory or high swap | everything except the ops coach | ops coach and model-backed manual query are skipped (`_ops_coach_allowed`) | advisory `ops_coach.status`, manual-query reason |
| Model runtime unreachable, timed out, endpoint not loopback (`llm_endpoint_*`) or `AZAZEL_LLM_ENABLED=0` | core; tactical score; SOC second pass; explanations | analyst result is `fallback` with policy `tactical_only_keep_recommendation`, or `disabled`; manual query answers from the static router or the fixed fallback text | advisory `llm.status` |
| Agent stopped | core decision and enforcement | no advisory, snapshot or v2 explanation for those events; the core drops and counts forwards (queue of 1024, write timeout 1 s); at the next start the agent records missed P0 decisions from the core's log (tail of at most 8 MiB, newest 256, older ones marked as past decisions) | forward stats, P0 queue (`reconciled`, `stale`) |
| Core stopped | nothing on the decision path | no decisions, no enforcement, and no release of applied actions until it runs again (`process_release_events` runs at start and in its loop); no other component takes over | unit status |
| Offline (no WAN or Internet) | everything above | nothing on the decision or advice path needs the Internet. The cognitive core's adapter accepts loopback by default, a private-LAN endpoint only with opt-in, HTTPS and a bearer token, and has no public or cloud fallback. The agent's endpoint (`AZAZEL_OLLAMA_ENDPOINT`) is accepted only when it is loopback; otherwise the agent stays in the no-model fallback (#388, section 9.2). Knowledge and AZ-06 degrade to "no advisory". | - |
| Cognitive core, model absent or blocked | the cycle ends with a typed state | `DEPENDENCY_UNAVAILABLE` (`model=None` gives `model_absent`) or a governance block; the deterministic `mio.no_model_handoff.v2` carries allowlisted frame fields and built-in playbook guidance | `ReasoningOutcome.handoff` |
| Cognitive core, stale frame, cancellation, budget, invalid output | the cycle ends with a typed state | `STALE_SUPERSEDED`, `OPERATOR_CANCELLED`, `BUDGET_EXHAUSTED`, `VALIDATION_REJECTED`, `INSUFFICIENT_EVIDENCE`, `ERROR_FALLBACK` | trace events |
| Cognitive core, trace sink cannot write (ENOSPC, EDQUOT, EROFS, rotation failure) | the cycle | the advisory is withheld (`advisory_allowed()` is false) until `reset_degraded()` | sink `dropped`, `drop_reasons` |

Runtime profiles with local and remote routing and a FULL, LITE, CORE ladder
moved to Azazel-Nexus#5 (#408). Edge implements only the rungs above.

## 6. Trust boundaries

| Boundary | What crosses | Treated as | Enforced by |
| --- | --- | --- | --- |
| Network to core | Suricata EVE lines | untrusted | ingress quota and shedding (`ingress.rs`). `decide_defense()` reads severity, sid, source address and target port. For a `redirect`, `resolve_redirect_decision()` then reads the redirect policy, the target port, `risk_score` and severity: a port without a prepared decoy mapping becomes the policy's unsupported-port action (default `notify`), or its high-risk action (default `isolate`) when `risk_score >= 80` or `severity >= 4`; a disabled or invalid policy becomes `notify`. Policy actions outside the five fall back to those defaults (`normalize_safe_action`). `risk_score` is computed by the core from the EVE severity. |
| Core to agent | decision events on `ai-bridge.sock` | trusted producer, one-way | socket 0600 in a 0700 directory owned by `azazel-agent`; the core (root) connects; the agent never writes back |
| Web UI to agent | `manual_query` on `agent-query.sock` | authenticated peer, untrusted question | `SO_PEERCRED` allows root or `azazel-web` only; one request type; 4 concurrent |
| Web UI to control daemon | named actions on `control.sock` | authenticated peer | `SO_PEERCRED` and the fixed `WEB_UI_ACTIONS` table; `migrate_path_schema` is root only |
| HTTP client to Web UI | API requests | per token role | `require_token`: `viewer` < `operator` < `responder` < `admin`; fail-closed unless `AZAZEL_AUTH_FAIL_OPEN=1` |
| Model output to agent | analyst, ops-coach, manual-query JSON | untrusted | closed schemas (`_normalize_analyst_result` and friends), length caps, fallback on parse failure |
| Model output to the cognitive core | structured JSON | untrusted | `TRUSTED_CONTROL` / `UNTRUSTED_DATA` separation, `GroundingValidator`, lifecycle rules, claim audit |
| Model evidence requests | capability name and arguments | untrusted | `CapabilityBroker`: frozen registry, typed parameters, budgets, timeouts, no write, exec or network primitive |
| Knowledge or AZ-06 to Edge | Fabric advisories and observations | untrusted, optional | fail-closed verification, fail-open availability |
| Explanation record to its reader | trust capsule | integrity check only | HMAC-SHA256 with the device key read by the agent's unit; without a key the capsule is `unsigned` (#498). The agent holds the key, so a signature shows the record was not changed by a party without the key; it does not attest anything independent of the agent. |
| Agent files to readers | advisory, snapshot, logs, explanations | readable by `azazel-web` only | directories 2750 `azazel-agent:azazel-web` ([privilege-inventory.md](privilege-inventory.md) §11.7) |

## 7. Contract ownership

| Contract | Owner | Location |
| --- | --- | --- |
| SituationFrame `mio.situation_frame.v2` (reads v1) | Edge-local (#361, #383) | `py/azazel_edge/mio/contracts.py` |
| Hypothesis, evidence gap, capability request and result, recommendation, reasoning states | Edge-local | `py/azazel_edge/mio/contracts.py`, `broker.py` |
| No-model handoff `mio.no_model_handoff.v2`, trace audit `mio.trace_audit.v2` | Edge-local | `py/azazel_edge/mio/handoff.py`, `trace_audit.py` |
| Agent advisory and snapshot fields | Edge-local | `py/azazel_edge_ai/agent.py` |
| v2 decision explanation and trust capsule | Edge-local, with Fabric projections written beside it | `py/azazel_edge/explanations/` |
| Deception and engagement contracts | Fabric (`azazel_fabric.deception_contracts`, `engagement_contracts`) | consumed by the modules in section 4.2 |

The rule the code follows: a contract that crosses a product boundary is a
Fabric model; M.I.O. reasoning contracts do not leave Edge and stay Edge-local.
A change to an Edge-local M.I.O. schema bumps its version in the same change
([mio-situation-frame.md](mio-situation-frame.md)).

## 8. Design decisions and rejected alternatives

| Alternative | Decision | Where it shows in the code |
| --- | --- | --- |
| LLM as arbiter | Rejected. The core decides; model output is advice. | `decide_defense()` takes no model input; `MioRecommendation.executable=False`; grounding is deterministic ("no LLM judges another LLM"). |
| AI before the decision | Rejected. | The core forwards to the agent only after `maybe_enforce()`. |
| Free-form shell or MCP agent | Rejected. M.I.O. selects capabilities; it does not invent commands. | `CapabilityBroker` registry rules; playbooks are non-executable data; the agent runs no command other than the route read. |
| Knowledge as policy authority | Rejected. | The Knowledge clients reject anything but `authority=advisory_only`, `executable=false`; availability is fail-open. |
| A second enforcer in Python | Rejected by owner decision #412. | `ActionArbiter` has no live caller; the boundary inventory test. |
| Cloud fallback for inference | Not built. | `OllamaStructuredTransport` refuses public endpoints; no fallback chain leaves the device. |

## 9. Open work and recorded differences

### 9.1 Tracked

| Item | Issue |
| --- | --- |
| Hostile review before any non-shadow M.I.O. influence | #373 |
| Operator surfaces with authority labels (fact, decision, advisory, hypothesis, recommendation, unknown) | #374 |
| Decision-level trace and evidence provenance in the console | #341 (being implemented in #501, open) |
| Final documentation package (operations, offline deployment, field validation) | #375 |
| Pi-class resource and latency evidence for the frame builder and models | #372 (frame budget follow-up from #383) |
| Live wiring of `ReasoningCoordinator` and of the trace audit port (`trace_recorder.py`, off by default; key provisioner not run by the installer) | #385 |
| Real read-only broker adapters, per-capability data minimization, cancelling handlers of stale cycles, RBAC tests | #384 |
| Claim classes from #366 Part B (per-ref freshness, arbiter contradiction, Knowledge-as-decision, AZ-06 belief, attribution wording); structured playbook selection; `select_playbook` in a runtime | #386 |
| Live callers that pass Edge's decision-audit records (`action_history`) and an AZ-06 facts projection (`deception_context`) to the frame builder; the v2 fields exist, but no running service fills them | #385 |
| Outcome-as-Evidence proof gates | #400 |
| Outcome reasoning and evidence-backed feedback to Knowledge | #369, #305 |
| Bounded Engagement Advisory; AZ-06 live-activation gates | #368, #358, #325 |
| Outward vocabulary migration to Defensive State | #390 |
| Core as a non-root account | #471 (stage 3) |
| Runtime profiles, Mission Packs, Knowledge Lite, rugged HIL | Azazel-Nexus#5, #3, #6, #4 (moved by #408) |

### 9.2 Recorded here without an issue

These are facts about the current code. They were not changed by the #388
design document; items marked "Done" were changed later.

- The agent's model calls (analyst, ops coach, manual query) do not pass
  `AIGovernance.should_invoke`. They are out of scope of that contract by the
  documented decision in [AI_OPERATION_GUIDE.md](../AI_OPERATION_GUIDE.md)
  §3.1 and record `in_scope=false` scope entries in the AI audit. In the
  running services only the cognitive core's adapter calls `authorize()`;
  `triage/selector.py` accepts a governance object but no service passes one.
- Done: the agent's model endpoint (`AZAZEL_OLLAMA_ENDPOINT`) is checked
  before every model call (#388). Only loopback is accepted; a host name must
  resolve only to loopback and the request goes to the checked address, with
  no redirects and no proxy. The agent has no private-LAN opt-in, unlike
  `OllamaStructuredTransport`, which also rejects DNS names other than
  `localhost` and does not resolve them. A refused endpoint gives the
  `fallback` analyst result with an `llm_endpoint_*` reason and one log line
  ([AI_OPERATION_GUIDE.md](../AI_OPERATION_GUIDE.md) §4).
- The agent's advisory `recommendation` can hold the analyst model's
  `suggested_action` (free text, at most 80 characters). The advisory keeps
  `llm.status` and `llm.model`, but no field marks the recommendation itself
  as model-written. Labelling on operator surfaces is #374.

## 10. Related documents

- [Decision Loop](decision-loop.md)
- [Local AI Triage](local-ai-triage.md)
- [X86_64 Integration Boundary](../X86_64_INTEGRATION_BOUNDARY.md) (decision and enforcement authority)
- [Privilege inventory](privilege-inventory.md) (accounts, sockets, files)
- [M.I.O. Cognitive Shadow Core](mio-cognitive-shadow-core.md)
- [SituationFrame contract](mio-situation-frame.md)
- [Capability Broker](mio-capability-broker.md)
- [Reasoning lifecycle and no-model handoff](mio-reasoning-lifecycle.md)
- [Grounding and evidence gaps](mio-grounding-and-evidence-gaps.md)
- [Reasoning playbooks](mio-reasoning-playbooks.md)
- [Reasoning trace and audit](mio-reasoning-trace.md)
- [AI Operation Guide](../AI_OPERATION_GUIDE.md)
- [M.I.O. Persona Profile](../MIO_PERSONA_PROFILE.md)
