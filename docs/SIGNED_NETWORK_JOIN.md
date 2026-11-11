# Signed network join instrumentation (test only, unfinished VM driver)

Status: hardware-free recording and service-coordinate components. The manual
four-VM driver remains a draft; no experiment has been frozen or run using it.
This is neither production admission nor an efficacy/causal-support result.
The old direct-core v3 experiment and all used scopes remain unchanged.

## Three different kinds of evidence

Keep the signed native stream, original live observer journal/outcomes, and
independent service/client audits unchanged. A root operator may separately
retain the complete raw nft chain response with its actual query times, source
pins, child/namespace identity and boot ID. That root-only lab query supplies no
observer privilege and is never a proxy available to the observer.

`tests/real_systemd/signed_network_recording.py` provides a test-only constructor
binding around the real `OutcomeTelemetryCollector` used by `run_live_resumable`.
`record_collector(path, policy=..., policy_source_ref=...)` calls unchanged super
methods and records their actual inputs, explicit epochs, monotonic call bounds,
returned samples, acceptance results and final Outcomes. It creates one exclusive
0600 sidecar under the existing observer-directory grant. It never calls an
extra sample or finalization. A call is marked inflight before entering super;
only its durable sidecar append clears that state. Caught exceptions, signals,
partial writes and exceeded bounds poison the recording and prevent a clean end.
Original journal results already persisted before a recording failure are retained
but cannot justify reconstructing missing calls. Bounds are 4 MiB/900 rows.

`read_calls` requires complete canonical finite JSON, duplicate-free keys,
sequence/hash continuity, ordered epoch/monotonic call bounds, a safe regular
single-link file, and stable identity/size/timestamps across reading. The hash
chain detects accidental changes; it does not authenticate a malicious operator
or the same UID. Signed source/witness/journal and source/assignment/clock checks
remain separate required inputs to the future coordinator.

`replay_calls` constructs a **read-only G5 projection** using those recorded
sample/event/finalize calls. It returns the original live Outcomes plus a plain
replay and, optionally, a separate root-probe-augmented replay. It never replaces
live outcomes or claims the live observer verified nft. The G5 constructor names
its policy source `golden-replay`, while the live constructor uses the real policy
file path. Comparison therefore names an explicit policy-source-label equivalence,
not byte equality: the canonical policy SHA must match, both exact references
must be derived by the unchanged policy constructor, and only
`telemetry_coverage.policy_ref` and its one exact `evidence_refs` entry may differ.
Both originals, hashes and exact differences remain in the result. Any other
Outcome delta, lost sample, incomplete coverage or changed sample timestamp refuses
the join. A changed augmented projection does not update the live Outcome.

## Service and clock coordinates

`tests/real_systemd/signed_network_service.py` reuses the existing
`network_measure_driver.measured_capture`, G5 and
`azazel_edge.benchmark.measurement.measure_experiment` contracts. There is no
replacement benefit calculator or independent private PASS.

The proposed new fixed plan has a five-second service horizon starting at actual
H0 and a client origin exactly H0 + 1.25 seconds. The unchanged peer uses its own
client origin for request elapsed times. `service_capture` adds that exact recorded
monotonic offset only to capture-input elapsed coordinates. It keeps original
audit hashes, nonce, transaction IDs, error flags, measured duration, service goal
commit time and actual deadline; client ACK never becomes objective truth. This
places six unchanged client requests at their original offsets within the common
service horizon, without moving a recorded collector sample/action/window.

`record_clock_anchor` reads wall time inside a real monotonic bracket.
`clock_binding` maps two independently retained observer/controller brackets to
actual service H0, carries the measured uncertainty and never tunes alignment.
The existing measurement gate still withholds uncertainty or disagreement above
5 ms. Its session/clock declarations require independent review; these helpers do
not authenticate arbitrary imported JSON. All original clock brackets must be
archived together with the source and namespace/time-domain identities.

`recorded_root_probe` accepts only the fixed nft throttle query, successful raw
text, declared root/boot/namespace/source bindings, the explicit independent-root
capture label and actual bounded UTC query interval. It performs no query. Keep
its original launch receipt and raw result as independent lab facts. The receipt
is not signed authority proof, and matching an owner marker alone is insufficient;
G5 invokes the strict production full-chain/plan/owner/tuple parser.

`measurement_record` uses `edge_recording=None` only for baseline role
`observe_only`. The actual signed/native disabled/dryrun facts must be retained
separately; they are never rewritten into an APPLIED observe action. Candidate
records carry the unchanged actual event, boot, decision, execution, mechanism,
objective and canonical policy bindings into G5. The existing measurement checks
coverage, horizons, independent mechanism readback, verified release absence,
clock mapping, safety and paired assignment completeness. Unit coverage explicitly
keeps a missing release **withheld** even when a separate synthetic root receipt
makes the mechanism observed in a projection.

## Remaining gates before any VM work

The draft `signed_network_measure.py` is not a supported CLI or a reviewed runnable
coordinator. It must still bind the recording sidecar to the authentic complete
signed source and durable observer journal; freeze all four source-bound
assignments before any per-assignment preparation; and retain complete evidence
on any failure. It must retain separate service-only facts when the join is
withheld, reject duplicate/conflicting artifact identity, and validate four unique
actual kernel boots/scopes. Review and pin the complete code before execution.

Only four manually provisioned independent cold-boot VMs, or cold clones of a
strictly unused dependency-only template, qualify for that proposed test. No used
registration, keys, ledger, source history, journal or namespaces may be reset or
reused. Existing v4 registration, sealed ELF, full policy/event binding, separate
UIDs, fixed paths, AppArmor profiles, zero-cap observer and provider capabilities
remain required. If the actual observer label cannot sample procfs, record the
commissioning gap and stop; do not broaden profiles or substitute an unconfined
collector. No runtime or experiment-freeze command is supplied here.

Interface counters, system metrics and source-IP activity remain broad/confounded.
A truthful flow mechanism scope and measured service change do not establish
flow-specific Outcome metrics, actor attribution, production readiness, or causal
support. Resource overhead and physical-device G6 gates remain separate.

Hardware-free checks:

```sh
PYTHONPATH=.:py python -m pytest -q tests/test_signed_network_recording.py tests/test_signed_network_service.py
```

The fixtures in these checks are synthetic, including root query envelopes; they
are not substitutes for an actual signed/sealed VM experiment.
