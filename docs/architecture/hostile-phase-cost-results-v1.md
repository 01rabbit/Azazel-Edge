# Declared 120% ingress timing/cost pilot: virtual Linux results

Tracking #400/#393. Conditions and refusal rules were committed before code and
collection in `hostile-phase-cost-v1.md` and the protocol fixture. The actual
trial used source `f93b0c456992d7b43a9bced81b6b241fb9f2e57f`.

## Observed scope and separate verdicts

One bounded offline Linux six-arm test passed in 49.20 seconds, without skips or
retries. All six fresh scopes offered the existing 1.2 × 2,500 non-alert quota,
with its existing 2% per-class rate tolerance, actual 3-second warmup and at least
6 seconds of actual writer activity. The core, signer, witness and optional
observer used the existing distinct identities and disabled enforcement. Source
and matching ARM64 core were mounted read-only; the existing disposable image
ran as its established root driver with network disabled and no added capability.
No production service, account, key, policy or permission changed.

| Arm | Actual written lines/s | Written non-alerts | Examined | Coverage |
| --- | ---: | ---: | ---: | ---: |
| original off | 2999.398 | 18,004 | 18,004 | 100% |
| instrumented off | 2999.753 | 18,000 | 18,000 | 100% |
| original on | 2999.873 | 18,008 | 18,008 | 100% |
| instrumented on | 2999.424 | 18,000 | 18,000 | 100% |
| original faulted | 2999.628 | 18,000 | 18,000 | 100% |
| instrumented faulted | 2999.753 | 18,004 | 18,004 | 100% |

Actual rates use the original observed start/end window, not a shortened
denominator. All 108,016 written non-alert lines were recounted from original
bytes and accounted for in the strict post-exit native audit. This passes the
unchanged **98% examined-accounting floor**, not a protected-service delivery or
safety threshold. Expected quota shedding and no alert shedding were verified.
Actual file hashes/counts differ across sequential writers; only the fixed
three marker alerts and their ordered decision projection are byte/semantically
matched. No adaptive throughput calibration or lower quota was substituted.

All six native/signed paths produced the same three marker decisions and clean
authenticated Source closure. On arms retained five cursors; faulted arms
retained three, SIGKILL exit and two unprocessed decisions without backfill.
Required phase calls were observed; the #609 narrow fault-gap exception was not
needed. Instrumented on/faulted observers retained 266/108 original callback
clock rows; 106/2 completed callbacks lay inside the actual load window after
warmup. Intentional signal stops left observer phase/clock closure incomplete.

The unchanged **5ms full-clock qualification is WITHHELD** because genuine
observer end anchors are absent. No completed callback body exceeded 5ms in
these retained rows, but that does not qualify the whole original epoch/call
enclosure or unsampled clock continuity. No last callback or controller timestamp
was substituted. Overall measurement and comparison remain **WITHHELD**, even
though the software test and finite ingress-accounting controls passed.

## Descriptive cost observations

Selected completed-call medians in the instrumented on arm, in milliseconds:

| Boundary | Median ms |
| --- | ---: |
| Source signature generation | 0.101 |
| Source append, inclusive | 2.034 |
| Source fsync call | 1.100 |
| Witness RPC, inclusive | 1.350 |
| Observation/cursor processing, inclusive | 4.868 |
| Journal append, inclusive | 2.055 |
| Sample callback | 0.356 |
| No-op finalize-due callback | 0.010 |
| Original controller polling wait | 23.177 |
| Source-stop confirmation adapter | 61.239 |

These intervals overlap and are not additive. Source-stop confirmation includes
the existing launcher stop plus read-only native-disappearance, stderr-join and
final-audit checks in the new adapter; it is not exact native kernel wait time.
Receive waits include idle blocking. The empty/stale policy exercises no active
Outcome window: active-window finalization wait remains null/not exercised.

Instrumented-minus-original marker-loop elapsed differences were -26.489ms off,
+17.778ms on and +5.217ms faulted. The original `elapsed_seconds` covers the
three-marker loop after warmup, not the full six-second load. Separate process
samples span the background-load interval and drain. Their native CPU differences
were -0.01s/-0.01s/0s at the recorded tick granularity. These are descriptive
single sequential trials; negative/quantized differences are retained, not
interpreted as causal improvement or zero overhead.

Signer/observer full-process metrics were unavailable where existing procfs
permissions denied reads, and remain null. No ptrace or other capability was
added to obtain them. Their actual self-recorded phase CPU brackets remain
separate bounded facts. Root witness shares the controller, workload generator,
stderr reader and retained prior-arm results: its process CPU/RSS/I/O cannot be
isolated as witness overhead. Write-loop timing excludes serialization/hash/lock
cost; no metric establishes physical storage wear, fsync durability or power-cut
behavior.

## Retention, provenance and unresolved gates

The actual report SHA-256 is
`45e263871ec097ee9278efb63b87ac2f77a6c6248b68e41a027d01a2762af440`.
The public export has the report plus 45 allowlisted original files: six each
of EVE, signed Source, public trust policy, final audit and pre-stop audit;
eleven phase traces and four callback/context traces. Private signing keys and
private bootstrap/configuration files are not exported. Original private fixture
stores remain in the stopped disposable container.

Native exit zero is derived from the pinned unchanged trusted launcher's real
conjunctive return, with observed launcher PID/start/status and separate native
incarnation/disappearance checks. It is explicitly not an independently waited
native status. Complete mixed stderr from startup through EOF and exact original
audit prefix/final bytes support the accounting check. Public test keys, hashes,
Root file custody and process assertions are lab premises, not independent
production enrollment or execution attestation.

This pilot does not close the provisional quota, full 5ms clock closure,
production confinement, protected-service benefit, whole-system safety, Pi/HIL,
resource budgets or physical durability gates. Historical #609/earlier failures
and clock refusals remain unchanged. A later complete-clock profile or target
run needs its own fixed stop/registration and observation contract; no permission
or production transition follows from these results. Final-head CI runs its own
separate real trial and publishes its own original receipts.
