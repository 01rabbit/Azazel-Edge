# Frozen telemetry v2 VM pilot — experiment WITHHELD

All four preregistered attempts ended and their fresh VMs were stopped. The
experiment remains **WITHHELD**: three runs exceeded the unchanged timing gate,
and all four safety categories were declared scope inputs rather than independent
violation measurements. No superiority, efficacy, causal or production-admission
claim follows from these results.

The historical execution source was
`e9cc6111a342c2eb503d7798397da342a5d1432f`, with source archive SHA256
`83e5442fb803446d251e910eaa7cc45ec6252dbc072693c309b6b3944f78c2cf`.
The four-assignment manifest was frozen as
`f0211572634f040d62a88010c1c6aeabaec990af1e64f488edec30253d4865dc`
before assignment work. Each attempt used an independent fresh boot and scope.
There were no fills, retries, replacement runs, threshold changes or retimed data.

## Original observations

The fixed execution order was **C0 → throttle → throttle → C0** (ABBA), two pairs,
with a five-second service horizon. Values below are retained raw service facts,
**not qualified comparative measurements or evidence of superiority**.

| Attempt / assignment | Arm | Worst call discrepancy (ns) | Historical reader | Raw goal completion (s) | Legitimate transactions / errors | Raw latency p95 (ms) |
| --- | --- | ---: | --- | ---: | --- | ---: |
| a0 / pair-0-c0 | C0 observe-only | 5,006,790 | withheld | 1.663559810 | 6 / 0 | 1.579418 |
| a1 / pair-0-flow_throttle | Flow throttle | 7,471,904 | withheld | null | 6 / 0 | 1.436215 |
| a2 / pair-1-flow_throttle | Flow throttle | 8,299,047 | withheld | null | 6 / 0 | 2.353326 |
| a3 / pair-1-c0 | C0 observe-only | 4,188,116 | calculation_available | 1.660045709 | 6 / 0 | 0.711125 |

`null` means the original service receipt recorded no goal completion within H5.
It does not establish that throttling caused that observation. The last run's
historical `calculation_available` status is not whole-experiment qualification,
independent safety measurement, production admission or permission to resume.
Broad interface/system telemetry also remains confounded.

The fixed call-timing budget was 5,000,000 ns. The three withheld runs reported
`supplied_epoch_call_interval_exceeds_budget`. Their sampled clock-offset
envelopes were only 44,830, 35,250 and 12,958 ns respectively; this identifies
argument-age/call-interval failure rather than establishing a wall-clock step.
In a0, event row 25's supplied epoch preceded the collector wrapper by about
4.789 ms; the wrapper's full bracket then spanned 215,489 ns. The exact conservative
result exceeded the gate by 6,790 ns. Epoch sampling occurs before decoding and
intake checks, while recorder anchors start at the collector call. The retained
data cannot separate decoding work from VM scheduling delay in that gap.
No timestamp was shifted to turn any run into a pass. Sampled consistency cannot
prove clock stability between observations.

## Safety and accounting limitations

The four categories were `protected_escape`, `unauthorized_action`,
`advisory_authority_conversion` and `forged_evidence_accepted`. Their zero values
originated as declared closed-scope inputs and were copied into capture/receipts.
They were **not four independently measured zero-violation counts**. Successful
commands, confinement checks, kernel readback or clean shutdown cannot silently
supply those missing measurement contracts.

Accordingly, no completed or failed ledger receipt was fabricated from those
zeros. All four ledger entries remain `running`/unfinished. Separately retained
operator evidence records that each actual attempt ended, its cleanup was checked
and its VM stopped before the next unused assignment started. This preserves all
four assignments in the denominator; it does not erase the attempted runs or
make their accounting complete.

The externally retained final start head is
`354be92e2041e5ec36fe06330f31bd404389372c27d5c01dea587950a55e5971`.
There are four start transitions and no finish transitions. The full experiment
must remain withheld even though one historical reader returned a calculation.

## Closure and retained evidence

For every attempt, retained independent observations showed all seven fixed unit
families inactive with PID0, all seven cgroups empty, all three owned namespaces
absent, no core process and an unchanged parent network snapshot. Each case's five
original clients exited without forcing; all twelve owned Root children were
reaped with empty process groups and no forced cleanup. These are bounded cleanup
facts, not measurements of the four safety categories throughout the horizon.

The original public-only evidence archives are retained privately under operator
control, excluding signing keys. No raw private contents or credentials accompany
this candidate report. Archive SHA256 values identify the unchanged originals:

| Attempt | Evidence archive SHA256 |
| --- | --- |
| a0 | `c5b275aa2d9b5c9b932985a013b009232baa523f22e910597046d156a492b1e3` |
| a1 | `e801860f99a77a550f11307436a9a41d36069da392d0700a4b176aee2739f276` |
| a2 | `a7648e2e199878515061cac0a295328b98d57d37d783ac39e20fb2715647c6d8` |
| a3 | `781c54dd345fc0884c038875e7b6f5fac596991cb566fc03756073a46aadcec9` |

## Follow-up gates

The later `ca56…` correction, integrated as `848daf…`, makes the reader
diagnostics-only and always withholds while independent safety measurements are
unavailable. It did **not** run in this historical trial and does not rewrite its
source, artifacts or reader outputs.

Before any new comparative qualification, characterize epoch-sampling and intake
latency without moving the historical timestamps or relaxing the fixed gate, and
define independently observed contracts/denominators for each safety category.
Any later run needs its own reviewed, frozen source and plan. Two pairs would
still support only a limited mechanical pilot; this trial provides no operational
superiority or production-activation result.
