# Read-only sampled-clock diagnostics

`tests/real_systemd/signed_network_clock_audit.py` exposes `audit_clock(**evidence)`
with the existing `qualify_clock` keyword arguments. It calls that qualifier first
and returns its original result unchanged. Invalid or missing clock evidence
produces no row diagnostics; missing required Python arguments retain the
qualifier's `TypeError`. The existing 900-row bound and fixed 5 ms gate apply.
There is no command-line runner, evidence importer, runtime action, or permission
change.

For valid original anchors, including a withheld result, each row reports the
existing exact supplied-epoch enclosure, the interval between that epoch and the
before-anchor epoch, both anchor spans, the full wrapper span, and the operation
body span. It reports both original gate discrepancy terms using the unchanged
whole-run offset envelope, their maximum, the worst row sequences, and rows
strictly exceeding 5,000,000 ns. It never shifts timestamps, interpolates a clock,
changes a threshold, or upgrades qualification. These are arithmetic diagnostics,
not authentication or continuous unsampled clock proof.

The timing-only fixture `tests/fixtures/clock-audit/trial1-a0-timing.json` retains
all 95 original a0 row sequences, supplied epochs, operation brackets, external
anchors, and the historical qualification. Event/sample/outcome payloads are
removed; the retained archive and original-recording hashes identify provenance
without authenticating this projection. It reproduces the historical sole
exceeding row: event 25 at **5,006,790 ns**, with supplied-epoch age before the
wrapper in **[4,789,115, 4,789,593] ns**, wrapper span 215,489 ns and body span
212,947 ns. The historical result remains withheld.

Elapsed time before the wrapper includes work and scheduling outside its sampled
interval. Their individual contributions are **UNKNOWN**; these fields cannot
attribute the delay to CPU activity, VM scheduling, or a clock step. The four-VM
pilot remains unqualified, and these diagnostics do not complete a measurement,
finish a ledger receipt, authorize a transition, or admit production use.

## Read-only audit of all four retained attempts

The diagnostic was also applied locally to the unchanged original reader returns
and clock anchors from all four [historical pilot](SIGNED_TELEMETRY_VM_PILOT_20261112.md)
archives. All four qualification objects exactly matched their historical values.
This is arithmetic on retained artifacts, not a new VM run or authentication.

| Attempt | Worst row | Before-anchor epoch age interval (ns) | Operation body (ns) | Full wrapper (ns) | Gate discrepancy (ns) |
| --- | --- | ---: | ---: | ---: | ---: |
| a0 | event 25 | 4,789,115–4,789,593 | 212,947 | 215,489 | 5,006,790 |
| a1 | finalize 63 | 13,847–14,325 | 7,420,537 | 7,427,745 | 7,471,904 |
| a2 | finalize 64 | 10,759–11,237 | 8,283,851 | 8,286,268 | 8,299,047 |
| a3 | event 26 | 3,928,929–3,929,407 | 242,542 | 245,458 | 4,188,116 |

Only the first three exceed the unchanged gate. The two worst candidate rows
each returned one outcome; their delay lies mainly inside the finalization body,
whereas a0's lies mainly before the event wrapper. Body time includes work and
scheduling: these observations do not identify journal synchronization or any
other individual operation as the cause. Durability and authentication must stay
intact in any later investigation; neither a faster-looking timestamp nor a
relaxed gate can replace missing timing evidence.
