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
