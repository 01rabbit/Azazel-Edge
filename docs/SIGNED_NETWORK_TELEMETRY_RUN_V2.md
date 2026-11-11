# Explicit telemetry assignment runner v2 (code only)

`signed_network_telemetry_run.run_telemetry_assignment` consumes the direct
privately constructed preparation context. It does not reopen ownership from
prepared JSON or select the legacy observer. Its separate
`--telemetry-root-query` selector accepts only the fixed v2 pins and fixed nft
read-only command in the currently owned EDGE namespace.

The Root controller anchor starts before the baseline query and ends after the
TTL absence query. The original service origin and five-second horizon remain
independent. The live budget starts at the earliest systemd-run **client** Popen
bracket, conservatively includes proof/setup, and remains forty seconds. The
observer PID comes from the separate Root actor proof. Natural helper return is
sampled immediately in `observer_helper_return_ns`; it is not reconstructed from
a terminal timestamp. Missing timing/terminal/cleanup evidence withholds output.

Before an active query the runner retains full original collector reads,
including partial tails, validates every complete row, and finds the original
matching event callback. Closed intake, malformed complete rows, missing or
duplicate callbacks, and exceeded budgets refuse the query. The final reader
must bind the retained prefix and inode to the unchanged closed recording.
Release/absence uses the same original-callback fence. Query UTC timestamps
come directly from each actual Root clock anchor; no clock realignment occurs.

Three `*-query-launch.json` and two `*-peer-launch.json` receipts record actual
child PID, original argv and immediate monotonic Popen brackets. The preparation
context owns all five children and actor/namespace cleanup. The runner naturally
reaps peers and queries, stops native while witness remains live, and publishes
run-facts only after context cleanup. Primary errors remain sticky if cleanup
also fails. Original raw observations and partial failure facts remain retained.

Focused unit checks use original collector rows and real private pipes with
explicitly synthetic Root/namespace metadata. Early failure tests use a
synthetic ownership context. Complete synthetic direct-context C0 and candidate orchestration tests also
exercise the unchanged decision helpers, service calculation and recording
parser with declared mocked actors/source/clock/privileged I/O. They establish
no actual namespaces, confinement, authentication, traffic effect, or
measurement acceptance. A full reviewed composition and fresh explicitly
marked VM run are still required. Existing actual manual positive/refusal evidence belongs to its
historical source and does not qualify this runner. No four-assignment run,
performance, production admission, or efficacy claim follows from this change.
