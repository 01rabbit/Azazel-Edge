# Opt-in C0 versus existing flow-throttle network trial

This test-only driver measures actual synthetic TCP service traffic across three
fresh Linux namespaces. It uses the existing release core and its flow-scoped
throttle commands. It changes no provider, production service, installed policy,
unit, account or product default. It starts no model. No redirect, source-wide
block or fictional defense arm is implemented.

The client namespace has separate attack and legitimate source addresses. Two
veth pairs connect client → Edge router → service. Only connected and explicit
lab subnet routes exist; no default route or host network interface is attached.
IPv4 forwarding is enabled inside the fresh router namespace only. The existing
`throttle` chain is PREROUTING priority -150, so it sees forwarded packets before
FORWARD. Router OUTPUT traffic would bypass it and is not used. Legitimate
traffic comes from an explicitly protected source to the same service port.

`tests/network_measure_driver.py` reuses the existing scoped-action alert shape,
core executable convention, receipt/capture contracts and durable RunLedger.
`tests/network_measure_peer.py` is a fixed synthetic TCP service/client program.
The optional test creates exactly two paired C0/flow-throttle comparisons (four
runs), counterbalanced within pairs. C0 runs first with enforcement disabled;
its plan/executed_count=0 and unchanged rule readback are checked. Candidate
runs use the existing critical-severity 16 KiB/s, 16 KiB burst restriction,
minimum 30-second lease and independently checked owned source/destination/TCP
port/rate/burst/drop rule. A 256 KiB upload commits a synthetic service-owned
objective when fully received. Six small legitimate requests run concurrently
from the separate protected address; errors stay in the denominator.

The controller's five-second horizon begins **before** alert append and peer
launch. Upload starts at +0.4 seconds; legitimate requests at +0.2 seconds and
then every 0.6 seconds. Missed launch budgets or late/missing results are failures,
not reasons to move the clock, repeat the attack or substitute replay times.
The service reports its own objective commit and complete terminal audit;
client ACK is recorded separately and never substitutes for objective truth.
The client must also report an actual in-window objective connection attempt
and completed bounded attempt procedure. Unexpected objective-thread failures
poison the client audit and cannot become a clean censored objective. Scheduled
waits compute one remaining interval and never pass negative sleep durations.
Both peers must cover the actual common horizon. Missing audit, crash, bad
identity or incomplete legitimate denominator supplies no normalized receipt.
The service stops processing at H. Release is measured afterward, within a
separate bound; it cannot extend the service measurement horizon. The core's
actual execution/release facts and independent nft readback remain separate
from service/client observations and read-only receipt calculations.

Every assignment is frozen and `start` is fsynced before namespace/process work.
Full capture/audits are exclusive-created and file+directory fsynced before
receipt admission. Failed runs remain running/pending in the frozen denominator;
there is no resume, retry, overwrite, repair or backfill. The fresh output
parent directory is private. Colocated head exports are not independent rollback
witnesses; retain exact heads outside the store before separate reopen/review.
Caller-supplied zero safety applies only to an independently reviewed closed
local scope. Unknown or positive safety refuses launch; the driver does not
measure production safety or turn unavailable observations into zeros.

All namespace names contain a fresh random identifier. Existing names are
refused, never predeleted. Creation intent is durably recorded before each
namespace add. A successful add pins its namespace handle and exact device/inode
before use; only confirmed identities can be cleaned automatically. A timed-out
or failed add with an existing handle is an unknown outcome, not ownership
proof: it is preserved and cleanup fails for manual review. Handle replacement
also preserves the unknown/foreign asset. Cleanup attempts every other owned
child and namespace despite earlier errors, writes a private aggregate report,
and fails after those attempts. Owned children are terminated/reaped; any
residual process is signaled through a pidfd only after its network namespace
inode matches the confirmed pinned namespace. Unverifiable residents are not
hidden by deleting their namespace name. Namespace removal and absence are
verified. A foreign-canary nft rule must remain unchanged through
apply/release. Root rules (excluding counters) and IPv4/IPv6 route snapshots must
match before/after, including on failure. Root sysctl/routes/rules are never
written. Failure cleanup stops the trial and leaves evidence for review.

## Prerequisites and review gate

Root must review the frozen source/manifest before actual enforcement. Use a
fresh disposable Ubuntu VM with no external/default route, prestaged Python
dependencies, `ip`, `nft`, `tc`, `conntrack`, and the pinned release core. No
installation, network download or runtime build occurs in the driver. Docker
NET_ADMIN alone may not provide named-namespace/mount capability.

Set the fixed core executable path and its reviewed SHA-256 explicitly:

```sh
EDGE_NETWORK_MEASURE_CORE=/usr/local/bin/edge393-core \
EDGE_NETWORK_MEASURE_CORE_SHA256=<reviewed-sha256> \
EDGE_NETWORK_MEASURE_SOURCE_COMMIT=<reviewed-source-commit> \
EDGE_NETWORK_MEASURE_REVIEWED_SCOPE=trusted_local_netns_mechanism_service_instrumentation_only \
EDGE_NETWORK_MEASURE_TESTS=1 PYTHONPATH=.:py \
python -m pytest -q tests/test_network_measure_driver.py
```

The root Linux/API opt-in, tool availability, exact binary hash, fixed plan hash,
closed safety/scope and absence of external/default routes are checked before
creating the output store. Tool hashes are retained. Asset setup, each command,
peer protocol reads and cleanup have explicit bounds. The normal four-run trial
waits for candidate lease expiry, so it takes approximately one to two minutes.
Without `EDGE_NETWORK_MEASURE_TESTS=1`, the network test skips and offline guard,
audit, readback and failure-accounting tests run without enforcement.

This direct core test path uses trusted local processes and synthetic EVE input.
It does **not** claim sealed/signed production-origin admission, G5 full-chain,
production #400 acceptance, independent UID/host attestation, detector quality,
hardware/HIL, C0–C6 completeness or causal defense efficacy. Source/environment
pins and safety acknowledgments require independent review; hashes alone do
not authenticate them. Paired analysis remains `mechanical_only`. An executed
network result must be retained separately before any runtime pass is claimed.
