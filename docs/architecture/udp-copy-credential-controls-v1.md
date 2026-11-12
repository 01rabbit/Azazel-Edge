# Real socket-copy credential and locator lifecycle controls — #400/#393

Freeze before test code, base ac9ba85a (#594). TEST HARNESS ONLY: no product/runtime
changes, privileges added, production services or keys, installer/security/systemd.
The existing sensor must stay Root+BPF/PERFMON-only, zero Inh/Amb, NNP. Root test
setup retains only its existing isolated UID/GID/KILL/descriptor setup authority;
receiver/sender/creator have zero effective/permitted/inheritable/ambient caps+NNP.

## Trust and finite conditions

An isolated creator UID61002 owns an IPv4 loopback UDP socket and sends its FD
through an inherited private Unix socketpair using SCM_RIGHTS. A separate receiver
obtains that same socket (inode/cookie/netns-cookie unchanged). The creator closes
its own descriptors and exits/reaps BEFORE observation: original locator is only
frozen provenance, never a currently living named receiver or identity continuity.
Root harness owns bootstrap/FD transfer and fixed synthetic keys, never observer
truth or production custody. No Unix listener/network namespace construction or
new sensor IPC. Sending, descriptor passing and receiving are test actors only.

Externally freeze actual socket identity, original locator, PID/time/network NS,
boot, tuple/64B challenge/window/BTF/kernel/ELF and contract/plan hashes before
attaching/traffic. Receiver reports own actual real/effective/saved UID, NNP and
zero caps as control_only. Actual copy evidence is solely the signed fixed three-
hook event, never recvmsg success or a counter. Original creator UID and socket
owner stay61002 even if a different permitted actor holds the FD.

Positive: receiver real=effective=saved61002, original creator exited. Require one
bound signed event with observed receiver PID/TID different from exited locator,
raw leader start_ns positive and both calling UIDs61002. Application/syscall/
qualified safety counts stay null. No process continuity or named receipt claim.

Negative: (real,effective)=(61003,61003),(61003,61002),(61002,61003), saved=effective.
Each receiver must actually consume matching64B while hooks attached, yet report
has no matching event and diagnostic count remains null (NEVER zero). This tests
separately the real and effective credential predicates on an unchanged socket.
Before each finite negative observation, require an independent same-socket
eligible same-UID positive under its own explicit plan/window/capture IDs; no
cross-run report aggregation, prior positive erased or inferred negative coverage.
Positive control failure or unestablished credentials/transfer/reaping/socket IDs/
capabilities/namespace/profile is failure/unknown, never a successful negative.

## Acceptance and unknowns

Four finite cases must run on actual Linux with fixed compiled ELF/actual BTF and
no skips in mandatory CI. Reuse existing approved exact4/5-arg build and capture/
evaluation without monkeypatches. Original signed bytes remain unchanged through
negative trials. Test fixture teardown is bounded, closes owned descriptors only,
and reaps/kills only its own children. No target mutation by product observer.

Synthetic parser/model tests do not substitute for these cases. Different actual
PID namespace, scheduler migration, checksum/GRO/iterator faults, power/reboot,
physical/Pi-HIL, production key independence, broad restoration, safety and
comparative benefit remain unmeasured. No missing interval/backfill/zero/automatic
resume or liveness check is introduced by this test-only slice.

## Validation record and corrected harness setup

First actual run:2 passed,2 failed BEFORE negative capture because execve reset
split real/effective IDs to the real UID. The strict actual-credential guard caught
this; those trials are FAILED setup, never successful credential negatives.
Fixed Root receiver bootstrap establishes the exact split UID/GID AFTER interpreter
exec, drops all capability sets/bounding to zero and fixes NNP BEFORE reading the
SCM socket. No later exec occurs. This uses only existing isolated test bootstrap
authority and changes no observer/product permission or expected result.

Fresh actual Linux6.8.0-117 exact5-argument profile:4 cases passed without skips;
each negative consumed64B on the unchanged socket while hooks were attached,
with separately completed same-socket eligible positive control and null negative
copy count. Control failure logs remain distinct from the fresh success. Root
integration subsequently fixed the receiver child's explicit tests-module search
path for CI's PYTHONPATH=.:py and sender's own NNP/capability guard; final exact-CI-
environment test and final-head hosted CI remain required. No synthetic test or
privileged parent status substitutes for actual child credential checks.

Independent review also found that a null report alone could pass if the negative
read occurred after the original window or during observation loss. The test now
brackets the complete receiver command with the shared zero-offset monotonic clock
and requires that bracket inside the signed start/original deadline/finish. Each
positive event's three timestamps must lie inside that bracket. Any link loss,
correlation loss, overflow or early bound makes this credential control FAIL,
not a negative pass. Native loss counters being zero are only validity gates;
they do not prove coverage, absence or a finite negative count. The report's
negative copy count remains null. A fresh final run is required after this guard.

Final guarded local run with exact CI PYTHONPATH=.:py:4 passed in10.79s, no skips.
Independent review CLEAN after both child import/NNP and time/loss guard fixes.
No product/native/observer source changed. Final-head complete hosted CI is still
required, including all four actual cases with skip rejection.
