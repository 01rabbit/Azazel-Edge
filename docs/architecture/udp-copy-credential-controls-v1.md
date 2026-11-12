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
