# Actual three-hook copy-observer FD loss — #400/#393

Freeze before implementation; base9edb4892 (#595). Test-only real kernel fault
injection using unchanged approved three-hook observer/ELF/BTF/domain/evaluator.
No production source/service/keys/installer/security/systemd or privilege changes.
Sensor keeps exact BPF+PERFMON-only, zero Inh/Amb and NNP; target/sender remain
separate test actors. No SYS_ADMIN, global BPF object queries or permission bypass.

## Trust boundary and controlled faults

Root isolated harness wraps libbpf ONLY to remember OWN loaded map/link FDs and
inject a single explicit close of an OWN link FD. Fixed callback uses OWN stats
only to choose injection time; counters are not copy evidence. Real target/socket/
loopback/64B traffic and unchanged signed native events supply finite positives.
The wrapper must not fabricate events/stats/signatures/clock/role/link identity,
modify foreign FDs or load replacement probes. Mark all fault_state as control_only.
Product capture must never reattach/retry or extend the original deadline.

Five cases: before_first (close entry before traffic, no event expected, count
null); after-positive close entry, consume or exit independently; after-positive
close entry then replace that exact FD number with a harmless OWN /dev/null FD.
Trigger after-positive faults only after own native stats accepted>=1, then require
an independently validated matching event in the signed report. Bound callback
and wait; no fault-trigger or profile/identity failure is a successful case.

All cases require exactly3 original attachment calls, explicit fault_applied,
observer_link_lost and unchanged original window/pins. Before-first count is null,
never zero/absence/coverage; no traffic before its fault/report, any separate
post-detach target read is merely a harness control. After-positive count stays1,
receiver/socket/UID/tuple/challenge/timestamps match original plan. Syscall/app/
qualified safety remain null. No new report if cleanup ownership is ambiguous.
The replaced /dev/null FD must remain valid after capture: cleanup must not close
foreign replacement identity or retry a freed libbpf pointer. Close only that
harness-owned replacement explicitly AFTER checking it.

## Acceptance and unknowns

Actual isolated Linux five cases, no skips in mandatory actual CI; compile through
existing exact localBTF4/5 profile. Record actual fault trigger/link name/attach
count/replacement status separately from signed report. Preserve prior published
bytes and all failed trial evidence; Root/kernel/approved C+ELF+BTF/labkey custody
remain trusted premises. Synthetic backend cleanup tests remain distinct.

Closing a link FD, healthy cleanup or a positive event DOES NOT prove actual
observer-object disappearance, complete global detach, independent load attestation,
no unseen duplicate observer, outage coverage, continuity/restart, application
receipt, broad restoration, Pi/HIL/production/whole safety or comparative efficacy.
Direct-ID disappearance remains unmeasured without SYS_ADMIN, which is prohibited.
No missing-data fill, zero conversion, backfill or automatic resumption.
