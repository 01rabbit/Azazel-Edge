# Outcome input: real systemd virtual-machine protocol

Tracking: #400. These are **virtual-host integration checks**, not Pi/G6,
physical power-cut/storage durability, enforcement/effect or comparative benefit
evidence. Production services, accounts and keys are not changed. This protocol
uses synthetic keys, disabled/dry-run enforcement and a new disposable scope.

## What changed and who owns it

The root operator still owns software/key/account/policy commissioning and the
reviewed service plan. The switch acts on its one fixed core unit only. No
production witness unit, ordering drop-in, user, privilege or activation default
is installed automatically. The separate observer retains public keys only and
its independent journal/witness recovery gate. Missing windows stay missing.

Actual systemd 255 exposed empty Exec arrays being omitted from `systemctl show`,
including with `--all`. The controller now obtains all four lifecycle-hook arrays
through fixed local `busctl get-property` calls, checks their exact known type,
and refuses missing/malformed/unsupported replies or configured hooks. It does
not assume an omitted property is empty. No remote bus override is inherited.

The opt-in witness `--systemd-notify` emits one local `READY=1` datagram only
after key/anchor/source validation, exclusive store locking and socket listen.
Absent/invalid notification configuration fails; there is no readiness on failed
validation. TERM/INT request bounded graceful shutdown and endpoint unlink.
After SIGKILL/reboot, an old socket may persist on disk. Only after verifying and
locking the original protected store may the witness retire that exact same-UID
socket, and only if a bounded connection attempt returns ECONNREFUSED. Live,
foreign, replaced, non-socket or uncertain endpoints refuse. Keys, anchors,
source and journal are never deleted, initialized or repaired by this step.

## Commission readiness without stop propagation

Use an explicitly commissioned witness unit with `Type=notify`,
`NotifyAccess=main`, `Restart=no`, finite start/stop timeouts and the installed
root-owned interpreter running `input_witness --systemd-notify` **without**
`--initialize`. One-time initialization is a separate empty-scope operator step.
The core unit must have `Wants=<that witness unit>` and `After=<that witness
unit>` before the reviewed handoff. READY completes the witness start job before
the core launcher is scheduled. Readiness is not an evidence admission token:
the managed entry still performs its fresh authenticated proof on every start.

Do not introduce `Requires=`, `BindsTo=` or `PartOf=` stop propagation from witness
to core: a later capture/witness failure must not terminate running defense.
Wants+After permits a failed witness start to finish, then the managed entry
refuses capture before preparing input or starting core. No unsigned fallback
or automatic repair is enabled. This opt-in profile can remain stopped; an
explicit ordinary-defense recovery procedure is a commissioning prerequisite.

## Disposable VM setup

Allocate a **new** Ubuntu 24.04 QEMU VM, e.g. with Multipass, 2 vCPUs/2 GiB RAM.
Never target an existing user/production VM. Keep its name and recovery evidence;
do not silently reuse/reset a used scope. Dependency downloads occur only during
explicit preparation. Prestage the reviewed core for the guest CPU/ABI and the
pinned `requirements/input-auth.txt` wheels plus pytest. The runtime never
downloads anything. No AI, Suricata, provider or activation service is installed.

Inside the new VM, as root:

1. Stage the exact source tree at `/opt/edge400-src`, **root-owned, no group/world
   writes**, and its commit ID at `/opt/edge400-src/SOURCE_REVISION`. Archive
   extraction must use `--no-same-owner` or explicit ownership normalization;
   preserving a workstation UID correctly causes service preflight refusal.
2. Install the matching ELF at `/usr/local/bin/azazel-edge-core`; create a
   root-owned `/opt/edge400-runtime` venv with the pinned optional crypto profile
   and pytest. A site-packages `.pth` names `/opt/edge400-src/py`; `python -I`
   must resolve the installed component. No caller PYTHONPATH fallback.
3. Disable IPv4/IPv6 default routes persistently **in this VM only**. For a
   Multipass Ubuntu netplan `default` interface, a protected override can set
   `dhcp4-overrides: {use-routes: false, use-dns: false}`, `dhcp6: false`,
   `accept-ra: false`. Retain only the local host management connection. Verify
   both `ip -4 route show default` and `ip -6 route show default` are empty after
   each OS boot. Services additionally restrict socket families to AF_UNIX.
4. Create `/etc/edge400-disposable-vm` containing exactly
   `edge400 dedicated disposable VM; no production state` followed by newline.
   This is an explicit destructive-lab authorization marker, not a security
   boundary against root. The driver also requires root, PID1 systemd, an actual
   VM (`systemd-detect-virt --vm`), no default routes and the explicit flag below.
   Prepare refuses existing lab state/unit/drop-in paths. Never remove those
   guards to run it on a workstation.

The driver generates a dependency-free fixture core unit using the real native
ExecStart, ordinary restart semantics and fully frozen disabled/dry-run settings.
It intentionally has no AI/IDS/activation dependency. This is not proof of an
arbitrary production unit or real provider/LSM commissioning. Dedicated numeric
capture/observer roles 61001/61002 are used, with no supplementary groups; the
witness remains root as required by the existing v3 trust profile.

## Phases and acceptance

Run in the guest:

```sh
/opt/edge400-runtime/bin/python -I /opt/edge400-src/tests/real_systemd/guest.py prepare --allow-disposable-vm
/opt/edge400-runtime/bin/python -I /opt/edge400-src/tests/real_systemd/guest.py exercise --allow-disposable-vm
```

`exercise` verifies real typed-hook rejection before stop; normal→signed
single-unit stop/reload/start and fresh native/signer/witness proof; ordinary,
signed and repeated-systemctl duplicate exclusion; actual service restart;
unread downtime exclusion with distinct live/downtime/fresh alert IDs; witness
stop with unchanged running core PID; masked/invalid witness, unregistered origin,
unsafe producer key and invalid signature refusal without source/anchor append;
witness SIGKILL/restart with unchanged protected history; and delayed notify
readiness preceding launcher start by systemd monotonic timestamps. Observer
reopens independently; zero committed synthetic Outcomes are required.

Fault injection/byte restoration belongs only to these disposable synthetic
fixtures; the invalid source is retained separately. It is **not** a production
repair/recovery API, and is never used to justify resuming unverifiable history.
Configured hook injection is removed only by the test that created it, before
normal stopping. No arbitrary or original administrator configuration is removed.

After `exercise`, the lab core is enabled and active solely for the OS test.
Reboot the VM through its hypervisor, then run:

```sh
/opt/edge400-runtime/bin/python -I /opt/edge400-src/tests/real_systemd/guest.py boot-check --allow-disposable-vm
```

Acceptance requires a different kernel boot ID, preserved source byte prefix,
clean previous signed session end, a new prepare/start, exactly one native core,
and witness-ready ≤ launcher-start timestamps. The observer independently reopens
with excluded startup/lifecycle records and no fabricated committed Outcome.
This phase then stops the core cleanly and withholds its registration for a
second OS reboot. Reboot again, then run:

```sh
/opt/edge400-runtime/bin/python -I /opt/edge400-src/tests/real_systemd/guest.py bad-boot-check --allow-disposable-vm
```

Acceptance requires another boot ID, failed managed start, zero native cores and
exactly unchanged signed-input size/hash. The final phase disables/stops the lab
units and retains evidence. Do not interpret notification, exit status, process
start or virtual filesystem sync as physical effect/durability proof.

`/var/lib/edge400-systemd-lab/results.jsonl` contains minimized case results,
boot/order metadata and hashes, not private keys or raw payloads. Preserve the
guest privately for debugging; export only this minimized result by default.
Each assertion has a finite wait; failure is not a completed phase.

## Continuous checks and remaining gates

The ordinary CI has a separate real-systemd job in a disposable hosted VM. It
uses a private network namespace for the driver (not the runner's control
network), with independent AF_UNIX-only service restrictions. It runs prepare,
exercise and smoke-finish, then uploads minimized results. **It does not reboot
the hosted runner.** Manual two-boot VM evidence remains a distinct result.
Actual root/UID process tests cover TERM/INT, SIGKILL/stale endpoints, wrong
owners/types/live endpoints, invalid anchors and failed readiness notification.

Target Pi accounts, capabilities, loader/dependencies, AppArmor/SELinux,
availability, real services/provider readback, hostile load/CPU/RSS/latency,
physical power loss/SD/cache/mount durability/wear, key revocation/rotation,
trusted clocks/boot and independent monotonic anchors remain unaccepted. Root/key
compromise and coordinated whole-store rollback remain outside this software
guarantee. #393 retains independent protected-service measurement. Keep #400
open; no production admission, telemetry completeness or causal benefit is claimed.

Readiness contract: [systemd.service](https://www.freedesktop.org/software/systemd/man/253/systemd.service.html)
and [local sd_notify](https://www.freedesktop.org/software/systemd/man/254/sd_notify.html).
