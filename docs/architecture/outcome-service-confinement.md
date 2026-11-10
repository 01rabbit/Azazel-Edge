# Outcome service accounts and AppArmor: virtual commissioning profile

Tracking: #400. This is an opt-in software/virtual-host commissioning slice,
not production activation or G6 physical acceptance. The existing sealed native
image, singleton, witness continuity, honest loss and provider-fact boundaries
remain. No missing input/window is fabricated or repaired.

## Registered capture confinement

An explicitly prepared new scope may use
`outcome-live-origin-registration/v3`. Its exact fields are v2's fields
(including an explicit `ai_socket_uid`, default 0) plus
`capture_apparmor_profile`, a bounded literal named enforcing profile. Both
public candidate helpers accept `--capture-apparmor-profile NAME`; they still
write no files/read no private keys. The existing trust-policy digest pins the
exact registration bytes. V1/v2 registrations and used journals are not migrated.
Removing the field or changing the version cannot silently downgrade a pinned
registration/journal. Profile names cannot contain argv/policy syntax.

For this mode the separate-UID signer executes the fixed `edge-capture` alias
beside the already protected installed Python interpreter. This must be a
root-owned, single-link, protected-parent, exactly 0755 regular file with bytes
identical to that interpreter. It shares the same installed venv and immutable
component code. No caller-supplied command, arbitrary executable or alias repair
is provided. Provision this copy and the policy from trusted offline artifacts.

Before stopping an existing core, the controller checks the alias hash and runs
an isolated fixed import/context probe as the producer UID/GID with no
supplementary groups. It checks retained capabilities/UIDs, fixes no-new-privs
and verifies its actual `/proc/self/attr/apparmor/current` is exactly the
registered `NAME (enforce)`. The alias/hash/profile are included in the reviewed
code references. This actual process proof avoids adding MAC_ADMIN merely to
enumerate policy. Missing support/profile, complain/unconfined/wrong attachment,
unsafe/mismatched alias or failed probe refuses preflight.

Every managed boot/start repeats that check. The receiver independently checks
its enforcing kernel label after the existing UID/GID/capability hardening and
before opening the signing key or writer/preparing a session. A profile lost
between preflight and receiver execution therefore fails before a connected
core starts. These checks derive from registration, not an optional runtime
flag that can be omitted. No unconfined fallback, implicit fresh scope, catch-up
or source/journal/anchor reset exists. A later recording failure still does not
kill/restart running defense.

The witness separately supports explicit `--apparmor-profile NAME`, checked
before opening its key/store or sending readiness. The commissioned unit must
require this option as well as `AppArmorProfile=NAME` without a `-` ignore prefix.
The observer's lab entry likewise verifies its own enforcing label before
journal access. Kernel labels are local point-in-time checks, not remote/kernel
attestation or a signature over policy contents. Policy-file hashes are audit
metadata; trusted root can reload rules or replace code/keys. Arbitrary process
execution as a trusted signer UID/key compromise is not prevented merely by a
pathname-attached service profile.

## Preserve the verified service identity

The managed drop-in now inherits the existing verified root User/Group instead
of injecting `User=root`/`Group=root`. On the tested systemd 255 stack, explicit
User=root combined with NoNewPrivileges and a tight bounding set lost effective
SETUID even though it remained in CapBnd. The real preflight correctly refused
the subsequent UID drop. Inheriting the original default-root identity retained
the intended limited effective set without adding ambient capabilities,
securebits, or disabling NoNewPrivileges.

The controller still refuses a non-root unit and verifies actual root core
UID/cgroup/effective capabilities. This is **not** a repair of unsupported base
units: an existing explicit-user profile with insufficient effective privileges
remains refused. A later non-root base-unit setting is no longer overridden to
root; the managed root-only entry fails before key access. No automatic privilege
grant/elevation or administrator-account edit is introduced.

## Tested role matrix

The guarded `tests/real_systemd/armor.py` driver uses the existing real-PID1
protocol, synthetic keys and a fresh scope in a dedicated Ubuntu 24.04 VM.
Its policy artifact is `tests/real_systemd/edge400.apparmor`, with no complain,
unconfined-exec or attach_disconnected debugging flags. It is a lab profile tied
to exact interpreter/state paths, **not a deployable production policy**.

| Role | Identity / capabilities | Mandatory checks and restrictions |
| --- | --- | --- |
| Launcher/native | existing default root; DAC_READ_SEARCH, SETGID, SETUID, NET_ADMIN only | no-new-privs; no ambient caps; private devices, kernel/control-group protection, namespace/SUID/personality restrictions, AF_UNIX-only fixture; existing singleton; native confinement requires the separately enrolled v4 bootstrap below |
| Signer | locked `edge400-capture`, UID/GID 61001; zero permitted/effective/ambient caps; empty supplementary groups | fixed alias, registered enforcing label, private key owned by that UID, signed-input write only; no-new-privs inherited/fixed |
| Witness | root remains required by the existing live trust contract; DAC_READ_SEARCH only | enforcing named policy, private key/anchors, journal/source read, local readiness and fixed witness socket; no-new-privs and AF_UNIX filter; no actor/control executor |
| Observer | locked `edge400-observer`, UID/GID 61002; zero capabilities, no extra groups | enforcing named policy; own journal only writable, public keys; independent authenticated witness recovery; no-new-privs and AF_UNIX filter |
| AI identity | locked `edge400-ai`, UID/GID 61003 | no login/home/extra groups or capture/observer key access; no AI/model service is activated |

Accounts are created only inside the explicitly marked disposable VM. Existing
accounts/aliases/policy must match exactly or preparation refuses; they are not
rewritten to make tests pass. Passwords are locked, shells nologin, homes
nonexistent. Primary GID membership of the observer service is distinguished
from extra/privileged groups. Runtime CLIs create no accounts, groups or policy.

## Actual refusals and independent controls

The driver checks active UID/groups/capabilities/no-new-privs/kernel labels and
denies cross-role key access, a DAC-readable canary, unregistered execution,
UID escalation/switch and even signal-0 access to the core. The canary remains
readable under the same UID outside AppArmor, so its refusal is not confused
with DAC. An observer's unrelated writable canary is refused by policy. A
separate unconfined fixed one-shot verifies ProtectSystem=strict returns EROFS;
this is not evidence that this filesystem namespace and AppArmor are compatible.

The tested stack did not reject standalone IPv4 socket creation/loopback connect
under the profile's declared inet deny alone. The driver records the observed
standalone result rather than claiming AppArmor network protection. **Required
IP isolation is the independently tested systemd RestrictAddressFamilies=AF_UNIX
plus the offline VM/private driver network.** Both IPv4 and IPv6 family attempts
must fail in the real role units. No external traffic is needed by these tests.

The tested private filesystem namespace plus pathname Unix notification produced
disconnected-path refusals. The supported witness/observer fixture therefore
uses capability/no-new-privs/address-family restrictions plus enforced AppArmor
filesystem permissions, not an unverified combined mount namespace. No runtime
fallback changes these settings. The native sealed memfd similarly produced
disconnected execution denial in the tested enforcing profile. The controller
now reads the core's typed AppArmorProfile property and refuses any declared
native profile, including ignore-failure forms, because it confines the launcher before anonymous sealed exec. V4 uses the
separate compatible early-native transition below. It does not enable unsafe disconnected-path flags
or replace the sealed image with a mutable executable to obtain a green test.

These are explicit limitations of this declared virtual profile, not proof
that arbitrary AppArmor/systemd/kernel combinations work or fail.

## Reproduction and stages

Use the [real-systemd VM protocol](outcome-systemd-vm.md) in a **new** VM, staging
this source and the matching core/root-owned runtime. Before disabling external
routes, prestage `apparmor`, `apparmor-utils` and the pinned optional crypto
profile. Require AppArmor actually enabled; never count a skipped/complain
simulation as kernel enforcement. Substitute `armor.py` for `guest.py` in
prepare/exercise/boot-check/bad-boot-check/smoke-finish. The destructive marker,
root/PID1/VM/no-default-route guards and fresh state/unit refusal remain.

Exercise includes all earlier handoff/duplicate/restart/witness/registration/key/
signature/loss tests, real role denials and positive controls, unsupported native
profile/account refusal, and no-recording refusals for missing/complain/wrongly
attached capture policies. Reloading the original policy is a controlled lab
fault restoration, not evidence repair or an automatic product recovery API.
Normal OS reboot and unregistered reboot phases retain the prior explicit
acceptance, with named confined observer recovery. CI runs separate baseline, role-AppArmor and native-AppArmor jobs; it does not reboot the hosted runner.

Keep #400 open. Production target units/accounts/LSM policy and full provider-native policy, arbitrary local IPC/broker mediation, real enforcing provider
permissions/readback, physical power-cut/SD/cache durability/wear and Pi resource/
hostile-load/decision-parity gates remain. No full production admission, causal
benefit, absolute anti-rollback, complete telemetry or physical effect is claimed.

References: [systemd execution restrictions](https://www.freedesktop.org/software/systemd/man/252/systemd.exec.html),
[AppArmor profile flags](https://apparmor-documentation-c38b15.gitlab.io/documentation/manpages/manpage_apparmor.d.5/).


## V4: sealed native bootstrap confinement

An explicit **new scope** may enroll `outcome-live-origin-registration/v4`:
all exact v3 fields plus `native_apparmor_profile`. Both public preparation
helpers accept `--native-apparmor-profile NAME` together with the capture
profile. Names must be bounded literals and distinct. The trust digest pins
both names and the exact ELF hash. Existing registrations, used scopes and
journals are never upgraded or stripped of this requirement automatically.

The launcher keeps the same verified, anonymous root-owned 0500 ELF memfd and
all four irreversible seals (WRITE, GROW, SHRINK, SEAL). There is no mutable
executable copy, mount preparation, additional library dependency, SYS_ADMIN,
MAC_ADMIN or disconnected-path flag. At the first application operation in Rust
`main`, before configuration, health/version/maintenance/capture subcommands,
instance state, recovery, threads, input or native session start, the bootstrap:

1. Validates the unique private profile argument derived from registration.
2. Opens its actual `/proc/self/exe` and verifies regular/root/0500/unlinked
   metadata and exactly all four seals. A disk image or partial seal fails.
3. Fixes no-new-privileges and performs the AppArmor `change_profile` kernel
   transition, then verifies its own exact `NAME (enforce)` kernel label.
4. Exits 3 with no fallback if any check fails. Only then may normal work begin.

The registered health probe executes **that same sealed image and gate** before
stopping an old service. The direct trusted launcher also repeats this before
starting the signer/opening a signed session. The real core repeats the gate
independently after execution, closing the preflight-to-start race. A failure
before the signer starts adds no evidence. A later race may leave the existing
honest `session_prepare` uncertainty marker; it cannot produce a native start or
clean end and subsequent continuation refuses. Never delete/repair that marker.
The controller checks the actual native child's enforcing label as well as the
signer's label and verified signed native start. No profiles are loaded or
repaired by product runtime. A normal health report's
`native_apparmor.enforced_profile=null` describes capability, not confinement;
only an actually guarded probe reports the verified profile.

This is application-directed confinement of an already trusted sealed program.
The ELF loader, Rust runtime initialization, libraries and small bootstrap run
before confinement and remain in the existing trusted root/code boundary. It is
not an isolation boundary against malicious code executed before transition,
policy replacement by trusted root, root compromise or kernel compromise. The
profile must deny later profile transitions, arbitrary exec/control IPC and key
access; a name/enforcing label does not attest policy semantics. Operator review
of the offline policy remains mandatory. The launcher remains unconfined; a
unit-level `AppArmorProfile=` is still refused rather than silently ignored.

The disposable native profile has read access to the synthetic EVE input and
write/lock access only to native state/logs, plus inherited Unix reporting and
minimum process reads. It grants no signing/witness key, signed input, observer
journal, policy-management, exec or profile-change permission. It does **not**
admit real tc/nft enforcement or general broker/IPC permissions. The unchanged
systemd capability bound is DAC_READ_SEARCH/SETGID/SETUID/NET_ADMIN; AppArmor
denies their unneeded use. No runtime receives SYS_ADMIN/MAC_ADMIN. IP isolation
continues to rely on the independently checked systemd family filter/offline
network; do not infer standalone AppArmor network mediation on every kernel.

Run `armor.py ... --native-core` for all five existing VM phases. The native CI
matrix is mandatory (real kernel enforcement, no skip); CI does not reboot its
host. Checks include actual native label and seals, independent same-root policy
denials and DAC-positive controls, role-to-native signal-0 denial, singleton,
registration/key/signature refusal, clean restart/boot/witness ordering,
complain/missing profile refusal before evidence append, and removal after a
successful preflight producing no native frame/start. Root Linux tests also
exercise all one-shot/daemon entries with absent/partial/full seals and missing
policy. No fixture loss is backfilled and no read-only result becomes an
execution fact. Physical durability/resources and production-provider policy/
readback remain separate #400 acceptance gates.
