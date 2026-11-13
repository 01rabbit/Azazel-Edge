# Independent authority-ingress observation v1

## Feasibility boundary fixed before implementation

Related: Edge #400/#393. Base: 9bd5eed5a68977cf24b028e6daff2b1d7569537d.
This slice investigates the EXISTING Python control daemon's pathname AF_UNIX
control.sock ingress, not a fabricated advisory-return-to-Rust execution bridge.
The existing real handle_client, kernel SO_PEERCRED, fixed peer table,
execute_action and sot_devices_patch path must remain unchanged.

The isolated harness may request only a fixed hostname patch of an existing
synthetic device in owned temporary SoT data using the existing AZAZEL_SOT_PATH
configuration and an owned audit destination. It never runs daemon.main,
background monitors, provider effects, network commands, installed services,
production keys or writes under installer/security/systemd. Root is already an
allowed peer. A separate advisory-like UID has no control-group membership.
Neither UID is inferred from request text or a claimed role. No account resolver,
peer-credential, policy, executor or persistence stubs are allowed in actual tests.

Preserve the deployed-shaped directory0750/socket0660 Root:control permissions.
No0666, advisory group grant, extra observer privilege, unconfined fallback or
production activation. Negative failure at DAC does NOT exercise the application's
peer table. Root cap0 positive uses real existing admission and atomic SoT edit;
its exact independently read-back original bytes demonstrate only this owned
fixture change, not native defense, enforcement or a model-induced effect.

## Finite feasibility experiment (before product implementation)

Investigate a passive kernel unix_stream_connect return hook with kernel-copied
AF_UNIX pathname, return value and, if feasible, connected peer socket identity.
Avoid mutable userspace sockaddr pointers as proof of destination. fentry/fexit
BPF-link attachment is preferred to tracefs/perf setup requiring more authority.
Observer remains exact BPF+PERFMON and no-new-privileges under the existing lab
profile; sender/server have zero retained capabilities. No SYS_ADMIN/SYS_PTRACE,
MAC_ADMIN, privileged container or seccomp bypass. Record unsupported kernel/BTF/
attach/permission conditions; no syscall-entry-only substitute labeled success.
The probe may use a fixed disposable Unix listener only as an explicit feasibility
control, never as evidence that the real daemon admitted or executed a request.
Pin actor/session/boot/PIDnamespace/start identity, exact code/object/input bytes,
finite times and original raw records. Define final wire/ABI/corpus before product
implementation once feasibility is known. No missing records/slots repaired.

Kernel connect return0 is a connection fact, not daemon accept/read/parse/admit or
an effect. EACCES with a kernel-copied requested pathname proves that finite
connection attempt failed, not listener arrival, application refusal or absence
of other access. If exact endpoint identity cannot be established, leave it
unknown. Root launch/namespace/file samples are trust premises, not cryptographic
execution attestation.

## Required product cases and acceptance to freeze after feasibility

Fresh positive Root patch, negative advisory DAC denial of the identical patch,
spoofed Root request metadata from the negative UID, wrong/unrelated pathname,
partial acquisition/link loss, missing readback, identity/path reuse and lifecycle
failure. Real kernel/process tests and synthetic parser tests are separate.
Root-independent descriptor reads bracket fixed original SoT/audit bytes and
metadata before/after joined handler completion (before cleanup). A real empty
precreated audit file is an observed empty file; missing is never made empty.
Atomic SoT replacement is expected for the positive. A negative samples unchanged
originals only; no transient-write or whole-system absence proof. Known changes
or positive connection records survive missing sibling evidence.

All authority/admission flags remain false and qualified safety counts null.
No automatic resume, zero-for-missing, backfill, full-horizon isolation, physical
or production acceptance. Mandatory actual Linux CI cannot skip as success.
Independent review, final-head complete CI and exact base/head/tree are merge gates.
