# Independent post-connect authorization response observation v1

Related: #400/#393. Base e1bb2a08c6b06b36c2f6caeccca0afd0aafc4571.

## Frozen boundary and feasibility (before implementation/collection)

The existing Root-service profile admits Root for every action. No real named
azazel-web account with existing transport access is established here. Do not
create that account, grant groups, change socket access or invent an advisory
bridge. This slice exercises the ALREADY supported nonroot development own-UID
profile: peer_may_connect admits the daemon's own UID; peer_action_allowed tests
ROOT_ONLY_ACTIONS before its own-UID allowance. Existing nobody/nogroup65534 is
required, never created. Daemon and actor run UID/GID65534, no supplementary groups,
all capabilities zero, no-new-privileges. They create their OWN temporary endpoint
parent0750/socket0660 and state0644 initially; never chown an installed endpoint or
widen its access. No production service, key, migration or activation. No changes
under installer/security/systemd. No external network; network=none lab only.

The isolated harness alone constructs processes/endpoints and sends requests.
Observer retains EXACT existing BPF+PERFMON+NNP; outer lab retains only existing
BPF,PERFMON,KILL,SETGID,SETPCAP,SETUID. No SYS_ADMIN/SYS_PTRACE/new capabilities.
Read-only observer never sends, mutates targets, wraps guards or adds callbacks.
Unchanged handle_client/SO_PEERCRED/peer table/execute_action/SoT writer are trusted
code premises. Root/kernel/code custody and sole writer are premises, not hostile
Root attestation. Positive and negative controllers/target logs are control-only.

Require existing NSS nobody65534/nogroup65534 and identity UID/GID maps
0 0 4294967295, same held user namespace for observer/server/actor before GO;
record namespace identity and maps under identity_profile. Unknown/restricted or
mapped namespaces refuse collection, never equate kernel kuid with mapped UID.
Fixed cap0 workers and unchanged code are held-identity premises after pre-GO;
no global census or namespace execution attestation is claimed.

## Facts, data and acceptance frozen before observation

Use new explicit edge-postconnect-authorization-plan/diagnostic/enrollment/
collection v1 and edge-postconnect-uid-copy-probe/v1. Never coerce #605 v1 or
reinterpret Root artifacts. New source postconnect_uid_copy_observer.bpf.c has
72-byte config: old six u64 and four u32 followed by server_uid,actor_uid u32.
Both are65534 in this profile. Event376, counters96, five maps, exact BTF validation,
256-byte single linear USER-destination frame, time<=5s, bounded max16, immutable
NOEXIST and known-copy retention are unchanged. Check UID/EUID against pinned
role UID in kernel and evaluator. Same explicit read_actor fentry/fexit layer.
No fragments stitched, no missing-zero/backfill/repair, no automatic resume.

Five literal cases in tests/fixtures/postconnect-authorization/v1/cases.json:
1. own_uid_patch: permitted real hostname patch, both original objects change.
2. root_only_refused: migrate_path_schema target_schema=v2,dry_run=true; actual
   error=forbidden,reason=root_only,action=migrate_path_schema reply.
3. spoofed_root_refused: same request plus untrusted peer_uid=0; same real refusal.
4. observer_loss_after_refusal: preserve both matching request/response copies,
   then close only own exit link; preserve unchanged samples, coverage unknown.
5. missing_after_sot: actual positive patch, omit submitted after-SoT only after
   sampling; retain independently changed audit and copies, coverage unknown.

Negative acceptance: actual full request and full refusal reply copies with
reciprocal socket identities/endpoint device+inode, fixed process/namespace/session/
start identity, ordered finite time and clean worker/handler closure; independent
before/after SoT/audit original bytes+metadata equal. No unrelated request, wrong
UID/session, validation error, stale identifier, partial frame or observer loss may
qualify complete coverage. Positive requires actual normalized hostname patch and
actual audit peer_uid65534. Missing sibling never erases independently known change.
All role UIDs/GIDs/groups/caps and maps verified before GO. Observer failure,
unsupported BTF/layout, missing evidence, malformed rows, mismatched/unclean life
or incomplete coverage remain unknown; known independently verified copies survive.

This measures development-profile authorization REFUSAL-RESPONSE consistency under
trusted unchanged code. It is distinct from validation failure, pre-read admission
failure, DAC refusal and client assertion. It does NOT independently observe the
Python internal branch or absence of migration dispatch: dry_run=true intentionally
contains accidental dispatch and also limits the state canary's strength. Internal
branch and authorization_refusal_verified remain null; a new explicit
root_only_refusal_response_consistent may be true only for a fully paired response.
No transport copy is final recv syscall completion. Sample equality covers two
bounded originals at two instants, not all persistent state or transient writes.
Fixture-owned accepted-FD hold remains explicit; production natural-close unknown.
Production Root/Web/advisory roles, real migration, physical/Pi/HIL, whole-system
safety and causal comparative superiority remain unmeasured.98% and1.2x unchanged.

## Export and validation gates

Public immutable Root0444 enrolled copies are read by separate UID65533, neither
actor nor server. Reuse protected-ancestor/held-FD/current-boot read-only intake
with explicit new schemas. Export before assertions: eight slots+manifest per case
and case-index once complete/missing; expected45 actual files/46 upper slots with
one declared absence. No keys/ELF/private tree. Preserve any failed run separately;
never repair/publish it as success. Pure parser tests are SYNTHETIC. Required real
ARM Linux five-case CI must run, no skip-as-pass; full final-head CI, independent
code/artifact review and exact base/head/tree match precede conditional merge.

The isolated Root controller uses primary GID65534 (existing SETGID setup only)
to read the owner-created0750 directory through existing group read/search bits;
no supplementary group addition or endpoint mutation. Only the owning fixture UID
removes its temporary directory AFTER all original samples/exports. Observer UID0
already has the Root peer-table grant; it never connects. Separate sealed artifact
reader remains65533, outside target access. This is a test harness setup detail,
not a production group or observer access grant.

Cross-UID /proc namespace inspection may require forbidden SYS_PTRACE. A separate
fixed cap0/NNP UID65534 read-only sampler reads the held server/actor namespace
identities, UID/GID maps and four credential IDs/groups/capability status before GO,
then the controller compares against its own identity map/namespace. It neither
connects nor writes targets. Same-UID custody is an explicit lab premise; no ptrace,
permission fallback, root bypass or claim of hostile same-UID isolation.
