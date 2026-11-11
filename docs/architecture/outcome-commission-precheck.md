# Public artifact commissioning PRECHECK

Tracking: #400. `azazel_edge.outcome.commission_precheck` provides a bounded,
offline artifact inventory before target-specific commissioning. It writes no
files, opens no private keys, invokes no commands, and creates no executable
image. It cannot stop/start services, alter qdiscs, enroll/upgrade scopes,
repair evidence or resume a recording. Existing sealed native, singleton,
registered-boot and no-backfill requirements remain unchanged.

Run as trusted root against an already provisioned protected bundle:

```sh
python -m azazel_edge.outcome.commission_precheck \
  --bundle /etc/azazel-edge/capture/example \
  --expected-trust-sha256 REVIEWED_CANONICAL_TRUST_SHA256
```

The mandatory pin is the independently reviewed `TrustPolicy.digest` (SHA256 of
canonical trust JSON), not an automatically accepted digest calculated from the
same unreviewed installation. Existing validators enforce trust schema/role,
exact bundle paths, registration bytes/digest/schema, role/scope binding, named
distinct v4 profiles and signed-source authentication. Protected bounded reads
check the public completion receipt and registered root-owned executable ELF
hash/metadata. Enforcement and high-impact automation must be disabled and
dry-run enabled. Older scopes are refused, never migrated. The source is
verified from its complete prefix under its enrolled byte/record bounds; this
may cost a full bounded history read. An unclosed or malformed history refuses.
No journal/anchor recovery or freshness proof is attempted.

Success outputs deterministic JSON with `status=PRECHECK_ONLY` and
`authorizes_transition=false`. Only public hashes, profile names, bundle path,
record count and unresolved gate names are emitted. A refusal prints a fixed
message and exits 1 without echoing file contents. The report is a point-in-time
inventory, not a transactionally locked snapshot, signed attestation, deployment
plan or reusable start permit. Trusted root/code/kernel remain trusted. Runtime
must revalidate current bytes, keys, witness/history and service state through
the existing normal entry gates; never feed this report to bypass them.

The unresolved list cannot be completed using CLI flags or operator checkboxes:

- Actual private-key matches and role access require the existing protected
  bundle/runtime validators; this public-only tool deliberately opens no keys.
- Installed dependencies, policy semantics, actual enforcing kernel labels,
  sealed native execution and target service/process identity remain untested.
- Singleton exclusion, witness readiness and registered reboot/history
  continuity require the existing actual runtime checks.
- Legacy tc provenance and exclusive-writer coordination remain unresolved.
  Matching handles/parameters, successful commands and operator assertions cannot
  establish exclusive ownership or exclude a concurrent privileged writer.
- Physical target durability, resources and acceptance remain separate gates.

See [legacy tc boundaries](outcome-legacy-tc-confinement.md),
[service confinement](outcome-service-confinement.md) and
[provider confinement](outcome-provider-confinement.md). No production admission
or physical acceptance follows from a passing PRECHECK.
