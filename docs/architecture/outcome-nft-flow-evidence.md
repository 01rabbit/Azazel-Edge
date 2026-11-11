# Owned nft flow-limit evidence: classification and read-only observation

Tracking: #400 / #393. The normal Rust core applies flow-scoped nft byte limits;
it does not create a root TBF qdisc for current throttles. The Python adapter now
represents a supported owned flow limit as `scope_kind=nft_flow_limit`, retaining
source/destination, IP family, explicit protocol, TCP/UDP destination port,
rate/burst, release task/resource and owner. No contract schema or enum change is
needed: the existing scope field is a mapping.

Only one exact native `nft insert rule inet azazel_edge throttle ...` command and
its exact owned rollback locator qualify. IPv4/IPv6 TCP/UDP and family-correct
ICMP/IPv6-ICMP forms are supported. Plan selectors must match the normalized
event. Required release metadata binds the full resource key, trace-derived
native FNV task ID, owner, due time, ledger state and absence of a tc handle.
This is deterministic consistency checking, not cryptographic ownership.
Missing/mixed/malformed/conflicting plans remain `unverified_throttle`, never a
fabricated root-qdisc scope. Recognizable legacy root-TBF plans keep the existing
TBF scope and verifier. Adapter classification alone always leaves a newly
applied mechanism **unverified**.

The existing ownership/postcondition API retains its initial-only lifecycle
rule: only an applied, active execution and unverified correlated mechanism may
be probed. The new branch revalidates the original complete command, rollback,
provider metadata, release reference, target and both scope mappings before any
query. It does not strip the owner or filter away chain/duplicate context.
Historical bare, quoted and nested nft-quoted owner renderings are parsed with
`shlex` as data; nothing is executed from a rendered plan.

The sole added query is this exact fixed shape:

```text
nft -j list chain inet azazel_edge throttle
```

The existing trusted binary resolver, cleared environment and time/output bounds
remain. No arbitrary chain, ruleset, namespace prefix or mutation is added to
the production runner. Successful command exit alone is insufficient. Readback
must include one complete `inet/azazel_edge/throttle` filter-chain header attached
to prerouting at priority -150 with accept policy, plus exactly one owned rule.
Its positive handle, family/table/chain, source and destination equality matches,
protocol/port (or explicit portless protocol), inverted byte limit per second,
exact normalized rate/burst and final drop must all agree. Expressions must
appear in native order; extra predicates/verdicts/limits, conflicting or duplicate
owners/handles, unsupported layouts, nonliteral identities and malformed JSON
cannot be accepted. JSON duplicate keys and nonfinite numbers refuse.

Matching complete evidence yields `observed`. A complete valid chain with no
owned rule or different supported parameters yields `not_observed`. Missing
chain metadata, ambiguity, unsafe/unverifiable inputs, malformed output, denied
queries and runtime failures remain `unverified`. Existing release, terminal,
partial and previously verified mechanisms are not reopened.

## Caller and authority boundary

The only existing product caller is G5's **recorded** probe runner. The live G3
collector does not call this verifier or gain an nft query. An unprivileged
observer with zero capabilities and AF_UNIX-only restrictions cannot be assumed
to query nft. Permission failure must remain unverified; no NET_ADMIN, policy,
service, namespace access or root proxy is introduced here.

A separately authorized disposable-namespace lab can retain an explicit manual
root read-only query's complete raw stdout, return code, original event,
namespace identity, query timestamps and hashes, then feed that recording to the
existing ownership API and G5. This proves that recorded mechanism semantics are
interpreted correctly; it is not automatic live postcondition verification,
production-origin admission or attestation of a running service. The original
v3 network trial retained only a rule, so it cannot prove this new full-chain
gate. A missing header must not be fabricated and described as actual evidence.

A finite owner comment, task consistency and matching readback do not prove
exclusive-writer provenance, defeat privileged replacement/races, or establish
that packets traversed this rule. Other rules and host state can affect traffic.
No Outcome, effect or causal support is promoted by this parser. Existing
telemetry joins correlate source-IP activity and broad interface/system metrics;
they do not become flow-specific or causal merely because the nft rule is
correctly classified and observed. Service-owned outcomes and all commissioning,
physical and efficacy gates remain separate.

Unit coverage exercises supported protocol/quote variants, exact data binding,
unknown/mixed input refusal, chain attachment, owners, duplicate/conflicting
expressions, byte-limit semantics, read failure and lifecycle/legacy regression.
An optional retained-v3 test validates the actual original native task/plan and
confirms that its rule-only evidence stays unverified. Actual complete kernel
readback requires a separately reviewed root lab run before claiming that proof.
