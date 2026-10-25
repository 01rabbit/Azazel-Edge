# M.I.O. reasoning trace: identity, working memory, durable audit, retention

Status: implemented as a library, advisory-only. Tracking: #389 (parent #377).
Builds on #383 (SituationFrame), #384 (Capability Broker), #385 (lifecycle,
`ReasoningCoordinator`), #386 (grounding/playbooks).

The M.I.O. trace complements the Edge audit and Decision Explanation. It is not
a second authoritative decision record. Nothing here calls the Action Arbiter,
enforcement handlers, AZ-06 or the Rust core; nothing on the deterministic path
imports it (tested). No systemd unit, installer or security path is changed.

| Item | Location |
|---|---|
| ID grammar, validation, Edge decision ref check | `py/azazel_edge/mio/trace_audit.py` (`ID_GRAMMAR`, `is_valid_id`, `require_id`, `cycle_belongs_to`) |
| Per-cycle working memory | `trace_audit.py` (`CycleWorkingMemory`) |
| Minimized projection | `trace_audit.py` (`project_outcome`, `mio.trace_audit.v1`) |
| Durable sink, retention, quota failure | `trace_audit.py` (`TraceAuditSink`, `record_cycle`) |
| Operator text masking | `py/azazel_edge/mio/redaction.py`, applied in `handoff.py` |
| Tests | `tests/test_mio_reasoning_trace_audit.py` |

## Lifecycle the trace relates

```text
SituationFrame (frame_id, material digest)
  -> playbook id/version/digest, template id
  -> hypotheses (id, status, evidence refs) + lifecycle audit (from/to/reason)
  -> evidence gaps (count) -> capability requests (request_id, capability) -> result status/refs
  -> recommendation (advisory_id, action code, refs, text digests) or handoff digest
  -> edge_decision_ref (supplied by Edge, linked, never minted here)
```

## Identity rules

IDs are minted by Edge or by M.I.O. code from validated parts. They are never
parsed out of model output or attacker-supplied text.

| Kind | Grammar | Minted by |
|---|---|---|
| `trace_id` | `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` | Edge |
| `cycle_id` | `<trace_id>:e<epoch>:c<seq>` | `ReasoningCoordinator.begin` (global sequence, epoch bumps on restore) |
| `request_id` | `<cycle_id>:req:<n>` | reasoning loop |
| `advisory_id` | `<cycle_id>:advisory` | reasoning loop |
| `hypothesis_id` | `[A-Za-z][A-Za-z0-9_-]{0,31}` | model-proposed, cycle-local only |
| `edge_decision_ref` | `edge-dec:<id>` | Edge only |
| `evidence_ref` | bounded ref grammar | Edge frame or broker |

Rules:

- Full-match validation (`fullmatch`), so a trailing newline or control char fails.
- `edge_decision_ref` and `advisory_id` are disjoint grammars. `project_outcome`
  raises on an `edge_decision_ref` that is malformed or advisory-shaped, so a
  M.I.O. advisory ID can never be recorded where an Edge decision is required.
- `cycle_belongs_to(cycle_id, trace_id)` checks ownership by exact `<trace>:e`
  prefix, so one trace's cycle cannot be attached to another trace.
- After restart the coordinator's epoch is higher, so new cycle IDs never equal
  pre-restart ones, and pre-restart tickets are not current (#385).
- In the audit projection a value that fails its grammar, looks like a token or
  credential, or (for evidence refs) was not issued by the frame or a successful
  broker result this cycle, is written as `h:<keyed digest>`, never verbatim.
  A model-emitted `edge-dec:...` or invented `ev:...` therefore never appears.

## Working memory (ephemeral)

`CycleWorkingMemory(coordinator, ticket)` holds the current frame projection,
pending requests, compiled context or a raw model response before validation.

- Namespace: one instance per cycle ticket; nothing is shared across cycles/traces.
- Bounds: `max_items` keys, `max_bytes` of JSON. Over the limit raises `ValueError`.
- Expiry (deterministic, no wall clock): cleared and refusing access once the
  ticket is no longer current in the coordinator (accepted, superseded,
  cancelled, abandoned on restart), after `max_steps` `tick()` calls (logical
  timeout), or on `close()`. Access afterwards raises `WorkingMemoryExpired`.
- Restart: never serialized. `ReasoningCoordinator.snapshot()` does not include
  it, so unvalidated work cannot be resurrected.

## Durable minimized audit projection

`project_outcome(ticket, outcome, key, frame=None, edge_decision_ref=None)` is a
pure function. The same inputs and key give the same bytes.

Kept: schema, IDs, epoch, frame material digest, playbook id/version/digest,
template id, terminal state, error codes, hypothesis IDs/status/evidence refs,
hypothesis lifecycle transitions and reason codes, evidence-gap count, broker
request ID, capability name, result status (`ok`/`not_ok`/`missing`) and refs,
advisory ID, recommended action code, handoff digest, `edge_decision_ref`,
`authority: advisory_only`.

Dropped: hypothesis statements, falsification conditions, recommendation
summary and rationale, broker result data, frame facts/summaries/mission,
prompts and raw model output. Where replay correlation needs text identity, the
record keeps `{"digest", "chars"}` only. Error codes of the form
`prefix:free-text` keep the prefix and digest the suffix.

Digests are HMAC-SHA256 (truncated to 96 bits). Key ownership:

- The caller supplies the key (`key=`); `new_audit_key()` makes a random one.
  This module never persists, logs or derives the key.
- With a per-process key (the default pattern, as in the broker), digests are
  not correlatable across restarts. Correlating across restarts needs the
  service to persist the key with owner-only permissions; that is a follow-up
  for whoever wires the sink into a service.
- The key is what stops offline guessing of low-entropy values; the digest is
  not an anonymisation claim. Discarding the key makes old digests
  un-correlatable.

Records are capped at `MAX_RECORD_BYTES` (4096). Over the cap, list fields are
trimmed in a fixed order with `truncated_<field>` counts; if still too large the
projection raises, and `record_cycle` treats that as a drop.

## Retention, quota and failure

`TraceAuditSink(path, max_file_bytes, max_files, fs)` writes append-only JSONL.
The real filesystem backend (`OsAuditFS`):

- opens with `O_APPEND | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, mode `0600`;
  refuses symlinks, FIFOs and other non-regular files (`fstat` + `S_ISREG`) and
  files not owned by the current user; repairs a wider mode with `fchmod`;
- takes `flock` on the data file for the append, `fsync`s every record, and
  `fsync`s the directory after creating a file and after rotation;
- on a partial write, `ftruncate`s back to the pre-write offset so no torn
  fragment remains; if an earlier crash left a file not ending in `\n`, a
  newline is written first so the next record starts on its own line.

Rotation assumes a single writer process per path. Appends inside one process
are serialized by a lock.

- Rotation: when the next record would exceed `max_file_bytes`, files shift to
  `.1` ... `.{max_files-1}` and the oldest is deleted. Disk use is bounded by
  `max_file_bytes * max_files`. This is separate from the Edge audit chain,
  whose retention is owned elsewhere and is not touched.
- Failure (ENOSPC, EDQUOT, EROFS, other I/O, rotation failure, refused path,
  non-mapping, oversize or unencodable record, any other exception including
  `RecursionError`, projection exception): the record is dropped, counted in
  `dropped` / `drop_reasons`, and the sink becomes degraded. `append` never
  raises and never blocks.
- Fail-closed for the advisory path only: `record_cycle` returns False and
  `advisory_allowed()` stays False while degraded, so the caller withholds the
  M.I.O. advisory whose trace is not durable. The deterministic Edge path never
  calls the sink and is unaffected. `reset_degraded()` is an explicit operator
  action after the cause is fixed.
- No secure-deletion claim is made for rotated files.

## Sensitive data

| Class | Audit projection | No-model handoff (operator text) |
|---|---|---|
| Credentials, tokens, API keys, auth headers, cookies, private keys | omitted (no free text); token-shaped IDs digested | masked as `[redacted:<kind>]` |
| Email-like PII | omitted; digested if in an ID | masked |
| IPs, hostnames | omitted from free text; kept only inside valid IDs/refs | kept (operator needs them) |
| Attacker-supplied strings, raw model output, prompts | omitted; digest + length only | model hypotheses labelled unverified and masked |
| Broker result data | omitted; status and refs only | not included |

Masking in `redaction.py` is a best-effort pattern list, not a guarantee:
label/value pairs (English and Japanese labels such as パスワード, 暗証番号,
秘密鍵, トークン; `:`, `=`, fullwidth `：`, prose "password is X"; quoted values
to the closing quote, unquoted to the field end), `Bearer`/`Basic`, JWTs,
common key prefixes (`sk-`, `xoxb-`, `ghp_`, `AKIA`, ...), URL userinfo, private
key blocks (also unterminated), emails and long opaque tokens. Matching runs on
an NFKC-normalised copy with zero-width chars removed and common
Cyrillic/Greek confusables mapped, and the original span is replaced. Pure hex
digests (32/40/64), digit runs, paths and structured refs (`ev:flow:<id>`) are
kept. Short labels that also occur in SOC prose (`auth`, `pin`, `pass`, `pw`,
`secret`, `token`) are kept only when the *whole* value is an ordinary phrase:
it starts with a status word (`failed`, `none`, `expired`, `rejected`,
`leaked`, ...) or a short count, and every word is a status word, an allowed
ordinary word, or a count of at most three digits followed by a unit word
(`pin: 3 hosts`; for `pin` the unit list is smaller). Any other word masks the
whole value (`token: expired abc123`, `pin: 4821 ok`); if unsure, mask.
`bearer token <x>` skips only the word "token" and then examines `<x>`.
Strong labels (`password`, `api_key`, ...) are always masked. Unquoted values
run to the field end; a closing bracket ends a value only when its opening
bracket precedes the label (`(pw: x)`). Scheme-less `user:pass@host` and passwords with spaces in URL
userinfo are masked; a plain email has no `:` and is handled by the email rule.
Masking runs before truncation so a cut cannot expose part of a token.

In the handoff, IDs (`trace_id`, `frame_id`, hypothesis IDs, evidence refs,
playbook id/version) are kept only if they match `ID_GRAMMAR` and are not
token-shaped; otherwise a fixed placeholder (`invalid-hypothesis-id-<n>`,
`[redacted:evidence_ref]`, ...) is used. No digest is used there because the
handoff has no key and the value may be low-entropy. All other text, including
playbook text and the reason, is masked.

## Not in scope

Live wiring of the sink into a running service and key management for it,
an incident export CLI, and #372/#374 consumers. These need a service owner and,
for any systemd/installer change, explicit approval.
