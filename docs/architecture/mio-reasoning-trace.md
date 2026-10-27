# M.I.O. reasoning trace: identity, working memory, durable audit, retention

Canonical architecture, authority matrix and degradation ladder: [M.I.O. Cognitive Plane](mio-cognitive-plane.md).

Status: implemented as a library, advisory-only, with a port for a service
that is off by default and a read-only incident export. Tracking: #389
(parent #377); running it in a service is #385.
Builds on #383 (SituationFrame), #384 (Capability Broker), #385 (lifecycle,
`ReasoningCoordinator`), #386 (grounding/playbooks).

The M.I.O. trace complements the Edge audit and Decision Explanation. It is not
a second authoritative decision record. Nothing here calls the Action Arbiter,
enforcement handlers, AZ-06 or the Rust core; nothing on the deterministic path
imports it (tested). No systemd unit or installer step runs any of it.

| Item | Location |
|---|---|
| ID grammar, validation, Edge decision ref check | `py/azazel_edge/mio/trace_audit.py` (`ID_GRAMMAR`, `is_valid_id`, `require_id`, `cycle_belongs_to`) |
| Per-cycle working memory | `trace_audit.py` (`CycleWorkingMemory`) |
| Minimized projection | `trace_audit.py` (`project_outcome`, `mio.trace_audit.v2`) |
| Durable sink, retention, quota failure | `trace_audit.py` (`TraceAuditSink`, `record_cycle`) |
| Digest key, config, port for a service (off by default) | `py/azazel_edge/mio/trace_recorder.py`, `config/mio_trace_audit.json`, `installer/internal/provision_mio_trace_audit_key.sh` |
| Read-only incident export | `py/azazel_edge/mio/trace_export.py`, `bin/azazel-mio-trace-export` |
| Operator text masking | `py/azazel_edge/mio/redaction.py`, applied in `handoff.py` |
| Tests | `tests/test_mio_reasoning_trace_audit.py`, `tests/test_mio_trace_lifecycle_389_v1.py` |

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

Kept: schema, `digest_key`, IDs, epoch, frame material digest, playbook id/version/digest,
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

- The caller supplies the key (`key=`) and says what it is (`digest_key`:
  `persistent` or `ephemeral`, default `ephemeral`). `trace_audit.py` never
  persists, logs or derives the key.
- With a per-process key (`new_audit_key()`, as in the broker), digests are
  not correlatable across restarts, and the record says `"digest_key":
  "ephemeral"`.
- The key is what stops offline guessing of low-entropy values; the digest is
  not an anonymisation claim. Discarding the key makes old digests
  un-correlatable.

`mio.trace_audit.v2` adds `digest_key` to v1; nothing else changed. In v2
`digest_key` is required, in v1 it is absent. The export reads both versions.

What `digest_key` is and is not:

- It is the writer's own statement in the record. It is not a signature,
  and nothing verifies it.
- The trace audit has no protection against changing or deleting whole
  records: a party that can write the file can write any record, including
  one that says `persistent`. The keyed digests only stop offline guessing
  of the values behind them.
- Digests from `ephemeral` records cannot be correlated across restarts (or
  between processes), not even by the device itself: that key is gone.

### Persisted digest key

The persisted key is handled like the trust capsule key (#498), with
stricter checks in addition:

- `installer/internal/provision_mio_trace_audit_key.sh [KEY_FILE]` (default
  `/etc/azazel-edge/mio-trace-audit.key`) writes 256 random bits as hex,
  `0600` (root:root when run as root) from its first byte
  (`write_private_file`, shared with the trust capsule script). Running it
  again keeps a usable key and narrows the mode. The key is never printed or
  put on a command line. The installer does not run it: nothing uses the key
  until a service enables the trace audit (#385).
- A key is usable only when it is one value of at least 32 characters of
  `[A-Za-z0-9._~+/=-]` after surrounding whitespace is removed, with at least
  8 different characters and none of the markers of a test or example key
  (`test`, `example`, `dummy`, `sample`, `changeme`, `devkey`, `dev-key`,
  `not-for-devices`), in a file of at most 4096 bytes without a NUL byte. So the repository's test keys (`"k" * 32`, the trust
  capsule tests' key) are never accepted as a device key. The script and
  `trace_recorder.key_is_usable` apply the same rule (tested).
- The script turns xtrace off first: run with `bash -x`, xtrace would print
  the key. Do not trace it by other means either.
- `load_audit_key` opens the file with `O_NOFOLLOW` and uses it only if no
  directory on its path is a symlink and it is a regular file owned by root
  or the current user with no group or other permission bits.
- The symlink check (`has_symlink_parent`, also used for the config file and
  the export) looks at every ancestor directory with `lstat`. It fails
  closed: a system whose ancestors are symlinks (macOS `/var` ->
  `/private/var`, a symlinked `/etc`) gets `symlink_parent` and must use the
  resolved path. The check and the later `open` are separate steps: a
  directory swapped for a symlink between them is not detected (a
  time-of-check/time-of-use gap). It guards against a misconfigured path, not
  against a local attacker who can rename the directories; those must be
  owned by root. A missing, refused or unusable key gives a random
  per-process key and `"digest_key": "ephemeral"`: never a built-in or known
  key. There is no environment variable for the key. Reasons are fixed codes
  (`missing`, `symlink`, `symlink_parent`, `mode_too_wide`, `owner`,
  `not_usable`, ...), never
  the value.
- A future unit should hand the root-owned file to its service account with
  `LoadCredential=` rather than widening the file's mode; that choice belongs
  to #385.

### Port for a service (off by default)

`trace_recorder.py` is the port a service will call. Nothing calls it today.

- `load_trace_audit_config(path)` reads `mio.trace_audit_config.v1` JSON
  (`enabled`, `path`, `key_file`, `max_file_bytes`, `max_files`; unknown
  fields are rejected). The file is opened like the key file (no symlink, also
  not in a parent directory; a regular file; no blocking on a FIFO).
  `config/mio_trace_audit.json` ships with
  `"enabled": false`; a missing file is also disabled.
- `open_trace_audit(config)` returns `None` when disabled, so the caller does
  nothing. Enabled, it returns a `TraceAuditRecorder` with a sink and the key
  above. The sink does not create its directory; the unit that runs it owns
  that (for example `StateDirectory=`).
- `TraceAuditRecorder.record(ticket=, outcome=, frame=, edge_decision_ref=,
  cycle_status=)` returns `record_cycle`'s answer: whether the M.I.O. advisory
  may be published. `stats()` adds `digest_key` and the key reason code.

The port adds no decision or enforcement authority and no approval flag. The
recorder writes only the minimized advisory audit.

### Read-only incident export

`bin/azazel-mio-trace-export --config FILE | --path FILE [--max-files N]
--trace-id ID [--cycle-id ID] [--limit N]` prints the records of one trace
from the active file and its rotated files, oldest first, as
`mio.trace_audit_export.v1` JSON. At most `--limit` (default 256, at most
1024) of the newest records are printed; `omitted` counts the rest.

- Read-only: it opens files `O_RDONLY | O_NOFOLLOW`, refuses non-regular files,
  files over 64 MiB and paths with a symlinked directory, and never writes,
  locks, rotates or truncates. It needs no key. The audit files are `0600`, so it runs as the account that
  writes them, or as root.
- Allowlist, not masking: every record is checked field by field against the
  shape `project_outcome` writes (IDs matching their grammar or `h:<digest>`,
  closed codes, hex digests, counts, `{digest, chars}`, `executable: false`,
  `authority: advisory_only`). A record with any other field or value is not
  printed and is counted as `invalid`; broken JSON and lines over
  `MAX_RECORD_BYTES` are counted as `malformed` and `oversize`. So text put
  into the file by hand or by a bug is not echoed.
- Each file is listed by its base name with `read`, `missing` or
  `refused:<reason>`. `complete` is false when no file could be read or any
  file was refused; the records may then be incomplete and the exit status
  is 1 (0 when complete). A missing rotated file is normal. Invalid
  arguments (including `--limit` and `--max-files`, unknown options and extra
  positional arguments) exit 2 with a fixed code and are not echoed.
- `complete` is about files only. `all_lines_valid` is false when any line
  was skipped (`malformed`, `oversize`, `invalid`); a record of the trace may
  be among them. It does not change the exit status; check it and `skipped`.
- `digest_key_counts` counts the printed records by `digest_key`
  (`persistent`, `ephemeral`, `not_recorded` for v1). It repeats what the
  records say; see above for what that is worth.
- The export does not lock against the writer. If the sink rotates while the
  export reads, a record can be read twice (from the old and the renamed
  file) or missed; records are never mixed or torn. Run it again for a
  stable view, or copy the files first.

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
秘密鍵, トークン; `:`, `=`, fullwidth `：`, URL-encoded `%3A`/`%3D`, a quoted
JSON or dict key such as `"password": "x"` or `'password': 'x'`, also with an
escaped (`\"`) or URL-encoded (`%22`, `%27`) quote; a label may follow any
`%XX` (`%26`, `%0D%0A`, `%20`, ...), a `.` or a `/` (`db.password: x`,
`/password%3Dx`) but not a `:` (`ev:auth:1` stays); prose
"password is X"; quoted values to the closing quote, with `\` escaping the
next character, unquoted to the field end and on over the following `,` `;`
`&` fields until one starts with its own `key:`/`key=`), `Bearer`/`Basic`, JWTs,
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
run to the field end and continue over the next fields (`token: expired,
abc123` and `password: a,b` are one value; `password: x, user: admin` stops
before `user:`). For a weak label every field of the value must be ordinary
(`auth: failed, admin` and `token: expired, retry later` are kept). After
the first word, IPv4 and IPv6 addresses (with an optional port; only what
Python's `ipaddress` parses, not the unspecified `::` or `0.0.0.0`), network
context words (`src`, `dst`, `port`, `peer`, ...) and a port number (at most
65535) after `port` also count as ordinary; the port exception does not apply
to `pin`. A word made only of `:` and punctuation masks the value. So `auth: failed, src 10.0.0.5` is kept;
hostnames are not recognised and mask the value. When a value ends at a
closing bracket inside its match, the rest of the match is searched again
for further labels (`[token: expired] [token: x]` masks `x`). A closing
bracket ends a value only when its opening bracket precedes the label
(`(pw: x)`) and the closer is followed by whitespace, end of text or `, ; .
! ? &`; otherwise the value continues (`(pw: p)ss)` masks `p)ss`). If a later
closer in the field has no opener of its own, the secret held the closer and
the value runs to that closer (`(pw: p) ss)` masks `p) ss`).
These two cases were the known partial leaks listed on #389.

Masking is linear in the input: the bracket depth before a label is computed
once per pattern pass, a value never continues past the next match of the
same pattern, the JWT rule needs a left boundary, and the searches again
after a bracket share a budget of about twice the text length; past the
budget the rest of that match is masked instead (safe side, only reached by
very long lines full of bracketed labels). Tests mask 1 MiB of repeated
label, bracket, comma, quote, JSON, URL-encoded and JWT shapes in a child
process with a wall-clock limit and check that the time grows linearly.

Known limits of the masking (best effort, not a guarantee):

- Double URL encoding (`password%253Dx`) is not decoded and not masked.
- A value's continuation stops at a field that looks like `key:` or `key=`
  (a key starts with a letter or `_`);
  if a secret itself continues with such a field (`password: a, b=c`), that
  part is kept.
- Labels outside the list, secrets without a label and of no known shape,
  and other encodings (base64 of a `password=` pair, double URL encoding,
  HTML entities) are not recognised.
- A masked JSON key loses its closing quote (`{"[redacted:secret_kv]}`): the
  text is for a human, not for a JSON parser.
- Weak-label values with a hostname are masked even when ordinary.

The handoff still uses masking rather than the allowlist of #501, because
its point is operator-readable frame facts and model hypotheses; the trace
audit and the export carry no free text at all. Scheme-less `user:pass@host` and passwords with spaces in URL
userinfo are masked; a plain email has no `:` and is handled by the email rule.
Masking runs before truncation so a cut cannot expose part of a token.

In the handoff, IDs (`trace_id`, `frame_id`, hypothesis IDs, evidence refs,
playbook id/version) are kept only if they match `ID_GRAMMAR` and are not
token-shaped; otherwise a fixed placeholder (`invalid-hypothesis-id-<n>`,
`[redacted:evidence_ref]`, ...) is used. No digest is used there because the
handoff has no key and the value may be low-entropy. All other text, including
playbook text and the reason, is masked.

## Not in scope

Running the cognitive core and the recorder in a service (#385), with the unit
that would create the sink directory and hand over the key
(`LoadCredential=`), and #372/#374 consumers. These need a service owner and,
for any systemd/installer change, explicit approval.
