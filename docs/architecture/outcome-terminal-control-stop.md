# Optional authenticated terminal CONTROL stop

The optional `run_live_resumable(..., terminal_stop_registration=Path(...))`
contract lets a separately authorized caller terminate an observer when its
already authenticated registered normal core ends. The default argument is
`None`: existing CLI callers and ordinary input handling still refuse every live
lifecycle boundary **before advancing its cursor**. No CLI option, unit, restart
policy, installer, privilege, profile or default is changed.

The optional registration argument is a protected public `origin.json` artifact.
Existing `input_live.registration` validates its exact root-owned hash binding to
the current trust policy and its registered environment/profile requirements;
this option additionally requires a v4 `live-core` registration. It does not call
`native_gate`, execute an image, open private keys, create a scope, or change
registration. The wire remains the existing authenticated live protocol; no new
native frame or persisted journal schema is introduced.

## Exact terminal disposition

The observer accepts only an authenticated `rust_core` `session_end` at the exact
complete final unread source line. Existing `SourceVerifier` verifies the entire
signed prefix, registration binding, session preparation/start order and native
sequence, and must report that same session/sequence closed. A complete fresh
`BoundedInput.snapshot` and reread through `lines` preserve the real candidate
cursor. A partial suffix, trailing record, next session, unknown boundary,
unregistered input, bad signature, wrong session/sequence, changed source or
unavailable journal/witness refuses. No fallback to EOF or automatic recovery is
introduced.

That terminal record is **control termination**, never activity, a release,
quiescence proof, an Outcome, a service result, or window continuation. The
existing cursor frame records `missed=True`: the terminal was deliberately not
observed as measurement. The exact previous/advanced prefix positions remain
available. The original signed wire bytes and the separately unwrapped decoded
record bytes remain unchanged, with separate hashes in the returned result; the
source is never rewritten. This distinction matters because `BoundedInput.lines`
normally unwraps signed input before supplying the collector-facing record.

The terminal path never calls the collector's observation or finalization
methods. Pending windows remain pending until the **existing journal close**
marks every durable pending identity lost and writes its ordinary session close.
There is no force-finalization or reconstruction. Previously committed Outcomes
remain unchanged. A failed close, wrong pending/lost count, extra commit,
persistence error, changed cursor/source, or missing/different final protected
witness acknowledgement prevents a terminal result. Source changes after a
cursor advance refuse without rolling that cursor back, repairing evidence,
retrying, or reopening a window.

The function returns a `TerminalControlStop` only after successful durable
journal close/witness acknowledgement, final source revalidation and read-only
source close. Its `to_dict()` uses
`disposition="verified_terminal_control_stop"`,
`cursor_disposition="control_not_observed"`, `cursor_missed=True`, both source
positions, registration/session/sequence, separate wire/decoded hashes and byte
counts, and the number of pending windows lost. Raw bytes remain separately
available as `signed_wire` and `decoded_record` fields; their repr is suppressed.
`measurement_completed=False` and `resume_authorized=False` are explicit.

## Limits and caller duties

A terminal result describes the verified tip at that observation; it is not a
permanent-scope-finality claim or a promise that a producer cannot append later.
Existing clean-close behavior still permits a later **explicit verified recovery**
under its unchanged restart/backlog-loss fence. This result authorizes no resume,
automatic reopen, new session or restart. An opted-in test service must separately
have effective `Restart=no`, with its actual unit/dependencies checked. No new
restart behavior is configured by this API.

The independently authorized controller must stop core/capture first, keep the
witness and observer alive while the signed terminal is consumed, then stop the
observer and witness in that order. Actual release absence, stopped actors,
cgroup/namespace quiescence and namespace cleanup are separate root/operator
checks. The API grants no query, enforcement or process-control authority. It does
not make broad interface/system metrics flow-specific or upgrade causal support.

Hardware-free tests use real Ed25519 signed terminal bytes and explicit mocked
journal/OS-role/witness boundaries. They check default refusal, original byte and
cursor preservation, pending loss, later valid sessions, trailing partial input,
source races and close/ack failures. They are not real-UID, sealed-core or VM
acceptance. A separately reviewed fresh-VM proof must exercise actual v4
registration, existing label/UID, signed core end and protected journal/witness
closure before claiming that integration works.
