# Offline bounded session observation adapter

Refs #547. `SessionObservationBuffer` is an opt-in **unregistered replay
helper**, not a live ingestion worker or decision-loop change. Default off;
there is no runtime flag, endpoint, exporter, model call or product pin change.
The current MIO pin can lack the new session helper; assessment then consumes
the window once and returns unavailable. The existing scorer is unchanged.

## Source coverage and ownership

| Existing source | Available normalized observations | Unavailable / restriction |
|---|---|---|
| Evidence-plane Suricata adapter | alert category, severity, event type, protocol, port, ingest time, evidence refs | no HTTP body/headers; SID/IP is not a session or actor identity |
| Flow-min adapter | flow/time/transport facts | timing alone cannot identify AI or maliciousness |
| Approved Deception interaction fact | package-local canary touch when separately validated and bound by product | no token/path/payload enters this buffer; touch is not actor identity |
| Reviewed replay context | explicit normalized client/capture annotations | no inference from spoofable headers; raw instruction text is refused |

The caller must mint safe boot/session/frame/event references and normalize
reviewed evidence before offering it. This is a local Python API, not a new
shared wire contract. Missing encrypted content stays absent; TLS interception,
a proxy and capture privileges are out of scope. Shared IP, source-port churn
or source address equality cannot mint a session identity here. Capture,
ambiguity and clock flags default to incomplete/uncertain, and only explicit
reviewed coverage can clear them. No HTTP extraction is added by this slice.

## Bounds and failure

At most 16 open windows, 64 event references per window, 9 closed feature names,
16 references per feature, 30-second idle expiry and 300-second absolute expiry
are enforced using caller-provided monotonic time. An offer processes one
bounded observation; no unbounded iterable/queue is accepted. Event duplicate
conflicts, reorder and feature contradictions withhold complete coverage.
Expiry and consumed IDs cannot reopen; capacity refusals are tombstoned, and
256 closed IDs seal this instance. Clock rollback seals and discards the buffer.
Drop/expiry/duplicate/malformed/unavailable counters contain no input text.

The buffer is memory-only: it has no full-disk path and no durable continuity
claim. Restart loses all windows; a caller must withhold coverage for that loss
and must not reconstruct a complete window from later observations. The
current unregistered/offline use does not solve live restart detection.

Assessment requires an existing frame with matching references. The optional
shared helper always abstains from AI identity, assesses no maliciousness and
authorizes nothing. It cannot select actions, raise severity, activate/renew
Deception or block defense. Returned hypotheses are task-local; no UI read leaf
is published. Production scheduling, bounded worker timeout/crash handling,
reviewed exact pin adoption, live evidence normalization and unchanged-Rust-
receipt replay parity remain open acceptance work in #547, before enablement.

Tests cover off, duplicates/conflicts, caps/sealing, boot mismatch, expiry,
reorder, rollback, sensitive references, missing helper and offline pure helper
integration. These are mechanical fixtures, not held-out accuracy or causal
benefit evidence. Existing G5/G6 and system comparison gates remain separate.
