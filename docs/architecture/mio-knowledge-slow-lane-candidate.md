# Optional loopback Knowledge context in the M.I.O. slow lane

The [cognitive-plane authority matrix](mio-cognitive-plane.md) remains authoritative.

This local candidate follows Edge #525 head `80445737f2ae6df2cae3bcdd7e79176352dffe24`
and uses the M.I.O. source pin `b441d431532507387fb81f1e03e31fd1aea57b68`,
which is publicly available at that immutable commit. MIO PR #41 selected
package version `0.1.0+git.c31c244` as a unique PEP 440 local version for its
integration wheel; this is not a public release. This is a candidate, not a
release or deployment claim. No installation, service configuration,
credential provisioning or production deployment is included.

This remains a historical Edge #525 / MIO `b441d43` evidence snapshot. The
later Edge #538 candidate advances its runtime pin to MIO main `5bb09c8`; the
process evidence below has not been rerun against that newer source.

A separate latest-only Knowledge worker can make one authenticated
`POST /v1/context` request on its own ten-second deadline. Ordinary event intake
queues it after deterministic scoring; it does not wait for model consent,
availability or completion. The model lane never makes a Knowledge request.
Knowledge requires all of:

- `AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED=1` (default disabled).
- `AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENDPOINT=http://127.0.0.1:<port>` or a numeric
  IPv6 loopback endpoint, with no path, user information, query or fragment.
- `AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN` containing an explicitly supplied
  QUERY-scoped Bearer token. No token is shipped, discovered or minted at runtime.

This opt-in creates a local data flow of existing normalized `src_ip` and
`dst_ip` to Knowledge as at most two validated IP entities. These come from
Rust's `NormalizedEvent`, where `dst_ip` is populated from EVE `dest_ip`.
They live in a separate bounded private current-generation buffer. They are
absent from MIO frames, public source context, snapshots, prompts and logs.
Disabling the context option prevents new capture into that buffer.
No address, actor, indicator, application protocol or technique is inferred.
`actor_key` stays empty. Category and protocol metadata retain exact values
in Knowledge's `event.alert.category` and `event.alert.proto`; a TCP port does
not become an application protocol. The event also carries bounded observed
kind, SID, severity, port and rule-declared technique IDs.

Transport uses direct numeric sockets without DNS or ambient proxy support.
It accepts HTTP only on loopback, does not follow redirects or retry, limits
response headers to 4 KiB and request/response bodies to 16 KiB, and rejects
transfer encoding. A single per-request cancellation watcher shuts down the captured socket on
supersession or the absolute remaining Knowledge deadline, including connect,
response headers and body reads. It checks supersession every 10 ms through the
auxiliary's lightweight current-generation scalar, not a full auxiliary snapshot, and is joined
before the serial worker starts another request, so stale I/O cannot consume the
latest queued request's deadline or create an accumulating pool of query threads. Generations are checked before
and after the request and before and after model-free projection. Late work cannot replace
a newer generation.

The raw response enters only MIO #18's typed advisory projection. That core
retains public ATT&CK identifiers, bounded source-group labels and freshness, marks them
`reported_unverified`, and excludes IOC values, source prose, scores and
recommendations. This candidate publishes a separate bounded `knowledge_analysis` receipt in the
agent snapshot (`azazel.mio_knowledge_analysis.v1`). Fields include generation,
event key, Edge source trace, MIO frame trace/ID, duration, request-attempt count,
status and `usage_status=not_applicable`. A successful model-free shared-core
projection retains only public ATT&CK IDs, source groups, reported freshness,
claim status and trust. Reported freshness is explicitly unverified at lookup;
it is never promoted to evidence or a claim of current source health. The
receipt expires after ten seconds, suppresses its projection when stale, and
checks current generation, event and both frame bindings before `is_current`.
There is no Knowledge-to-model join. The control daemon carries the receipt within its bounded `mio_auxiliary`
object. The normal dashboard summary API now replaces the nested receipt with
an allowlisted display projection: fixed status, current marker, reported-unverified
claim and trust labels, public ATT&CK IDs, bounded source-group labels, and six
parent-bound correlation identifiers: `generation`, `frame_generation`,
`source_trace_id`, `event_key`, `trace_id` and `frame_id`. Each correlation identifier
equals the parent envelope's value, which is checked before projection; it is rendered
so the browser can verify the binding, not as newly displayed data, and the allowlist
does not make these identifiers private. The separate Knowledge panel labels these
as reported and unverified, independent of the measured model result. It does
not expose source prose, routes, actions or reported defensive state.
The read path checks generation, event, Edge trace and both MIO frame bindings.
It also reuses the fast producer's handoff validation against the same enclosing
envelope: the handoff must be matched and agree with the generation, event key,
observed Edge trace/action/mode/result and MIO trace/frame IDs. Missing or
mismatched handoff or Edge-event fields suppress the receipt display.
It conservatively expires at the fast frame's deadline (at most ten seconds),
which can suppress a later Knowledge completion early; it never extends the
Knowledge receipt lifetime. The browser also clears the panel at that deadline
when polling stops. An invalid outer receipt schema, authority, usage status or
status is unavailable.
Once the outer envelope validates, a projected receipt whose freshness, bindings
or projection metadata (for example a wrong `claim_status` or `trust`) fail keeps
only its bounded `projected` status with `is_current=false` and no references.
A stale, expired or mismatched receipt follows the same status-only rule; the
operator console labels it "projected but not current" and shows no ATT&CK or
source-group references.
Knowledge latency is independent of the fast-frame wait: waiting for the frame
is bounded by the existing ten-second window, and the bounded query then gets its
own existing ten-second deadline starting at frame capture (no new target).
After the fast frame expires, the lane keeps at most one result as a display-only
"last report" for the same generation, event, Edge trace, MIO trace and frame. It
is never labelled current, carries its measured age (at last refresh) and the
reported-unverified markers, and is dropped on a new generation or event, a new
submission, a disabled lane, any binding mismatch or a malformed value. It is
never an input to the fast scorer, M.I.O. reasoning, the model lane or actions.
Operators see fixed read-only cues for timeout, unavailable, disabled,
missing_token and auth_rejected; they carry no token or raw error and trigger no
automatic retry.
This display projection does not modify the producer receipt or fast/model lane.
Existing Edge decisions, tactical scores and frame evidence remain
unchanged. The deterministic, DPI, arbiter and action paths make no calls.
Knowledge's own API may write its normal query audit in its local store.

Edge's governed audit record persists the Knowledge dependency status as
`knowledge_status` only when it belongs to the fixed allowlisted vocabulary;
other values are dropped. A model enqueue failure is isolated from event and
advisory persistence, and truncated model output audits as degraded. See
[mio-live-auxiliary.md](mio-live-auxiliary.md) for details.

`tests/test_knowledge_slow_lane.py` runs transport boundary tests by default.
Its real-process test additionally requires local Knowledge and Fabric source
exports via `EDGE_TEST_KNOWLEDGE_SOURCE` and `EDGE_TEST_FABRIC_SOURCE`, and an
environment with their API dependencies plus the candidate MIO installed.
The test launches actual Uvicorn on numeric loopback, creates temporary
synthetic databases and ephemeral QUERY/INGEST principals, checks IOC source
matches and exact/near-miss mappings, traverses the independent Knowledge worker and
pinned MIO projection with the model opt-in disabled, and checks bounded status and
absence of raw IOC/token output. This is synthetic local integration evidence;
it does not establish production credentials, deployment or remote TLS readiness.

Optional local model lane (default off): set `EDGE_TEST_MIO_OLLAMA=1` and
`EDGE_TEST_OLLAMA_MODEL=<exact-installed-tag>` alongside the two source exports
above, then run:

```sh
PYTHONPATH=. .venv/bin/python -m pytest -q tests/test_knowledge_slow_lane.py -k actual_knowledge_process
```

Before starting Knowledge or running baselines, the test reads `/api/tags` from
local Ollama at `127.0.0.1:11434` and requires an exact installed tag. Model
calls use the fixed loopback endpoint and `/api/chat`; this test does not install
or pull a model. Without the opt-in flag, the ordinary Edge handler is asserted
disabled with zero model HTTP submissions.

The model-enabled handler is polled for at most 12 seconds and its child process
has a 16-second timeout; baseline children have 6- and 12-second limits. A model
that is not complete, metered and untruncated within those limits fails this
opt-in test. The test intercepts each attempted model HTTP request before
submission and checks its serialized JSON for the QUERY token and synthetic IPs
or subnet values; it also requires positive prompt/completion token counts and
elapsed time. Final assertions bind Knowledge and the model lane's
`fast_generation` / `frame_generation` to the generation and trace in Edge's
persisted MIO handoff; the MIO frame ID and trace must match the model result.
The independent workers are
checked at their final projected/complete states; the test makes no claim about
which poll first observed them. Edge score and comparison fields must match the
model-disabled run.

The child audit hook is a best-effort test guard: it rejects `open` calls that
request writes outside the run's temporary directory, limits socket connections
to approved numeric loopback ports or UNIX sockets under the run directory, and
blocks common Python subprocess, fork and exec audit events plus
`sendto`/`sendmsg` UDP sends. It does not mediate every filesystem operation and
is not a general-purpose sandbox. The test does not retain raw prompt or raw completion
text; bounded, validated MIO result fields remain in pytest's temporary snapshot
and child result. It checks the QUERY token in produced artifacts and the
synthetic source marker in scanned logs. It does not claim every Edge event or
advisory artifact omits synthetic IPs. This is synthetic local advisory evidence;
it is not full-node Nexus authentication, production readiness or HG evidence.
