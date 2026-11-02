# Optional loopback Knowledge context in the M.I.O. slow lane

The [cognitive-plane authority matrix](mio-cognitive-plane.md) remains authoritative.

This local candidate follows Edge #525 head `80445737f2ae6df2cae3bcdd7e79176352dffe24`
and uses the M.I.O. source pin `9fedb01bc9936531407a5181aa8fa5553ec19d55`, which is
publicly available at that immutable commit. This is a candidate, not a release or
deployment claim. No installation, service configuration, credential provisioning
or production deployment is included.

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
transfer encoding. A socket shutdown timer enforces the absolute remaining
Knowledge deadline, including response headers. Generations are checked before
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
There is no Knowledge-to-model join. The control daemon/UI does not yet admit
or render this new schema; a separate consumer change is required.
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
