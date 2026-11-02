# Optional loopback Knowledge context in the M.I.O. slow lane

The [cognitive-plane authority matrix](mio-cognitive-plane.md) remains authoritative.

This local candidate follows Edge #525 at `a676849adb87415c89545a1fdf7dd9e6ecc16587`.
It depends on merged MIO main at `c6a0e0d6ef589693bc7bd54a4c2c1cdf32371524`,
not a production release. This source pin includes
`KnowledgeContextResponseAdvisory`. No installation, service configuration,
credential provisioning or production deployment is included.

The existing governed slow advisory worker can make one authenticated
`POST /v1/context` request before its shared-core model analysis. Both the
existing `AZAZEL_MIO_MODEL_ENABLED=1` setting and its ordinary governance
approval remain required. Knowledge additionally requires all of:

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
slow-lane deadline, including response headers. Generations are checked before
and after the request and before and after analysis. Late work cannot replace
a newer generation.

The raw response enters only MIO #18's typed advisory projection. That core
retains public ATT&CK identifiers, bounded source-group labels and freshness, marks them
`reported_unverified`, and excludes IOC values, source prose, scores and
recommendations. The slow model lane publishes a bounded receipt only when this
typed advisory was returned and its frame trace and accepted fast generation
still match. It carries the core's bounded source groups, ATT&CK identifiers,
and freshness, with explicit `read_only_advisory` authority. The UI reports
`not_queried`, `unavailable`, `rejected`, `stale`, `timeout`, or `received`;
failure, cancellation, stale work, and foreign bindings cannot display a
positive receipt. Raw response data is not published. Existing Edge decisions,
tactical scores and frame evidence remain unchanged. The deterministic, DPI,
arbiter and action paths make no calls.
Knowledge's own API may write its normal query audit in its local store.

`tests/test_knowledge_slow_lane.py` runs transport boundary tests by default.
Its real-process test additionally requires local Knowledge and Fabric source
exports via `EDGE_TEST_KNOWLEDGE_SOURCE` and `EDGE_TEST_FABRIC_SOURCE`, and an
environment with their API dependencies plus the candidate MIO installed.
The test launches actual Uvicorn on numeric loopback, creates temporary
synthetic databases and ephemeral QUERY/INGEST principals, checks IOC source
matches and exact/near-miss mappings, traverses the governed slow worker and
MIO #18 with a deliberately failing model, and checks bounded status and
absence of raw IOC/token output. This is synthetic local integration evidence;
it does not establish production credentials, deployment or remote TLS readiness.
