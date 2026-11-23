# Fresh v2 lab adapters and immutable snapshot publication

Prospective implementation refinement of1223359/d418c9f. V1 APIs/defaults remain.
FreshSourceObserveV2Lab explicitly selects protocol-v2 SHA107595f5c7d85d410d65517a7f50bdb6e3dd3b31bdb4cffcd3936be98b65ea59,
all edge-fresh-* /v2 containers, the v2 core module,49 files and v2 observer entry.
Timestamp/manifest formats are unchanged but carry their explicit /v2 tags.
Bootstrap/GO also /v2; same existing fresh-<nonce> Root-runtime config location.
Config paths additionally publication, metadata seven recipe keys unchanged.
Composite code pin is helper+NUL+input recorder+NUL+fresh_publication.py bytes.

Readiness and interrupt records add only publication_checkpoint {size,sha256}.
Root verifies original publication row chain/header metadata/identity and actual
commit file objects against stable read-only calls/input_calls snapshots. Its
fsynced prefix hash/byte count/last sequence must cover the exact first sample
or selected event+handler-return rows before Root readiness/signal time. Original
Source/journal/witness evidence and <6s deadline still apply independently.

Optional post_snapshot_error(case_id,error,*,stage,cleanup_errors=[]) is a new
TEST-LAB hook on shared Close/Finite cleanup. Only v2 implements it. After a sealed
snapshot it records an outer disposition error and never writes failure.json.
Legacy classes without the hook retain their original publication behavior.
Observer close errors similarly call the optional hook after available originals
are preserved. Shared core authorization, shutdown and manager calls do not change.

V2 publishes each original file and evaluation once using exclusive create,
fsync, then exclusive <case>-snapshot.json with exactly49 actual sha/null pins,
including the actual evaluation hash. This seal is the immutable publication
boundary before qualification assertions. Pre-seal failures retain available
originals and typed collection failure; no existing file is overwritten. Later
qualification, manager-reference or observer-close failure changes only final
outer disposition state/error/cleanup_errors. No accepted state can override an
existing rejected/collection_failed/cleanup_failed state. Later cases stay not_run.
The final disposition is written once after owned cleanup/reference release,
including all known errors, then strict run replay is required for success.
Missing disposition/seal or publication failure remains incomplete/failed and is
reported through existing Root diagnostic output; never rewrite originals to pass.

The separate v2 CI flavor is fresh-source-observe-v2, CLI --fresh-source-observe-v2.
V1 helper/harness remains callable; only the new prospective flavor is mandatory
for this PR candidate. Static collector selects v2 directory/file49 map and copies
only recipe-declaration.json, two case snapshot seals and disposition.json at top
level. Missing/failed/NOTRUN cases are explicit in inventory. Retain old v1 raw.
