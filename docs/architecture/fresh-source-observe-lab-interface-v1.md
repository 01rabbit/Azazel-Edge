# Fresh Source observation lab interface, version 1

Prospective refinement of fresh-source-observe-v1 before dependent implementation.
Protocol SHA256 f12b5d79b277856251ee674994e5a3527cb07c7ae2c161ebf9241a73c3488bf2;
input recipe SHA256 46d83e1ea8551a5010f37a45a76044d81ce15d3e8a8e1196ed4d3114fa7da1ea.
Canonical public JSON is sorted compact UTF8, ensure_ascii true, finite numbers,
plus LF. Exact-key objects, null for unavailable actual facts. Known TEST keys
and Root receipts are isolated lab provenance, not operational independence.

## Files and explicit profile

Exactly the existing finite-load45 filenames plus fresh-controller.json,
fresh-timestamp-receipts.json and observer-input-calls.raw. Every evaluator gets
all48 names mapped to original bytes or null and separate externally retained
SHA256 pins or null. Stored evaluation.json is never authority. Collector has a
static48 allowlist and fixed case order fresh-controls, fresh-interrupted.
Fresh controller128KiB, timestamp receipts64KiB, input calls4MiB/256rows; all
original45 per-file limits remain unchanged. No private keys, arbitrary paths or
extra files are exported. New mandatory Linux flavor fresh-source-observe runs
armor.py with --native-core --fresh-source-observe, phases prepare/exercise/
smoke-finish. Fresh finish uses the existing verified clean finite-load gate,
never the legacy native interrupted-history finish. Old flavor behavior remains
unchanged. Every failed/NOTRUN case stays explicit; no pooling across runs.

The old45 containers are retained with explicit fresh contexts. load-controller
schema is edge-fresh-load-controller/v1, with the original finite-load controller
fields plus input_recipe_sha256. Its corpus_sha256 is the actual completed raw
hash, null until actual bytes exist; it is never a prospective recipe hash.
Other original generic close/ingress objects select only the new protocol/cases
through explicit profile APIs. No conversion to old load case IDs is allowed.
All original Root actor/custody/ref/drain/resource/audit shapes remain unchanged.
Measured observer-journal/sidecars are copied before independent post-window
audit; audit advances cannot upgrade measured callback prefixes or clocks.
Initial audit, measured observer and all later independent audits consistently
use the NEW0.1-second journal/sample context, poll0.05, unchanged objective
fixture/path/source_ref/interface lo. No context migration or history reset.

## Config and runtime entry

Role_probe mode fresh-source invokes the new helper only. Main arguments remain
(challenge,config_path=None,config_sha256=None,create=False). Root config is
exclusively0444 at /opt/edge400-runtime/finite-load-configs/fresh-<32hex>-config.json
under Root0555 directory, unchanged trusted ancestor walk and existing read
permissions. Filename nonce equals metadata.run_id. No observer-owned config
ancestor or source-tree ancestor fallback. Root bootstrap/GO uses explicit
edge-fresh-source-observer-bootstrap/v1 and edge-fresh-source-observer-go/v1;
fields otherwise exactly match prior finite-load Root identity bootstrap/GO.

Config exact keys: schema_version,case_id,protocol_sha256,input_recipe_sha256,
registration_sha256,trust_sha256,helper_sha256,paths,metadata. Config schema
edge-fresh-source-observer-config/v1. paths exact keys registration,trust,policy,
phase,calls,context,completion,journal,outcomes,input_calls. Input calls is a
separate exclusive observer-owned file in existing observer directory. All
path alias/singlelink/owner/mode/helper/config/interpreter pins remain required.
Metadata exact keys run_id,arm,role,input_recipe_sha256,code_sha256,
core_sha256,interpreter_sha256; arm is the fresh case ID, role observer. It must
never label the prospective recipe hash input_sha256. New explicit fresh phase,
clock context and completion versions retain original operation/clock/control
semantics; legacy loaders/recorders are not relaxed. Input recorder's exact row
schema is separately frozen by its implementation owner before dependent code.
Original collector callback CallRecording format is unchanged and contains real
supplied epoch, exact event and actual returned False/exception semantics.

## Actual dynamic input manifest

corpus-manifest.json schema edge-fresh-input-manifest/v1 has exact keys
schema_version,case_id,protocol_sha256,input_recipe_sha256,sha256,bytes,
lf_records,nonalert_records,per_class,markers,timestamp_receipts_sha256.
Per-class exact keys flow,dns,stats,http. Markers are ordered exact objects
{event_ref,kind,sid,occurrence,after_nonalert,start_offset,end_offset,raw_sha256,
timestamp}. They describe actual independently retained bytes after writer
completion, never a pre-known raw hash or a same-byte cross-case comparison.
Root writes the prospective protocol/recipe declaration before case one. It
publishes each actual manifest only after actual writes and retained EVE reads.

fresh-timestamp-receipts.json schema edge-fresh-timestamp-receipts/v1 has exact
keys schema_version,case_id,protocol_sha256,input_recipe_sha256,rows,errors.
Rows are ordered exact objects:
{event_ref,kind,sid,occurrence,after_nonalert,duplicate_of,generation_anchor,
timestamp_epoch_ns,timestamp,start_offset,end_offset,raw_sha256,
materialization_before_ns,materialization_after_ns,write_before_ns,write_after_ns,
error}. Anchors use actual {monotonic_before_ns,epoch_ns,monotonic_after_ns}.
All integer ns values are actual observations, not planned deadlines. For fresh,
stale and future rows, the anchor is sampled immediately before serialization;
UTC ISO8601 to microseconds uses floor(epoch_ns/1000)*1000, with fixed -/+600s
only for the declared stale/future controls. Timestamp_epoch_ns is the exact
microsecond epoch represented by the raw timestamp. No retry/re-date/adjustment.
For duplicate-two, duplicate_of is duplicate-one, generation_anchor null, and
actual raw bytes/timestamp/epoch copy that first row exactly. Its separate
materialization/write brackets and physical span remain actual. Other rows have
duplicate_of null. Error is null or bounded {type,message}; errors list exact
{stage,type,message}, message at most4096chars. Receipts do not replace actual
held-FD EVE snapshots or signed ingress_origin hashes.

Nonalert rows keep the exact deterministic600B structural recipe. Each complete
row is paced at the predeclared3000/s schedule, not delayed for a favorable
callback. Warmup firstwrite-before to firstalert-write-before >=3s; measurement
firstalert-write-before to finalnonalert-write-after >=6s; full >=9s. Native
examined numerator retains the entire finite input including warmup. Load writer
and original ingress writer retain equal actual shared fields, real bytes/hash,
write calls, fsync and join. No planned warmup counter subtraction or generated
bytes as measured denominator. Thread failures preserve actual partial prefixes.

## Fresh controller, Source bindings and interrupted boundary

fresh-controller.json exact keys:
{schema_version,case_id,protocol_sha256,input_recipe_sha256,session_ref,
started_ns,finished_ns,timestamp_receipts_sha256,input_manifest_sha256,
input_calls_sha256,readiness,observations,interrupt_boundary,errors}.
Schema edge-fresh-source-controller/v1. Hashes are actual final original file
hashes or null, not producer claims. Started/finished are actual Root monotonic
bounds. Observations is an ordered list, one per actually authenticated declared
Source decision, with exact keys
{event_ref,observed_ns,session_ref,source_position,source_checkpoint,ingress_origin}.
Source_position is exact {offset,sha256} at the end of that unique original signed
frame; Source_checkpoint is exact {seq,head,size,sha256} for that same verified
prefix. Ingress_origin is the unmodified signed Source event field. Bind each
observation to the original exact decoded event/session/registration, EVE span
and manifest row. No SID-only, timestamp-only, hash-only or trace-only join.

interrupt_boundary is null for controls. For interrupted it has exact keys
{observed_ns,event_ref,input_calls_checkpoint,handler_id,event_call_id,
source_position}. Input_calls_checkpoint is actual {size,sha256} of the complete
pre-signal recorder prefix. Handler/event IDs are the frozen input recorder IDs,
not assumed Source sequence aliases. The separate existing observer fault
boundary still retains actual pre-signal Source/journal/witness evidence and
original observer-fault-anchors.raw. Both boundaries identify the same first
signed Source frame and Root observed time. Require an actual completed original
event callback return before durable cursor and protected witness; Root checks
all original rows before SIGKILL. Root kill request must precede the fixed
firstwrite-before+6s deadline; input schedule never waits or adapts to readiness.
Missing any barrier is adverse. Original interrupted observer cannot be restarted
or given a fabricated end/closure/clock. Later callbacks remain unknown, not
measured zero or classified missed by absence.

## Closure and acceptance

Normal controls must prove exactly5 original observe_event returns False and2
complete stale/future handler filters with actual supplied live_floor/now,
authenticated Source and protected cursor evidence. Callback accepted False does
not mean no activity, and no APPLIED/window/Outcome is claimed. Repeated byte pair
has distinct signed positions and exactly two legitimate callbacks. Negative
signed-wire replay/retained APPLIED identity fixtures remain synthetic only.
Both actual cases require complete native finite input, actual load/floor,
Source End/witness/RO readback under explicit profile. Normal clock uses unchanged
5ms qualifier over real original brackets and domain, normal API/resource close
and actual exit0; fail/unknown is retained adverse, never accepted as pass.
Interrupted requires independently verified first callback/cursor/witness and
actual SIGKILL, clock null, no fake end. Clean teardown preserves exact closed
Source and disables/stops only owned fixture units. No new actor authority.

## Original readiness and composite helper pin

fresh-controller additionally has readiness, null until actually observed, then
exactly `{observed_ns,first_sample_seq,clock_calls_checkpoint,input_ready_position,
journal_checkpoint,witness_boundary}`. Checkpoints are actual `{size,sha256}`;
position is `{offset,sha256}`. Root must observe the FIRST original returned
record_sample row (its original CallRecording sequence), together with the
journal's original input_ready fence and protected witness covering that fence,
before starting the writer's fixed schedule. File existence is insufficient.
Do not generate an extra sample, recover again, or select a later favorable
sample. A returned sample may retain its actual missing metric coverage; this
readiness proves callback completion, not complete telemetry. Original
CallRecording prefix, final journal and final anchors retain the bounded prefix
bytes needed for independent verification of these checkpoint pins. Missing
readiness is adverse. Actual live_floor remains solely the original handler's
supplied value captured by the dedicated context recorder.

helper_sha256 pins fresh_source_observer.py only. metadata.code_sha256 is exactly
SHA256(fresh_source_observer.py bytes + single NUL byte +
fresh_source_recording.py bytes). Both helpers are adjacent Root-protected test
source. No new file grant or alternate interpreter is introduced. Other reused
shared recorder code remains covered by the externally retained source revision.

## Default-preserving shared test-lab seams

The existing finite_load_cost.ObserverProcess gains class attributes role_mode,
bootstrap_schema,go_schema,side_files, defaulting to its exact existing finite-load
mode/tags/six sidecars. Its existing command/identity/ref/drain checks read those
attributes. FreshObserverProcess alone overrides them for the fresh entry and
seventh input-call sidecar. stage_observer_config gains a checked prefix argument
whose default remains load; only fresh selects fresh, preserving Root-runtime
staging checks and exclusive0444 semantics. No old schema, arm or auth gate is
relaxed, and old default outputs/limits are unchanged. No additional authority.
