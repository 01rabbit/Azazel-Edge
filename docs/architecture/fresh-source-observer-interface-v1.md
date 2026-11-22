# Fresh observer interface v1 — prospective wire freeze

This refines fresh-source-observe-v1.md for protocol
`f12b5d79b277856251ee674994e5a3527cb07c7ae2c161ebf9241a73c3488bf2`
and recipe `46d83e1ea8551a5010f37a45a76044d81ce15d3e8a8e1196ed4d3114fa7da1ea`.
No product admission logic, objective horizon, authority or old helper changes.

New role `fresh-source` calls fresh_source_observer.main(challenge,
config_path=None,config_sha256=None,create=False). New bootstrap/GO schemas are
edge-fresh-source-observer-bootstrap/v1 and edge-fresh-source-observer-go/v1,
with exactly the existing load bootstrap/GO fields and actual Root identity.
Audit and run both use sample interval0.1 and poll0.05 from initial journal
creation; fixed sampled clock budget remains5ms. Child never self-reads forbidden
stat/time namespaces. Existing protected Root identity/code custody remains needed.

Config schema edge-fresh-source-observer-config/v1 has exactly
schema_version,case_id,protocol_sha256,input_recipe_sha256,registration_sha256,
trust_sha256,helper_sha256,paths,metadata. Its Root0444 physical path is
/opt/edge400-runtime/finite-load-configs/fresh-<run_id32>-config.json.
Paths are exactly registration,trust,policy,phase,calls,context,completion,journal,
outcomes,input_calls. Registration/trust/policy retain existing fixed locations;
all outputs are distinct direct children of existing bundle/observer. Metadata
has exactly run_id,arm,role,input_recipe_sha256,code_sha256,core_sha256,
interpreter_sha256; arm is fresh-controls/fresh-interrupted, role observer.
helper_sha256 pins top fresh_source_observer.py. metadata.code_sha256 pins
SHA256(top helper bytes + NUL + adjacent fresh_source_recording.py bytes).
No actual input hash exists prospectively; independent original write/EVE evidence
supplies it later. Root and all imported protected shared modules remain trusted.

Fresh phase/context schemas are edge-fresh-phase-timing-record/v1 and
edge-fresh-clock-context/v1. Their envelopes, limits, actual clocks and original
calls remain those of the existing recorders; only fresh metadata/versions are
selected by this entry. Original CallRecording format/callbacks stay unchanged.
Normal completion uses edge-fresh-observer-completion/v1 with original completion
fields plus input_calls in sidecars, after all original resources/sidecars close.

New fresh_source_recording.record_inputs(path,metadata=,identity=,binding=)
wraps the original observe_input inside the original record_collector context.
Binding has exactly case_id,run_id,registration_sha256,trust_sha256,
input_recipe_sha256. Context envelope has exactly schema_version,seq,prev,kind,data;
schema edge-fresh-input-record/v1, seq starts1, prev is SHA256 of previous full
canonical JSON+LF row (first64zeros). Canonical JSON is sorted compact ASCII,
finite numbers, plus LF. Max256rows/4MiB. No Source records are modified.

Kinds/data fields are exact:

- begin: metadata,identity,binding,limits (max_rows,max_bytes).
- input_intent: input_id,decoded_event_sha256,position,cursor_before,live_floor,
  supplied_now,start_ns. input_id starts1 per actual handler call. position and
  cursor fields are actual signed Source prefix positions {offset,sha256}.
  decoded_event_sha256 hashes actual InputLine.raw, including canonical LF.
- input_return: input_id,end_ns,handler_result,cursor_after,callbacks.
  handler_result is original result (currently null), never invented success.
- input_raise: input_id,end_ns,exception_type,cursor_after,callbacks.
  Original exception object is re-raised unchanged; unavailable context remains
  partial, never repaired. Metadata failures do not replay/suppress original calls.
- end: completed_inputs,completed_callbacks,final_cursor,normal_return,incomplete.
  End exists only after genuine normal API/control-result return, with true/false
  final flags. final_cursor is last observed returned handler cursor, not invented
  from a later audit. No end on SIGKILL, exceptions or recording failure.

Each callback object has exactly call_seq,event_sha256,return_value,
observed_epoch,activity. call_seq is the ACTUAL original CallRecording event row
sequence, observed only after its append/fsync returns. Its complete event must
match the authenticated decoded Source event. return_value is actual observe_event
return, distinct from callback occurrence or activity. activity is null or the
actual super._record_activity return with exactly epoch,src_ip,dst_ip,target_port,
sid,evidence_ref. No APPLIED/window/dedup claim is created by this instrumentation.
Controller handler_id maps input_id; event_call_id maps call_seq;
source_position maps actual cursor_after of the selected completed handler.

Intent and return facts are buffered in bounded memory before publication.
There is no context durable write/fsync before the original handler/callback.
Flush intent+return after handler completion; only one context fsync at normal
close, never per handler. Existing original callback recorder durability is
unchanged. Actual original call/clock overhead remains adverse. Truncated bytes,
missing callbacks, cursor failures or incomplete recordings stay unknown.
