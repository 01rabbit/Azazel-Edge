"""Prospective four-stream measurement profile; never converts prior raw evidence."""

from . import fresh_source_observe_v2 as shared

PROTOCOL_SHA256 = "01f653e970f4313aaa6066219ded163e21c0753ee97d5ded5cbfedd2872a938a"
RECIPE_SHA256 = shared.RECIPE_SHA256
CASES = shared.CASES
FILES = shared.FILES
file_limit = shared.file_limit
wire = shared.wire
nonalert_lines = shared.nonalert_lines
event_specs = shared.event_specs
materialize_alert = shared.materialize_alert
STREAMS = dict(
    shared.STREAMS, phase="observer-phase.raw", context="observer-context.raw"
)
LIMITS = dict(
    shared.LIMITS,
    queue_rows=5254,
    queue_bytes=12599296,
    stream_rows=dict(calls=900, input_calls=256, phase=4096, context=2),
    stream_bytes=dict(calls=4194304, input_calls=4194304, phase=4194304, context=16384),
)


def evaluate_publication(artifacts, *, expected):
    return shared._evaluate_publication_profile(
        artifacts,
        expected=expected,
        version=3,
        protocol_sha256=PROTOCOL_SHA256,
        publication_version=2,
        streams=STREAMS,
        limits=LIMITS,
    )


def evaluate_fresh_source_case(artifacts, *, expected):
    return shared._evaluate_fresh_source_profile(
        artifacts,
        expected=expected,
        version=3,
        protocol_sha256=PROTOCOL_SHA256,
        publication_verifier=evaluate_publication,
    )


def evaluate_fresh_run_evidence(cases, snapshots, disposition, *, expected):
    return shared._evaluate_run_profile(
        cases,
        snapshots,
        disposition,
        expected=expected,
        version=3,
        protocol_sha256=PROTOCOL_SHA256,
        leaf_evaluator=evaluate_fresh_source_case,
    )
