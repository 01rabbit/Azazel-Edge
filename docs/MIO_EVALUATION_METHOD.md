# M.I.O. Evaluation Method

Issue #372 defines an invariant-based, replay-first evaluation harness for the
M.I.O. cognitive shadow. It measures whether a bounded advisory is grounded and
safe; it does not grade prose quality or give M.I.O. enforcement authority.

## CI-safe corpus

`tests/fixtures/mio/evaluation_core.json` uses `mio-evaluation-scenario/v1`.
Each scenario names a normalized Situation Frame fixture, recorded model output
(inline or a `recorded_output_fixture`), an evaluation mode, and expected
structured invariants. `tests/test_mio_evaluation_replay.py` runs it with a
static in-process broker: it makes no network request and does not require
Ollama.

Run the same corpus manually with `PYTHONPATH=py:. bin/azazel-mio-evaluate`.

The core corpus covers accepted recorded Qwen 3.5 2B output, contradictory
evidence roles, the #381 empty-recommendation failure, malformed output,
untrusted prompt-injection directives, fabricated/cross-trace references,
stale evidence, timeout, and no-model/dependency-unavailable degradation.

The evaluator records terminal state, unresolved/fabricated references,
prohibited directive fields, hypothesis count, broker calls, reasoning rounds,
fallback reason, recommendation grounding, `executable`, and the deterministic
validation digest. A scenario passes when its declared invariants hold; a bad
model fixture is therefore a *passing regression test* only when the product
rejects or safely degrades as expected.

## Boundaries and comparison discipline

`pure_replay` is the CI gate. `dependency_fault` and `adversarial_fixture` are
also offline. Future `model_compare` runs must keep the same frame, prompt
template, static broker replies, validators, and repeated-run policy. Record
model/runtime identity rather than inferring it from an outcome.

`ResourceTimer` provides elapsed process time and peak RSS for separate HIL
runs. It does not measure CPU, swap, queue effects, or device-wide memory by
itself. Pi-class results must use the results template and state hardware,
OS/runtime, model, configuration, sample count, and workload. They are not
portable claims about other hardware.

No-LMM output is an expected degraded advisory outcome, not a successful model
evaluation and not a claim that deterministic Edge has failed. Deterministic
Edge remains the authoritative path. This harness has no Arbiter call,
enforcement primitive, or live-action path; every recommendation remains
`executable=false`.

See [BENCHMARK_DEFINITIONS.md](BENCHMARK_DEFINITIONS.md) for unrelated Edge
benchmark taxonomy; this document does not redefine it.
