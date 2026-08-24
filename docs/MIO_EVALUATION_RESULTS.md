# M.I.O. Evaluation Results

## CI baseline (recorded replay)

| Field | Value |
| --- | --- |
| Harness | `mio-evaluation-scenario/v1` |
| Execution | offline static broker; no network; no Ollama |
| Recorded model fixture | Qwen 3.5 2B, local Ollama capture from #381 |
| Result | accepted fixture completes grounded and non-executable; adverse fixtures reject/degrade deterministically |
| Scope | validator/replay behavior only; not a model-quality, latency, or hardware claim |

Run: `PYTHONPATH=py:. .venv/bin/pytest -q tests/test_mio_evaluation_replay.py`

## Hardware/model result template

Fill one row per measured configuration. Do not compare rows with different
frames, prompt versions, broker fixtures, validators, or repeat counts.

| Date | Hardware/OS | Runtime/version | Model/quantization | Prompt/version | Corpus/repeats | Latency | Peak RSS | Swap/queue | Result artifact | Caveat |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| pending HIL | not measured | not measured | not measured | `auth-ambiguity-v1` | not measured | not measured | not measured | not measured | pending | No Pi-class measurement is claimed by this baseline. |

This template intentionally contains no synthetic Pi latency or resource value.
