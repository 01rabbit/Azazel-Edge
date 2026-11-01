Run this explicitly; it starts four unprivileged Edge AI agent subprocesses and
sends one synthetic accepted Rust event to each ordinary Unix event socket.
It never calls `_handle_event`, enables enforcement, edits runtime policy, or
fetches a dependency/model. The exact clean MIO runtime-pin checkout is required.

```
MIO_PROCESS_EVIDENCE=/absolute/new/private/evidence \
MIO_EXACT_SOURCE=/absolute/clean/mio-runtime-pin \
/path/to/dependency-complete/python tools/verification/mio_real_process.py
```

The harness locks `/tmp/azazel-mio-local-model-smoke.lock` and refuses nonempty
`ollama ps` before inference. Reserve Ollama with other local operators too:
the advisory file lock cannot constrain unrelated applications. Only the installed
`qwen3.5:0.8b` digest prefix `f3817196d142` is accepted. The model may remain loaded
after the run; unload only this run's model before repeating.

The disabled baseline, real loopback model, unavailable port, and a local timeout
HTTP stub run sequentially. Assertions compare independent process score and
recommendation, unchanged synthetic enforcement, advisory authority, Knowledge
`not_queried` with no references, matching handoff, and model generation/frame/trace
for accepted model output. Degraded fallback carries the current fast generation;
it does not assert absent model frame IDs as though model output were accepted.
The eight-second real-model deadline is unchanged. The timeout case explicitly
uses a 0.2-second process-only deadline. Socket operations and polling are bounded.
The ordinary production latest-only worker/backpressure is covered by existing
`test_mio_model_lane.py` tests; no costly real-model burst is performed here.

`process.log` retains daemon stdout/stderr without printing prompts or raw model
text. Runtime event/snapshot/audit files contain only this synthetic input and its
output; keep these private. Harness stdout contains only allowlisted measurements.
The full saved report is private evidence, not a publication artifact.

This is local synthetic process evidence, not product deployment, HIL, real traffic,
or a reliability claim. The Web query account is absent on the development host;
that path disables normally, while the ordinary event socket remains operational.
