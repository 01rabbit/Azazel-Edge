# Downstream observer cost and decision parity lab

Tracking: #400; measurement boundary shared with #393. This opt-in tests-only
harness runs the real built Linux Rust core, separate-UID signer, authenticated
witness and existing foreground Outcome telemetry collector. It creates fresh
synthetic scopes, disables enforcement/high-impact automation, enables dry-run,
and never invokes a provider or changes system services, users or policy.

The three sequential arms use the same fixed EVE bytes and distinct alert SIDs:

- **off:** signed launcher/core/signer active; downstream observer absent;
- **on:** the actual telemetry CLI processes authenticated signed input using
  `LinuxProcTelemetrySource`, bounded input and durable journal cursors;
- **faulted:** the same real observer processes the first alert, then is killed
  with SIGKILL; the core/signer must process the complete remaining input.

This isolates the downstream observer increment. The signer and test-controller
witness remain active in every arm; this is not unsigned-versus-signed overhead.
The witness runs in the controller process and is not independently profiled.
Three alerts are a functional measurement smoke run, not a statistically powered
performance comparison or a hostile-load threshold declaration.

## Run and retain

Run only as root in a disposable Linux container or VM with the source, Python
runtime and compiled matching Linux core prestaged. No downloads or network
access are required. For example, using the existing test image:

```sh
docker run --rm --network none --user root \
  -v "$PWD:/src:ro" -v /absolute/built/azazel-edge-core:/core:ro \
  -v /absolute/private/results:/results -w /src \
  -e PYTHONPATH=.:py:tests -e EDGE_ORIGIN_TEST_CORE=/core \
  azazel-edge-service-tests:20261110 \
  python3 tests/run_observer_cost.py --allow-isolated-linux-root \
  --output /results/observer-cost.json
```

The output file must not exist. The standalone harness retains all original
synthetic fixture files in the guest's reported `/tmp/ea-*` directories; retain
the guest/container storage privately if those originals are required after it
stops. These directories include synthetic keys: export only the minimized
report by default. Failed fixtures are never cleaned or repaired. Automated
successful tests remove only their own fresh synthetic fixtures.

Each observer scope is initialized exactly once while its signed source is
empty, using the existing authenticated journal APIs under the observer UID.
After the signed core starts, the actual collector reopens that existing scope
and honestly excludes lifecycle backlog through normal recovery. No used source,
journal, anchor, key or registration is reset, replaced or re-enrolled to resume.
A refusal aborts the run; there is no fallback or fake collector.

## Evidence and interpretation

The comparison first requires the exact ordered SID sequence in the native log
and independently authenticated signed source. It then compares an explicit
allowlist of normalized input, complete defense decisions, enforcement status,
and enforcement mode/result/action/commands/rollback/errors/failure counts.
Timestamps, ingest epochs, trace IDs and variable release metadata are excluded;
this is semantic parity for that declared projection, not byte equality of all
metadata. A missing, duplicated or reordered decision cannot pass. Signed
session closure is required. No command success is promoted into an effect.

Identical input timestamps remain fixed across the sequential arms. They are
intentionally stale: durable missed-input counts remain missed. The objective
policy is empty because no provider applies an effect in this experiment.
This measures disabled-path intake, proc sampling and cursor costs, **not**
full applied-window telemetry cost. The faulted arm's unprocessed decision suffix
is reported separately from signed capture coverage; no missing Outcome or
baseline is fabricated. An off observer has unavailable counters, not zeros.

Process samples pin PID and kernel start ticks before/after procfs reads. CPU
uses user+system ticks divided by the reported `SC_CLK_TCK`; it excludes child
CPU. Reports distinguish sampled peak RSS from kernel lifetime `VmHWM` (KiB).
Missing files, permission failures, exit or PID reuse make the sample unavailable.
Incomplete interval coverage leaves CPU/I/O deltas null, while any earlier
sampled peak is explicitly partial. The killed observer's final RSS is null.

Logical fixture byte growth includes native/signed/journal/anchor/log files;
unsafe entries or inventory failure make it unavailable. Kernel process I/O
counters are reported separately and can be unavailable under procfs security.
Neither is an SD write-amplification, fsync latency, power-cut durability, wear or
physical storage measurement. Short sampled intervals can quantize CPU to zero;
that is not a zero-cost claim. Harness/controller work is outside measured PIDs.

SO03/SO04 delivery/release objectives and G5 pure replay remain separate. The
result is software lab evidence only: no Pi acceptance, comparative service
benefit, causal efficacy, production commissioning or G6 completion follows.
