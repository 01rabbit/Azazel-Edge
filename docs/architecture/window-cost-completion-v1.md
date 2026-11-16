# Observer window lifecycle and cost completion v1

Tracking #400/#393. Base `190750e3`. This contract and protocol precede
implementation or a new trial. Existing #609/#610/#611 reports, failures,
qualifications and raw artifacts remain immutable.

## Feasibility and authority

`OutcomeTelemetryCollector.observe_event` admits a nonempty observation window
only for throttle/redirect/isolate with `ExecutionStatus.APPLIED`, a matching
objective and usable persistence. `input_resume.objective_identity` has the
same disruptive-action/APPLIED guard. The adapter may label an ordinary observe
decision APPLIED; that is insufficient to open a disruptive observation window.

The existing actual normal-clock lab disables enforcement and high-impact
automation, enables dry-run and uses an empty objective policy. Under this
authorized profile, a genuine applied disruptive window is unavailable. Merely
adding an objective does not change this guard. Editing an event to say applied,
re-signing it or using an existing public test signature cannot establish that
the real core applied an action. No attempt to enable enforcement, providers,
new privileges or a different production profile is authorized by this slice.

Freeze `actual_applied_window_status=unavailable_under_existing_authority`.
Do not spend the two-hour feasibility allowance seeking additional authority.
Nonempty-window expiry and loss cases use explicitly SYNTHETIC inputs and
recorded test premises only. Their counters, real test-function execution and
bounded filesystem operations are not a native APPLIED measurement, physical
effect, production sensor truth or independently commissioned witness evidence.

No runtime changes, new services/accounts/groups/capabilities, installer/security/
systemd edits, new enforcement, production keys or network traffic. Root,
bootstrap code, known test keys and host/kernel custody remain lab premises.

## Files and interfaces

Add only the following implementation surfaces after this freeze is reviewed:

- `tests/window_cost_completion_lab.py`: `run_synthetic_window_cases(work)`
  creates bounded, separate SYNTHETIC cases using the existing
  `test_outcome_control_stop.Lab` and original telemetry/journal APIs. The normal
  expiry case uses the actual `OutcomeTelemetryCollector.finalize_due` on a
  known synthetic APPLIED fixture; it does not populate an outcome dictionary
  and call that an observed commit. Stop-loss occurs before the synthetic
  deadline and uses ordinary journal/control close, never forced finalization.
- `tests/window_cost_completion_analysis.py`:
  `analyze_window_cost_completion(actual_result, synthetic_result, *,
  actual_phase_raw_by_arm_role, synthetic_artifact_raw_by_case)` is bounded and
  read-only: no I/O, subprocesses, clocks, writes, new sampling or qualifications.
  `actual_result` is the retained original normal-clock evaluation and its
  externally retained artifact descriptors/metadata. Raw inputs are supplied
  separately as bytes, with null meaning declared absence. Verify exact hashes
  and bounds before parsing. Invalid optional evidence affects that item and
  retains valid siblings and original published results.
- `tests/run_window_cost_completion.py`: call
  `run_observer_normal_clock.run()` exactly once for the actual matrix; collect
  the separate synthetic cases; pass bounded originals to the analyzer. Reuse
  the original public exporter into `original-normal-clock/`; write the new
  top-level `window-cost-completion.json` separately. Never rewrite an original
  report, repair an interrupted trace or retry for a more favorable result.
- `tests/test_window_cost_completion.py` and
  `tests/test_window_cost_completion_linux.py`: synthetic negatives and one
  mandatory offline actual matrix using the cached runtime/matching core.

The original six-arm order, marker recipe, 10/20/50/50ms polling, actual
three-second warmup, at least six-second load, 1.2 x 2500 non-alert lines/s,
2% per-class rate tolerance, final audit and 98% examined-accounting floor
remain unchanged. The existing 5,000,000ns qualifier is neither replaced by
phase duration nor relaxed. A genuine normal end may still withhold that gate.

## Evidence separation and bounded replay

For actual on-arm closure, call the existing pure `verify_normal_end` with the
retained completion, request, trust, Source, journal, anchors and sidecars, and
the original externally retained control metadata/pins. Recompute original
clock and phase reports through those unchanged verification APIs; do not
trust imported `eligible`, `normal_end_verified`, footer or exit-zero fields.
For other roles, replay raw phase traces through `analyze_trace` with their
Root-retained header/incarnation pins. Compare recomputed and published values
canonically, preserving the original evaluation verbatim on a mismatch while
reporting the new item unavailable/incomplete. No supplemental fact modifies
an original clock/load/control verdict or expands its scope.

Existing limits remain: phase traces 4096 rows/4MiB/depth16; clock callbacks
900 rows/4MiB; clock context two rows/16KiB; normal completion 64KiB; Source
2MiB; journal/anchors 4MiB; trust 64KiB; EVE/audit 16MiB with the existing
32768-row EVE bound. The synthetic bundle has at most 16 declared cases,
64MiB total original bytes, one journal/trace at most 4MiB each and no private
key export. Unknown fields, duplicate IDs/JSON keys, bad types, mismatched
hashes, oversized input and invalid chains do not become successful zero counts.

## Frozen report fields

The new report has schema `edge-window-cost-completion/v1` and exactly these
top-level fields:

`schema_version`, `actual_applied_window_status`,
`original_normal_clock_evaluation`, `actual_lifecycle`, `actual_cost_by_arm_role`,
`synthetic_window_cases`, `blockers`, `authority_flags`,
`whole_measurement_qualified`, `comparison_qualified`, `qualified_safety_count`.

`actual_lifecycle` contains `evidence_kind`, `normal_stops`, `fault_prefixes`,
`applied_window_exercised`, `expiry_commit_cost`, `pending_stop_loss_cost`,
`active_deadline_wait`, `reasons`. Its evidence kind is
`actual_existing_unconfined_software_lab`; applied-window exercise is false;
the three cost/wait fields are null. Proven ordinary close counters may be
reported within `normal_stops` as finite counters, never as a nonempty-window
cost or causal effect. Faults retain their actual interrupted-prefix status.

Each `actual_cost_by_arm_role` item has `arm_id`, `role`, `evidence_kind`,
`raw_sha256`, `status`, `phase_report`, `process_metrics`, `cost_scope`,
`full_interval_cpu_seconds`, `full_interval_read_bytes`,
`full_interval_write_bytes`, `sampled_peak_rss_kib`, `kernel_hwm_kib`,
`window_specific_cost`, `reasons`. Replayed original phase and process evidence
remain separate. A phase body is inclusive and may contain child calls and
trace work; never sum nested spans or subtract unobserved gaps to assign cause.
The controller includes harness, witness, drainer and recording work. Witness
thread CPU may be observed, but witness RSS/I/O/process CPU are not isolated.
Incomplete process intervals keep full CPU/I/O deltas null while preserving
explicitly partial earlier peaks. An absent role has unavailable metrics,
not zero cost. Receiver blocking time is not kernel receipt latency.
Wall-minus-thread-CPU remains causally UNKNOWN. Actual window-specific cost is
null because the authorized actual profile exercises no applied windows.

Each synthetic case has `id`, `evidence_kind`, `applied_premise`, `status`,
`expected_lifecycle`, `observed_lifecycle`, `journal_summary`, `outcomes`,
`control_receipt`, `phase_report`, `process_metrics`, `raw_sha256`, `reasons`.
Evidence kind is `SYNTHETIC_RECORDED_TEST_ONLY`; applied premise is
`synthetic_fixture_not_observed_native_action`. Preserve actual recorded
synthetic return values and prefixes. Normal expiry commits an original
collector-built outcome at/after its synthetic deadline. Control stop before
deadline loses pending windows and commits no substitute outcome. Missing
commit/ACK/close evidence remains unknown, not an expiry or successful loss.

`authority_flags` uses the unchanged five safety flags, all false. Whole
measurement/comparison qualifications remain false; qualified safety count is
null. Fixed blockers include actual applied window unavailable, synthetic
premise not native execution, incomplete/partial cost coverage where applicable,
mixed controller/witness accounting and causal benefit unestablished.

## Frozen cases and acceptance

The protocol lists fixed independent cases and expected lifecycle states.
Synthetic expiry-before-deadline, expiry commit, pending-stop loss, duplicate
execution, commit failure, witness/close failure and interrupted recording
must retain the original APIs' semantics. Existing Source/witness/receipt
negative tests are synthetic controls; do not claim they were new kernel or
actual fault trials. Only an actually executed fresh fault is reported as such.

Test raw/published disagreement, null metrics, PID/start/boot mismatch, malformed
or truncated/overflowing traces, bad nesting, independent valid siblings and
old over-5ms withholding. Test no original report mutation, no extra actual
callbacks, no conversion of synthetic APPLIED into actual evidence and no
loss-to-commit conversion. Public exports are closed allowlists of original
reports/bytes; never private key files, bootstrap configuration or secret paths.

After independent freeze review and Root approval, implement and test locally.
Root coordinates the one actual offline Linux six-arm run and final-head CI.
Preserve every assigned scope and any failure before analysis/export assertions.
A correctly withheld measurement may be a passing software test, but unknown
nonempty actual window cost remains unknown. Independent final code/raw-artifact
review and exact base/head/tree checks precede any conditional merge decision.

## First retained actual matrix and assertion correction (2026-11-16 JST)

Source `765d8871b97fa10972f541d74bc4acd86f085051` ran one existing actual
network-disabled Linux six-arm matrix plus all seven separate synthetic cases.
No added capabilities, production service/key, provider or runtime change.
All six original 1.2x load/98% accounting/marker gates and both genuine on-arm
normal stops passed; 108,024 non-alerts were written, actual offered rates
2999.619–2999.926/s. The unchanged sampled 5ms clock qualifier passed, with worst
discrepancy 1,627,622ns and observed offset-envelope width 33,626ns. Actual
APPLIED-window exercise and its costs remain unavailable/null.

The first mandatory test FAILED after 50.15s on its overly broad synthetic-case
status assertion. The analyzer correctly withheld the witness-close case:
its raw journal has five rows/1935bytes ending in a written LOST row and no CLOSE,
while the failed witness ACK left memory at the exact four-row/1551byte prefix,
with pending1/lost0/write_failures1 and no receipt. The original journal writes
and fsyncs before witness acknowledgement and applies in-memory state afterward.
An unacknowledged written loss is not a verified protected close or successful loss.

The original report SHA256
`f1981dc20fe41dd4d85af5d720fb3507b2a494ca48f42ab8a8f7ca33b9d27f92`,
113 local retained files and failed log remain unchanged. Of these, the closed
CI/public evidence set is 99 files:62 original normal-clock files,35 declared
synthetic artifact files plus their manifest, and the new completion report.
The other14 local files are non-export synthetic fixture setup inputs/policies.

After independent diagnosis, ONLY test assertions were corrected to require
this witness case WITHHELD with the exact mismatch reason, null receipt, no
CLOSE and unavailable observed lifecycle. The strict analyzer and its report
were not changed. The entire corrected assertion function passed against the
SAME saved report with the runner stubbed; no actual matrix or analyzer rerun.
A targeted unit regression also passed. This is an assertion correction, not a
new passing Linux trial or retrospective qualification. The fresh final-head CI
matrix remains mandatory and its results must be retained separately.

All seven synthetic recipes remain distinct from native APPLIED evidence.
The30 role/arm cost rows retain partial and unavailable metrics rather than
zero; Root controller/witness process accounting remains mixed. Original reports,
clock refusals, missing CPU/I/O, incomplete lifecycle and physical/custody/causal
limitations are unchanged. Independent artifact replay and full CI remain gates.

## Publication-only copy boundary

CI43892376481 passed the mandatory B test (49.49s), then artifact upload failed
with EACCES while traversing a Root0700 synthetic setup directory. The later
normal-clock step was skipped and the full suite did not execute. No B artifact
was uploaded; ephemeral raw receipts from that CI job are unavailable. Preserve
its log and incomplete final-CI status. This is not a qualification change.

Publish a separate copy under `publication/`; never widen or modify original
setup, role, private, report or evidence paths. The fixed evidence inventory is
99 files: the completion report; the synthetic manifest and five public outputs
for each of the seven frozen recipes; and 62 normal-clock originals. The latter
are its report, five raw slots for each fixed arm, controller/signer/witness
traces for instrumented arms, observer traces and both clock slots for
instrumented on/fault arms, requests for all arms, journal/anchors for on/fault
arms, and completion receipts for the two on arms. No recursive discovery,
private keys, configs, bootstrap files or other synthetic setup files are copied.

`tests/window_cost_publication.py:publish_publication(output_dir)` accepts the
existing retained output directory. It uses only fixed relative source names;
descriptor paths never direct reads. Reject symlink/non-directory ancestors
for every source and target using directory-FD/no-follow rooted traversal and
stable identity checks, not leaf-only NOFOLLOW. The publication directory must
be fresh/exclusive; no reused target or overwrite. Pin normal-copy leaves to the retained
normal report's original descriptors and synthetic leaves to its retained
manifest descriptors. Cross-check the normal report against the completion
report's unchanged original evaluation. Read regular leaves with NOFOLLOW,
bounded reads and stable named/opened identity fences. Bounds are16MiB per leaf,
4MiB per synthetic leaf and256MiB total. Create fresh exclusive copies with
directories0755 and files0444, retaining original bytes and modes unchanged.

Every planned missing, changed, unsafe, oversized or unreadable leaf has an
explicit error; already copied valid siblings remain available. Write a separate
readonly `publication/publication-index.json` listing all99 planned evidence
paths, copied hashes/lengths and per-leaf errors. This diagnostic index is outside
the frozen analysis report. Completion requires all99 copies and no errors; a
missing file never becomes a zero or a qualified result. The primary report is
written before publication, so publication failure cannot discard it. Mandatory
Linux CI requires a complete publication index before upload. Publication-only
replay may reuse existing retained evidence; it does not rerun or requalify the
actual matrix. Final-head CI remains required.
