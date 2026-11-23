# Isolated ARM compiler probe provenance, version 1

Prospective test-only correction for PR624's original ARM prerequisite timeout.
The original45085427927 log shows one module-fixture clang -E timeout causing9
fixture errors. It does not identify PATH-selected executable or establish a
kernel/BPF/observer failure. Preserve that failure; do not relax its10s deadline.

The approved_object fixture selects literal /usr/bin/clang for BOTH native syscall
preprocessing and subsequent BPF compilation. Resolve it, verify executable regular
ELF64 AArch64 (machine183), retain SHA256 of its actual bytes (max256MiB), and
record the independently resolved PATH lookup for clang. This uses the existing
apt-provisioned compiler, not a new tool, privilege or network dependency.
The macro input remains exactly the existing asm/unistd.h plus five syscall names;
expected bytes remain172,221,281,220,435. Probe deadline remains10s, compile60s,
bpftool30s. No fallback to another compiler or retry after failure.

Before acquisition Root retains advisory-exec-public/toolchain-probe.json with
schema_version=edge-arm-clang-probe/v1,selected_path,resolved_path,elf_machine,
sha256,path_lookup,path_lookup_resolved,version,macro_probe,error. Version and
macro_probe are null until attempted, then exact objects argv,started_ns,
finished_ns,timeout_seconds,returncode,stdout_base64,stderr_base64,stdout_bytes,
stderr_bytes,truncated,timed_out,error; macro_probe additionally stdin_sha256.
Errors null or {type,message<=4096}. Version uses the selected --version at10s;
macro probe uses the unchanged -E -P -x c - and exact stdin. Capture original
stdout/stderr prefixes64KiB each, total byte counts and timeout partial output.
Fixed Root-selected tool and fixed small input are trusted lab dependencies;
truncation, wrong native ELF, wrong macros or any subprocess error fails strictly.
Write diagnostics even on fixture setup failure and collect the fixed filename
as public CI evidence, independently of absent acquisition cases. No environment
secrets or unrestricted environment dump. A missing compiler/header ordinarily
fails nonzero; the diagnostic distinguishes tool resolution/startup/macro stages,
without claiming an existing unobserved root cause.

## Exclusive public-root ownership correction

Prospective correction after actual v2 CI45164558889: the toolchain probe created
`advisory-exec-public` before the existing public fixture exclusively created the
same directory. The resulting FileExistsError is a fixture ordering bug, not a
compiler failure. The `public_export` fixture remains the single exclusive owner
of public-root creation. `approved_object` explicitly depends on that fixture;
`approved_clang` receives its already-created root and only exclusively creates
`toolchain-probe.json`. With no configured public export, approved_object uses its already exclusive
temporary compiler directory for the diagnostic. No exist_ok acceptance, deletion, or
reuse of an unrelated existing public directory is allowed. Preserve probe bytes
through case-index publication and fixture teardown. A composed synthetic test
must drive actual fixture creation, probe publication, and public-index teardown;
BTF/compiler execution and the unprivileged readback subprocess may be mocked.
Compiler selections, inputs, deadlines, native assertions and nine actual cases
remain unchanged.

## Exact optional diagnostic readback contract

Prospective correction after v3 source acquisition succeeded and ARM job137673131882
passed all nine cases but failed public-reader teardown: the original reader's
closed root allowlist omitted the new diagnostic. Keep both failed trials and
this teardown failure unchanged. Add ONLY optional `toolchain-probe.json` to that
allowlist. Root retains its SHA256 from the exact bytes exclusively written and
fsynced by approved_clang in fixture-local state; pass that retained pin as the
reader's third argument, or literal `-` if publication never completed. `-`
requires the slot absent; a digest requires the slot present with exactly matching
bytes. Do not derive a replacement pin from reader-time bytes or silently accept
an unpinned diagnostic. Probe publication sets mode0444 before recording its pin.
The fixture's two-value root/inventory iteration remains unchanged.

The diagnostic reader uses the existing O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK
regular-file, mode0444, single-link and1MiB bound; no file write or overwrite.
Require canonical JSON+LF and exact edge-arm-clang-probe/v1 fields as above;
selected_path is /usr/bin/clang, optional paths/digest/machine and stage objects
remain nullable for actual early failures. Paths are strings<=4096, hashes64lower
hex, machine null or integer0..65535. Command stages have exact keys, string argv,
nonnegative ordered monotonic bounds, timeout_seconds10, nullable integer return,
strict booleans, bounded base64 prefixes<=64KiB and matching total/truncation facts,
nullable typed bounded errors. Macro stage additionally pins exact stdin SHA.
No advisory/kernel authority follows from this diagnostic. Unknown root slots,
changed pins, symlinks, malformed schema or absent required pin fail strictly.
Synthetic composed tests execute the REAL PUBLIC_READER body with only the local
UID assertion stubbed when needed, rather than mocking every readback success;
cover fixture/probe/index teardown, pre-probe absence and strict negative cases.
