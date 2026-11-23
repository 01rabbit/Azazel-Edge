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
