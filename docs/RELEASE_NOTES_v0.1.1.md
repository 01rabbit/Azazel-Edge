# Azazel-Edge v0.1.1 Release Notes 

## Theme

v0.1.1 is a hardening and readiness release. It improves safety, reproducibility, and external review clarity without introducing a broad new subsystem.

## Highlights

### Runtime correctness
- Protocol-aware prepared decoy redirect mapping in `azazel-edge-core`.
- Unsupported destination ports no longer imply blind redirect to a single decoy port.
- Deterministic fallback actions are explicit and traceable.

### Demo and deployment clarity
- New Arsenal reproducibility profile: `docs/ARSENAL_DEMO_PROFILE.md`.
- New deployment profile matrix: `docs/DEPLOYMENT_PROFILES.md`.

### Benchmark claim boundary
- New benchmark scope boundary and staged hardware-in-the-loop plan:
  - `docs/BENCHMARK_SCOPE_AND_HIL_PLAN.md`
- Benchmark report now carries explicit mode/scope metadata.

### Documentation safety updates
- README status/testing sections aligned to CI/release-trace model.
- Non-overclaiming language reinforced:
  - not a production SIEM replacement
  - not an autonomous AI defender

## Scope boundaries

- Deterministic First remains unchanged.
- AI remains optional and bounded.
- Fail-safe enforcement gates remain in place.
- This release does not claim full hardware-in-the-loop forwarding or enforcement performance.

## Validation checklist (release candidate)

```bash
PYTHONPATH=py:. .venv/bin/pytest -q
PYTHONPATH=py:. .venv/bin/pytest -q tests/benchmark -v
bin/azazel-bench pipeline
bin/azazel-bench accuracy
bin/azazel-bench report
```

If Rust toolchain is available:

```bash
cd rust/azazel-edge-core
cargo test
```
