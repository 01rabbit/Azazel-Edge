# Implementation checkpoint — 2026-11-08

Branch: `arsenal/bheurope-2026`. The upstream `main` branch is unchanged.

## Delivered code

- `tools/arsenal_bheurope_2026.py`: synthetic deterministic replay, explanation and
  audit evidence capture, gate including selected action, rejected alternatives
  with reasons, release condition, trace and chain verification.
- `tools/arsenal_bheurope_monitor.py`: loopback-only read-only dashboard,
  replay state and optional resource verification report.
- `tools/arsenal_preflight.py`: read-only macOS/Linux environment preflight.
- `tools/arsenal_edge_core_verify.py`: offline Nexus v2 Edge Core integrity
  and ELF architecture check. Works on Mac without executing Linux binaries.
- `tools/arsenal_nexus_resources.py`: resource discovery without admission.
- `tools/arsenal_knowledge_verify.py`: optional producer verifier adapter;
  fails closed when Azazel-Knowledge is not installed, refuses missing input
  and distinguishes fixture verification from production verification.

## First Mac setup and acceptance commands

```bash
git clone -b arsenal/bheurope-2026 https://github.com/01rabbit/Azazel-Edge.git
cd Azazel-Edge
bash scripts/arsenal-bheurope-setup.sh
.venv/bin/python tools/arsenal_preflight.py --output artifacts/bheurope-2026/preflight.json
.venv/bin/python -m pip install 'pytest>=9,<10'
.venv/bin/python -m pytest -q tests/test_bheurope_2026_gate.py \
  tests/test_bheurope_2026_monitor.py tests/test_arsenal_nexus_resources.py \
  tests/test_arsenal_edge_core_verify.py tests/test_arsenal_knowledge_verify.py
.venv/bin/python tools/arsenal_bheurope_2026.py --out artifacts/bheurope-2026
.venv/bin/python tools/arsenal_bheurope_monitor.py --artifacts artifacts/bheurope-2026
```

Open http://127.0.0.1:8765 on the same Mac.

## Optional producer-backed Knowledge verification

Install the **pinned and reviewed** Azazel-Knowledge verifier in the demo
virtual environment before running this optional command. It needs its own
dependency set, including PyNaCl, and external trust anchor and rollback
state files. Never use the committed fixture anchor for production.

```bash
.venv/bin/python tools/arsenal_knowledge_verify.py \
  --bundle /path/to/lite.tar.gz \
  --anchors /path/to/production-anchors.toml \
  --state /path/to/state.toml \
  --output artifacts/bheurope-2026/knowledge-verification.json
```

A verified bundle is **advisory-only**. No data is wired into action selection.
The verifier does not currently project parsed knowledge rows into the monitor.

## Outstanding blockers (do not claim complete)

1. Run the Mac replay and resolve any real Python import/runtime failures.
2. Run the full contract test suite and capture its actual output.
3. Validate the original Edge Core manifest and archive bytes on both CPU types.
4. Verify a real signed Knowledge bundle with the actual producer package,
   production trust anchor, rollback watermark and per-claim expiry semantics.
5. Run on Raspberry Pi-class ARM64 Linux and record evidence.
6. Record, review and submit the required 10–20-minute video by Dec 1.
7. Only after passing these checks, freeze and tag the exact demo commit.

No administrative, sudo, firewall, network-extension or secret permissions
are needed for the current read-only demo. Avoid granting them unnecessarily.
