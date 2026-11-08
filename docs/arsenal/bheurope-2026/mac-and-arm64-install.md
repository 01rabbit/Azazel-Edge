# macOS-first demo and ARM64 deployment preparation

## Supported execution model

The **offline deterministic replay**, evidence gate and **read-only dashboard**
are designed to run on macOS (Apple Silicon or Intel) and Linux (including
Raspberry Pi aarch64). The original full Edge network sensor and enforcement
stack is Linux-specific. This branch does **not** claim that Suricata,
iptables/nftables, systemd or packet isolation can run unchanged on macOS.
Live enforcement is deliberately out of scope for the recording.

## macOS demo setup

Requirements: Git, Python >=3.10, internet access once for Python packages.
After installation, replay and monitor require no network connection.

```bash
git clone --branch arsenal/bheurope-2026 https://github.com/01rabbit/Azazel-Edge.git
cd Azazel-Edge
bash scripts/arsenal-bheurope-setup.sh
.venv/bin/python tools/arsenal_bheurope_2026.py --out artifacts/bheurope-2026
.venv/bin/python tools/arsenal_bheurope_monitor.py --artifacts artifacts/bheurope-2026
```

Open http://127.0.0.1:8765 on the same Mac. Refresh is automatic every three
seconds. Replay can be re-run in a second terminal while the monitor is open.
Do not expose the dashboard to an untrusted network: it is loopback-only,
read-only, and has no login.

## Raspberry Pi / ARM64 Linux preparation

Use 64-bit Raspberry Pi OS or Debian with Python >=3.10, Git and venv support.
Use the same commands above. This demo does not install systemd services,
modify firewall rules, or alter interfaces. For a kiosk-style deployment,
start the monitor in a user session; do not run as root.

## Verification

```bash
.venv/bin/python -m pip install 'pytest>=9,<10'
.venv/bin/python -m pytest -q tests/test_bheurope_2026_gate.py tests/test_bheurope_2026_monitor.py
```

If imports fail, identify the missing Python dependency and document it before
extending the bootstrap. Do not silently install the entire runtime requirements
file: it contains an optional external MIO Git dependency.

## Pre-recording acceptance

- Run the gate on macOS; verify gate.json ok=true.
- Record the action, explanation, trace ID, audit verification on the dashboard.
- Repeat on ARM64 Linux and record hardware details.
- Keep the actual live enforcement separate from deterministic replay claims.
- Do not tag the release until both host checks pass.

## Security and limitations

The dashboard is an observational projection of replay files, not a production
SOC console. It does not initiate replay, choose actions, or enforce traffic
controls. Replay inputs are synthetic. A valid hash chain detects edits to
retained records but cannot by itself prevent replacement of the entire chain.
