# R0 Raspberry Pi HIL bridge

This bridge makes an R0 Pi validation session repeatable from a Mac laptop and produces one redacted Markdown report for review. It supports roadmap issue #408 R0 gates: #400 Outcome-as-Evidence and #372 Pi/HIL validation.

It does not alter the Edge authority model. M.I.O. remains a shadow/replay-only, non-executable advisory system. The bridge neither calls an Action Arbiter nor enables a live M.I.O. execution path.

## Safety boundary

Default HIL tests are observation-only. They never install packages, pull models, clone a checkout, restart a service, or change routing, firewall, nftables, or `tc` qdiscs. `full` and `prepare` do synchronize a **clean `main` checkout** with `git fetch origin main` and `git pull --ff-only origin main` before HIL starts. A dirty checkout or a non-`main` branch blocks the run; the bridge never resets, stashes, checks out another branch, or overwrites local work. `tc qdisc show` and `nft list ruleset` are independent, read-only postcondition observations—not applications of a mechanism. `nft list ruleset` needs privileges, so it is read through `sudo -n` (never prompts); if it cannot be read, the result is recorded as **unobserved**, never as passed.

SSH uses batch mode and `StrictHostKeyChecking=yes`; establish and verify the Pi's host key yourself before use. The SSH identity is passed to OpenSSH but its contents are never read, copied, or written into the result bundle. Bearer tokens, authorization values, password-like fields, and private-key blocks are redacted.

The only mutation supported is a service restart for a deliberate reconciliation test. It requires both `--allow-service-restart` and one or more explicit `--service NAME` values, accepts only `azazel-edge-*` units, and runs `sudo -n systemctl restart`; a refused or failed restart is recorded as failed. No flag in this tool can apply an nftables rule, qdisc, routing change, release, or enforcement action.

## Mac prerequisites

- A current local checkout of this repository.
- macOS `ssh`, `scp`, and `python3`.
- An existing Pi checkout (default `~/Azazel-Edge`) and a pre-trusted SSH host key.

No Python package is installed on either host. The stdlib-only remote runner is copied into the session directory at `~/.cache/azazel-hil/<session>/`.

## What is validated, with which interpreter

- The Edge Python dependencies live in the runtime venv, not in the system interpreter. Dependency checks (`pip check`, imports), the offline replay, and the observer exercise use `--remote-python` if given, otherwise `/opt/azazel-edge/venv/bin/python` when it exists, otherwise `python3`. The report states which interpreter was used and why.
- HIL validates the **checkout** (`--remote-repo`), not the deployed `/opt/azazel-edge` copy that the systemd services run. The report lists both: the checkout Git SHA, and for `/opt/azazel-edge` its Git SHA when it has one (installer copies do not, shown as unsupported) plus whether a fixed set of deployed files is identical to the checkout.
- Ollama runs in Docker on the Pi, so it is detected and measured through the loopback HTTP API at `127.0.0.1:11434` (`/api/version`, `/api/tags`, `/api/ps`, and one bounded `/api/generate` per installed model). The host `ollama` CLI is not required. Models are never pulled.

## Exact workflow

Run from the repository root. Replace the target and user with the Pi's values. `run` requires the preparation gate from the same session, so `full` is the normal entrypoint.

```bash
tools/hil/azazel-hil --target pi5.local --user azazel full
```

`full` performs preflight, repository/dependency preparation, bootstrap checks, and R0 tests, then writes a single paste-ready report. It prints the session ID first. If a stage fails (for example the preparation gate is blocked or SSH drops), it prints the session ID, the stage, and the reason, still collects what was recorded, and marks the report `INCOMPLETE` before exiting non-zero:

```bash
tools/hil/azazel-hil --target pi5.local --user azazel full
# azazel-hil: session r0-20260829T010000Z-a1b2c3 (reuse with --session ... to resume or collect)
# Copy artifacts/hil/r0-.../CHATGPT_PASTE.md into ChatGPT.
```

Before HIL, `prepare` verifies: clean `main`, fast-forward update, Git SHA, `pip check`, required Python imports, Rust/Cargo availability, and the repository's offline M.I.O. invariant replay. The latter has no network, live model, or enforcement path. To inspect readiness without changing the checkout, use:

```bash
tools/hil/azazel-hil --target pi5.local --user azazel prepare --no-update-repo
```

For a non-default SSH port/key, Pi checkout, or interpreter:

```bash
tools/hil/azazel-hil --target 192.168.1.50 --user azazel --port 2222 \
  --identity ~/.ssh/azazel_pi_ed25519 --remote-repo ~/src/Azazel-Edge \
  --remote-python /opt/azazel-edge/venv/bin/python full
```

`run` and `collect` only make sense inside an existing session, so always pass the session ID that `full` or `prepare` printed. To resume without repeating passed test IDs, keep the session identifier:

```bash
tools/hil/azazel-hil --target pi5.local --user azazel --session r0-20260829T010000Z-a1b2c3 prepare
tools/hil/azazel-hil --target pi5.local --user azazel --session r0-20260829T010000Z-a1b2c3 run
tools/hil/azazel-hil --target pi5.local --user azazel --session r0-20260829T010000Z-a1b2c3 collect
```

## What R0 `run` records

- Pi OS/kernel/CPU/RAM/swap/disk/thermal, Python/Rust availability, Ollama API version and model inventory, checkout SHA/status, `/opt/azazel-edge` identity, and current named Edge service state.
- Bounded local inference profiles for `qwen3.5:0.8b` and `qwen3.5:2b`: command exit status, latency, before/after memory and temperature. Missing models are **skipped**—the bridge never downloads one.
- Isolated observer append timing, rotation at a small bound, oversized-record drop, and write/backpressure-bound behavior. It does not attach a daemon to the live control path.
- Restart/reconciliation checkpoint evidence and out-of-order-record handling.
- Read-only `tc` and `nft` host observations. A successful mechanism command is not treated as postcondition proof; those observations are retained separately.

Every command writes timestamp, argv, stdout/stderr tail, exit status, test ID, and elapsed time to JSONL. `collect` copies raw session artifacts to the Mac and generates `CHATGPT_PASTE.md`.

## Optional disruptive reconciliation test

Only use this during an approved maintenance window. It restarts exactly the services named; it still cannot activate enforcement.

```bash
tools/hil/azazel-hil --target pi5.local --user azazel --session r0-20260829T010000Z-a1b2c3 run \
  --allow-service-restart --service azazel-edge-core
```

The SSH user needs non-interactive sudo for `systemctl restart` of that unit (and for `nft list ruleset` if you want the nft observation); without it the restart is recorded as failed and nft as unobserved.

## SSH/bootstrap troubleshooting

The following produces copy-paste-safe remote diagnostics without exposing a private key:

```bash
tools/hil/azazel-hil --target pi5.local --user azazel --session r0-20260829T010000Z-a1b2c3 doctor
tools/hil/azazel-hil --target pi5.local --user azazel --session r0-20260829T010000Z-a1b2c3 collect
```

If SSH cannot connect at all, the bridge prints which step failed (`ssh`/`scp`) and OpenSSH's own error line; check the host key, target/user/port and local key path. A Git failure in `prepare` reports Git's actual error (for example `not a git repository` or `dubious ownership`) rather than a generic message. Do not paste a private key, a bearer token, or `~/.ssh` contents into a report.
