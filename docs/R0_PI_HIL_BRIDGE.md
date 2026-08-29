# R0 Raspberry Pi HIL bridge

This bridge makes an R0 Pi validation session repeatable from a Mac laptop and produces one redacted Markdown report for review. It supports roadmap issue #408 R0 gates: #400 Outcome-as-Evidence and #372 Pi/HIL validation.

It does not alter the Edge authority model. M.I.O. remains a shadow/replay-only, non-executable advisory system. The bridge neither calls an Action Arbiter nor enables a live M.I.O. execution path.

## Safety boundary

Default commands are observation-only. They never install packages, pull models, clone or modify the Pi checkout, restart a service, or change routing, firewall, nftables, or `tc` qdiscs. `tc qdisc show` and `nft list ruleset` are independent, read-only postcondition observations—not applications of a mechanism.

SSH uses batch mode and `StrictHostKeyChecking=yes`; establish and verify the Pi's host key yourself before use. The SSH identity is passed to OpenSSH but its contents are never read, copied, or written into the result bundle. Bearer tokens, authorization values, password-like fields, and private-key blocks are redacted.

The only mutation supported is a service restart for a deliberate reconciliation test. It requires both `--allow-service-restart` and one or more explicit `--service NAME` values. No flag in this tool can apply an nftables rule, qdisc, routing change, release, or enforcement action.

## Mac prerequisites

- A current local checkout of this repository.
- macOS `ssh`, `scp`, and `python3`.
- An existing Pi checkout (default `~/Azazel-Edge`) and a pre-trusted SSH host key.

No Python package is installed on either host. The stdlib-only remote runner is copied into the session directory at `~/.cache/azazel-hil/<session>/`.

## Exact workflow

Run from the repository root. Replace the target and user with the Pi's values.

```bash
tools/hil/azazel-hil --target pi5.local --user azazel preflight
tools/hil/azazel-hil --target pi5.local --user azazel bootstrap --dry-run
tools/hil/azazel-hil --target pi5.local --user azazel run
tools/hil/azazel-hil --target pi5.local --user azazel collect
```

`full` performs those same safe stages and writes a single paste-ready report:

```bash
tools/hil/azazel-hil --target pi5.local --user azazel full
# Copy artifacts/hil/r0-.../CHATGPT_PASTE.md into ChatGPT.
```

For a non-default SSH port/key and Pi checkout:

```bash
tools/hil/azazel-hil --target 192.168.1.50 --user azazel --port 2222 \
  --identity ~/.ssh/azazel_pi_ed25519 --remote-repo ~/src/Azazel-Edge full
```

To resume without repeating passed test IDs, keep the session identifier:

```bash
tools/hil/azazel-hil --target pi5.local --user azazel --session r0-20260829T010000Z-a1b2c3 run
tools/hil/azazel-hil --target pi5.local --user azazel --session r0-20260829T010000Z-a1b2c3 collect
```

## What R0 `run` records

- Pi OS/kernel/CPU/RAM/swap/disk/thermal, Python/Rust/Ollama availability, model inventory, repo SHA/status, and current named Edge service state.
- Bounded local inference profiles for `qwen3.5:0.8b` and `qwen3.5:2b`: command exit status, latency, before/after memory and temperature. Missing models are **skipped**—the bridge never downloads one.
- Isolated observer append timing, rotation at a small bound, oversized-record drop, and write/backpressure-bound behavior. It does not attach a daemon to the live control path.
- Restart/reconciliation checkpoint evidence and out-of-order-record handling.
- Read-only `tc` and `nft` host observations. A successful mechanism command is not treated as postcondition proof; those observations are retained separately.

Every command writes timestamp, argv, stdout/stderr tail, exit status, test ID, and elapsed time to JSONL. `collect` copies raw session artifacts to the Mac and generates `CHATGPT_PASTE.md`.

## Optional disruptive reconciliation test

Only use this during an approved maintenance window. It restarts exactly the services named; it still cannot activate enforcement.

```bash
tools/hil/azazel-hil --target pi5.local --user azazel run \
  --allow-service-restart --service azazel-edge-core
```

## SSH/bootstrap troubleshooting

The following produces copy-paste-safe remote diagnostics without exposing a private key:

```bash
tools/hil/azazel-hil --target pi5.local --user azazel doctor
tools/hil/azazel-hil --target pi5.local --user azazel collect
```

If SSH cannot connect at all, check the host key, target/user/port and local key path. Do not paste a private key, a bearer token, or `~/.ssh` contents into a report.
