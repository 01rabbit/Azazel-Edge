# Configuration Reference

This document is the configuration entry point for Azazel-Edge.

## Runtime Configuration Layers

- Runtime defaults and environment files under `/etc/default/azazel-edge-*`
- Deterministic SOC policy files under `config/soc_policy*.yaml`
- Concept-to-profile mapping under `concept_profiles/*.yaml`
- Installer toggles under `installer/internal/*.sh`

## Key Configuration Domains

- Authentication and fail-closed posture
- SOC/NOC policy thresholds
- AI assist thresholds and resource guardrails
- Demo replay and overlay behavior
- Aggregator and optional integration toggles

## Authoritative Documents

- AI-related runtime tuning: [AI Operation Guide](AI_OPERATION_GUIDE.md)
- SOC threshold and redirect policy controls: [SOC Policy Guide](SOC_POLICY_GUIDE.md)
- Deployment profile intent and scope: [Deployment Profiles](DEPLOYMENT_PROFILES.md)
- Generic x86_64 package and commissioning boundary: [x86_64 Integration Boundary](X86_64_INTEGRATION_BOUNDARY.md)
- Socket/runtime permission posture: [Post-demo Socket Permission Model (#105)](POST_DEMO_SOCKET_PERMISSION_MODEL_105.md)
- Concept-profile mapping layer: [../concept_profiles/README.md](../concept_profiles/README.md)

## Installer Settings

Environment variables read by the installer scripts under
`installer/internal/`. Pass them on the command line, e.g.
`sudo AP_SSID=Shelter-Net SKIP_LUKS=1 bash installer/internal/install_all.sh`;
`install_all.sh` hands them on to the step scripts. The defaults below are the
ones in the scripts.

### Internal network (`install_internal_network.sh`, run when `ENABLE_INTERNAL_NETWORK=1`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `AP_SSID` | `Azazel-Edge-Internal` | SSID of the internal Wi-Fi AP on `wlan0` (part of `br0`, `172.16.0.254/24`). 1..32 characters. |
| `AP_PSK` | none (unset) | WPA2 passphrase of the internal AP: 8..63 bytes, valid UTF-8, no newline or carriage return. Unset: the one saved by an earlier run in `/etc/azazel-edge/internal-ap.psk` is kept, else the one already in the AP profile, else a random 20-character one is generated. Whichever is used is saved in `/etc/azazel-edge/internal-ap.psk` (`0600 root:root`; read it with `sudo cat`) and never printed. The former built-in default `ChangeMe1234` is refused (given in `AP_PSK`) or replaced by a random one (found in the AP profile). When the AP profile exists but `nmcli` cannot read its passphrase, the installer stops instead of replacing it; giving `AP_PSK` explicitly avoids that. |
| `WIFI_COUNTRY` | none (unset) | Wi-Fi regulatory country, a two-letter ISO 3166-1 code (e.g. `JP`; case does not matter). Raspberry Pi OS only (with `raspi-config` and `/boot/firmware/config.txt`): set with `raspi-config nonint do_wifi_country`, then Wi-Fi is unblocked (`rfkill`). Unset: the country already configured is used; when none is (or it is `00`), the installer stops before changing anything, because Raspberry Pi OS keeps Wi-Fi blocked and the AP cannot start. Ignored on other systems. |
| `WAN_IF` | the interface of the default route (field 5 of `ip route show default`) | Uplink interface. The NAT (masquerade) and forward rules for `172.16.0.0/24` go out through it. The installer stops if none is found. `set_dev_remote_access.sh` uses it too. |
| `ALLOW_EXTERNAL_SSH` | `false` | `false`: `sshd` listens only on `172.16.0.254` (the internal LAN). `true` (any case): the installer's `ListenAddress` is left out, so `sshd` listens on all interfaces, the uplink included. Temporary use only. |

### App stack (`install_migrated_tools.sh`, run when `ENABLE_APP_STACK=1`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `ENABLE_RUST_CORE` | `1` | `1`: build the Rust defense core (`rustc`/`cargo` from apt) and install and enable `azazel-edge-core`. `0`: not built, its unit not installed; the runtime sync check then skips its sources. Only `0` or `1` is accepted (checked before anything changes). Also read by `install_all.sh`. |
| `ENABLE_NTFY` | `1` | `1`: install the local ntfy notification server (`install_ntfy.sh`) and restart the Web UI. `0`: skipped. |
| `ENABLE_LOCAL_CA` | `1` | `1`: create the device's local CA and the Web UI server certificate (`install_local_ca.sh`, under `/etc/azazel-edge/tls/`). |
| `ENABLE_HTTPS` | `1` | `1`: configure nginx (`install_https_proxy.sh`): HTTPS on port 443 in front of the Web UI (`127.0.0.1:8084`), HTTP on port 80 redirected to HTTPS. |
| `ENABLE_SECURITY_STACK` | `1` | `1`: install and enable Suricata and OpenCanary (`install_security_stack.sh`), with the encrypted secrets volume unless `SKIP_LUKS=1`. |
| `SKIP_LUKS` | `0` | `0`: set up the LUKS-encrypted secrets volume (Edge#206). Its passphrase is typed on a terminal, so without one (stdin not a terminal) the installer stops before changing anything. `1`: install without the encrypted volume. Also read by `install_all.sh` and `install_security_stack.sh`. |
| `ENABLE_SERVICES` | `1` | `1`: enable and start the services. `0`: install files only; `install_all.sh` then skips the final selftest. |

The app stack also creates the key that signs the decision trust capsules
(Edge#477): `provision_trust_capsule_key.sh` writes a random key to
`/etc/azazel-edge/trust-capsule.env` (`AZAZEL_TRUST_CAPSULE_HMAC_KEY`,
`0600 root:root`, never printed), read by the AI agent's unit
(`EnvironmentFile=`). An existing key is kept when the installer runs again;
without the file, a key set by hand in `/etc/default/azazel-edge-security` is
carried over. Only a key of at least 32 characters of `[A-Za-z0-9._~+/=-]`
that is not the public former default is kept or carried over; anything
else is replaced by a new random key (with a NOTICE, never the value). The
agent trims surrounding whitespace from the value. Without a key the agent writes the capsules unsigned
(`signature_state: "unsigned"`, empty `hmac_sig`); it never signs with a
built-in key, and the public former default key is refused like an unset one.
`azazel-edge-audit-review` shows the state as `capsule:signed`,
`capsule:unsigned` or `capsule:not_recorded` (it does not verify the HMAC).
Capsules written before this change carry no `signature_state`; unless a key
was set, they were signed with that public key and are not evidence of
anything.

### AI runtime (`install_ai_runtime.sh`, run when `ENABLE_AI_RUNTIME=1`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `ENABLE_OLLAMA` | `1` | `1`: start the Ollama container (`security/docker-compose.ollama.yml`, `127.0.0.1:11434`) and pull its models. `0`: skipped (no model download). |
| `ENABLE_MATTERMOST` | `0` on aarch64 (`uname -m`), `1` elsewhere | `1`: start Mattermost (`security/docker-compose.mattermost.yml`) and provision its workspace and the `/mio` slash command. `0`: skipped (`[ai/5] Skip Mattermost …`). Mattermost's official image is amd64 only: on aarch64 (Raspberry Pi 5) it runs under qemu-user emulation, which is not verified on the Pi 5's 16K-page kernel, so it is off by default there. `ENABLE_MATTERMOST=1` still installs it on aarch64, with a `NOTICE:` line saying so ([HARDWARE_FIRST_RUN_CHECKLIST.md](HARDWARE_FIRST_RUN_CHECKLIST.md) 2.8 and 3.8). Without Mattermost the Web UI's `/ops-comm` page shows it as unreachable with mode `disabled`, posting to Mattermost fails with `mattermost_not_configured`, and the dashboard's Mattermost handoff is disabled; the rest of the Web UI and M.I.O. (`POST /api/ai/ask`) work as before. |

The AI agent reads the model endpoint from `AZAZEL_OLLAMA_ENDPOINT` (default
`http://127.0.0.1:11434`, for example in `/etc/default/azazel-edge-security`).
It accepts loopback only (`127.0.0.0/8`, `::1`, or a name that resolves only to
those, such as `localhost`), without `user:password@` or a query, and does not
follow redirects or use proxy variables. Any other value leaves the agent in
its no-model fallback with reason `llm_endpoint_not_loopback` (or a related
`llm_endpoint_*` reason); see [AI_OPERATION_GUIDE.md](AI_OPERATION_GUIDE.md) §4.

### Local CA distribution

With `ENABLE_LOCAL_CA=1` and `ENABLE_HTTPS=1`, nginx serves the local CA
certificate (public part only) at

```text
http://<device>/.well-known/azazel-edge-local-ca.crt
https://<device>/.well-known/azazel-edge-local-ca.crt
```

from `/var/lib/azazel-edge/public/azazel-edge-local-ca.crt`
(`AZAZEL_CA_EXPORT_PATH` in `install_https_proxy.sh`). Install it as a trusted
CA on operator devices so the browser accepts `https://<device>/`. The CA key
stays in `/etc/azazel-edge/tls/ca/` and is never served.

The Web UI server certificate (`/etc/azazel-edge/tls/webui.crt`) names the
device as the LAN reaches it: the `br0` address (`172.16.0.254`), the host
name (`hostname -f` and `hostname -s`), its mDNS name (`hostname -s` with
`.local`, e.g. `Azazel-Edge.local`), `localhost` and `127.0.0.1`. The
uplink (WAN) address is not in it, since nginx answers ports 80 and 443 only
to this device and `172.16.0.0/24`, also with `set_dev_remote_access.sh`
`MODE=open` (which opens SSH and mDNS only). Every run of
`install_local_ca.sh` issues a new server key and certificate and keeps the
existing CA, so clients that trust the CA need nothing new. On a device
installed earlier, re-run the installer, or run
`sudo /opt/azazel-edge/install_local_ca.sh` and then
`sudo systemctl reload nginx`. The host name is read when the certificate is
issued: after changing it (for example with `set_dev_remote_access.sh`
`DEVICE_HOSTNAME=…`), issue the certificate again the same way.

### Final selftest (`install_all.sh`)

With `ENABLE_APP_STACK=1` and `ENABLE_SERVICES=1`, `install_all.sh` runs
`bin/azazel-edge-selftest` last and prints its findings. A critical failure
(an inactive Web UI or control daemon, an enabled but inactive Suricata or
OpenCanary, a failed config checksum or SD write test) makes `install_all.sh`
exit non-zero. The result is also in
`/var/log/azazel-edge/selftest_latest.json`.

Then it installs the periodic selftest (`install_selftest_timer.sh`:
`/usr/local/bin/azazel-edge-selftest`, `azazel-edge-selftest.service` and
`.timer`), also after a failed selftest. The timer runs it 5 minutes after
every boot and quarterly (and right away when it is first enabled); a critical
failure leaves the service failed (`systemctl --failed`). Each run writes
10 MiB once to `/var/lib/azazel-edge/selftest` for the SD write test and
removes it. `install_selftest_timer.sh` supports aarch64 only; on another
architecture `install_all.sh` prints a notice and installs no timer.

## EPD Web Preview

The "EPD on Web" routes (`/api/epd`, `/api/epd/preview.png`, `/dev/epd`; see
[API Reference](API_REFERENCE.md)) read the e-paper runtime state. On hardware
these live under `/run/azazel-edge/`. For dev hosts without the panel, the
runtime directory can be redirected via environment variables (following the
same `AZAZEL_*` path-override precedent used elsewhere in `azazel_edge_web/app.py`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `AZAZEL_EPD_RUNTIME_DIR` | `/run/azazel-edge` | Base dir for both EPD state files below |
| `AZAZEL_EPD_STATE_PATH` | `$AZAZEL_EPD_RUNTIME_DIR/epd_state.json` | Explicit override for the desired-frame input |
| `AZAZEL_EPD_LAST_RENDER_PATH` | `$AZAZEL_EPD_RUNTIME_DIR/epd_last_render.json` | Explicit override for the last-drawn-frame record |
| `DISPLAY_ROTATION_DEG` | `180` | Panel orientation compensation applied before preview/display (read by the renderer) |

These paths intentionally track the edge-tier runtime name regardless of
`AZAZEL_PATH_SCHEMA`, matching the EPD renderer and orchestrator.

## Implementation Sources

- Policy loader: `py/azazel_edge/policy.py`
- AI governance entrypoint: `py/azazel_edge/ai_governance.py`
- Installer scripts: `installer/internal/`

## Operational Note

Use deployment-appropriate profiles and validate changes in a dry-run or test environment before production field use.

## Optional G3 observation journal

The foreground `python -m azazel_edge.outcome.telemetry --policy ...` collector
is volatile by default. The following CLI arguments enable a local journal
explicitly; no environment flag, installer or service enables it automatically.

| Argument | Default | Requirement |
| --- | --- | --- |
| `--journal-directory` | absent (disabled) | Precreated physical absolute directory, owned by collector UID, mode `0700`; all symlink components refused. |
| `--journal-scope` | absent | Explicit experiment identity, unchanged on recovery. ASCII alphanumeric, hyphen or underscore, up to 128 characters, beginning alphanumeric. |
| `--journal-boot-id` | absent | Current trusted OS boot identity supplied by operator (same identifier syntax); no wall-time boot inference. |
| `--journal-initialize` | false | First creation only in an empty directory. Omit on every subsequent open. |
| `--journal-max-bytes` | 16777216 | Exact retained budget, 131072..67108864 bytes. Unchanged on recovery. |
| `--journal-max-identities` | 4096 | Exact retained budget, 1..16384. Unchanged on recovery; no eviction. |

Scope/boot identity are required together with the directory. Policy/source
identity, interface, sampling and memory budgets are bound into its context.
The file is `observations.journal` (`0600`, same UID, one hard link), held by one
nonblocking exclusive writer lock. Keep this under a trusted private parent;
root/same-UID tampering and rollback are outside the integrity guarantee.

A missing file, mismatch, invalid record, unsafe permissions or unavailable
sync/lock stops collection. Exhaustion seals new admission; admitted windows
may finish within reserved space, then the foreground process exits with an
error. A persistence I/O failure stops the foreground process without a
volatile fallback. An unclean restart preserves results and marks known pending
windows lost, but seals all new admission even if no pending identity was
saved. The CLI refuses a sealed journal before reading procfs/input. See the
[full recovery runbook](architecture/outcome-observation-journal.md) before use.

This opt-in has software/process fault coverage only. Device power-loss,
filesystem behavior, write latency/wear and concurrent defense overhead are
still G6 acceptance work; it is not installed or enabled by this change.

### Verified input resumption (new v2 scope only)

Add `--journal-resume-input` together with the journal directory/scope/boot flags
for a new, explicitly initialized scope. Input must initially be empty, at a
physical absolute path with a trusted append-only producer. `--input-max-bytes`
defaults to 16777216 (65536..67108864); `--input-max-records` defaults to 8192
(1..32768). These exact budgets and input identity/path bind the header and
cannot be changed during recovery. Normal reopen omits `--journal-initialize`
and keeps `--journal-resume-input` and the same scope/policy/input/budgets.

V2 verifies the durable byte position and prefix, tombstones pending windows,
discards the bounded startup backlog as loss, then fences a fresh telemetry
segment before new observations. Warmup, stale/delayed/unclocked/future input
cannot become replacement windows. File rotation/replacement/truncation,
partial restart tail, corruption or mismatch stop resumption. Live incomplete
lines wait, without moving the saved position. Capacity closes admission.

V1 is not migrated or unsealed; selecting the new flag for an old scope is
refused. Trusted append-only producer/parent and clock/boot identity remain
operator preconditions, not cryptographic authentication. Read the
[resumption contract and limitations](architecture/outcome-input-resume.md)
before use. No installer/service or default activation changes.

### Authenticated capture with a protected witness (new v3 scope only)

`--input-auth-policy /physical/trust.json` requires `--journal-resume-input`
and its complete explicit journal configuration. The public policy pins two
Ed25519 public keys, scope/stream, three distinct producer/observer/witness UIDs,
fixed source/journal/Unix-socket/anchor paths and exact budgets. It is owned by
the witness UID, not writable by the observer. The signing keys remain in the
producer and witness roles. No existing scope is migrated or downgraded.

Preprovision `requirements/input-auth.txt` for offline use. A separately started
foreground witness is required; no installer, users, permissions, unit or
activation default is changed. It owns a private signed high-water log and
requires Linux peer credentials. Missing/invalid/unavailable evidence, an
unwitnessed journal tail or rollback behind the protected high-water state
refuses restart without EOF/unsigned/v2 fallback. Missing windows stay lost.

See the [full v3 contract, setup and trust limits](architecture/outcome-authenticated-input.md).
The guarantee covers separately witnessed prefixes, not coordinated rollback
of all three stores or compromise of signing roles. External monotonic anchoring,
physical storage/resource acceptance and production enrollment remain open.

For a new enrolled read-only Rust capture scope, use
`outcome-input-trust/v2` with `origin_registration_sha256` and the separate
`input_enroll`/`input_origin` foreground commands. The observer still uses
`--journal-resume-input --input-auth-policy`; no automatic enrollment, downgrade,
service or key provisioning occurs. See the [exact registration/runbook](architecture/outcome-registered-origin.md).

A new `outcome-input-trust/v3` scope supports the explicitly supervised normal
core via `input_live_enroll` and `input_live`. Its root-owned registration pins
the exact existing core environment and image; no inherited enforcement flags,
replay, arbitrary command or activation default is added. Unclosed capture
history refuses a new core launch; capture failure after launch leaves defense
running. See the [configuration, roles and recovery procedure](architecture/outcome-live-origin.md).
