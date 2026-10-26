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
