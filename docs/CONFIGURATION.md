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
`sudo AP_SSID=Shelter-Net WIFI_COUNTRY=JP SKIP_LUKS=1 bash installer/internal/install_all.sh`;
`install_all.sh` hands them on to the step scripts. The defaults below are the
ones in the scripts.

### Internal network (`install_internal_network.sh`, run when `ENABLE_INTERNAL_NETWORK=1`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `AP_SSID` | `Azazel-Edge-Internal` | SSID of the internal Wi-Fi AP on `wlan0` (part of `br0`, `172.16.0.254/24`). 1..32 characters. |
| `AP_PSK` | `ChangeMe1234` | WPA2 passphrase of the internal AP, 8..63 characters. **Change it**: the default is public. After #486: see the note below. |
| `WAN_IF` | the interface of the default route (`ip route show default`) | Uplink interface. The NAT (masquerade) and forward rules for `172.16.0.0/24` go out through it. The installer stops if none is found. `set_dev_remote_access.sh` uses it too. |
| `ALLOW_EXTERNAL_SSH` | `false` | `false`: `sshd` listens only on `172.16.0.254` (the internal LAN). `true` (any case): the installer's `ListenAddress` is left out, so `sshd` listens on all interfaces, the uplink included. Temporary use only. |
| `WIFI_COUNTRY` | (unset) | Effective after #486 is merged. Wi-Fi regulatory country, a two-letter ISO 3166-1 code (e.g. `JP`), set with `raspi-config nonint do_wifi_country`. On Raspberry Pi OS the installer stops before changing anything when it is unset and no country is configured yet (the radio would stay blocked by rfkill and the AP could not start); elsewhere it is ignored. |

After #486 is merged, `AP_PSK` has no default: unset, the passphrase saved by
an earlier run is kept (else the one in the existing AP profile, else a new
random 20-character one is generated). It is saved `0600 root:root` in
`/etc/azazel-edge/internal-ap.psk` and never printed (read it with
`sudo cat /etc/azazel-edge/internal-ap.psk`). `ChangeMe1234` is refused. The
uplink (`WAN_IF`) must then be an interface other than `eth0`, `wlan0` and
`br0` (a USB Ethernet or USB Wi-Fi adapter on a Pi 5), since those become the
internal LAN.

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
