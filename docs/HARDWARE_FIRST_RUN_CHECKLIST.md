# Hardware First-Run Checklist (Raspberry Pi 5)

Last updated: 2026-10-27

The first installation of Azazel-Edge on a real Raspberry Pi 5, and what to
check on it. Each check has an ID, the command, the expected result, a
pass/fail column and the PR or issue it comes from. Japanese version:
[HARDWARE_FIRST_RUN_CHECKLIST_JA.md](HARDWARE_FIRST_RUN_CHECKLIST_JA.md).

Refs #408 (R0), #372 (Pi-class HIL), #471 (privilege separation), #477
(hardening).

## 0. What this checklist assumes

- `main` contains **#479–#488 and #490** (all merged; #490: TUI
  `PermissionError` on the control socket, HIL `FileNotFoundError`). Install
  from a `main` that has them (2.3). A row tagged with a PR that is not in the
  checkout does not apply: mark it `N/A (PR not merged)`, never `pass`.
- **#489** (host input filter, WAN default deny) is a draft and **off by
  default**. Section [3.13](#313-host-firewall-trial-489-draft-optional) tries it
  separately, on its own branch, and rolls it back. Once #489 is merged, the
  `main` checkout has it (`installer/internal/azazel-host-firewall` exists)
  and 3.13 runs on `main` instead (see its first paragraph).
- Every result in those PRs comes from containers or VMs. **None of it is
  device evidence**; this run is the first. A container result is never copied
  into this sheet as a pass.
- Commands, paths, account names and ports below were checked against the
  code of those PR branches. Anything that could not be checked that way is
  marked **(to confirm)** and is part of what this run finds out.

Placeholders: `<pi-user>` is the login account created when the SD card was
written; `<CC>` the Wi-Fi country code decided in 1.3; `<WAN_IF>` the uplink interface (USB Ethernet or USB Wi-Fi);
`<WAN-ADDR>` the address the uplink got (`ip -4 -br addr show <WAN_IF>`);
`<hostname>` the device's host name. The LAN address `172.16.0.254` and the
LAN `172.16.0.0/24` are fixed by `installer/internal/install_internal_network.sh`.

## 1. Preparation

### 1.1 Hardware

| Item | Notes |
| --- | --- |
| Raspberry Pi 5 | 8 GB recommended (Ollama models, optional Mattermost under emulation). Record the RAM size. |
| Power supply | USB-C 5 V / 5 A (the label in [PHYSICAL_SETUP_GUIDE.md](PHYSICAL_SETUP_GUIDE.md) §2 says 5V/5A MIN). An inline USB-C power meter for the R0 power figures (section 3.12). |
| Boot media | Industrial-grade SD card or a USB/NVMe SSD. The Ollama models and Docker images need several GB: record the size and the free space after install. |
| EPD | Waveshare 2.13" e-Paper (B) V4 (the code uses `epd2in13b_V4`), on the 40-pin header (SPI). |
| Touch Display 2 | Raspberry Pi Touch Display 2 (1280x720). Needs the desktop image (section 1.2). |
| Uplink adapter | **Required.** The on-board `eth0` and `wlan0` become the internal LAN (`br0`); the uplink needs a USB Ethernet adapter or a USB Wi-Fi adapter ([PHYSICAL_SETUP_GUIDE.md](PHYSICAL_SETUP_GUIDE.md) §1.1). For the Wi-Fi checks (3.4) a USB Wi-Fi adapter is needed in addition; the simplest first run is USB Ethernet as the uplink plus a USB Wi-Fi adapter for the Wi-Fi checks. |
| LAN clients | A laptop that joins the internal AP (WPA2) and, if possible, one wired client on a switch behind `eth0`. The Mac that runs the HIL bridge (3.11) must be on the LAN side: after install SSH listens on `172.16.0.254` only. |
| Upstream test host | A second machine on the uplink network (same segment as `<WAN_IF>`), with `curl`, `nc` and `dig`, for the WAN exposure checks (3.7). |
| Test access points | For 3.4: a WPA2-PSK AP, a WPA3-SAE-only AP, a WPA2/WPA3 transition-mode AP, and an 802.1X (WPA2-Enterprise) AP. Lab APs, not production networks. |
| Console | Keyboard and display on the Pi (micro-HDMI), or a serial console you have already verified. The installers must run on the console or inside `tmux` (1.4). |

### 1.2 Operating system

- **Raspberry Pi OS (64-bit), Debian 13 "trixie" based.** The PRs were
  checked on trixie arm64 only. A bookworm image is not the target (for
  example `install_ntfy.sh` installs `ntfy` from the Debian archive, which
  bookworm does not carry).
- The desktop image is needed for the Touch Display 2 kiosk (3.9); the Lite
  image is enough without it.
- Record the exact image (`/etc/rpi-issue`), `/etc/os-release`, the kernel
  (`uname -r`) and the page size (`getconf PAGESIZE`; the Pi 5 default kernel
  uses 16K pages, which matters for Mattermost in 3.8). Which image release
  was used is part of this run's record **(to confirm: no image release has
  been tested yet)**.
- When writing the card, set the user, host name, locale and SSH. Do not
  configure a Wi-Fi client network on the on-board Wi-Fi: `wlan0` becomes the
  internal AP and the installer takes its client profiles down.

### 1.3 Values to decide before installing

| Value | Where | Decision |
| --- | --- | --- |
| `WIFI_COUNTRY` | `install_internal_network.sh` | Two-letter ISO 3166-1 code (e.g. `JP`). Required on Raspberry Pi OS unless one is already set (`sudo raspi-config nonint get_wifi_country` prints a code other than `00`); without either the installer stops before changing anything. |
| `AP_SSID` | `install_internal_network.sh` | SSID of the internal AP (1–32 characters, default `Azazel-Edge-Internal`). **Pass the same value on every re-run**, or the SSID returns to the default. The commands below quote it in single quotes inside a double-quoted `script -c` string: an SSID containing `'`, `"`, `$` or a backslash needs other quoting (or choose a plain one). |
| `AP_PSK` | `install_internal_network.sh` | Leave unset: a random passphrase is generated and saved root-only (0600) in `/etc/azazel-edge/internal-ap.psk`. `ChangeMe1234` is refused. |
| `WAN_IF` | `install_internal_network.sh` | The USB uplink interface. Optional when the default route already goes through it; the installer stops if the default route is on `eth0`, `wlan0` or `br0`. |
| `SKIP_LUKS` | `install_all.sh` and the security stack | `0` (default): an encrypted secrets volume (`/var/lib/azazel-secrets.img`, mapper `azazel-secrets`) is created and its passphrase typed on the terminal. `1`: no encrypted volume. Decide before the run; the passphrase is not stored by the installer. **If the passphrase is lost the volume cannot be opened again and its content is gone** (no recovery key): keep it off the device, as the field team's procedure requires. |
| `ENABLE_MATTERMOST` | `install_ai_runtime.sh` | Recommended `0` for the first `install_all.sh` run, then Mattermost on its own (2.8): whether the amd64-only image runs on the Pi 5 is unknown, and a failure there would stop `install_all.sh` before its selftest. |
| `AZAZEL_UP_IF` | `/etc/default/azazel-edge-security` | The uplink interface for the disconnect action; default `wlan0`, which is the internal AP and is refused. Set in 3.4 (WIFI-09). |
| `ALLOW_EXTERNAL_SSH` | `install_internal_network.sh` | Leave `false`: sshd then listens on `172.16.0.254` only. |

### 1.4 Console or tmux

Run every installer on the local console or inside `tmux`, not in a plain SSH
session ([PHYSICAL_SETUP_GUIDE.md](PHYSICAL_SETUP_GUIDE.md) §1.2). SSH over
`eth0` or the on-board Wi-Fi is cut when `br0` is built, and after sshd is
restarted a new SSH session from the uplink side is refused. Inside `tmux`
the installer keeps running; reconnect from the LAN (`ssh <pi-user>@172.16.0.254`)
and `tmux attach`.

### 1.5 The result sheet

Keep the results in a local file (copy the tables of section 3 and fill the
pass/fail column). Section 4 says what may go into an issue.

## 2. Installation

### 2.1 First boot and versions

```bash
sudo apt update && sudo apt full-upgrade -y
sudo reboot
# after the reboot: record these
cat /etc/rpi-issue /etc/os-release
uname -r
getconf PAGESIZE
tr -d '\0' < /proc/device-tree/model; echo
free -h
df -h /
```

Expected: trixie in `/etc/os-release`, a Raspberry Pi 5 model string,
`getconf PAGESIZE` 16384 (default kernel) or 4096.

### 2.2 Uplink

Connect the USB uplink adapter first, then:

```bash
ip -br link
iw dev
ip route show default
```

Expected: the USB interface (`eth1`, `wlan1` or a predictable name such as
`enx…`) is listed and the default route goes through it, not through `eth0`
or `wlan0`. For a USB Wi-Fi uplink, connect it without putting the passphrase
on the command line: `sudo nmcli --ask dev wifi connect '<SSID>' ifname <WAN_IF>`
(nmcli prompts for it).

If it stops: no default route → the uplink has no DHCP lease (`nmcli dev`,
cable, upstream DHCP). Default route on `eth0`/`wlan0` → the installer will
refuse; move the uplink to the USB adapter or pass `WAN_IF=<WAN_IF>`.

### 2.3 Checkout

```bash
sudo apt install -y git tmux
git clone https://github.com/01rabbit/Azazel-Edge ~/Azazel-Edge
cd ~/Azazel-Edge
git log --oneline -n 40
```

Expected: the merge commits of #479–#488 and of #490 are in
the log (their subjects end with `(#NNN)`). The HIL bridge (3.11) expects
this checkout at `~/Azazel-Edge` on a clean `main`; do not edit files in it.

### 2.4 Pre-checks (change nothing)

```bash
sudo raspi-config nonint get_wifi_country
rfkill list
ls -l /dev/spidev0.0
```

Expected: a country code or `WIFI_COUNTRY` decided in 1.3; Wi-Fi may still be
soft-blocked (the installer unblocks it); `/dev/spidev0.0` may be missing
until SPI is enabled and the Pi rebooted (2.6).

### 2.5 Run the installer

On the console, inside `tmux`. `script` keeps a log and gives the installer a
terminal for the LUKS passphrase (do not pipe stdin):

```bash
tmux new -s install
cd ~/Azazel-Edge
script -c "sudo WIFI_COUNTRY=<CC> AP_SSID='<your SSID>' WAN_IF=<WAN_IF> ENABLE_MATTERMOST=0 installer/internal/install_all.sh" ~/install-first-run.log
```

Add `SKIP_LUKS=1` only if 1.3 decided so. Record the start and end time
(install duration, R0-04).

Expected output, in order (the step lines are printed by the scripts):

| Stage | Expected lines | If it stops |
| --- | --- | --- |
| Start | `[all/1] Azazel-Edge unified installer` and the `ENABLE_*` values | `ENABLE_RUST_CORE must be 0 or 1`: a typo. `ERROR: the encrypted secrets volume … needs a passphrase typed on a terminal`: stdin is not a terminal; use the `script -c` form above. |
| Internal network | `[all/2] Apply internal network baseline`, then (in this order) `Wi-Fi country: … (already configured)` when `WIFI_COUNTRY` is not given, `Uplink (WAN) interface: <WAN_IF>`, the package installation, `Wi-Fi country: <CC>` when `WIFI_COUNTRY` is given, `===== verify =====` with its listing, `Internal AP + DHCP baseline applied.`, `AP SSID: …`, `AP passphrase: a new random one, saved root-only in /etc/azazel-edge/internal-ap.psk …`, `SSH listen scope: 172.16.0.254 only.`, `From internal host, verify: …`; then `[avahi] allow-interfaces=br0 in /etc/avahi/avahi-daemon.conf (…)` (`changed` on a fresh install) | `ERROR: no Wi-Fi country is configured, …` → pass `WIFI_COUNTRY`. `ERROR: the uplink is <IF>, which becomes part of the internal LAN …` or `ERROR: WAN interface not found …` → 2.2. `ERROR: the internal AP (lan-wlan0-ap on wlan0) did not come up` → `rfkill list`, `nmcli radio`, `journalctl -u NetworkManager`. `ERROR: sshd rejects the new configuration` → `sudo sshd -t`; the old config stays. |
| App stack | `[all/3] Install Azazel-Edge app stack`, `[1/16] Install OS dependencies`, `[1/16] Enable SPI for the EPD (Raspberry Pi OS)` (possibly `NOTICE: SPI is enabled … reboot before the EPD can draw.`), `[2/16] Create base directories` … `[8/16] Build Python runtime (venv + pip)` … `[11.8/16] Build and install the Rust defense core …` (the longest step), `[12/16] Enable services` and `… is active` for the control daemon, the AI agent, the Web UI and the core (in that order), `[13/16] Install local CA and TLS cert (optional)`, `[14/16] Install HTTPS reverse proxy (optional)` ending with `[https] nginx TLS reverse proxy enabled on :443 (this device and … only)`, `[15/16] Install ntfy (optional)` ending with `[ntfy] Service healthy on http://127.0.0.1:8081 (loopback only, anonymous access denied)`, `[16/16] Install security stack (OpenCanary + Suricata, optional)` (the LUKS passphrase prompt comes here unless `SKIP_LUKS=1`), `[17/17] Verify runtime sync`, `Installed Azazel-Edge stack …` | `ERROR: <unit> did not stay active …` → `journalctl -u <unit> -b`. Exit status 78 → the SOC policy / ATT&CK YAML under `/opt/azazel-edge/config` is invalid. A `cargo build` failure stops here (fail-closed). An ntfy `ERROR:` line names the failed check (health, anonymous access, token). |
| AI runtime | `[all/4] Install AI runtime stack`, `[ai/4] Start Ollama and provision models` (model download), `[DONE] AI runtime stack installed.` | `docker exec … ollama pull` failing → uplink/DNS; re-run `install_all.sh` with the same values. |
| Optional parts | `[all/5]` … `[all/7]` `Skip …` with the defaults | – |
| Selftest | `[all/8] Run selftest`, then `[all/9] Install the periodic selftest timer` with `[selftest 1/4] Install selftest binary` … `[selftest] timer started` (aarch64 only; installed also when the selftest failed), then `Unified installation completed.` | `ERROR: the selftest found a critical failure …` → `/var/log/azazel-edge/selftest_latest.json` and section 3.10. |

A re-run with the same values is safe (the scripts are idempotent); always
pass the same `AP_SSID`.

### 2.6 Reboot

```bash
sudo reboot
```

The reboot is needed for `/dev/spidev0.0` when SPI was enabled during the
install, and it is the first test of the boot path (SSH and the AP come back,
3.6 and 3.3). With LUKS, `crypttab` uses `nofail` and a 90 s timeout: boot
continues without the passphrase and the secrets volume stays closed until
it is unlocked. Record whether a passphrase prompt appeared on the console.

### 2.7 Dashboard

From a LAN client: install the local CA from
`http://172.16.0.254/.well-known/azazel-edge-local-ca.crt` as a trusted CA,
then open `https://172.16.0.254/`. The first time, open it with `?token=` and
the token from `sudo cat /etc/azazel-edge/web_token.txt` (on the device; do
not copy it into notes or issues), as [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md)
describes. A token in the address reaches the nginx and gunicorn access logs
and the browser history: do it once, on a trusted LAN client, never on
`/touch` ([TOUCH_CONSOLE_KIOSK.md](TOUCH_CONSOLE_KIOSK.md)), and rotate the
token if the address was shared.

### 2.8 Mattermost (optional, after the first run passes)

```bash
cd ~/Azazel-Edge
sudo ENABLE_OLLAMA=0 installer/internal/install_ai_runtime.sh
```

Expected:
`[ai/5] Start Mattermost stack`,
`[ai/6] Provision Mattermost workspace`,
`[ai/7] Provision Mattermost slash command`,
`[DONE] AI runtime stack installed.`
Exit status 1 with instructions: the LAN proxy could not be
set up (read the message). Exit status 3 with `[ACTION REQUIRED]`: an old
default admin password (not expected on a fresh install). If the Mattermost
container does not start, collect 3.8 MM-01/MM-02 and stop; it is an owner
decision (section 5).

## 3. Checks

Fill the `Result` column with `pass`, `fail` (with a note) or `N/A (reason)`.

### 3.1 Services and accounts (#471 stages 1–2)

```bash
# SVC-02: the account each unit's main process runs as
for u in azazel-edge-control-daemon azazel-edge-core azazel-edge-web azazel-edge-ai-agent; do
  printf '%s ' "$u"; ps -o user= -p "$(systemctl show -p MainPID --value "$u")"
done
# SVC-05
systemctl show -p NRestarts azazel-edge-control-daemon azazel-edge-core azazel-edge-web azazel-edge-ai-agent
```

SVC-09 has two steps. Step 1 only reads:

```bash
# SVC-09 step 1: enforcement stays off (the unit's defaults; the environment file must not change them)
systemctl show -p Environment azazel-edge-core
sudo grep -E '^AZAZEL_DEFENSE_' /etc/default/azazel-edge-security
sudo wc -l /var/log/azazel-edge/ai/core-decision-audit.jsonl /var/log/azazel-edge/ai/p0-alert-queue.jsonl
date -Is
```

Run step 2 **only when** step 1 shows `AZAZEL_DEFENSE_ENFORCE=false` and
`AZAZEL_DEFENSE_DRY_RUN=true` in the unit and the `grep` prints nothing;
otherwise do not inject and mark SVC-09 `N/A` with the reason. The test
alerts stay for good: in the append-only core decision audit chain, in the P0
queue and in `normalized-events.jsonl` (they cannot be removed without
breaking the chain), and a P0 may set off the visual or voice notification
downstream of the queue. Record the time before and after, so the entries can
be told apart later.

```bash
# SVC-09 step 2: test alerts into the eve.json the core reads
sudo azazel-edge-dummy-eve emit --scenario ssh_bruteforce --count 20
# a few seconds later
sudo wc -l /var/log/azazel-edge/ai/core-decision-audit.jsonl /var/log/azazel-edge/ai/p0-alert-queue.jsonl
date -Is
```

If no P0 entry appears after `ssh_bruteforce` and then `port_scan`, mark
SVC-09 `N/A (no P0 decision from the test alerts)` and record the scenarios
and the line counts.

```bash
# SVC-10: terminal 1, the Web UI's ntfy bridge (the token goes on stdin)
sudo sed 's/^/X-Auth-Token: /' /etc/azazel-edge/web_token.txt | curl -skN -H @- --max-time 30 https://127.0.0.1/api/events/stream
# SVC-10: terminal 2, publish a test message with the Edge ntfy token
sudo sed 's/^/Authorization: Bearer /' /etc/azazel-edge/ntfy.token | curl -s -o /dev/null -w '%{http_code}\n' -H @- -d 'first-run test' http://127.0.0.1:8081/azg-info-status
# SVC-11: monitoring state as the Web UI reports it
sudo sed 's/^/X-Auth-Token: /' /etc/azazel-edge/web_token.txt | curl -sk -H @- https://127.0.0.1/api/state | python3 -c 'import json, sys; print(json.load(sys.stdin)["monitoring"])'
```

SVC-12 is optional and changes the device: `install_sensors.sh` overwrites
`/etc/default/azazel-edge-sensors` (without `SNMP_TARGETS` it writes no SNMP
target, and SNMP stays off with `ENABLE_SNMP=0`; `ENABLE_SNMP=1` without
`SNMP_TARGETS` naming real targets stops without changing anything) and
leaves the NetFlow unit enabled. Undo it afterwards with
`sudo systemctl disable --now azazel-edge-netflow-receiver`.

Two cautions when SNMP targets are set:

- `sudo SNMP_TARGETS=… installer/internal/install_sensors.sh` leaves the
  community on the installer's command line (visible to other local users
  while it runs) and in the shell history. Read the value without echo
  first (`read -rs SNMP_TARGETS && export SNMP_TARGETS`) and pass it with
  `sudo --preserve-env=SNMP_TARGETS` (or `sudo -E`) instead.
- Running `install_sensors.sh` again without `SNMP_TARGETS` rewrites
  `/etc/default/azazel-edge-sensors` without the targets, so targets written
  there by hand are lost; give the same `SNMP_TARGETS` again.

```bash
# SVC-12 (optional): the NetFlow sensor unit
cd ~/Azazel-Edge && sudo ENABLE_NETFLOW=1 ENABLE_SERVICES=1 installer/internal/install_sensors.sh
systemctl show -p ActiveState -p Result -p User azazel-edge-netflow-receiver
```

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| SVC-01 | Units active | `systemctl is-active azazel-edge-control-daemon azazel-edge-core azazel-edge-web azazel-edge-ai-agent azazel-edge-suricata azazel-edge-opencanary nginx ntfy` | `active` for each | | #483 |
| SVC-02 | Accounts of the main processes | script above | control-daemon `root`, core `root`, web `azazel-web`, ai-agent `azazel-agent` | | #475, #476 |
| SVC-03 | Nothing failed | `systemctl --failed` | `0 loaded units listed` | | #483, #486 |
| SVC-04 | Sandbox exposure | `systemd-analyze security azazel-edge-web azazel-edge-ai-agent` | Record the scores (containers showed 3.1 OK offline; the device value is new) | | #475, #476 |
| SVC-05 | No restart loop | command above | `NRestarts=0` for each | | #483 |
| SVC-06 | Accounts | `getent passwd azazel-web azazel-agent azazel-sensor` and `id azazel-web` | `azazel-web` and `azazel-agent` exist with a nologin shell; `azazel-web` is in `azazel-control`; `azazel-sensor` only if SNMP/NetFlow was enabled | | #475, #476, #480 |
| SVC-07 | TUI without permission | as `<pi-user>` (not in `azazel-control`): `azazel-edge-tui --curses` | No traceback; the View shows `(control.sock: permission denied)` and the evidence names the `azazel-control` group; quitting exits 0. `sudo azazel-edge-tui --curses` shows the live state | | #490, #479 |
| SVC-08 | Web UI as `azazel-web` | dashboard (2.7): status, Wi-Fi scan, SoT edit, M.I.O. question (`/api/ai/ask`) | Each answers; a failure is shown as a failure, never as success | | #475, #476, #479 |
| SVC-09 | P0 relay from the real core | steps 1 and 2 above (step 2 only after step 1 passed) | Step 1: `AZAZEL_DEFENSE_ENFORCE=false` and `AZAZEL_DEFENSE_DRY_RUN=true` in the unit, nothing from the environment file. Step 2: `core-decision-audit.jsonl` grows and a P0 entry is added to `p0-alert-queue.jsonl`. Which scenario gives a P0 (enforcement-bearing or SOC-critical) decision on the device is **(to confirm)**; none: `N/A` as above | | #476 |
| SVC-10 | ntfy SSE through the token file | commands above | Terminal 2 prints `200`; terminal 1 shows an event carrying `first-run test` | | #475, #485 |
| SVC-11 | OpenCanary/Suricata display | command above | `opencanary`, `suricata` and `ntfy` are `ON`; `container_check` is `not_checked` (the Web UI no longer asks Docker) | | #475 |
| SVC-12 | SNMP/NetFlow (optional) | commands above (not installed by default: `ENABLE_SNMP`/`ENABLE_NETFLOW` are `0`, and `install_sensors.sh` enables units only with `ENABLE_SERVICES=1`) | `User=azazel-sensor`; `ActiveState=inactive`, `Result=success`: the module has no entry point and exits 0 at once, so **no sensor runs** (section 5) | | #480, #483 |

### 3.2 Sockets, directories and secrets (#471 stages 1–2)

```bash
sudo stat -c '%a %U:%G %n' /run/azazel-edge /run/azazel-edge/control.sock \
  /run/azazel-edge-ai /run/azazel-edge-ai/ai-bridge.sock \
  /run/azazel-edge-agent /run/azazel-edge-agent-query /run/azazel-edge-agent-query/agent-query.sock \
  /var/log/azazel-edge/ai /var/lib/azazel-edge-agent \
  /run/azazel-edge-web /var/lib/azazel-edge-web /var/log/azazel-edge-web /etc/azazel-edge
sudo stat -c '%a %U:%G %n' /etc/azazel-edge/web_token.txt /etc/azazel-edge/ntfy.token
sudo stat -c '%a %U:%G %n' /etc/azazel-edge/internal-ap.psk
```

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| SOCK-01 | Control socket | first `stat` above | `/run/azazel-edge` `750 root:azazel-control`; `control.sock` `660 root:azazel-control` | | #475 |
| SOCK-02 | Agent sockets | first `stat` above | `/run/azazel-edge-ai` `700 azazel-agent:azazel-agent`, `ai-bridge.sock` `600 azazel-agent:azazel-agent`; `/run/azazel-edge-agent-query` `2750 azazel-agent:azazel-web`, `agent-query.sock` `660 azazel-agent:azazel-web` | | #476 |
| SOCK-03 | Agent and Web UI directories | first `stat` above | `/run/azazel-edge-agent` and `/var/log/azazel-edge/ai` `2750 azazel-agent:azazel-web`; `/var/lib/azazel-edge-agent` `750 azazel-agent:azazel-agent`; the three `azazel-edge-web` directories `750 azazel-web:azazel-web`; `/etc/azazel-edge` `750 root:azazel-web` on a fresh install | | #475, #476 |
| SOCK-04 | Others cannot reach the control socket | as `<pi-user>`: `ls /run/azazel-edge/` | `Permission denied` | | #475 |
| SOCK-05 | Tokens | second `stat` above | `640 root:azazel-web` (and `/etc/azazel-edge/mattermost-command-token` the same once Mattermost is set up) | | #475, #485 |
| SOCK-06 | Root-only secrets | third `stat` above; after 2.8 also `/etc/azazel-edge/mattermost-db.env` and `/etc/azazel-edge/mattermost-credentials.env` | `600 root:root` | | #485, #486 |
| SOCK-07 | ntfy refuses anonymous reads | `curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8081/azg-alert-critical/json?poll=1'` | `401` or `403` | | #485 |

### 3.3 Internal AP

```bash
# AP-05: the keyfile of the AP profile
nmcli -t -f NAME,FILENAME con show
sudo nmcli -g 802-11-wireless-security.psk-flags con show lan-wlan0-ap
# AP-06: the passphrase is in neither the install log nor this boot's journal
sudo python3 - ~/install-first-run.log <<'EOF'
import subprocess, sys
psk = open("/etc/azazel-edge/internal-ap.psk", "rb").read().strip()
log = open(sys.argv[1], "rb").read()
journal = subprocess.run(["journalctl", "-b", "-o", "cat"], capture_output=True).stdout
print("in install log:", psk in log, "| in journal:", psk in journal)
EOF
```

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| AP-01 | Radio not blocked | `rfkill list` | Wireless LAN: `Soft blocked: no`, `Hard blocked: no` | | #486 |
| AP-02 | Country | `sudo raspi-config nonint get_wifi_country` | The code from 1.3 | | #486 |
| AP-03 | AP up, also after reboot | `nmcli -t -f NAME,DEVICE con show --active` | `lan-wlan0-ap:wlan0` and `lan-br0:br0`; after the reboot `systemctl show -p Result azazel-internal-apply` is `Result=success` (a oneshot unit: `inactive` once it has run is normal) | | #486 |
| AP-04 | PSK file | third `stat` in 3.2 | `600 root:root`, 20 characters when generated (do not print it; `sudo wc -c` gives 21 with the newline) | | #486 |
| AP-05 | Keyfile | commands above | The file named for `lan-wlan0-ap` is `600 root:root` (`sudo stat`); `psk-flags` starts with `0` (system-owned) | | #486 |
| AP-06 | PSK never printed | script above | `in install log: False` and `in journal: False` | | #486 |
| AP-07 | A client joins | On a LAN laptop, join `AP_SSID` with the passphrase from `sudo cat /etc/azazel-edge/internal-ap.psk` (read it on the console) | WPA2 association, a DHCP address in `172.16.0.101`–`172.16.0.200`, `https://172.16.0.254/` reachable | | #486 |
| AP-08 | Old default refused | `sudo AP_PSK=ChangeMe1234 WIFI_COUNTRY=<CC> AP_SSID='<your SSID>' installer/internal/install_internal_network.sh` | Stops with `ERROR: the AP passphrase is the old built-in default; …` before changing anything (the AP stays up) | | #486 |

### 3.4 Uplink Wi-Fi (USB Wi-Fi adapter)

Connect from the dashboard's Wi-Fi panel or the `/touch` Network tab (both
`POST /api/wifi/connect`, operator token). Never put a passphrase on a command
line. Before each connect, start this watcher in a second console; it asks
for the passphrase without echo and looks for it in every process's command
line for 60 s:

```bash
sudo python3 - <<'EOF'
import getpass, glob, time
secret = getpass.getpass("passphrase to look for: ").encode()
hits, end = set(), time.time() + 60
while time.time() < end:
    for path in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            if secret in open(path, "rb").read():
                hits.add(path)
        except OSError:
            pass
    time.sleep(0.05)
print("found in:", sorted(hits) if hits else "none")
EOF
```

After each connect:

```bash
nmcli -t -f DEVICE,TYPE,STATE,CONNECTION dev
nmcli -t -f NAME,DEVICE con show --active
nmcli -t -f NAME,UUID con show
```

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| WIFI-01 | WPA2-PSK, new | connect with passphrase | Connected on the USB Wi-Fi interface; `lan-wlan0-ap` still active on `wlan0`; watcher prints `found in: none` | | #478, #486 |
| WIFI-02 | WPA3-SAE only, new | as WIFI-01 | as WIFI-01 | | #478 |
| WIFI-03 | WPA2/WPA3 transition, new | as WIFI-01 | as WIFI-01 | | #478 |
| WIFI-04 | Saved profile, no passphrase | disconnect, then connect to each of the three as a saved network | Reconnects without a passphrase; the AP stays up | | #478 |
| WIFI-05 | Saved profile, new passphrase | change one AP's passphrase, connect with the new one | Connected; no `azazel-wifi-pending-…` profile left in `nmcli … con show`; watcher `none` | | #478 |
| WIFI-06 | Saved profile, wrong passphrase | connect with a wrong passphrase | Fails; the saved profile still connects with the right one afterwards; no pending profile left | | #478 |
| WIFI-07 | 802.1X refused | connect to the 802.1X SSID | Refused with `802.1X (WPA-Enterprise) networks are not supported here; set the profile up with NetworkManager directly`; no new profile | | #478 |
| WIFI-08 | No USB Wi-Fi | unplug the USB Wi-Fi adapter, scan | `No wireless interface for the uplink: …`; the AP stays up; the control daemon logs `wifi sensor: not scanning: …` once | | #486 |
| WIFI-09 | Disconnect never takes the AP | with `AZAZEL_UP_IF` unset: `sudo sed 's/^/X-Auth-Token: /' /etc/azazel-edge/web_token.txt` piped into `curl -sk -H @- -w '\n%{http_code}\n' -X POST https://127.0.0.1/api/action/disconnect` | Body with `uplink_interface_serves_internal_lan:wlan0`, then `500`; the AP stays up. Then (optional, cuts the uplink; from the LAN or console) set `AZAZEL_UP_IF=<WAN_IF>` in `/etc/default/azazel-edge-security`, `sudo systemctl restart azazel-edge-control-daemon`, repeat: `<WAN_IF>` goes down; restore with `sudo ip link set <WAN_IF> up` | | #475, #486 |
| WIFI-10 | Japanese locale (optional) | with the system locale `ja_JP.UTF-8`, repeat WIFI-01 | as WIFI-01 | | #480 |

The token goes to curl on stdin (`-H @-`), not on its command line; the
`sed` output is piped (`sudo sed … | curl …`).

### 3.5 EPD

```bash
# EPD-02
sudo /opt/azazel-edge/venv/bin/python -c 'import spidev, gpiozero, lgpio, gpiozero.pins.lgpio; print("ok")'
# EPD-03 (gpiozero internal API; record the error if it has none)
sudo /opt/azazel-edge/venv/bin/python -c 'from gpiozero import Device; f = Device._default_pin_factory(); print(type(f).__name__); f.close()'
# EPD-04: force one draw (the refresh draws only when the frame changed)
sudo rm -f /run/azazel-edge/epd_last_render.json
sudo systemctl start azazel-edge-epd-refresh.service
systemctl show -p Result azazel-edge-epd-refresh.service
journalctl -u azazel-edge-epd-refresh -b --no-pager -n 20
systemctl list-timers azazel-edge-epd-refresh.timer
```

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| EPD-01 | SPI device | `ls -l /dev/spidev0.0` | Present (after the reboot in 2.6) | | #486 |
| EPD-02 | GPIO modules in the venv | command above | `ok` | | #486 |
| EPD-03 | Pin factory | command above | Record the class name. `LGPIOFactory` is expected (lgpio drives the Pi 5's RP1); another factory or an error is a finding. The check uses a gpiozero internal function **(to confirm that it is the right probe)** | | #486 |
| EPD-04 | Draw | commands above | The panel redraws; `Result=success`; timer listed with a next run | | #486 |
| EPD-05 | Failure is visible, timer continues | power off, disconnect the EPD, boot, run EPD-04 again | `Result=exit-code`: the refresh exits 1 both when the renderer fails and when it gives up after 45 s, and the journal says which (`azazel-edge-epd-refresh: ERROR: EPD renderer exited with status …` or `… timed out after 45 s …`); `Result=timeout` would mean the unit's own 60 s limit was hit (a finding). `systemctl list-timers` still shows the next run. Which of the two the missing panel gives is **(to confirm)**. Power off and reconnect afterwards | | #486 |
| EPD-06 | Waveshare board detection | `grep -c Raspberry /proc/cpuinfo` | `1` or more (the Waveshare `epdconfig` detects the Pi from `/proc/cpuinfo`) | | #486 |

### 3.6 SSH

```bash
systemctl is-enabled ssh.service ssh.socket
systemctl show -p Restart -p RestartUSec ssh.service
sudo sshd -T | grep -i listenaddress
sudo ss -Hltnp 'sport = :22'
# SSH-04, after a reboot
journalctl -b -u ssh --no-pager
systemctl show -p ActiveEnterTimestampMonotonic ssh.service
```

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| SSH-01 | Socket vs service | `systemctl is-enabled ssh.service ssh.socket` | `enabled` / `disabled`. Record what the fresh image had before the install (2.1) | | #486 |
| SSH-02 | Drop-in | `systemctl cat ssh.service` and `systemctl show` above | The drop-in `azazel-edge-listen.conf` is listed; `Restart=on-failure`, `RestartUSec=5s` | | #486 |
| SSH-03 | Listen scope | `sshd -T` and `ss` above | `listenaddress 172.16.0.254:22` only; sshd listens on `172.16.0.254:22` only | | #486 |
| SSH-04 | Late `br0` address at boot | reboot, then the journal above | If sshd started before `br0` had its address: `Cannot bind any address` followed by a restart 5 s later and `active`; SSH from the LAN works within seconds to tens of seconds. Record the time | | #486 |
| SSH-05 | Existing session survives the install | the LAN SSH session used during a re-run of the installer | Not dropped | | #486 |

### 3.7 WAN exposure (#485, #488; #489 off)

On the device, list every listener first:

```bash
sudo ss -Hltunp
```

Expected listeners: `0.0.0.0:80` and `0.0.0.0:443` (nginx), `0.0.0.0:8065`
(nginx, only after 2.8), `127.0.0.1:8081` (ntfy), `127.0.0.1:8084` (Web UI),
`127.0.0.1:18065` (Mattermost, after 2.8), `127.0.0.1:11434` (Ollama),
`127.0.0.1:18080` and `127.0.0.1:12222` (OpenCanary), `172.16.0.254:22`
(sshd), dnsmasq on `br0` (53, 67), avahi on 5353/udp and on one random high UDP port (its unicast query socket). Anything else on
`0.0.0.0`, `*` or `[::]` is a finding: note the port and process (not the
addresses) in the result.

From the **upstream test host** (replace `<WAN-ADDR>`):

```bash
curl -s  -o /dev/null -w '%{http_code}\n' --max-time 5 http://<WAN-ADDR>/health
curl -sk -o /dev/null -w '%{http_code}\n' --max-time 5 https://<WAN-ADDR>/health
curl -s  -o /dev/null -w '%{http_code}\n' --max-time 5 http://<WAN-ADDR>:8065/
for p in 8081 22 8084 11434 18065; do nc -vz -w 3 <WAN-ADDR> "$p"; done
dig +time=2 +tries=1 -p 5353 @<WAN-ADDR> <hostname>.local
```

From a **LAN client** (wired or the internal AP):

```bash
curl -s  -o /dev/null -w '%{http_code}\n' --max-time 5 http://172.16.0.254/health
curl -sk -o /dev/null -w '%{http_code}\n' --max-time 5 https://172.16.0.254/health
curl -s  -o /dev/null -w '%{http_code}\n' --max-time 5 http://172.16.0.254:8065/
nc -vz -w 3 172.16.0.254 22
dig +time=2 +tries=1 -p 5353 @172.16.0.254 <hostname>.local
```

| ID | Check | From | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| WAN-01 | 80/tcp | upstream | `403` (nginx deny) | | #488 |
| WAN-02 | 443/tcp | upstream | `403` | | #488 |
| WAN-03 | 8065/tcp (Mattermost) | upstream | `403` after 2.8; connection refused without Mattermost | | #485 |
| WAN-04 | 8081, 8084, 11434, 18065/tcp | upstream | Connection refused (loopback only) | | #480, #485 |
| WAN-05 | 22/tcp | upstream | Connection refused or timeout | | #486 |
| WAN-06 | 5353/udp | upstream | No answer (timeout) | | #488 |
| WAN-07 | 2055/udp (NetFlow) | device: `sudo ss -Hlunp 'sport = :2055'` | Nothing listening (the receiver has no entry point; see section 5), or `172.16.0.254:2055` only if NetFlow was enabled | | #488 |
| WAN-08 | LAN still served | LAN client | `/health` over http `301`, over https `200`; 8065 `200` after 2.8; 22 open; 5353 answers | | #485, #488 |
| WAN-09 | Weak host model (informative) | upstream host with a route `172.16.0.0/24 via <WAN-ADDR>` | 22/tcp on `172.16.0.254` is reachable while #489 is off (known; nginx still answers 403). Record; #489 is the layer that closes it | | #488, #489 |
| WAN-10 | Certificate SAN | device: `sudo openssl x509 -in /etc/azazel-edge/tls/webui.crt -noout -ext subjectAltName` | `172.16.0.254`, the host name, `Azazel-Edge.local` (the host name with `.local`), `localhost` and `127.0.0.1`; not the WAN address (do not paste the output). A device installed before this change keeps its old certificate until it is issued again: re-run the installer, or `sudo /opt/azazel-edge/install_local_ca.sh` and then `sudo systemctl reload nginx` (the CA is kept) | | #488, #477 |

### 3.8 Mattermost (only if used; after 2.8)

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| MM-01 | amd64 emulation on 16K pages | `getconf PAGESIZE`; `ls /proc/sys/fs/binfmt_misc/` | Record the page size; a `qemu-x86_64` entry is present | | #485 |
| MM-02 | Container runs | `sudo docker ps --filter name=azazel-edge-mattermost`; `sudo docker logs --tail 50 azazel-edge-mattermost` | `Up`, not restarting. If it exits, record the log tail (no secrets are in it, but check) and stop here: whether to keep Mattermost on by default is an owner decision | | #485 |
| MM-03 | API on loopback | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18065/api/v4/system/ping` | `200` | | #485 |
| MM-04 | LAN access through nginx | LAN browser: `http://172.16.0.254:8065` | Login page; log in as `azazelops` with the password from `/etc/azazel-edge/mattermost-credentials.env` (read on the device) | | #485 |
| MM-05 | Slash command | in the `soc-noc` channel: `/mio <question>` (alias `/azops`) | An answer from M.I.O.; not `403` (the callback comes from `172.31.250.0/24`, admitted by nginx) | | #485, #488 |
| MM-06 | Docker network | `sudo docker network inspect security_mattermost` | Subnet `172.31.250.0/24` (network `mattermost` of the compose project `security`) | | #488 |

### 3.9 Touch Display 2 (`/touch`)

Follow [TOUCH_CONSOLE_KIOSK.md](TOUCH_CONSOLE_KIOSK.md) (kiosk in the desktop
user's session, `http://127.0.0.1:8084/touch?lang=ja`, token entered on the
Settings tab; never `?token=` on `/touch`).

```bash
# TCH-05: Web UI CPU time over 5 minutes, panel untouched, then while touching
systemctl show -p CPUUsageNSec azazel-edge-web
# ... wait 300 s ...
systemctl show -p CPUUsageNSec azazel-edge-web
# open state streams to the Web UI
sudo ss -Htn state established '( sport = :8084 )'
```

If `CPUUsageNSec` shows `[not set]` (CPU accounting off), sample
`top -b -n 1` for the `gunicorn` processes instead and note the method.

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| TCH-01 | Kiosk start | reboot with the autostart line in place | Chromium opens `/touch` full screen; the layout fits 1280x720 without scrolling | | #484 |
| TCH-02 | Touch | tap each tab, scan Wi-Fi | Responds to touch (pointer events); Japanese text renders (`fonts-noto-cjk`) | | #484 |
| TCH-03 | Press and hold | Wi-Fi connect / runbook execute | A tap does nothing; 1.2 s hold runs it; lifting early cancels | | #484 |
| TCH-04 | Wake from blanking | let the screen blank (`swayidle`/`wlopm`), touch | The screen wakes; that touch starts no operation | | #484 |
| TCH-05 | SSE load | commands above | After 5 min untouched no stream connection is open; record CPU % = delta ns / 3e11 × 100, untouched and in use | | #484 |
| TCH-06 | Stale state | stop the control daemon briefly (`sudo systemctl stop azazel-edge-control-daemon`, then start) | Marked STALE/UNVERIFIED, never green; recovers after start | | #484, #479 |
| TCH-07 | `/touch` through nginx (HTTPS) | LAN browser with the local CA trusted: `https://172.16.0.254/touch`, keep touching for more than 2 minutes | The state keeps updating every second past nginx's 120 s read timeout (the stream sends data every second and the app sets `X-Accel-Buffering: no`); the header does not drop to periodic updates while in use | | #484 |

### 3.10 Selftest, Suricata and watchdog

The installer runs the selftest once (`[all/8]`) and installs it as
`/usr/local/bin/azazel-edge-selftest` with a timer (`[all/9]`, aarch64 only):
5 minutes after every boot and quarterly.

```bash
sudo azazel-edge-selftest; echo "exit=$?"
sudo cat /var/log/azazel-edge/selftest_latest.json
# ST-06: the timer and its service
systemctl list-timers azazel-edge-selftest.timer
systemctl show -p Result azazel-edge-selftest.service
journalctl -u azazel-edge-selftest -b --no-pager -n 20
sudo suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/azazel-lite.rules -l "$(mktemp -d)"; echo "exit=$?"
# ST-05
ls -l /dev/watchdog*
sudo dmesg | grep -i -E 'bcm2835-wdt|watchdog'
systemctl show -p RuntimeWatchdogUSec
```

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| ST-01 | Selftest exit | first command | `exit=0`; the printed list has no failure | | #487 |
| ST-02 | Known warnings | JSON | `"failures": []`; warnings expected today: `config_checksums_missing` (nothing creates `/etc/azazel-edge/.config_checksums`; section 5) and `python_smoke_tests_missing` | | #487 |
| ST-03 | SD write test | JSON | No `sd_write_test_skipped:not_on_sd:…` on an ext4 root; `sd_write_speed_low:…` only if the medium is slow (record the value) | | #478, #487 |
| ST-04 | Suricata rules load | last command | `exit=0`; 13 active rules (sid 9901211 is disabled: Suricata 7 cannot match ARP) | | #481 |
| ST-05 | Hardware watchdog (optional setting) | commands above | `/dev/watchdog` exists and the kernel log names `bcm2835-wdt` (driver message **(to confirm)**); `RuntimeWatchdogUSec=0` (Azazel-Edge does not enable it). Turning it on is optional, per [PHYSICAL_SETUP_GUIDE.md](PHYSICAL_SETUP_GUIDE.md) §4 | | #486 |
| ST-06 | Selftest timer | ST-06 commands, after a reboot (the timer runs it 5 min after boot) | The timer is listed with a next run; after it ran, `Result=success` (a critical finding makes the oneshot unit `failed`, visible in `systemctl --failed`) | | #487 |

### 3.11 HIL bridge (from the Mac on the LAN)

Prerequisites: the Mac is on the LAN, its checkout is on `main`, the Pi's host
key is verified (compare `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on
the console with the first `ssh <pi-user>@172.16.0.254`), and
`sudo -n true` works for `<pi-user>` (needed for `nft list ruleset`;
otherwise the nft observation is `unobserved` and the outcome exit 3).
[R0_PI_HIL_BRIDGE.md](R0_PI_HIL_BRIDGE.md) is the reference.

```bash
tools/hil/azazel-hil --target 172.16.0.254 --user <pi-user> prepare --no-update-repo
tools/hil/azazel-hil --target 172.16.0.254 --user <pi-user> full; echo "exit=$?"
```

`full` exit status: `0` completed; `1` a test failed; `2` a stage stopped
(for example the preparation gate); `3` incomplete (an `unobserved`
observation, a missing or skipped required test — **an uninstalled model
gives 3** — or no events); `255` SSH/SCP failure.

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| HIL-01 | Readiness | `prepare --no-update-repo` | Exit 0; a refusal names the real reason (not on `main`, uncommitted changes) | | #482, #490 |
| HIL-02 | Full run | `full` | Exit `0`. Exit `3` with the models from `[ai/4]` installed is a finding | | #482, #372, #408 |
| HIL-03 | Interpreter | report | `/opt/azazel-edge/venv/bin/python` chosen, with the reason | | #482 |
| HIL-04 | Ollama | report | Version and both models (`qwen3.5:0.8b`, `qwen3.5:2b`) measured through `127.0.0.1:11434` | | #482 |
| HIL-05 | Read-only observations | report | `tc` and `nft` observed (not `unobserved`); a missing command is `unobserved`, not `failed` | | #482, #490 |
| HIL-06 | Restart (optional, maintenance window) | `tools/hil/azazel-hil --target 172.16.0.254 --user <pi-user> --session <id> run --allow-service-restart --service azazel-edge-core` (`<id>`: the session `full` printed; `<pi-user>` needs non-interactive sudo for `systemctl restart`) | The restart is recorded and the unit is `active` within 15 s | | #482 |

### 3.12 R0 measurements (#408, #372)

```bash
systemd-analyze
systemd-analyze critical-chain azazel-edge-web.service
systemctl show -p ActiveEnterTimestampMonotonic azazel-edge-web azazel-edge-control-daemon azazel-edge-core
vcgencmd measure_temp
vcgencmd get_throttled
vcgencmd pmic_read_adc
free -m
df -h /
sudo du -sh /var/log/azazel-edge /var/lib/docker
```

| ID | Measurement | How | Record | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| R0-01 | Boot time | `systemd-analyze` after a cold boot | Total and userspace times | | #408 |
| R0-02 | Service ready times | `ActiveEnterTimestampMonotonic` (µs since boot) | Web UI, control daemon, core | | #408 |
| R0-03 | Power | inline USB-C meter: idle 5 min after boot; during the HIL `full` run (inference); `vcgencmd pmic_read_adc` as a supplement (board rails only, not USB devices; reading it is **(to confirm)**) | W idle / W peak; compare with [POWER_PLAYBOOK.md](POWER_PLAYBOOK.md) §1 | | #408, #372 |
| R0-04 | Install duration | start/end times of 2.5 | minutes, and how long `[11.8/16]` took | | #408 |
| R0-05 | Thermal and throttling | `vcgencmd measure_temp`, `vcgencmd get_throttled` during and after the HIL run | Peak °C; `throttled=0x0` (anything else: record the value) | | #372 |
| R0-06 | Memory and disk | `free -m`, `df -h /`, `du` above | Used/available, swap; disk used after install and after the HIL run | | #372 |
| R0-07 | HIL profile | the HIL report | Inference latency, memory before/after, observer timing (as reported) | | #372, #408 |

### 3.13 Host firewall trial (#489, draft, optional)

**Precondition: the #489 branch contains the current `main`.** #489 has been
rebased onto `main` (after #490). When `main` moves on after that (this
checklist itself came later, as #491), the branch may no longer contain it:
check on the device before the FW rows. If it does not, ask for #489 to be
rebased again; until then every FW row is `N/A (#489 not rebased)`.

**If #489 is merged** (the `main` checkout of 2.3 has
`installer/internal/azazel-host-firewall`): this precondition, the fetch below
and `git switch try-489` do not apply; run the stages from that `main`
checkout (the host firewall is still off until `--enable-host-firewall`).

```bash
cd ~/Azazel-Edge
git fetch origin main pull/489/head:try-489
git merge-base --is-ancestor origin/main try-489 && echo rebased || echo "not rebased: FW rows are N/A"
```

The rows run in this order: FW-01 (enable and keep), then FW-02–FW-05 and
FW-07–FW-12 with the rules **enabled**, then FW-06 (automatic rollback) last,
then the rollback below. Before each stage, `sudo azazel-host-firewall status`
must print `state=enabled` and `loaded=yes`; if it does not, the rows of that
stage are `N/A` with the status line as the reason.

**Stage 1 (FW-01): enable and keep.** Only after 3.1–3.12, on the
**console** (a terminal, no SSH session from the uplink):

```bash
git switch try-489
sudo WIFI_COUNTRY=<CC> AP_SSID='<your SSID>' WAN_IF=<WAN_IF> installer/internal/install_internal_network.sh --enable-host-firewall
# the installer loads the rules on trial and asks:
#   Host firewall on trial. Type 'yes' within 100 s to keep it (anything else, or nothing, takes it off):
# type: yes   (the WAN checks of FW-02 come after this, without a time limit)
sudo azazel-host-firewall status
```

The installer asks only when stdin is a terminal and no SSH session came in
through the uplink; anything other than `yes`, or no answer within 100 s,
runs `disable` (state removed, `Host firewall not kept.`). Without a terminal
it prints a NOTICE and the helper's timer takes the rules off after 120 s
unless `sudo azazel-host-firewall confirm` is run from a **new** connection
(console or a new LAN SSH session; an open session survives as an
established connection).

**Stage 2 (FW-02–FW-05, FW-07–FW-12): with the rules enabled.**

```bash
sudo azazel-host-firewall status   # state=enabled, loaded=yes (again after the FW-05 reboot)
# FW-04: on the device, after half the DHCP lease time
journalctl -u NetworkManager -b --no-pager | grep -i -E 'dhcp4|dhcp6'
ip -6 addr show dev <WAN_IF>
# FW-09: docker networks and the FORWARD policy docker set
sudo docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' $(sudo docker network ls -q)
sudo iptables -S FORWARD | head -n 1
# FW-11 (only if nftables.service is enabled; from the console, see the row)
systemctl is-enabled nftables
sudo systemctl reload nftables
sudo nft list tables
sudo systemctl start azazel-internal-apply   # only if "ip azazel_internal" is missing
```

**Stage 3 (FW-06): automatic rollback, last.** stdin must not be a terminal,
so the installer does not ask:

```bash
sudo azazel-host-firewall disable
sudo WIFI_COUNTRY=<CC> AP_SSID='<your SSID>' WAN_IF=<WAN_IF> installer/internal/install_internal_network.sh --enable-host-firewall </dev/null
sudo azazel-host-firewall status   # state=pending while the timer runs
# wait 120 s, then
sudo azazel-host-firewall status
```

| ID | Check | Command | Expected | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| FW-01 | Kept by the installer prompt | stage 1 (`yes`) | `status` prints `state=enabled`, `loaded=yes`, `remote_access=off` | | #489 |
| FW-02 | WAN closed | stage 2: repeat 3.7 from the upstream host | 80/443/8065/8081/22 not reachable (time out), 5353 no answer; WAN-09 no longer reachable | | #489 |
| FW-03 | LAN unchanged | stage 2: repeat WAN-08, AP-07, MM-05 (wired LAN and internal AP: Web UI, SSH, DHCP/DNS, mDNS) | As before | | #489 |
| FW-04 | Uplink DHCP and IPv6 | stage 2 commands; IPv6 only if the uplink has it | The DHCPv4 lease is renewed; RA/SLAAC (and DHCPv6, if the uplink uses it) addresses kept | | #489 |
| FW-05 | Boot order | stage 2: reboot; `systemctl show -p ActiveEnterTimestampMonotonic azazel-host-firewall NetworkManager`; `systemctl --failed`; `status` again | `azazel-host-firewall` has the smaller timestamp (active before NetworkManager); nothing failed; still `state=enabled` | | #489 |
| FW-07 | PMTU | stage 2: download a file of 100 MB or more over HTTPS from a LAN client (through the NAT) and on the device | Completes without stalling | | #489 |
| FW-08 | Containers | stage 2: `sudo docker exec azazel-edge-ollama ollama pull qwen3.5:0.8b` (outbound); MM-05 (container to host) | Both work | | #489 |
| FW-09 | Docker networks and FORWARD | stage 2 commands | Every docker network in 172.17.0.0/16–172.31.0.0/16; record the FORWARD policy line (docker usually sets `-P FORWARD DROP`) | | #489 |
| FW-10 | Remote access pair | stage 2: re-run the installer with `ALLOW_EXTERNAL_SSH=true` (and the other values), then without it; `sudo DEVICE_HOSTNAME=<hostname> MODE=open installer/internal/set_dev_remote_access.sh`, then `MODE=close` | `ALLOW_EXTERNAL_SSH=true` or `MODE=open`: 22/tcp and 5353/udp reachable from the upstream host, 8081 still not; without it / `MODE=close`: closed again. Side effects of `set_dev_remote_access.sh`: it sets the host name to `DEVICE_HOSTNAME` (default `Azazel-Edge`), rewrites `/etc/ssh/sshd_config` (a `sshd_config.bak.<time>` copy is kept; `open` removes every `ListenAddress`, `close` puts `ListenAddress 172.16.0.254` back) and restarts ssh, and it prints the uplink address (do not paste its output). Run it from the console. | | #489 |
| FW-11 | `nftables.service` reload | stage 2 commands, only if `systemctl is-enabled nftables` is `enabled`, from the **console** | `inet azazel_host` is listed again. A reload also runs `flush ruleset`, which removes `ip azazel_internal` (the LAN NAT): LAN clients lose the uplink until it is back. If `nft list tables` lacks it, run `sudo systemctl start azazel-internal-apply`, check again, and record it as a finding. If nftables is not enabled: `N/A` (do not start it: the same flush, known in #489) | | #489 |
| FW-12 | Enforcement tables | stage 2: `sudo nft list tables` | `N/A` unless the owner has created `table inet azazel_edge` and enabled enforcement (section 5); then the core's isolate/redirect rules and `inet azazel_host` must both stay | | #489, #480 |
| FW-06 | Automatic rollback (last) | stage 3 (`</dev/null`, or an SSH session without a pty) | The installer prints the NOTICE (no question); after 120 s `status` prints `state=rolled-back`, `loaded=no`; the WAN results are as in 3.7 again | | #489 |

Rollback (always, at the end):

```bash
sudo azazel-host-firewall disable
sudo azazel-host-firewall status   # state=off, loaded=no
git switch main
sudo WIFI_COUNTRY=<CC> AP_SSID='<your SSID>' WAN_IF=<WAN_IF> installer/internal/install_internal_network.sh
sudo nft list tables               # no "inet azazel_host"; "ip azazel_internal" present
```

The helper and its units stay installed after the rollback; with the state
off they load nothing at boot. Undo FW-10 if it was left open
(`MODE=close`).

## 4. Recording results and collecting failures

What may go into an issue (#408, #372, #471, #477, or a new one):

- The tables of section 3 with IDs, results and short notes; the OS image
  name, kernel version, page size, RAM size; the R0 numbers.
- **Never**: passphrases, tokens, passwords, the content of any file under
  `/etc/azazel-edge` (other than modes and owners), private keys, IP
  addresses other than the fixed LAN ones, MAC addresses, serial numbers,
  host names, SSIDs of real networks, boot IDs, HIL session IDs, image
  digests and other hashes or identifiers. Redact them before pasting; the
  HIL report is redacted for secrets but not for addresses.
- Mark container or VM observations as such; they are not device results.

When a check fails, collect on the device and keep locally (review and redact
before sharing anything):

```bash
systemctl --failed
systemctl status <unit> --no-pager
journalctl -b -u <unit> --no-pager -n 200
sudo cat /var/log/azazel-edge/selftest_latest.json
nmcli dev; nmcli -t -f NAME,DEVICE con show --active; rfkill list
ip -br addr; ip route
sudo ss -Hltunp
vcgencmd get_throttled
sudo dmesg | tail -n 100
```

plus the install log (`~/install-first-run.log`) and, for the HIL bridge,
the session directory under `artifacts/hil/` on the Mac.

## 5. Open questions for the owner

Not decided in code; each needs the owner's decision. This run may give
evidence for some of them.

| Topic | State | Where |
| --- | --- | --- |
| Creating `table inet azazel_edge` | No installer creates it; with enforcement enabled, `nft insert` fails and nothing is applied. Creating it (and choosing hooks/priorities) changes what enforcement does. | #480, #477 |
| `redirect_policy` and OpenCanary ports | OpenCanary SSH listens on 12222; the core's honeypot default is 2222 and the relative `config/redirect_policy.yaml` is not loaded on the device. | #479, privilege-inventory §12 |
| Writer of `decision-explanations.jsonl` | The Web UI reads v2 explanations from `/var/log/azazel-edge`; no live service writes them. | #479, privilege-inventory §12 |
| NetFlow/SNMP entry points | `azazel_edge.sensors.netflow_receiver` and `snmp_poller` have no `__main__`; the units exit 0 at once. | #483, #488 |
| ARP spoofing detection | Suricata 7 cannot match ARP; sid 9901211 is disabled and no other detector exists. | #481 |
| Mattermost on by default | `ENABLE_MATTERMOST=1` by default; the image is amd64-only and untested under emulation on a 16K-page kernel (3.8). | #485 |
| Host INPUT filter default | #489 is off by default (option B); turning it on by default is a separate decision after FW-01–FW-12. | #489 |
| Selftest `.config_checksums` | Nothing creates `/etc/azazel-edge/.config_checksums`, so the selftest always warns `config_checksums_missing`. | #487 |
| portal-viewer | `azazel-edge-portal-viewer.service` is started by the daemon but not shipped; there is no viewer code in this repository. | #479 |
| Status API on 8082 | No server in this repository answers on 8082; contain/release/stage_open go only there. | #479, privilege-inventory §12 |
