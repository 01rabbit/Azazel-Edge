# Physical Setup Guide

Last updated: 2026-10-27

This guide defines wiring, labeling, enclosure, and physical checks for reliable
field operation.

---

## 1. Connection Map (ASCII)

```
 [Power Source]
      |
      v
 [DC-DC / Adapter] ---> [UPS HAT (optional)]
      |
      v
 [Azazel-Edge Unit (Raspberry Pi 5)]
   |              |                 |               |
   |              |                 |               +--> [EPD Display] (SPI)
   |              |                 +--> on-board Wi-Fi (wlan0): internal AP
   |              +--> on-board Ethernet (eth0) --> [LAN Switch] (client segment)
   +--> USB Ethernet or USB Wi-Fi adapter ----------> [WAN Uplink Router]
```

Rules:
- Route power and data cables separately when possible.
- Use strain relief loops near each connector.

### 1.1 Required network hardware (Raspberry Pi 5)

The internal network installer (`installer/internal/install_internal_network.sh`)
bridges the on-board Ethernet (`eth0`) and the on-board Wi-Fi (`wlan0`, as the
internal AP) into the client segment `br0` (172.16.0.254/24). The Pi 5 has
only these two network interfaces and one radio, so **the uplink (WAN) needs a
third interface**: a USB Ethernet adapter or a USB Wi-Fi adapter.

- The installer finds the uplink from the default route before it builds
  `br0`. If the default route goes through `eth0` or `wlan0` (both become part
  of `br0`), it stops with an error and changes nothing: connect the USB
  adapter first (or set `WAN_IF=<its name>`).
- Wi-Fi scan and connect in the Web UI never use an interface that serves the
  internal LAN (AP mode, `br0` or a port of it). Without a USB Wi-Fi adapter
  they answer "No wireless interface for the uplink" instead of taking the
  internal AP down. A USB Ethernet uplink needs no Web UI step.
- The uplink disconnect action (`AZAZEL_UP_IF`, default `wlan0`) refuses an
  interface that serves the internal LAN. With a USB uplink, set
  `AZAZEL_UP_IF=<its name>` in `/etc/default/azazel-edge-security`.
- The name of a USB adapter (`eth1`, `wlan1`, or a predictable name such as
  `enx…`) is only known on the device: check it with `ip -br link` and
  `iw dev` before setting `WAN_IF` / `AZAZEL_UP_IF`.

### 1.2 Raspberry Pi OS settings the installers make

Only on Raspberry Pi OS (`raspi-config` and `/boot/firmware/config.txt` present):

- SPI is enabled for the EPD (`raspi-config nonint do_spi 0`). If
  `/dev/spidev0.0` is not there yet, reboot before the EPD can draw.
- The Wi-Fi country is required: Raspberry Pi OS keeps Wi-Fi blocked (rfkill)
  until one is set. Give it with `WIFI_COUNTRY=JP` (ISO 3166-1 alpha-2) or set
  it beforehand (`sudo raspi-config`); without either, the internal network
  installer stops before changing anything. It then unblocks Wi-Fi
  (`rfkill unblock wifi`). The internal AP not coming up is an error (the
  installer and `azazel-internal-apply.service` fail) instead of being ignored.
- The EPD GPIO libraries come from the Raspberry Pi repository
  (`python3-lgpio`, `python3-rpi-lgpio`, `python3-gpiozero`); `python3-rpi.gpio`
  does not drive the Pi 5 GPIO (RP1) and is no longer installed. On plain
  Debian (no Raspberry Pi repository) no GPIO library is installed and the EPD
  has no hardware output.

### 1.3 Internal AP passphrase

Leave `AP_PSK` unset: the installer generates a random passphrase and saves it
root-only (0600) in `/etc/azazel-edge/internal-ap.psk`, and a re-run keeps it.
It is never printed or logged. Read it with `sudo cat
/etc/azazel-edge/internal-ap.psk` and copy it to the STATUS_CARD kept with the
unit. A passphrase set with `AP_PSK` is saved there too; the old built-in
default `ChangeMe1234` is refused.

---

## 2. Label Templates

Print and attach labels on enclosure and cable ends:

```
+----------------------+
| PWR-IN               |
| 5V/5A MIN            |
+----------------------+

+----------------------+
| USB-UPLINK           |
| WAN / BACKHAUL       |
+----------------------+

+----------------------+
| ETH-LAN (eth0)       |
| CLIENT SEGMENT       |
+----------------------+

+----------------------+
| EPD                  |
| STATUS DISPLAY       |
+----------------------+
```

---

## 3. Storage and Boot Media Health

- Prefer industrial-grade SD or USB SSD boot media.
- Run selftest before every deployment:

```bash
sudo bin/azazel-edge-selftest
```

Expected:
- no critical media errors

---

## 4. Hardware Watchdog (optional, off by default)

Azazel-Edge does not enable a hardware watchdog. To have the board reset when
the system hangs, systemd can drive the SoC watchdog. Check on the device
first; a container or VM proves nothing here:

1. The driver is loaded and the device exists: `ls -l /dev/watchdog*` and
   `dmesg | grep -i -E 'bcm2835-wdt|watchdog'` (on the Pi 5 the watchdog is
   provided by the `bcm2835-wdt` driver). Do not continue without it.
2. Nothing else drives the watchdog (for example the `watchdog` package):
   only one process can open `/dev/watchdog`.
3. Put the settings in a drop-in, e.g. `/etc/systemd/system.conf.d/90-watchdog.conf`:

   ```ini
   [Manager]
   RuntimeWatchdogSec=15s
   RebootWatchdogSec=2min
   ```

   then `sudo systemctl daemon-reexec`, and confirm with
   `systemctl show -p RuntimeWatchdogUSec` and
   `journalctl -b | grep -i watchdog`.

Notes:
- The hardware limit of the timeout is driver-specific; systemd reports the
  value it actually set. Keep it well above the longest expected stall (heavy
  SD-card I/O, a Rust core build) or the board resets in normal operation.
- A reset by the watchdog is a power-cycle-like event: the encrypted secrets
  volume needs its passphrase again, and an unclean shutdown can damage the
  boot media.
- To undo, remove the drop-in and run `sudo systemctl daemon-reexec`.

## 5. Enclosure Recommendation

Minimum recommendation:
- IP54-rated enclosure or better
- Operating temperature: -10C to +55C
- Mechanical retention for all external cables

For vehicle or heavy vibration, use additional anti-vibration mounts.

---

## 6. Pre-deployment Physical Checklist

- Enclosure screws tightened
- Labels visible and consistent
- Cable strain relief in place
- Power connector stable under light pull test
- EPD cable seated and secured
- USB uplink adapter (Ethernet or Wi-Fi) attached and retained

---

## Supplementary (日本語)

- 配線は電源系と通信系を分離し、各端子に必ずストレインリリーフを設けます。
- ラベルは筐体とケーブル両端に貼付し、現地で迷わない状態にします。
- 出動前に selftest で媒体健全性を確認してください。
- Raspberry Pi 5 では内蔵 Ethernet（eth0）と内蔵 Wi-Fi（wlan0、内部 AP）が内部 LAN（br0）になるため、上流（WAN）には USB Ethernet か USB Wi-Fi のアダプタが別に必要です。既定経路が eth0/wlan0 のままだとインストーラは何も変えずに停止します。
- Raspberry Pi OS では Wi-Fi の国設定（`WIFI_COUNTRY=JP` など）が必須です。未設定だと Wi-Fi が rfkill で止まったままで内部 AP が上がらないため、インストーラは変更前に停止します。
- 内部 AP のパスフレーズは既定でランダム生成され、`/etc/azazel-edge/internal-ap.psk`（root のみ読める 0600）に保存されます。表示・ログには出ません。
- ハードウェアウォッチドッグは既定で無効です。使う場合は実機で `bcm2835-wdt` と `/dev/watchdog` を確かめてから、第 4 節の手順で設定してください。
