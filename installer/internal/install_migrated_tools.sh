#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENABLE_SERVICES="${ENABLE_SERVICES:-1}"
ENABLE_NTFY="${ENABLE_NTFY:-1}"
ENABLE_HTTPS="${ENABLE_HTTPS:-1}"
ENABLE_LOCAL_CA="${ENABLE_LOCAL_CA:-1}"
VENV_DIR="/opt/azazel-edge/venv"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

echo "[1/15] Install OS dependencies"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 python3-venv python3-pip \
  network-manager iw curl dnsmasq nginx openssl

echo "[2/15] Create base directories"
install -d \
  /opt/azazel-edge/py/azazel_edge \
  /opt/azazel-edge/py/azazel_edge/tactics_engine \
  /opt/azazel-edge/py/azazel_edge/sensors \
  /opt/azazel-edge/py/azazel_edge_control/scripts \
  /opt/azazel-edge/azazel_edge_web/static \
  /opt/azazel-edge/azazel_edge_web/templates \
  /opt/azazel-edge/fonts \
  /opt/azazel-edge/icons/epd \
  /opt/azazel-edge/logs/tactics_engine

echo "[3/15] Install azazel_edge core modules"
install -m 0644 "$REPO_ROOT/py/azazel_edge/__init__.py" /opt/azazel-edge/py/azazel_edge/__init__.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/path_schema.py" /opt/azazel-edge/py/azazel_edge/path_schema.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/control_plane.py" /opt/azazel-edge/py/azazel_edge/control_plane.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/cli_unified.py" /opt/azazel-edge/py/azazel_edge/cli_unified.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/cli_unified_textual.py" /opt/azazel-edge/py/azazel_edge/cli_unified_textual.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/__init__.py" /opt/azazel-edge/py/azazel_edge/sensors/__init__.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/wifi_scanner.py" /opt/azazel-edge/py/azazel_edge/sensors/wifi_scanner.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/wifi_channel_scanner.py" /opt/azazel-edge/py/azazel_edge/sensors/wifi_channel_scanner.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/system_metrics.py" /opt/azazel-edge/py/azazel_edge/sensors/system_metrics.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/network_analytics.py" /opt/azazel-edge/py/azazel_edge/sensors/network_analytics.py

echo "[4/15] Install tactics modules"
install -m 0644 "$REPO_ROOT/py/azazel_edge/tactics_engine/__init__.py" /opt/azazel-edge/py/azazel_edge/tactics_engine/__init__.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/tactics_engine/config_hash.py" /opt/azazel-edge/py/azazel_edge/tactics_engine/config_hash.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/tactics_engine/decision_logger.py" /opt/azazel-edge/py/azazel_edge/tactics_engine/decision_logger.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/tactics_engine/eve_parser.py" /opt/azazel-edge/py/azazel_edge/tactics_engine/eve_parser.py

echo "[5/15] Install control-daemon modules"
install -m 0644 "$REPO_ROOT/py/azazel_edge_control/__init__.py" /opt/azazel-edge/py/azazel_edge_control/__init__.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_control/daemon.py" /opt/azazel-edge/py/azazel_edge_control/daemon.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_control/mode_manager.py" /opt/azazel-edge/py/azazel_edge_control/mode_manager.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_control/wifi_scan.py" /opt/azazel-edge/py/azazel_edge_control/wifi_scan.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_control/wifi_connect.py" /opt/azazel-edge/py/azazel_edge_control/wifi_connect.py
install -m 0755 "$REPO_ROOT/py/azazel_edge_control/scripts/"*.sh /opt/azazel-edge/py/azazel_edge_control/scripts/

echo "[6/15] Install WebUI and EPD modules"
install -m 0644 "$REPO_ROOT/azazel_edge_web/app.py" /opt/azazel-edge/azazel_edge_web/app.py
install -m 0644 "$REPO_ROOT/azazel_edge_web/static/app.js" /opt/azazel-edge/azazel_edge_web/static/app.js
install -m 0644 "$REPO_ROOT/azazel_edge_web/static/style.css" /opt/azazel-edge/azazel_edge_web/static/style.css
install -m 0644 "$REPO_ROOT/azazel_edge_web/templates/index.html" /opt/azazel-edge/azazel_edge_web/templates/index.html
install -m 0644 "$REPO_ROOT/py/azazel_edge_menu.py" /opt/azazel-edge/py/azazel_edge_menu.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_status.py" /opt/azazel-edge/py/azazel_edge_status.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_epd.py" /opt/azazel-edge/py/azazel_edge_epd.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_epd_mode_refresh.py" /opt/azazel-edge/py/azazel_edge_epd_mode_refresh.py

echo "[7/15] Install assets"
install -m 0644 "$REPO_ROOT/fonts/StardosStencilBold-9mzn.ttf" /opt/azazel-edge/fonts/StardosStencilBold-9mzn.ttf
install -m 0644 "$REPO_ROOT/fonts/icbmss20.ttf" /opt/azazel-edge/fonts/icbmss20.ttf
install -m 0644 "$REPO_ROOT/icons/epd/"*.png /opt/azazel-edge/icons/epd/

echo "[8/15] Build Python runtime (venv + pip)"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/python" -m pip install --upgrade pip wheel setuptools
"$VENV_DIR/bin/pip" install -r "$REPO_ROOT/requirements/runtime.txt"

echo "[9/15] Install launchers"
install -m 0755 "$REPO_ROOT/bin/azazel-edge-path-schema" /usr/local/bin/azazel-edge-path-schema
install -m 0755 "$REPO_ROOT/bin/azazel-edge-tui" /usr/local/bin/azazel-edge-tui
install -m 0755 "$REPO_ROOT/bin/azazel-edge-web" /usr/local/bin/azazel-edge-web
install -m 0755 "$REPO_ROOT/bin/azazel-edge-epd" /usr/local/bin/azazel-edge-epd
install -m 0755 "$REPO_ROOT/bin/azazel-edge-epd-refresh" /usr/local/bin/azazel-edge-epd-refresh
install -m 0755 "$REPO_ROOT/bin/azazel-edge-control-daemon" /usr/local/bin/azazel-edge-control-daemon

echo "[10/15] Install systemd units"
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-control-daemon.service" /etc/systemd/system/azazel-edge-control-daemon.service
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-web.service" /etc/systemd/system/azazel-edge-web.service
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-epd-refresh.service" /etc/systemd/system/azazel-edge-epd-refresh.service
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-epd-refresh.timer" /etc/systemd/system/azazel-edge-epd-refresh.timer
systemctl daemon-reload

echo "[11/15] Prepare runtime/config paths"
install -d /etc/azazel-edge /var/log/azazel-edge /run/azazel-edge
if [[ ! -f /run/azazel-edge/ui_snapshot.json ]]; then
  cat > /run/azazel-edge/ui_snapshot.json <<'EOD'
{"now_time":"","ssid":"-","user_state":"CHECKING","recommendation":"Initializing","evidence":[],"snapshot_epoch":0}
EOD
fi
if [[ ! -e /etc/azazel-gadget ]]; then
  ln -s /etc/azazel-edge /etc/azazel-gadget
fi
if [[ ! -e /var/log/azazel-gadget ]]; then
  ln -s /var/log/azazel-edge /var/log/azazel-gadget
fi
if [[ ! -e /run/azazel-gadget ]]; then
  ln -s /run/azazel-edge /run/azazel-gadget
fi

echo "[12/15] Enable services"
if [[ "$ENABLE_SERVICES" == "1" ]]; then
  systemctl enable --now azazel-edge-control-daemon.service
  systemctl enable --now azazel-edge-web.service
  systemctl enable --now azazel-edge-epd-refresh.timer
  systemctl restart azazel-edge-control-daemon.service
  systemctl restart azazel-edge-web.service
fi

echo "[13/15] Install local CA and TLS cert (optional)"
install -m 0755 "$REPO_ROOT/installer/internal/install_local_ca.sh" /opt/azazel-edge/install_local_ca.sh
if [[ "$ENABLE_LOCAL_CA" == "1" ]]; then
  /opt/azazel-edge/install_local_ca.sh
fi

echo "[14/15] Install HTTPS reverse proxy (optional)"
install -m 0755 "$REPO_ROOT/installer/internal/install_https_proxy.sh" /opt/azazel-edge/install_https_proxy.sh
if [[ "$ENABLE_HTTPS" == "1" ]]; then
  /opt/azazel-edge/install_https_proxy.sh
fi

echo "[15/15] Install ntfy (optional)"
if [[ "$ENABLE_NTFY" == "1" ]]; then
  "$REPO_ROOT/installer/internal/install_ntfy.sh"
  if [[ "$ENABLE_SERVICES" == "1" ]]; then
    systemctl restart azazel-edge-web.service
  fi
fi

echo "Installed Azazel-Edge stack (WebUI/TUI/EPD/control/HTTPS) under /opt/azazel-edge and /usr/local/bin."
