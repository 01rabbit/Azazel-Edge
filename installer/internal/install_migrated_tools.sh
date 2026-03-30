#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENABLE_SERVICES="${ENABLE_SERVICES:-1}"
ENABLE_NTFY="${ENABLE_NTFY:-1}"
ENABLE_HTTPS="${ENABLE_HTTPS:-1}"
ENABLE_LOCAL_CA="${ENABLE_LOCAL_CA:-1}"
ENABLE_SECURITY_STACK="${ENABLE_SECURITY_STACK:-1}"
ENABLE_RUST_CORE="${ENABLE_RUST_CORE:-1}"
VENV_DIR="/opt/azazel-edge/venv"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

echo "[1/16] Install OS dependencies"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 python3-venv python3-pip \
  network-manager iw curl dnsmasq nginx openssl arp-scan \
  python3-dev python3-numpy python3-pil python3-spidev \
  python3-rpi.gpio python3-gpiozero fonts-noto-cjk git

DEBIAN_FRONTEND=noninteractive apt-get install -y rustc cargo

if [[ ! -d /opt/waveshare-epd ]]; then
  echo "[1/16] Clone Waveshare e-Paper repository"
  git clone https://github.com/waveshare/e-Paper /opt/waveshare-epd
fi

echo "[2/16] Create base directories"
install -d \
  /opt/azazel-edge/py/azazel_edge \
  /opt/azazel-edge/py/azazel_edge/arbiter \
  /opt/azazel-edge/py/azazel_edge/audit \
  /opt/azazel-edge/py/azazel_edge/correlation \
  /opt/azazel-edge/py/azazel_edge/demo \
  /opt/azazel-edge/py/azazel_edge/evaluators \
  /opt/azazel-edge/py/azazel_edge/evidence_plane \
  /opt/azazel-edge/py/azazel_edge/explanations \
  /opt/azazel-edge/py/azazel_edge/impact \
  /opt/azazel-edge/py/azazel_edge/integrations \
  /opt/azazel-edge/py/azazel_edge/knowledge \
  /opt/azazel-edge/py/azazel_edge/notify \
  /opt/azazel-edge/py/azazel_edge/tactics_engine \
  /opt/azazel-edge/py/azazel_edge/sensors \
  /opt/azazel-edge/py/azazel_edge/sigma \
  /opt/azazel-edge/py/azazel_edge/sot \
  /opt/azazel-edge/py/azazel_edge/triage \
  /opt/azazel-edge/py/azazel_edge/triage/flows \
  /opt/azazel-edge/py/azazel_edge/ti \
  /opt/azazel-edge/py/azazel_edge/yara \
  /opt/azazel-edge/py/azazel_edge_control/scripts \
  /opt/azazel-edge/py/azazel_edge_ai \
  /opt/azazel-edge/azazel_edge_web/static \
  /opt/azazel-edge/azazel_edge_web/templates \
  /opt/azazel-edge/runbooks/noc \
  /opt/azazel-edge/runbooks/ops \
  /opt/azazel-edge/runbooks/soc \
  /opt/azazel-edge/runbooks/user \
  /opt/azazel-edge/security/opencanary \
  /opt/azazel-edge/security/suricata \
  /opt/azazel-edge/rust/azazel-edge-core/src \
  /opt/azazel-edge/fonts \
  /opt/azazel-edge/images \
  /opt/azazel-edge/icons/epd \
  /opt/azazel-edge/logs/tactics_engine

echo "[3/16] Install azazel_edge core modules"
install -m 0644 "$REPO_ROOT/py/azazel_edge/__init__.py" /opt/azazel-edge/py/azazel_edge/__init__.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/path_schema.py" /opt/azazel-edge/py/azazel_edge/path_schema.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/control_plane.py" /opt/azazel-edge/py/azazel_edge/control_plane.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/cli_unified.py" /opt/azazel-edge/py/azazel_edge/cli_unified.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/cli_unified_textual.py" /opt/azazel-edge/py/azazel_edge/cli_unified_textual.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/ai_governance.py" /opt/azazel-edge/py/azazel_edge/ai_governance.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/config_drift.py" /opt/azazel-edge/py/azazel_edge/config_drift.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/demo_overlay.py" /opt/azazel-edge/py/azazel_edge/demo_overlay.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/opencanary_redirect.py" /opt/azazel-edge/py/azazel_edge/opencanary_redirect.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/runbooks.py" /opt/azazel-edge/py/azazel_edge/runbooks.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/runbook_review.py" /opt/azazel-edge/py/azazel_edge/runbook_review.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/__init__.py" /opt/azazel-edge/py/azazel_edge/sensors/__init__.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/wifi_scanner.py" /opt/azazel-edge/py/azazel_edge/sensors/wifi_scanner.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/wifi_channel_scanner.py" /opt/azazel-edge/py/azazel_edge/sensors/wifi_channel_scanner.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/system_metrics.py" /opt/azazel-edge/py/azazel_edge/sensors/system_metrics.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/network_analytics.py" /opt/azazel-edge/py/azazel_edge/sensors/network_analytics.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/network_health.py" /opt/azazel-edge/py/azazel_edge/sensors/network_health.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/sensors/noc_monitor.py" /opt/azazel-edge/py/azazel_edge/sensors/noc_monitor.py

for package in \
  arbiter \
  audit \
  correlation \
  demo \
  evaluators \
  evidence_plane \
  explanations \
  impact \
  integrations \
  knowledge \
  notify \
  sigma \
  sot \
  triage \
  ti \
  yara
do
  install -m 0644 "$REPO_ROOT/py/azazel_edge/${package}/"*.py "/opt/azazel-edge/py/azazel_edge/${package}/"
done

echo "[4/16] Install tactics modules"
install -m 0644 "$REPO_ROOT/py/azazel_edge/tactics_engine/__init__.py" /opt/azazel-edge/py/azazel_edge/tactics_engine/__init__.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/tactics_engine/config_hash.py" /opt/azazel-edge/py/azazel_edge/tactics_engine/config_hash.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/tactics_engine/decision_logger.py" /opt/azazel-edge/py/azazel_edge/tactics_engine/decision_logger.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/tactics_engine/eve_parser.py" /opt/azazel-edge/py/azazel_edge/tactics_engine/eve_parser.py
install -m 0644 "$REPO_ROOT/py/azazel_edge/tactics_engine/scorer.py" /opt/azazel-edge/py/azazel_edge/tactics_engine/scorer.py

echo "[5/16] Install control-daemon modules"
install -m 0644 "$REPO_ROOT/py/azazel_edge_control/__init__.py" /opt/azazel-edge/py/azazel_edge_control/__init__.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_control/daemon.py" /opt/azazel-edge/py/azazel_edge_control/daemon.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_control/mode_manager.py" /opt/azazel-edge/py/azazel_edge_control/mode_manager.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_control/wifi_scan.py" /opt/azazel-edge/py/azazel_edge_control/wifi_scan.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_control/wifi_connect.py" /opt/azazel-edge/py/azazel_edge_control/wifi_connect.py
install -m 0755 "$REPO_ROOT/py/azazel_edge_control/scripts/"*.sh /opt/azazel-edge/py/azazel_edge_control/scripts/
install -m 0644 "$REPO_ROOT/py/azazel_edge_ai/__init__.py" /opt/azazel-edge/py/azazel_edge_ai/__init__.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_ai/agent.py" /opt/azazel-edge/py/azazel_edge_ai/agent.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_runbook_broker.py" /opt/azazel-edge/py/azazel_edge_runbook_broker.py

echo "[6/16] Install WebUI and EPD modules"
install -m 0644 "$REPO_ROOT/azazel_edge_web/app.py" /opt/azazel-edge/azazel_edge_web/app.py
install -m 0644 "$REPO_ROOT/azazel_edge_web/static/app.js" /opt/azazel-edge/azazel_edge_web/static/app.js
install -m 0644 "$REPO_ROOT/azazel_edge_web/static/ops_comm.js" /opt/azazel-edge/azazel_edge_web/static/ops_comm.js
install -m 0644 "$REPO_ROOT/azazel_edge_web/static/ops_comm.css" /opt/azazel-edge/azazel_edge_web/static/ops_comm.css
install -m 0644 "$REPO_ROOT/azazel_edge_web/static/style.css" /opt/azazel-edge/azazel_edge_web/static/style.css
install -m 0644 "$REPO_ROOT/azazel_edge_web/templates/index.html" /opt/azazel-edge/azazel_edge_web/templates/index.html
install -m 0644 "$REPO_ROOT/azazel_edge_web/templates/ops_comm.html" /opt/azazel-edge/azazel_edge_web/templates/ops_comm.html
install -m 0644 "$REPO_ROOT/py/azazel_edge_menu.py" /opt/azazel-edge/py/azazel_edge_menu.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_status.py" /opt/azazel-edge/py/azazel_edge_status.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_epd.py" /opt/azazel-edge/py/azazel_edge_epd.py
install -m 0644 "$REPO_ROOT/py/azazel_edge_epd_mode_refresh.py" /opt/azazel-edge/py/azazel_edge_epd_mode_refresh.py

echo "[7/16] Install assets"
install -m 0644 "$REPO_ROOT/fonts/StardosStencilBold-9mzn.ttf" /opt/azazel-edge/fonts/StardosStencilBold-9mzn.ttf
install -m 0644 "$REPO_ROOT/fonts/icbmss20.ttf" /opt/azazel-edge/fonts/icbmss20.ttf
install -m 0644 "$REPO_ROOT/icons/epd/"*.png /opt/azazel-edge/icons/epd/
install -m 0644 "$REPO_ROOT/images/"* /opt/azazel-edge/images/

echo "[8/16] Build Python runtime (venv + pip)"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/python" -m pip install --upgrade pip wheel setuptools
"$VENV_DIR/bin/pip" install -r "$REPO_ROOT/requirements/runtime.txt"

echo "[9/16] Install launchers"
install -m 0755 "$REPO_ROOT/bin/azazel-edge-path-schema" /usr/local/bin/azazel-edge-path-schema
install -m 0755 "$REPO_ROOT/bin/azazel-edge-tui" /usr/local/bin/azazel-edge-tui
install -m 0755 "$REPO_ROOT/bin/azazel-edge-web" /usr/local/bin/azazel-edge-web
install -m 0755 "$REPO_ROOT/bin/azazel-edge-compose" /usr/local/bin/azazel-edge-compose
install -m 0755 "$REPO_ROOT/bin/azazel-edge-epd" /usr/local/bin/azazel-edge-epd
install -m 0755 "$REPO_ROOT/bin/azazel-edge-epd-refresh" /usr/local/bin/azazel-edge-epd-refresh
install -m 0755 "$REPO_ROOT/bin/azazel-edge-control-daemon" /usr/local/bin/azazel-edge-control-daemon
install -m 0755 "$REPO_ROOT/bin/azazel-edge-ai-agent" /usr/local/bin/azazel-edge-ai-agent
install -m 0755 "$REPO_ROOT/bin/azazel-edge-runbook-broker" /usr/local/bin/azazel-edge-runbook-broker
install -m 0755 "$REPO_ROOT/bin/azazel-edge-inject-test-events" /usr/local/bin/azazel-edge-inject-test-events
install -m 0755 "$REPO_ROOT/bin/azazel-edge-demo" /usr/local/bin/azazel-edge-demo
install -m 0755 "$REPO_ROOT/installer/internal/set_dev_remote_access.sh" /opt/azazel-edge/set_dev_remote_access.sh
install -m 0755 "$REPO_ROOT/installer/internal/install_ai_runtime.sh" /opt/azazel-edge/install_ai_runtime.sh
install -m 0755 "$REPO_ROOT/installer/internal/provision_mattermost_workspace.sh" /opt/azazel-edge/provision_mattermost_workspace.sh
install -m 0755 "$REPO_ROOT/installer/internal/provision_mattermost_command.sh" /opt/azazel-edge/provision_mattermost_command.sh
install -m 0755 "$REPO_ROOT/installer/internal/verify_runtime_sync.sh" /opt/azazel-edge/verify_runtime_sync.sh
install -m 0755 "$REPO_ROOT/installer/internal/verify_runtime_sync.sh" /usr/local/bin/azazel-edge-runtime-sync-check

echo "[10/16] Install systemd units"
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-control-daemon.service" /etc/systemd/system/azazel-edge-control-daemon.service
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-web.service" /etc/systemd/system/azazel-edge-web.service
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-epd-refresh.service" /etc/systemd/system/azazel-edge-epd-refresh.service
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-epd-refresh.timer" /etc/systemd/system/azazel-edge-epd-refresh.timer
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-opencanary.service" /etc/systemd/system/azazel-edge-opencanary.service
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-suricata.service" /etc/systemd/system/azazel-edge-suricata.service
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-ai-agent.service" /etc/systemd/system/azazel-edge-ai-agent.service
install -m 0644 "$REPO_ROOT/systemd/azazel-edge-core.service" /etc/systemd/system/azazel-edge-core.service
systemctl daemon-reload

echo "[11/16] Prepare runtime/config paths"
install -d /etc/azazel-edge /var/log/azazel-edge /run/azazel-edge
if [[ ! -f /run/azazel-edge/ui_snapshot.json ]]; then
  cat > /run/azazel-edge/ui_snapshot.json <<'EOD'
{"now_time":"","ssid":"-","user_state":"CHECKING","recommendation":"Initializing","evidence":[],"snapshot_epoch":0}
EOD
fi

echo "[11.5/16] Install runbook registry and AI compose assets"
install -m 0644 "$REPO_ROOT/security/docker-compose.ollama.yml" /opt/azazel-edge/security/docker-compose.ollama.yml
install -m 0644 "$REPO_ROOT/security/docker-compose.mattermost.yml" /opt/azazel-edge/security/docker-compose.mattermost.yml
install -m 0644 "$REPO_ROOT/security/.env" /opt/azazel-edge/security/.env
install -m 0644 "$REPO_ROOT/runbooks/noc/"*.yaml /opt/azazel-edge/runbooks/noc/
install -m 0644 "$REPO_ROOT/runbooks/ops/"*.yaml /opt/azazel-edge/runbooks/ops/
install -m 0644 "$REPO_ROOT/runbooks/soc/"*.yaml /opt/azazel-edge/runbooks/soc/
install -m 0644 "$REPO_ROOT/runbooks/user/"*.yaml /opt/azazel-edge/runbooks/user/
install -m 0644 "$REPO_ROOT/py/azazel_edge/triage/flows/"*.yaml /opt/azazel-edge/py/azazel_edge/triage/flows/
if [[ ! -e /etc/azazel-gadget ]]; then
  ln -s /etc/azazel-edge /etc/azazel-gadget
fi
if [[ ! -e /var/log/azazel-gadget ]]; then
  ln -s /var/log/azazel-edge /var/log/azazel-gadget
fi
if [[ ! -e /run/azazel-gadget ]]; then
  ln -s /run/azazel-edge /run/azazel-gadget
fi

echo "[12/16] Enable services"
if [[ "$ENABLE_SERVICES" == "1" ]]; then
  systemctl enable --now azazel-edge-control-daemon.service
  systemctl enable --now azazel-edge-web.service
  systemctl enable --now azazel-edge-epd-refresh.timer
  systemctl enable --now azazel-edge-ai-agent.service
  systemctl enable --now azazel-edge-core.service
  systemctl restart azazel-edge-control-daemon.service
  systemctl restart azazel-edge-web.service
fi

echo "[13/16] Install local CA and TLS cert (optional)"
install -m 0755 "$REPO_ROOT/installer/internal/install_local_ca.sh" /opt/azazel-edge/install_local_ca.sh
if [[ "$ENABLE_LOCAL_CA" == "1" ]]; then
  /opt/azazel-edge/install_local_ca.sh
fi

echo "[14/16] Install HTTPS reverse proxy (optional)"
install -m 0755 "$REPO_ROOT/installer/internal/install_https_proxy.sh" /opt/azazel-edge/install_https_proxy.sh
if [[ "$ENABLE_HTTPS" == "1" ]]; then
  /opt/azazel-edge/install_https_proxy.sh
fi

echo "[15/16] Install ntfy (optional)"
if [[ "$ENABLE_NTFY" == "1" ]]; then
  "$REPO_ROOT/installer/internal/install_ntfy.sh"
  if [[ "$ENABLE_SERVICES" == "1" ]]; then
    systemctl restart azazel-edge-web.service
  fi
fi

echo "[16/16] Install security stack (OpenCanary + Suricata, optional)"
install -m 0755 "$REPO_ROOT/installer/internal/install_security_stack.sh" /opt/azazel-edge/install_security_stack.sh
install -m 0644 "$REPO_ROOT/security/docker-compose.yml" /opt/azazel-edge/security/docker-compose.yml
install -m 0644 "$REPO_ROOT/security/opencanary/Dockerfile" /opt/azazel-edge/security/opencanary/Dockerfile
install -m 0644 "$REPO_ROOT/security/opencanary/opencanary.conf" /opt/azazel-edge/security/opencanary/opencanary.conf
install -m 0644 "$REPO_ROOT/security/suricata/azazel-lite.rules" /opt/azazel-edge/security/suricata/azazel-lite.rules
if [[ "$ENABLE_SECURITY_STACK" == "1" ]]; then
  ENABLE_SERVICES="$ENABLE_SERVICES" /opt/azazel-edge/install_security_stack.sh
fi

echo "[17/17] Install Rust defense core source (optional)"
install -m 0644 "$REPO_ROOT/rust/azazel-edge-core/Cargo.toml" /opt/azazel-edge/rust/azazel-edge-core/Cargo.toml
install -m 0644 "$REPO_ROOT/rust/azazel-edge-core/src/main.rs" /opt/azazel-edge/rust/azazel-edge-core/src/main.rs
cargo build --release --manifest-path /opt/azazel-edge/rust/azazel-edge-core/Cargo.toml
install -m 0755 /opt/azazel-edge/rust/azazel-edge-core/target/release/azazel-edge-core /usr/local/bin/azazel-edge-core

echo "[18/18] Verify runtime sync"
/opt/azazel-edge/verify_runtime_sync.sh "$REPO_ROOT" /opt/azazel-edge

echo "Installed Azazel-Edge stack (WebUI/TUI/EPD/control/HTTPS/security) under /opt/azazel-edge and /usr/local/bin."
