#!/usr/bin/env bash
# install_wazuh_agent.sh - Install Wazuh Agent on Azazel-Edge (ARM64)
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"; exit 1
fi

ARCH="$(uname -m)"
if [[ "${ARCH}" != "aarch64" ]]; then
  echo "[ERROR] Expected aarch64, got ${ARCH}"; exit 1
fi

WAZUH_MANAGER_HOST="${WAZUH_MANAGER_HOST:?'ERROR: Set WAZUH_MANAGER_HOST env var (Wazuh Manager IP)'}"
WAZUH_MANAGER_PORT="${WAZUH_MANAGER_PORT:-1514}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-azazel-edge-$(hostname -s)}"
WAZUH_VERSION="${WAZUH_VERSION:-4.9.0}"
ENABLE_SERVICES="${ENABLE_SERVICES:-1}"

echo "[wazuh-agent 1/5] Add Wazuh APT repository (ARM64)"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update

echo "[wazuh-agent 2/5] Install wazuh-agent"
WAZUH_MANAGER="${WAZUH_MANAGER_HOST}" \
WAZUH_MANAGER_PORT="${WAZUH_MANAGER_PORT}" \
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" \
  apt-get install -y "wazuh-agent=${WAZUH_VERSION}-*"

echo "[wazuh-agent 3/5] Configure FIM for Azazel-Edge critical paths"
python3 - <<'PYEOF'
import xml.etree.ElementTree as ET

tree = ET.parse('/var/ossec/etc/ossec.conf')
root = tree.getroot()
syscheck = root.find('syscheck')
if syscheck is None:
    syscheck = ET.SubElement(root, 'syscheck')

azazel_dirs = [
    '/etc/azazel-edge',
    '/opt/azazel-edge',
    '/var/log/azazel-edge',
    '/etc/suricata/rules',
    '/etc/azazel-edge/vector',
]
existing = {d.text for d in syscheck.findall('directories')}
for path in azazel_dirs:
    if path not in existing:
        el = ET.SubElement(syscheck, 'directories')
        el.set('check_all', 'yes')
        el.set('report_changes', 'yes')
        el.set('realtime', 'yes')
        el.text = path

tree.write('/var/ossec/etc/ossec.conf', encoding='utf-8', xml_declaration=True)
print('[wazuh-agent] FIM directories configured.')
PYEOF

echo "[wazuh-agent 4/5] Keep Wazuh observation-only (no active response on this host)"
# Edge#412: defensive actions come only from the Rust azazel-edge-core
# (decide_defense -> maybe_enforce). The Wazuh agent here provides FIM and SCA
# and is never an enforcer. Earlier versions of this installer generated
# /var/ossec/active-response/bin/azazel-block.sh; remove it on upgrade, and
# turn the agent's active response off so no manager-side command (including
# Wazuh's stock scripts) can run on this host. Both steps are idempotent.
LEGACY_AR_SCRIPT="/var/ossec/active-response/bin/azazel-block.sh"
if [[ -e "${LEGACY_AR_SCRIPT}" || -L "${LEGACY_AR_SCRIPT}" ]]; then
  rm -f -- "${LEGACY_AR_SCRIPT:?}"
  echo "[wazuh-agent] Removed legacy active response script ${LEGACY_AR_SCRIPT}"
fi
python3 - <<'PYEOF'
import xml.etree.ElementTree as ET

tree = ET.parse('/var/ossec/etc/ossec.conf')
root = tree.getroot()
blocks = root.findall('active-response')
if not blocks:
    blocks = [ET.SubElement(root, 'active-response')]
for block in blocks:
    disabled = block.find('disabled')
    if disabled is None:
        disabled = ET.SubElement(block, 'disabled')
    disabled.text = 'yes'

tree.write('/var/ossec/etc/ossec.conf', encoding='utf-8', xml_declaration=True)
print('[wazuh-agent] Active response disabled on this agent.')
PYEOF

echo "[wazuh-agent 5/5] Enable and start wazuh-agent"
systemctl daemon-reload
if [[ "${ENABLE_SERVICES}" == "1" ]]; then
  systemctl enable --now wazuh-agent
  systemctl is-active wazuh-agent && echo "[wazuh-agent] Service started OK"
fi

echo "[wazuh-agent] Install complete."
echo "  Manager:    ${WAZUH_MANAGER_HOST}:${WAZUH_MANAGER_PORT}"
echo "  Agent name: ${WAZUH_AGENT_NAME}"
echo "  FIM paths:  /etc/azazel-edge, /opt/azazel-edge, /etc/suricata/rules"
echo "  Active response: disabled (Wazuh is observation-only; defensive actions come only from azazel-edge-core)"
echo ""
echo "NEXT: Register agent on Wazuh Manager:"
echo "  manager$ /var/ossec/bin/manage_agents -a  (or use Wazuh Dashboard)"
