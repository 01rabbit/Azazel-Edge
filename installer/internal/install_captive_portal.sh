#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PI_IP="${AZAZEL_CAPTIVE_PI_IP:-172.16.0.254}"
PORTAL_PORT="${AZAZEL_CAPTIVE_PORT:-8085}"
DNSMASQ_CONF="/etc/dnsmasq.d/azazel-captive.conf"
NFT_FILE="/etc/nftables.d/azazel-captive.nft"

echo "[captive 1/5] Install dnsmasq/nftables if needed"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq nftables

echo "[captive 2/5] Configure dnsmasq captive DNS"
install -d /etc/dnsmasq.d
cat > "${DNSMASQ_CONF}" <<EOD
# Azazel captive portal DNS redirect
address=/captive.local/${PI_IP}
# Optional catch-all redirect for unauthenticated clients can be added in site-specific rules.
EOD

systemctl enable --now dnsmasq
systemctl restart dnsmasq

echo "[captive 3/5] Configure nftables HTTP redirect"
install -d /etc/nftables.d
cat > "${NFT_FILE}" <<EOD
table inet azazel_captive {
  chain prerouting {
    type nat hook prerouting priority dstnat;
    tcp dport 80 redirect to ${PORTAL_PORT}
  }
}
EOD

nft -f "${NFT_FILE}" || true

echo "[captive 4/5] Ensure captive template is installed"
if [[ -f "${REPO_ROOT}/azazel_edge_web/templates/captive_consent.html" ]]; then
  install -d /opt/azazel-edge/azazel_edge_web/templates
  install -m 0644 "${REPO_ROOT}/azazel_edge_web/templates/captive_consent.html" /opt/azazel-edge/azazel_edge_web/templates/captive_consent.html
fi

echo "[captive 5/5] Complete"
echo "captive portal install baseline complete"
echo "- dnsmasq: ${DNSMASQ_CONF}"
echo "- nftables: ${NFT_FILE}"
echo "- page: http://captive.local/"
