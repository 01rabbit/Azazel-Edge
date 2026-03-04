#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

MGMT_IP="${MGMT_IP:-127.0.0.1}"
NTFY_PORT="${NTFY_PORT:-8081}"
NTFY_USER="${NTFY_USER:-azazel-notify}"
TOPIC_ALERT="${NTFY_TOPIC_ALERT:-azg-alert-critical}"
TOPIC_INFO="${NTFY_TOPIC_INFO:-azg-info-status}"

SERVER_CFG="/etc/ntfy/server.yml"
TOKEN_PATH_PRIMARY="/etc/azazel-edge/ntfy.token"
TOKEN_PATH_COMPAT="/etc/azazel/ntfy.token"

echo "[ntfy] Installing package..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ntfy

install -d /etc/azazel-edge /etc/azazel /var/lib/ntfy /var/cache/ntfy
chown _ntfy:_ntfy /var/lib/ntfy /var/cache/ntfy
chmod 0750 /var/lib/ntfy /var/cache/ntfy

if [[ -f "$SERVER_CFG" ]] && [[ ! -f "${SERVER_CFG}.azazel-edge.bak" ]]; then
  cp "$SERVER_CFG" "${SERVER_CFG}.azazel-edge.bak"
fi

cat > "$SERVER_CFG" <<EOF
# Managed by Azazel-Edge installer
base-url: "http://${MGMT_IP}:${NTFY_PORT}"
listen-http: ":${NTFY_PORT}"
cache-file: "/var/cache/ntfy/cache.db"
auth-file: "/var/lib/ntfy/user.db"
auth-default-access: "read-write"
behind-proxy: false
web-root: "/"
EOF

systemctl daemon-reload
systemctl restart ntfy.service
for _ in {1..20}; do
  [[ -f /var/lib/ntfy/user.db ]] && break
  sleep 0.2
done
if [[ ! -f /var/lib/ntfy/user.db ]]; then
  echo "ERROR: ntfy auth DB was not created: /var/lib/ntfy/user.db"
  exit 1
fi

ntfy_password="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
if ! NTFY_PASSWORD="$ntfy_password" ntfy user add "$NTFY_USER" >/dev/null 2>&1; then
  NTFY_PASSWORD="$ntfy_password" ntfy user change-pass "$NTFY_USER" >/dev/null 2>&1 || true
fi

ntfy access "$NTFY_USER" "$TOPIC_ALERT" read-write >/dev/null 2>&1 || true
ntfy access "$NTFY_USER" "$TOPIC_INFO" read-write >/dev/null 2>&1 || true
ntfy access everyone "$TOPIC_ALERT" read-write >/dev/null 2>&1 || true
ntfy access everyone "$TOPIC_INFO" read-write >/dev/null 2>&1 || true

token_output="$(ntfy token add "$NTFY_USER" 2>&1 || true)"
token=""
if [[ "$token_output" =~ (tk_[a-z0-9]+) ]]; then
  token="${BASH_REMATCH[1]}"
fi
if [[ -z "$token" ]]; then
  echo "ERROR: failed to create ntfy token"
  exit 1
fi

umask 077
printf '%s\n' "$token" > "$TOKEN_PATH_PRIMARY"
printf '%s\n' "$token" > "$TOKEN_PATH_COMPAT"
chown root:root "$TOKEN_PATH_PRIMARY" "$TOKEN_PATH_COMPAT"
chmod 0600 "$TOKEN_PATH_PRIMARY" "$TOKEN_PATH_COMPAT"

systemctl enable ntfy.service >/dev/null
systemctl restart ntfy.service

for _ in {1..20}; do
  if curl -fsS --max-time 3 "http://127.0.0.1:${NTFY_PORT}/v1/health" | grep -q '"healthy":true'; then
    echo "[ntfy] Service healthy on 127.0.0.1:${NTFY_PORT}"
    echo "[ntfy] token file: ${TOKEN_PATH_PRIMARY}"
    exit 0
  fi
  sleep 0.25
done

echo "ERROR: ntfy did not pass health checks on 127.0.0.1:${NTFY_PORT}"
exit 1
