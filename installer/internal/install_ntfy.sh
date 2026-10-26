#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

# ntfy listens on loopback only (Edge#477). Its only clients are on this
# host: the Web UI's SSE bridge and health probe (azazel_edge_web/app.py) and
# the CLI health probe. Nothing on the LAN or the WAN uses it, so it is not
# reachable from there, and there is no setting that widens the address.
NTFY_LISTEN_ADDR="127.0.0.1"
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

# An existing /etc/azazel-edge keeps its mode (Edge#471: never widened).
[[ -d /etc/azazel-edge ]] || install -d -m 0750 /etc/azazel-edge
install -d /etc/azazel /var/lib/ntfy /var/cache/ntfy
chown _ntfy:_ntfy /var/lib/ntfy /var/cache/ntfy
chmod 0750 /var/lib/ntfy /var/cache/ntfy

if [[ -f "$SERVER_CFG" ]] && [[ ! -f "${SERVER_CFG}.azazel-edge.bak" ]]; then
  cp "$SERVER_CFG" "${SERVER_CFG}.azazel-edge.bak"
fi

cat > "$SERVER_CFG" <<EOF
# Managed by Azazel-Edge installer
# Anonymous clients get nothing (deny-all); the Edge account below reads and
# writes the two topics with a token. The web app is off: nobody uses it.
base-url: "http://${NTFY_LISTEN_ADDR}:${NTFY_PORT}"
listen-http: "${NTFY_LISTEN_ADDR}:${NTFY_PORT}"
cache-file: "/var/cache/ntfy/cache.db"
auth-file: "/var/lib/ntfy/user.db"
auth-default-access: "deny-all"
behind-proxy: false
web-root: "disable"
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

# Under deny-all a missing grant would cut the Web UI off, so a failure stops
# the install here instead of being ignored.
ntfy access "$NTFY_USER" "$TOPIC_ALERT" read-write >/dev/null
ntfy access "$NTFY_USER" "$TOPIC_INFO" read-write >/dev/null
# Earlier installs granted anonymous read-write on both topics (anyone who
# reached the port could read the alerts and post fake ones). Remove those
# entries; deny-all then applies to anonymous clients.
ntfy access --reset everyone "$TOPIC_ALERT" >/dev/null 2>&1 || true
ntfy access --reset everyone "$TOPIC_INFO" >/dev/null 2>&1 || true
if ntfy access everyone 2>/dev/null | grep -Eq "(read|write)"; then
  echo "ERROR: ntfy still grants anonymous access; see 'ntfy access everyone'"
  exit 1
fi

# The token of an earlier run, removed once the new one is written.
old_token=""
if [[ -f "$TOKEN_PATH_PRIMARY" ]]; then
  old_token="$(grep -Eo '^tk_[a-z0-9]+$' "$TOKEN_PATH_PRIMARY" 2>/dev/null | head -n 1 || true)"
fi

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
# Token files the Web UI reads are 0640 root:azazel-web (Edge#471 stage 1:
# the Web UI runs as azazel-web). Without that account they stay 0600 root.
web_readable_secret() {
  if getent group azazel-web >/dev/null 2>&1; then
    chown root:azazel-web "$1"
    chmod 0640 "$1"
  else
    chown root:root "$1"
    chmod 0600 "$1"
  fi
}
web_readable_secret "$TOKEN_PATH_PRIMARY"
web_readable_secret "$TOKEN_PATH_COMPAT"
if [[ -n "$old_token" && "$old_token" != "$token" ]]; then
  ntfy token remove "$NTFY_USER" "$old_token" >/dev/null 2>&1 || true
fi
unset token_output old_token

# The ntfy CLI above ran as root on the auth database.
chown -R _ntfy:_ntfy /var/lib/ntfy

systemctl enable ntfy.service >/dev/null
systemctl restart ntfy.service

NTFY_URL="http://${NTFY_LISTEN_ADDR}:${NTFY_PORT}"
healthy=0
for _ in {1..20}; do
  if curl -fsS --max-time 3 "${NTFY_URL}/v1/health" | grep -q '"healthy":true'; then
    healthy=1
    break
  fi
  sleep 0.25
done
if [[ "$healthy" != "1" ]]; then
  echo "ERROR: ntfy did not pass health checks on ${NTFY_URL}"
  exit 1
fi

# An anonymous read must be refused; the token must be accepted. The token
# goes to curl on stdin (-H @-), not on its command line.
anon_status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "${NTFY_URL}/${TOPIC_ALERT}/json?poll=1" || true)"
if [[ "$anon_status" != "401" && "$anon_status" != "403" ]]; then
  echo "ERROR: ntfy answered an anonymous read of ${TOPIC_ALERT} with HTTP ${anon_status} (want 401/403)"
  exit 1
fi
auth_status="$(printf 'Authorization: Bearer %s\n' "$token" \
  | curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -H @- "${NTFY_URL}/${TOPIC_ALERT}/json?poll=1" || true)"
unset token
if [[ "$auth_status" != "200" ]]; then
  echo "ERROR: ntfy refused the Edge token for ${TOPIC_ALERT} (HTTP ${auth_status})"
  exit 1
fi

echo "[ntfy] Service healthy on ${NTFY_URL} (loopback only, anonymous access denied)"
echo "[ntfy] token file: ${TOKEN_PATH_PRIMARY}"
exit 0
