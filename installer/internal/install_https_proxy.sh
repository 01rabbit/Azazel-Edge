#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

AZAZEL_WEB_UPSTREAM_HOST="${AZAZEL_WEB_UPSTREAM_HOST:-127.0.0.1}"
AZAZEL_WEB_UPSTREAM_PORT="${AZAZEL_WEB_UPSTREAM_PORT:-8084}"
AZAZEL_TLS_CERT="${AZAZEL_TLS_CERT:-/etc/azazel-edge/tls/webui.crt}"
AZAZEL_TLS_KEY="${AZAZEL_TLS_KEY:-/etc/azazel-edge/tls/webui.key}"
AZAZEL_TLS_DAYS="${AZAZEL_TLS_DAYS:-825}"
AZAZEL_TLS_CN="${AZAZEL_TLS_CN:-$(hostname -f 2>/dev/null || hostname)}"
NGINX_SITE="/etc/nginx/sites-available/azazel-edge-web.conf"
NGINX_LINK="/etc/nginx/sites-enabled/azazel-edge-web.conf"
CA_EXPORT_PATH="${AZAZEL_CA_EXPORT_PATH:-/var/lib/azazel-edge/public/azazel-edge-local-ca.crt}"
LAN_IF="br0"
LAN_CIDR_DEFAULT="172.16.0.0/24"
# Docker's default address pools for bridge networks (172.17.0.0/16 ..
# 172.31.0.0/16, all inside 172.16.0.0/12). The Mattermost container is on
# such a network and calls the slash-command endpoint from there.
DOCKER_BRIDGE_POOL="172.16.0.0/12"

# Who may reach nginx (Edge#477, #471). nginx listens on every address, so
# without these rules the uplink (WAN) side reached the Web UI, the local CA
# download, /health and the unauthenticated /api/wifi/scan and
# /api/captive/register. Only the device itself and the internal LAN may.
#
# The rules are allow/deny, not `listen <LAN address>`: nginx fails to start
# when that address is not on br0 yet (boot order, a LAN that is down), which
# would cut the LAN off as well; allow/deny does not depend on it.
#
# The LAN subnet is the one on br0 (the route the kernel adds for its
# address, set up by install_internal_network.sh); 172.16.0.0/24 (that
# script's LAN_CIDR) when br0 has none yet. There is no setting that widens
# it. Re-run this script after changing the LAN subnet.
detect_lan_cidr() {
  local cidr
  cidr="$(ip -4 -o route show dev "$LAN_IF" proto kernel scope link 2>/dev/null | awk '{print $1; exit}' || true)"
  [[ -n "$cidr" ]] || cidr="$LAN_CIDR_DEFAULT"
  if [[ ! "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]] \
      || (( 10#${BASH_REMATCH[2]} < 8 || 10#${BASH_REMATCH[2]} > 32 )); then
    echo "ERROR: the LAN subnet must be an IPv4 CIDR with a prefix of /8../32 (got: ${cidr})" >&2
    exit 1
  fi
  printf '%s' "$cidr"
}

LAN_CIDR="$(detect_lan_cidr)"
echo "[https] Access limited to this device and the LAN (${LAN_CIDR})"

echo "[https] Installing nginx and openssl"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y nginx openssl

install -d /etc/azazel-edge/tls

if [[ ! -s "$AZAZEL_TLS_CERT" || ! -s "$AZAZEL_TLS_KEY" ]]; then
  echo "[https] Creating self-signed certificate (CN=${AZAZEL_TLS_CN})"
  openssl req -x509 -nodes -newkey rsa:2048 -sha256 \
    -days "$AZAZEL_TLS_DAYS" \
    -subj "/CN=${AZAZEL_TLS_CN}" \
    -keyout "$AZAZEL_TLS_KEY" \
    -out "$AZAZEL_TLS_CERT"
fi

chmod 0600 "$AZAZEL_TLS_KEY"
chmod 0644 "$AZAZEL_TLS_CERT"

cat > "$NGINX_SITE" <<EOF
server {
  listen 80;
  server_name _;

  allow 127.0.0.1;
  allow ::1;
  allow ${LAN_CIDR};
  deny all;

  location = /.well-known/azazel-edge-local-ca.crt {
    alias ${CA_EXPORT_PATH};
    default_type application/pkix-cert;
    add_header Cache-Control "no-store";
  }
  # Mattermost's slash commands call back here (provision_mattermost_command.sh:
  # http://172.16.0.254/api/mattermost/command). Mattermost runs in Docker on
  # this device, so the callback comes from its bridge network, not from the
  # LAN; that pool is allowed here only. The endpoint checks the command token.
  location = /api/mattermost/command {
    allow 127.0.0.1;
    allow ::1;
    allow ${LAN_CIDR};
    allow ${DOCKER_BRIDGE_POOL};
    deny all;
    proxy_pass http://${AZAZEL_WEB_UPSTREAM_HOST}:${AZAZEL_WEB_UPSTREAM_PORT};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto http;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header Connection "";
    proxy_redirect off;
    proxy_read_timeout 120s;
  }
  # Through a named location, not `return` here: `return` runs before the
  # allow/deny above are checked, so the uplink would still get the redirect.
  location / {
    try_files /.azazel-edge-no-such-file @to_https;
  }
  location @to_https {
    return 301 https://\$host\$request_uri;
  }
}

server {
  listen 443 ssl;
  http2 on;
  server_name _;

  ssl_certificate ${AZAZEL_TLS_CERT};
  ssl_certificate_key ${AZAZEL_TLS_KEY};
  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers off;

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;

  client_max_body_size 2m;

  allow 127.0.0.1;
  allow ::1;
  allow ${LAN_CIDR};
  deny all;

  location = /.well-known/azazel-edge-local-ca.crt {
    alias ${CA_EXPORT_PATH};
    default_type application/pkix-cert;
    add_header Cache-Control "no-store";
  }

  location /api/events/stream {
    proxy_pass http://${AZAZEL_WEB_UPSTREAM_HOST}:${AZAZEL_WEB_UPSTREAM_PORT};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 3600s;
  }

  location / {
    proxy_pass http://${AZAZEL_WEB_UPSTREAM_HOST}:${AZAZEL_WEB_UPSTREAM_PORT};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header Connection "";
    proxy_redirect off;
    proxy_read_timeout 120s;
  }
}
EOF

ln -sfn "$NGINX_SITE" "$NGINX_LINK"
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl enable --now nginx.service
systemctl restart nginx.service

echo "[https] nginx TLS reverse proxy enabled on :443 (this device and ${LAN_CIDR} only)"
