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
  location = /.well-known/azazel-edge-local-ca.crt {
    alias ${CA_EXPORT_PATH};
    default_type application/pkix-cert;
    add_header Cache-Control "no-store";
  }
  location = /api/mattermost/command {
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
  location / {
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

echo "[https] nginx TLS reverse proxy enabled on :443"
