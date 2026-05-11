#!/usr/bin/env bash
set -euo pipefail

TOKEN_FILE="${AZAZEL_WEB_TOKEN_FILE:-/etc/azazel-edge/web_token.txt}"
TOKEN_DIR="$(dirname "$TOKEN_FILE")"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

install -d -m 0750 "$TOKEN_DIR"

if [[ -s "$TOKEN_FILE" ]]; then
  chmod 0640 "$TOKEN_FILE" || true
  echo "[web-token] keep existing token: $TOKEN_FILE"
  exit 0
fi

if command -v openssl >/dev/null 2>&1; then
  token="$(openssl rand -hex 32)"
else
  token="$(date +%s)-$RANDOM-$RANDOM-$RANDOM"
fi

printf '%s\n' "$token" > "$TOKEN_FILE"
chmod 0640 "$TOKEN_FILE"
echo "[web-token] generated token: $TOKEN_FILE"
