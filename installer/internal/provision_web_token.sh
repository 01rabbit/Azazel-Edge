#!/usr/bin/env bash
set -euo pipefail

TOKEN_FILE="${AZAZEL_WEB_TOKEN_FILE:-/etc/azazel-edge/web_token.txt}"
TOKEN_DIR="$(dirname "$TOKEN_FILE")"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

# A missing directory is created 0750; an existing one keeps its mode
# (Edge#471: never widened). The Web UI runs as azazel-web (stage 1) and
# reads its token, which is 0640 root:azazel-web; setup_web_account.sh gives
# it access to the directory.
[[ -d "$TOKEN_DIR" ]] || install -d -m 0750 "$TOKEN_DIR"
web_token_mode() {
  if getent group azazel-web >/dev/null 2>&1; then
    chown root:azazel-web "$TOKEN_FILE"
  else
    chown root:root "$TOKEN_FILE"
  fi
  chmod 0640 "$TOKEN_FILE"
}

if [[ -s "$TOKEN_FILE" ]]; then
  web_token_mode
  echo "[web-token] keep existing token: $TOKEN_FILE"
  exit 0
fi

if command -v openssl >/dev/null 2>&1; then
  token="$(openssl rand -hex 32)"
else
  token="$(date +%s)-$RANDOM-$RANDOM-$RANDOM"
fi

(umask 077; printf '%s\n' "$token" > "$TOKEN_FILE")
web_token_mode
echo "[web-token] generated token: $TOKEN_FILE"
