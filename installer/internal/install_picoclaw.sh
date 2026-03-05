#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

ARCH="$(uname -m)"
if [[ "${ARCH}" != "aarch64" ]]; then
  echo "[ERROR] arch is '${ARCH}' (expected aarch64). abort."
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OWNER_USER="${SUDO_USER:-$(id -un)}"
OWNER_GROUP="$(id -gn "${OWNER_USER}")"

echo "[1/8] Install OS dependencies"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y curl jq ca-certificates

echo "[2/8] Resolve PicoClaw latest release asset"
RELEASE_JSON="$(curl -fsSL https://api.github.com/repos/sipeed/picoclaw/releases/latest)"
ASSET_URL="$(
  printf '%s' "${RELEASE_JSON}" | jq -r '
    .assets[]
    | select(
        .name=="picoclaw-linux-arm64"
        or .name=="picoclaw_Linux_arm64.tar.gz"
        or .name=="picoclaw_aarch64.deb"
      )
    | .browser_download_url
  ' | head -n 1
)"

if [[ -z "${ASSET_URL}" || "${ASSET_URL}" == "null" ]]; then
  echo "[ERROR] could not resolve picoclaw-linux-arm64 from latest release. abort."
  exit 1
fi

echo "[3/8] Download and install PicoClaw binary"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
ASSET_NAME="$(basename "${ASSET_URL}")"
ASSET_PATH="${TMP_DIR}/${ASSET_NAME}"
curl -fL "${ASSET_URL}" -o "${ASSET_PATH}"

if [[ "${ASSET_NAME}" == *.tar.gz ]]; then
  tar -xzf "${ASSET_PATH}" -C "${TMP_DIR}"
  BIN_PATH="$(find "${TMP_DIR}" -maxdepth 2 -type f -name picoclaw | head -n 1)"
  if [[ -z "${BIN_PATH}" ]]; then
    echo "[ERROR] picoclaw binary not found in tarball."
    exit 1
  fi
  install -m 0755 "${BIN_PATH}" /usr/local/bin/picoclaw
elif [[ "${ASSET_NAME}" == *.deb ]]; then
  dpkg -i "${ASSET_PATH}"
else
  install -m 0755 "${ASSET_PATH}" /usr/local/bin/picoclaw
fi

echo "[4/8] Verify PicoClaw"
picoclaw --help >/dev/null
echo "[INFO] picoclaw installed: $(command -v picoclaw)"
picoclaw status || true

echo "[5/8] Prepare dual-profile directories"
install -d /opt/azazel/ai/picoclaw-suri/workspace
install -d /opt/azazel/ai/picoclaw-ops/workspace
install -d /opt/azazel/ai/picoclaw-suri/.picoclaw
install -d /opt/azazel/ai/picoclaw-ops/.picoclaw
chown -R "${OWNER_USER}:${OWNER_GROUP}" /opt/azazel/ai/picoclaw-suri /opt/azazel/ai/picoclaw-ops

echo "[6/8] Onboard (best effort)"
set +e
timeout 30 runuser -u "${OWNER_USER}" -- env HOME=/opt/azazel/ai/picoclaw-suri picoclaw onboard
timeout 30 runuser -u "${OWNER_USER}" -- env HOME=/opt/azazel/ai/picoclaw-ops picoclaw onboard
set -e

echo "[7/8] Write profile configs for Ollama models"
cat > /opt/azazel/ai/picoclaw-suri/.picoclaw/config.json <<'EOF'
{
  "agents": {
    "defaults": {
      "workspace": "/opt/azazel/ai/picoclaw-suri/workspace",
      "restrict_to_workspace": true,
      "model": "qwen35-2b",
      "model_name": "qwen35-2b",
      "max_tokens": 2048,
      "temperature": 0.2,
      "max_tool_iterations": 12
    }
  },
  "model_list": [
    {
      "model_name": "qwen35-2b",
      "model": "ollama/qwen3.5:2b",
      "api_base": "http://127.0.0.1:11434/v1",
      "request_timeout": 300
    }
  ]
}
EOF

cat > /opt/azazel/ai/picoclaw-ops/.picoclaw/config.json <<'EOF'
{
  "agents": {
    "defaults": {
      "workspace": "/opt/azazel/ai/picoclaw-ops/workspace",
      "restrict_to_workspace": true,
      "model": "qwen35-4b",
      "model_name": "qwen35-4b",
      "max_tokens": 3072,
      "temperature": 0.3,
      "max_tool_iterations": 16
    }
  },
  "model_list": [
    {
      "model_name": "qwen35-4b",
      "model": "ollama/qwen3.5:4b",
      "api_base": "http://127.0.0.1:11434/v1",
      "request_timeout": 300
    }
  ]
}
EOF

ln -sf /opt/azazel/ai/picoclaw-suri/.picoclaw/config.json /opt/azazel/ai/picoclaw-suri/config.json
ln -sf /opt/azazel/ai/picoclaw-ops/.picoclaw/config.json /opt/azazel/ai/picoclaw-ops/config.json

chown -R "${OWNER_USER}:${OWNER_GROUP}" /opt/azazel/ai/picoclaw-suri /opt/azazel/ai/picoclaw-ops

install -m 0755 "${REPO_ROOT}/bin/picoclaw-suri" /usr/local/bin/picoclaw-suri
install -m 0755 "${REPO_ROOT}/bin/picoclaw-ops" /usr/local/bin/picoclaw-ops

echo "[8/8] Final checks"
curl -fsS http://127.0.0.1:11434/api/tags >/dev/null
runuser -u "${OWNER_USER}" -- env HOME=/opt/azazel/ai/picoclaw-suri picoclaw status || true
runuser -u "${OWNER_USER}" -- env HOME=/opt/azazel/ai/picoclaw-ops picoclaw status || true

echo "[DONE] PicoClaw host install completed."
echo "Use:"
echo "  picoclaw-suri agent -m 'Summarize this Suricata alert as JSON'"
echo "  picoclaw-ops agent -m 'NOC triage next steps for slow web issue'"
