#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

TLS_DIR="${AZAZEL_TLS_DIR:-/etc/azazel-edge/tls}"
CA_DIR="${TLS_DIR}/ca"
CA_KEY="${CA_DIR}/azazel-edge-local-ca.key"
CA_CERT="${CA_DIR}/azazel-edge-local-ca.crt"
CA_SERIAL="${CA_DIR}/azazel-edge-local-ca.srl"
SERVER_KEY="${TLS_DIR}/webui.key"
SERVER_CSR="${TLS_DIR}/webui.csr"
SERVER_CERT="${TLS_DIR}/webui.crt"
SERVER_EXT="${TLS_DIR}/webui.ext"
CA_DAYS="${AZAZEL_CA_DAYS:-3650}"
SERVER_DAYS="${AZAZEL_SERVER_DAYS:-825}"
CN="${AZAZEL_TLS_CN:-$(hostname -f 2>/dev/null || hostname)}"
MGMT_IP="${MGMT_IP:-$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}')}"
INTERNAL_IP="${AZAZEL_INTERNAL_IP:-$(ip -4 -o addr show br0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)}"
EXTRA_SANS="${AZAZEL_TLS_EXTRA_SANS:-}"
TRUST_CA="/usr/local/share/ca-certificates/azazel-edge-local-ca.crt"
CA_EXPORT="/var/lib/azazel-edge/public/azazel-edge-local-ca.crt"

echo "[ca] Installing openssl + ca-certificates"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y openssl ca-certificates

install -d "$TLS_DIR" "$CA_DIR" /var/lib/azazel-edge/public

recreate_ca=0
if [[ ! -s "$CA_KEY" || ! -s "$CA_CERT" ]]; then
  recreate_ca=1
else
  if ! openssl x509 -in "$CA_CERT" -noout -text | grep -q "CA:TRUE"; then
    recreate_ca=1
  fi
  if ! openssl x509 -in "$CA_CERT" -noout -text | grep -q "Certificate Sign"; then
    recreate_ca=1
  fi
fi

if (( recreate_ca == 1 )); then
  echo "[ca] Creating local root CA"
  rm -f "$CA_CERT" "$CA_KEY" "$CA_SERIAL"
  openssl genrsa -out "$CA_KEY" 4096
  openssl req -x509 -new -nodes -sha256 \
    -key "$CA_KEY" \
    -days "$CA_DAYS" \
    -subj "/CN=Azazel-Edge Local Root CA/O=Azazel-Edge" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$CA_CERT"
fi

echo "[ca] Creating server certificate signed by local CA"
openssl genrsa -out "$SERVER_KEY" 2048
openssl req -new -key "$SERVER_KEY" -subj "/CN=${CN}" -out "$SERVER_CSR"

{
  echo "authorityKeyIdentifier=keyid,issuer"
  echo "basicConstraints=CA:FALSE"
  echo "keyUsage=digitalSignature,keyEncipherment"
  echo "extendedKeyUsage=serverAuth"
  echo "subjectAltName=@alt_names"
  echo "[alt_names]"
  echo "DNS.1=${CN}"
  echo "DNS.2=$(hostname -s 2>/dev/null || hostname)"
  echo "DNS.3=localhost"
} > "$SERVER_EXT"

idx_ip=1
if [[ -n "$MGMT_IP" ]]; then
  echo "IP.${idx_ip}=${MGMT_IP}" >> "$SERVER_EXT"
  idx_ip=$((idx_ip + 1))
fi
if [[ -n "$INTERNAL_IP" && "$INTERNAL_IP" != "$MGMT_IP" ]]; then
  echo "IP.${idx_ip}=${INTERNAL_IP}" >> "$SERVER_EXT"
  idx_ip=$((idx_ip + 1))
fi
echo "IP.${idx_ip}=127.0.0.1" >> "$SERVER_EXT"
idx_ip=$((idx_ip + 1))

if [[ -n "$EXTRA_SANS" ]]; then
  idx_dns=10
  if (( idx_ip < 10 )); then
    idx_ip=10
  fi
  IFS=',' read -r -a sans <<< "$EXTRA_SANS"
  for san in "${sans[@]}"; do
    san_trimmed="$(echo "$san" | xargs)"
    [[ -z "$san_trimmed" ]] && continue
    if [[ "$san_trimmed" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "IP.${idx_ip}=${san_trimmed}" >> "$SERVER_EXT"
      idx_ip=$((idx_ip + 1))
    else
      echo "DNS.${idx_dns}=${san_trimmed}" >> "$SERVER_EXT"
      idx_dns=$((idx_dns + 1))
    fi
  done
fi

openssl x509 -req -sha256 \
  -in "$SERVER_CSR" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -CAserial "$CA_SERIAL" \
  -out "$SERVER_CERT" \
  -days "$SERVER_DAYS" \
  -extfile "$SERVER_EXT"

install -m 0644 "$CA_CERT" "$TRUST_CA"
update-ca-certificates

install -m 0644 "$CA_CERT" "$CA_EXPORT"
chmod 0600 "$SERVER_KEY"
chmod 0644 "$SERVER_CERT" "$CA_CERT"

cat > /etc/azazel-edge/ca-distribution.txt <<EOF
Azazel-Edge Local CA distribution:
1) Copy this CA file to client devices:
   ${CA_EXPORT}
2) Import as trusted Root CA on each client.
3) Access WebUI with a hostname/IP contained in SAN:
   CN=${CN}
   MGMT_IP=${MGMT_IP}
   INTERNAL_IP=${INTERNAL_IP}
EOF

echo "[ca] Local CA ready: ${CA_CERT}"
echo "[ca] Server cert ready: ${SERVER_CERT}"
echo "[ca] Client distribution file: ${CA_EXPORT}"
