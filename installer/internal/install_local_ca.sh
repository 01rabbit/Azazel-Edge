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
SHORT_NAME="$(hostname -s 2>/dev/null || hostname)"
# The server certificate names the device only as the LAN reaches it
# (Edge#477): the br0 address, the host name, its mDNS name (.local) and
# localhost/127.0.0.1. The uplink (WAN) address is not put in: nginx answers
# 80/443 to loopback and the LAN only (install_https_proxy.sh), the host
# firewall refuses the WAN, and set_dev_remote_access.sh MODE=open opens only
# SSH and mDNS, so the address would only tell the WAN side the device's
# address through the certificate.
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
  # Read into a variable first: piped into `grep -q`, openssl is killed by
  # SIGPIPE when grep exits at the match, and pipefail would read a good CA
  # as a bad one and recreate it on every run.
  ca_text="$(openssl x509 -in "$CA_CERT" -noout -text 2>/dev/null)" || ca_text=""
  if ! grep -q "CA:TRUE" <<<"$ca_text"; then
    recreate_ca=1
  fi
  if ! grep -q "Certificate Sign" <<<"$ca_text"; then
    recreate_ca=1
  fi
fi

if (( recreate_ca == 1 )); then
  echo "[ca] Creating local root CA"
  rm -f "$CA_CERT" "$CA_KEY" "$CA_SERIAL"
  (umask 077; openssl genrsa -out "$CA_KEY" 4096)
  chmod 0600 "$CA_KEY"
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
(umask 077; openssl genrsa -out "$SERVER_KEY" 2048)
chmod 0600 "$SERVER_KEY"
openssl req -new -key "$SERVER_KEY" -subj "/CN=${CN}" -out "$SERVER_CSR"

write_server_ext() {
  local out="$1" idx_ip=1 idx_dns=10 idx_name=1 seen_dns="" name san san_trimmed
  local -a sans
  {
    echo "authorityKeyIdentifier=keyid,issuer"
    echo "basicConstraints=CA:FALSE"
    echo "keyUsage=digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=serverAuth"
    echo "subjectAltName=@alt_names"
    echo "[alt_names]"
    # The mDNS name (<short host name>.local, as avahi announces it on the
    # LAN) is how the device is reached on site. A name already listed (e.g.
    # hostname -f equal to hostname -s) is written once.
    for name in "$CN" "$SHORT_NAME" "${SHORT_NAME}.local" localhost; do
      [[ -z "$name" || " ${seen_dns} " == *" ${name} "* ]] && continue
      seen_dns="${seen_dns} ${name}"
      echo "DNS.${idx_name}=${name}"
      idx_name=$((idx_name + 1))
    done
    if [[ -n "$INTERNAL_IP" ]]; then
      echo "IP.${idx_ip}=${INTERNAL_IP}"
      idx_ip=$((idx_ip + 1))
    fi
    echo "IP.${idx_ip}=127.0.0.1"
    idx_ip=$((idx_ip + 1))
    if [[ -n "$EXTRA_SANS" ]]; then
      if (( idx_ip < 10 )); then
        idx_ip=10
      fi
      IFS=',' read -r -a sans <<< "$EXTRA_SANS"
      for san in "${sans[@]}"; do
        san_trimmed="$(echo "$san" | xargs)"
        [[ -z "$san_trimmed" ]] && continue
        if [[ "$san_trimmed" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
          echo "IP.${idx_ip}=${san_trimmed}"
          idx_ip=$((idx_ip + 1))
        else
          echo "DNS.${idx_dns}=${san_trimmed}"
          idx_dns=$((idx_dns + 1))
        fi
      done
    fi
  } > "$out"
}

if [[ -z "$INTERNAL_IP" ]]; then
  echo "[ca] WARNING: br0 has no IPv4 address; the certificate names only the host name and localhost/127.0.0.1" >&2
fi
write_server_ext "$SERVER_EXT"

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
   INTERNAL_IP=${INTERNAL_IP}
EOF

echo "[ca] Local CA ready: ${CA_CERT}"
echo "[ca] Server cert ready: ${SERVER_CERT}"
echo "[ca] Client distribution file: ${CA_EXPORT}"
