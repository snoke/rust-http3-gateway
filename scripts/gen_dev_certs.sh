#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs"

mkdir -p "${CERT_DIR}"

CERT_PEM="${CERT_DIR}/dev_cert.pem"
KEY_PEM="${CERT_DIR}/dev_key.pem"

if [[ -f "${CERT_PEM}" && -f "${KEY_PEM}" ]]; then
  # We need a *leaf* server cert. Some quick-and-dirty OpenSSL one-liners produce CA:TRUE,
  # which Chromium rejects for server auth (even if you try to pin it for WebTransport).
  if openssl x509 -in "${CERT_PEM}" -noout -text 2>/dev/null | grep -q "CA:FALSE"; then
    echo "Dev certs already exist: ${CERT_DIR}"
    exit 0
  fi

  echo "Existing dev cert is not a leaf server cert (expected CA:FALSE). Regenerating..."
fi

echo "Generating self-signed dev certs into ${CERT_DIR}"

tmp_cfg="$(mktemp)"
cat > "${tmp_cfg}" <<'EOF'
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3_req

[dn]
CN = localhost

[v3_req]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -keyout "${KEY_PEM}" \
  -out "${CERT_PEM}" \
  -config "${tmp_cfg}" \
  -extensions v3_req

rm -f "${tmp_cfg}"
chmod 600 "${KEY_PEM}"

echo "Wrote:"
echo "  ${CERT_PEM}"
echo "  ${KEY_PEM}"
