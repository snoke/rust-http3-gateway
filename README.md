# Rust HTTP/3 / WebTransport Gateway

Rust gateway that terminates TLS+QUIC (HTTP/3) and accepts browser WebTransport sessions (streams + datagrams).
It also exposes a small publisher HTTP API (`POST /internal/publish`) to send datagrams to an existing connection by `connection_id`.

## Dev
Build:
```bash
cargo build
```

Generate dev certs:
```bash
./scripts/gen_dev_certs.sh
```

Run:
```bash
# Provide a leaf server cert + key (PEM)
CERT_PEMFILE=/run/certs/dev_cert.pem \
KEY_PEMFILE=/run/certs/dev_key.pem \
WEBTRANSPORT_PORT=4433 \
HTTP_API_PORT=8080 \
./target/debug/gateway
```

## Configuration
Environment variables:
- `CERT_PEMFILE` (default: `/run/certs/dev_cert.pem`)
- `KEY_PEMFILE` (default: `/run/certs/dev_key.pem`)
- `WEBTRANSPORT_PORT` (default: `4433`)
- `HTTP_API_PORT` (default: `8080`)
- `WEBHOOK_URL` (optional; enable webhook POSTs)
