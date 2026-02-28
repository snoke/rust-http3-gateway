# Rust HTTP/3 / WebTransport Gateway

Rust gateway that terminates TLS+QUIC (HTTP/3) and accepts browser WebTransport sessions (streams + datagrams).
It also exposes a small publisher HTTP API (`POST /internal/publish`) to send datagrams to an existing connection by `connection_id`.

## Dev
Build:
```bash
cargo build
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
