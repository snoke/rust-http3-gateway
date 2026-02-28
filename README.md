# Rust HTTP/3 / WebTransport Gateway

Rust gateway that terminates TLS+QUIC (HTTP/3) and provides a WebTransport endpoint for browser clients.

This repo is meant to be used as part of the Symfony + HTTP/3 stack scaffold:
- `snoke/symfony-http3-gateway`

## Dev
Build:
```bash
cargo build
```

Run (see the scaffold repo for Docker Compose wiring and certificate generation).
