# Rust Realtime Supergateway (Core Mode)

Stateless Rust gateway with a transport-agnostic core and pluggable transport adapters.
It bridges client events to Redis streams and pushes outbound events back to connected clients.

This gateway is designed for **core mode** (broker-first) and does **not** use webhook/terminator flows.

## Capabilities
- Shared gateway core for:
  - AuthN/AuthZ
  - Event envelope/schema
  - Presence/subscriptions
  - Conversation/message routing
  - Broker integration (Redis streams)
  - Idempotency/retry primitives
- Transport adapters:
  - `webtransport` (HTTP/3 QUIC)
  - `websocket` (WS)
- Auth handshake on first client stream (JWT)
- Redis stream bridge:
  - inbound from clients → `ws.inbox`
  - outbound to clients ← `ws.outbox`
  - connection lifecycle → `ws.events`
- Optional HTTP API to publish events to connected clients

## Transport & Framing
Set transport via:
- `GATEWAY_TRANSPORT=webtransport` (default)
- `GATEWAY_TRANSPORT=websocket`

### WebTransport framing
**Framing:** one JSON message per stream (no length-prefix).  
**Client → Gateway:** open a bidirectional stream and write a single JSON payload.  
**Gateway → Client:** gateway opens a unidirectional stream per message and writes JSON.

Datagrams are supported and are parsed as JSON in the same way.

### WebSocket framing
One JSON message per text frame.

## Auth (WebTransport)
Browsers don’t allow custom headers for WebTransport. The gateway expects:
```
{ "type": "auth", "token": "<JWT>" }
```
as the **first** bidirectional stream message within 5 seconds of session start.

On success the gateway replies:
```
{ "type": "auth_ok", "user_id": "<subject>" }
```

If auth fails, the session is closed (no auth_ok).

## Redis Streams (Core Mode)
The gateway publishes to:
- `REDIS_INBOX_STREAM` (default: `ws.inbox`)  
  events of type `message_received` with `message`, `raw`, and connection metadata.
- `REDIS_EVENTS_STREAM` (default: `ws.events`)  
  events `connected` / `disconnected`.

The gateway consumes from:
- `REDIS_STREAM` (default: `ws.outbox`)  
  expects entries containing a JSON `payload` and `subjects` array.

Outbound entries are converted to:
```
{ "type": "event", "payload": <payload> }
```
and sent to each subject (e.g. `user:alice@example.com`).

## HTTP API (optional)
`POST /internal/publish`  
Body:
```json
{ "subjects": ["user:alice@example.com"], "payload": { "type": "chat", "text": "hi" } }
```

If `GATEWAY_API_KEY` is set, include it via `X-Api-Key` header (or `api_key` field).

Other endpoints:
- `GET /internal/connections`
- `GET /internal/users/:user_id/connections`
- `GET /health`
- `GET /ready`

## Dev
Generate a **leaf** server cert (required by Chromium for WebTransport):
```bash
./scripts/gen_dev_certs.sh
```

Compute a cert pin (base64 SHA‑256):
```bash
openssl x509 -in certs/dev_cert.pem -outform der | openssl dgst -sha256 -binary | base64
```

Run (WebTransport):
```bash
CERT_PEMFILE=./certs/dev_cert.pem \
KEY_PEMFILE=./certs/dev_key.pem \
REDIS_DSN=redis://localhost:6379 \
GATEWAY_TRANSPORT=webtransport \
WEBTRANSPORT_PORT=4433 \
HTTP_API_PORT=8080 \
cargo run
```

Run (WebSocket):
```bash
REDIS_DSN=redis://localhost:6379 \
GATEWAY_TRANSPORT=websocket \
WEBSOCKET_PORT=8081 \
HTTP_API_PORT=8080 \
cargo run
```

## Environment Variables
- `JWT_ALG` (`RS256`/`HS256`/…)
- `GATEWAY_TRANSPORT` (`webtransport` | `websocket`)
- `JWT_USER_ID_CLAIM` (default: `user_id`)
- `JWT_PUBLIC_KEY` or `JWT_PUBLIC_KEY_FILE`
- `JWT_JWKS_URL` (optional)
- `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_LEEWAY`
- `GATEWAY_API_KEY` (optional, HTTP API auth)
- `REDIS_DSN`
- `REDIS_STREAM` (outbox, default `ws.outbox`)
- `REDIS_INBOX_STREAM` (default `ws.inbox`)
- `REDIS_EVENTS_STREAM` (default `ws.events`)
- `WEBTRANSPORT_PORT` (default `4433`)
- `WEBSOCKET_PORT` (default `8081`)
- `HTTP_API_PORT` (default `8080`)
- `CERT_PEMFILE` / `KEY_PEMFILE`

## Browser Support
- Chrome / Edge: enable `#webtransport-developer-mode` and `#enable-quic`.
- Firefox: WebTransport is still experimental (Nightly only).
