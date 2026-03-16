# Remodex Relay

A high-performance WebSocket relay for [Remodex](https://github.com/Emanuele-web04/remodex), rewritten in Rust. This project implements the relay component that enables secure, end-to-end encrypted communication between the Mac bridge and iPhone client.

The original Remodex project provides a Node.js relay implementation. This project rewrites the relay in Rust for better performance and lower resource usage, with full Docker support.

## Public Relay

A public relay server is available for immediate use:

```
wss://relay.owo.nz
```

The server is located in Japan with optimized network routing for China mainland carriers (China Mobile, China Unicom, China Telecom) - typically under 30ms latency.

To use it, set the relay URL before starting Remodex:

```bash
REMODEX_RELAY="wss://relay.owo.nz/relay" remodex up
```

## Self-Hosting

### Docker (Recommended)

```bash
docker run -d \
  --name remodex-relay \
  -p 127.0.0.1:9000:9000 \
  ghcr.io/missuo/remodex-relay:latest
```

Or with Docker Compose:

```yaml
services:
  relay:
    image: ghcr.io/missuo/remodex-relay:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:9000:9000"
    volumes:
      - relay-data:/data
    environment:
      PORT: 9000
      REMODEX_ENABLE_PUSH_SERVICE: false
      REMODEX_TRUST_PROXY: false

volumes:
  relay-data:
```

### Build from Source

```bash
cargo build --release
PORT=9000 ./target/release/remodex-relay
```

## Reverse Proxy

A reverse proxy with TLS is required for `wss://` connections.

### Caddy

```
relay.example.com {
    reverse_proxy 127.0.0.1:9000
}
```

Caddy automatically handles TLS certificates and WebSocket upgrades.

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

When using Nginx, set `REMODEX_TRUST_PROXY=true` to correctly resolve client IPs from `X-Real-IP` / `X-Forwarded-For` headers.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9000` | Listening port |
| `REMODEX_TRUST_PROXY` | `false` | Trust `X-Real-IP` / `X-Forwarded-For` headers |
| `REMODEX_ENABLE_PUSH_SERVICE` | `false` | Enable APNs push notification service |
| `REMODEX_PUSH_STATE_FILE` | `~/.codex/remodex/push-state.json` | Path for push state persistence |
| `REMODEX_APNS_TEAM_ID` | - | Apple Team ID (push service) |
| `REMODEX_APNS_KEY_ID` | - | APNs Key ID (push service) |
| `REMODEX_APNS_BUNDLE_ID` | - | iOS app bundle ID (push service) |
| `REMODEX_APNS_PRIVATE_KEY` | - | APNs private key PEM content (push service) |
| `REMODEX_APNS_PRIVATE_KEY_FILE` | - | Path to APNs private key file (push service) |

## License

MIT
