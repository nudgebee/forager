# Forager

Lightweight agent that runs in a customer environment (VM, container, or
Kubernetes pod) and proxies requests from Nudgebee's cloud platform to
internal datasources — databases, HTTP APIs, MCP servers, Kafka, Redis,
SSH targets, and more. Customers never need to expose those datasources
to the internet; the agent only makes outbound connections to the
Nudgebee relay.

Licensed under [Apache 2.0](LICENSE).

## What it does

```
┌──────────────────────────────┐         ┌──────────────────────────────┐
│      Nudgebee Cloud          │         │   Customer Environment       │
│                              │   wss   │                              │
│   Cloud API ──► Relay ◄──────┼─────────┼──► Forager Agent             │
│                              │         │       │                      │
└──────────────────────────────┘         │       ├──► PostgreSQL/MySQL  │
                                         │       ├──► HTTP API          │
                                         │       ├──► MCP server        │
                                         │       └──► ...               │
                                         └──────────────────────────────┘
```

The agent opens a single outbound WebSocket connection to the relay,
receives signed action requests (Ed25519), routes them to the right proxy
module by datasource ID, and returns responses. No inbound ports needed.

See [docs/architecture.md](docs/architecture.md) for the full request
flow and connection lifecycle.

## Install

### Linux

```bash
curl -fsSL https://github.com/nudgebee/forager/releases/latest/download/install.sh \
  | sudo NB_ACCESS_KEY=... NB_ACCESS_SECRET=... bash
```

Installs the binary to `/usr/local/bin/nudgebee-forager`, drops config
under `/etc/nudgebee/`, and registers a systemd unit.

### macOS

```bash
curl -fsSL https://github.com/nudgebee/forager/releases/latest/download/install-macos.sh \
  | sudo NB_ACCESS_KEY=... NB_ACCESS_SECRET=... bash
```

Installs the binary to `/usr/local/bin/nudgebee-forager`, drops config
under `/usr/local/etc/nudgebee/`, and registers a launchd daemon at
`/Library/LaunchDaemons/com.nudgebee.forager.plist` (requires root).

### Windows (PowerShell, as Administrator)

```powershell
$env:NB_ACCESS_KEY = "..."
$env:NB_ACCESS_SECRET = "..."
iwr -useb https://github.com/nudgebee/forager/releases/latest/download/install.ps1 | iex
```

### Kubernetes (Helm)

```bash
helm install forager oci://ghcr.io/nudgebee/charts/forager \
  --set forager.accessKey=... \
  --set forager.accessSecret=...
```

### Docker

```bash
docker run -d --name forager \
  -e NB_ACCESS_KEY=... \
  -e NB_ACCESS_SECRET=... \
  -v forager-data:/data \
  ghcr.io/nudgebee/forager:latest
```

The Docker image is the only build that bundles Oracle Instant Client
for `oracle` datasources. Standalone binaries (Linux/macOS/Windows) ship
without Oracle support.

### AWS (CloudFormation)

A ready-to-launch EC2 template lives at
[deploy/cloudformation/forager-ec2.yaml](deploy/cloudformation/forager-ec2.yaml).

## Configure

Minimal `forager.yaml`:

```yaml
relay_url: wss://relay.nudgebee.com/register
access_key: <agent-key>
access_secret: <agent-secret>
data_dir: /var/lib/nudgebee
```

All config values can also be set via `NB_*` environment variables
(`NB_RELAY_URL`, `NB_ACCESS_KEY`, ...). Local datasources, cloud secret
providers, and the full env-var surface are documented in
[docs/configuration.md](docs/configuration.md).

## Supported datasources

| Module       | Protocols                                              |
| ------------ | ------------------------------------------------------ |
| `db-proxy`   | PostgreSQL, MySQL, MSSQL, ClickHouse, Oracle (Docker only) |
| `http-proxy` | Any HTTP API (basic / bearer / custom-header auth)     |
| `mcp-proxy`  | Model Context Protocol (HTTP, stdio, SSE transports)   |
| `mongo-proxy`| MongoDB                                                |
| `redis-proxy`| Redis                                                  |
| `kafka-proxy`| Kafka (PLAIN / SCRAM)                                  |
| `ssh-proxy`  | SSH (password or key)                                  |

Full details and config keys in
[docs/proxy-modules.md](docs/proxy-modules.md).

## Build from source

```bash
git clone https://github.com/nudgebee/forager
cd forager
make build              # → bin/forager
make test               # unit tests with -race
make build-all          # cross-compile: linux/{amd64,arm64}, darwin/{amd64,arm64}, windows/amd64
docker build -t forager .   # local Docker image (with Oracle support)
```

## Releases

- **Docker images** — `ghcr.io/nudgebee/forager:vX.Y.Z` and `:latest`,
  multi-arch (linux/amd64 + linux/arm64), cosign-signed.
- **Standalone binaries** — attached to each
  [GitHub Release](https://github.com/nudgebee/forager/releases):
  linux/{amd64,arm64}, darwin/{amd64,arm64}, windows/amd64.
- **Helm chart** — `oci://ghcr.io/nudgebee/charts/forager`.

## Documentation

- [Architecture](docs/architecture.md) — overview and request flow.
- [Configuration](docs/configuration.md) — config file, env vars, secret
  providers.
- [Connection lifecycle](docs/connection-lifecycle.md) — WS reconnect,
  state machine.
- [Proxy modules](docs/proxy-modules.md) — per-module config and creds.
- [Request flow](docs/request-flow.md) — how a request travels end-to-end.

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev loop,
PR guidelines, and the DCO sign-off requirement.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
