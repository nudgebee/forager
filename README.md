# Forager

[![CI](https://github.com/nudgebee/forager/actions/workflows/ci.yml/badge.svg)](https://github.com/nudgebee/forager/actions/workflows/ci.yml)
[![CodeQL](https://github.com/nudgebee/forager/actions/workflows/codeql.yml/badge.svg)](https://github.com/nudgebee/forager/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/nudgebee/forager/badge)](https://scorecard.dev/viewer/?uri=github.com/nudgebee/forager)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

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

## Try VM discovery without setting anything up

Discovery finds machines on a network and lists the packages installed on
each, over SSH, with nothing installed on the machines themselves. You can
run it straight from the binary — no account, no relay, no config file.

```bash
# macOS (arm64); swap for your platform from the releases page
curl -fsSL -o forager \
  https://github.com/nudgebee/forager/releases/download/v0.1.4-rc.5/nudgebee-forager-darwin-arm64
chmod +x forager

# What is on this network?
./forager sweep --cidr 192.168.1.0/24 --ports 22
```

```json
{
  "addresses_scanned": 254,
  "hosts": [
    {"ip": "192.168.1.50", "open_ports": [22], "mac": "aa:bb:cc:dd:ee:ff",
     "rdns": "web-01.lan", "sources": ["tcp", "arp"]}
  ]
}
```

To list installed packages you need two things: a read-only SSH login on the
target, and a signed content pack — the file that says which commands to run.
Packs are signed so the agent never runs collection commands it cannot
attribute, which is why there is no flag to skip verification.

```bash
# Make a key and sign the example pack
PRIV=$(./forager pack keygen)          # public key is printed to stderr
./forager pack sign docs/content-packs/linux-inventory-example.yaml --key "$PRIV"

# Collect from a host you can SSH into
./forager inventory \
  --cidr 192.168.1.0/24 \
  --targets 192.168.1.50 \
  --user nudgebee-ro --key ~/.ssh/id_ed25519 \
  --pack docs/content-packs/linux-inventory-example.yaml \
  --pack-key <public key from keygen>
```

Results go to stdout as JSON and logs to stderr, so output pipes into `jq`.
`mac` appears only for hosts on the same network segment, and `rdns` only
when reverse DNS resolves — a host missing either is normal, not an error.

Notes worth knowing:

- `--cidr` is required for both commands. It bounds what can be contacted, so
  a mistyped target is refused rather than reached.
- Scanning a network looks like an attack to security tooling. On anything
  you do not own, tell whoever runs intrusion detection first.
- `--rate-pps` defaults to 100 and can be lowered. Sweeps use ordinary TCP
  connections, not crafted packets.
- On the target, `nudgebee-ro` needs only an SSH key and permission to run
  read-only commands. Nothing is written or changed.

Full flag reference, output shapes and troubleshooting are in
[docs/cli.md](docs/cli.md). `./forager help` lists the commands.

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

- [Running discovery from the CLI](docs/cli.md) — sweep, inventory and
  content packs without a relay, with flags, output shapes and what the
  common failures mean.
- [Architecture](docs/architecture.md) — overview and request flow.
- [Configuration](docs/configuration.md) — config file, env vars, secret
  providers.
- [Connection lifecycle](docs/connection-lifecycle.md) — WS reconnect,
  state machine.
- [Proxy modules](docs/proxy-modules.md) — per-module config and creds.
- [Request flow](docs/request-flow.md) — how a request travels end-to-end.

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev loop,
PR guidelines, and the CLA requirement.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
