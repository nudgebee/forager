# Forager Architecture

Forager is a lightweight agent that runs in customer environments (VMs, containers) and proxies requests from Nudgebee's cloud platform to customer datasources (databases, HTTP APIs, MCP servers, etc.). Customers never need to expose their datasources to the internet.

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Nudgebee Cloud                                                        │
│                                                                        │
│  Cloud API ──> Relay Server ──> RabbitMQ                               │
│                     ▲                │                                  │
│                     │ HTTP response  │ Per-account queue                │
│                     │                ▼                                  │
│                Relay Server ◄── RabbitMQ reply queue                    │
└──────────────────────┬─────────────────────────────────────────────────┘
                       │ WebSocket (persistent, outbound from agent)
                       │
┌──────────────────────▼─────────────────────────────────────────────────┐
│  Customer Environment                                                  │
│                                                                        │
│  Forager Agent                                                         │
│  ├─ WS Client (connects to relay, auto-reconnect)                      │
│  ├─ Handler (routes messages to proxy modules)                         │
│  ├─ Registry (manages proxy instances by datasource ID)                │
│  └─ Proxy Modules                                                      │
│     ├─ db-proxy     → PostgreSQL, MySQL, MSSQL, ClickHouse, Oracle     │
│     ├─ http-proxy   → Any HTTP API (Grafana, Prometheus, custom)       │
│     ├─ mcp-proxy    → MCP servers (HTTP, stdio, SSE transports)        │
│     ├─ mongo-proxy  → MongoDB                                          │
│     ├─ redis-proxy  → Redis                                            │
│     ├─ kafka-proxy  → Kafka                                            │
│     └─ ssh-proxy    → SSH tunnels                                      │
└────────────────────────────────────────────────────────────────────────┘
```

## Connection Lifecycle

### 1. Startup

```
main.go
  ├─ Load config (forager.yaml or env vars)
  ├─ Initialize credential store (encrypted at rest)
  ├─ Initialize proxy registry
  ├─ Configure local datasources from config file
  ├─ Create WS client with handler
  ├─ Wire reporters (inventory, metadata, health)
  └─ client.Run() — blocks with auto-reconnect
```

### 2. WebSocket Connection

The agent initiates an outbound WebSocket connection to the relay server. The relay never connects inbound to the agent.

```
Agent                          Relay Server
  │                                │
  │── WS connect (Basic auth) ───>│  Authorization: Basic base64(key:secret)
  │                                │
  │── Greeting ──────────────────>│  {"action":"auth","agent_type":"proxy",
  │                                │   "version":"1.0.0","capabilities":{...}}
  │                                │
  │── Inventory ─────────────────>│  {"action":"datasource_inventory",
  │                                │   "datasources":[{id,type,proxy_type,name}]}
  │                                │
  │── Metadata (async) ─────────>│  {"action":"datasource_metadata",
  │                                │   "metadata":{"local:pg":{"version":"16.4",...}}}
  │                                │
  │◄─ Ping/Pong (30s interval) ─>│  Keep-alive
  │                                │
  │── Health (60s interval) ────>│  {"action":"datasource_health_update",
  │                                │   "datasources":{"local:pg":{"status":"healthy"}}}
```

**Auto-reconnect:** On disconnect, the agent reconnects with exponential backoff (3s → 6s → 12s → ... → 30s max).

### 3. Config Sync

The cloud can push datasource configurations at any time via WebSocket:

```
Relay ──> Agent: {"action":"datasource_config_sync", "datasources":[...]}
Agent ──> Relay: {"action":"datasource_config_sync_ack", "status":"ok"}
```

Each datasource in the sync includes:
- `id`, `type`, `proxy_type`, `name`
- `config` — transport-specific settings (host, port, URL, etc.)
- `credentials` — auth credentials (or reference to secret provider)
- `credential_source` — where creds come from: `cloud_push`, `local`, `aws_secrets_manager`, etc.

The handler creates/reconfigures proxy instances and removes any datasources not in the new config.

## Request Flow

### Cloud → Agent → Datasource → Agent → Cloud

```
1. Cloud API receives request (e.g., run SQL query, call MCP tool)
2. Relay server serializes request, publishes to RabbitMQ queue
   Queue: relay_requests_{account_id}_proxy
3. Relay's WebSocket handler consumes from queue, sends to agent over WS
4. Agent's readLoop receives message, spawns goroutine for processing
5. Handler routes to appropriate proxy module based on message format:
   - Action request (has body.action_name) → handleActionRequest
   - HTTP request (has method + url) → handleHTTPRequest
6. Proxy module executes against the datasource
7. Response sent back over WS with matching request_id
8. Relay matches response by correlation ID, returns to HTTP caller
```

### Message Routing in Handler

```go
// handler.go — HandleMessage
switch {
case action == "datasource_config_sync":
    → handleConfigSync()        // Reconfigure all proxies

case body.action_name != "":
    → handleActionRequest()     // DB queries, MCP calls, SSH commands
    → routes by datasource_id from params

case url != "":
    → handleHTTPRequest()       // HTTP proxy (Grafana, Prometheus, etc.)
    → routes to first http-proxy
}
```

### Action Request Format

Sent by cloud for DB queries, MCP tool calls, etc.:

```json
{
  "request_id": "abc-123",
  "body": {
    "action_name": "run_query",
    "action_params": {
      "datasource_id": "local:my-postgres",
      "query": "SELECT version()"
    }
  }
}
```

### HTTP Proxy Request Format

Sent by cloud for Grafana/Prometheus/custom HTTP APIs:

```json
{
  "request_id": "abc-123",
  "method": "GET",
  "url": "/api/v1/query?query=up",
  "header": {"Authorization": ["Bearer token"]},
  "body": ""
}
```

### Response Format

All responses follow this structure:

```json
{
  "request_id": "abc-123",
  "status_code": 200,
  "data": "..."
}
```

## Proxy Modules

Each proxy implements the `Proxy` interface:

```go
type Proxy interface {
    Type() string
    Configure(config map[string]any, creds map[string]string) error
    HandleRequest(ctx context.Context, req *ActionRequest) (*ActionResponse, error)
    HealthCheck(ctx context.Context) error
    Close() error
}
```

Optional `MetadataCollector` interface for reporting version/connection info:

```go
type MetadataCollector interface {
    CollectMetadata(ctx context.Context) (map[string]any, error)
}
```

### DB Proxy (`db-proxy`)

Supports PostgreSQL, MySQL, MSSQL, ClickHouse, Oracle. Opens a connection pool, executes SQL queries, returns results as JSON.

### HTTP Proxy (`http-proxy`)

Generic reverse proxy for any HTTP API. Supports auth injection: `basic`, `bearer`, `custom_header`. Forwards method, URL, headers, body. Base64-encodes response body.

### MCP Proxy (`mcp-proxy`)

Forwards JSON-RPC requests to MCP (Model Context Protocol) servers. Supports three transports:

| Transport | How it works |
|-----------|-------------|
| `http` (default) | POST JSON-RPC to server URL |
| `stdio` | Spawn process, write to stdin, read from stdout |
| `sse` | POST to SSE endpoint, parse `data:` lines from event stream |

Auth support (for `http` and `sse`): `basic`, `bearer`, `custom_header`, `api_key`.

**stdio transport details:**
- Lazy-starts the subprocess on first request
- Requests are serialized (mutex) since stdio is single-channel
- Process lifecycle: SIGTERM → 5s grace → SIGKILL
- Stderr is captured and logged

### MongoDB Proxy (`mongo-proxy`)

Connects via MongoDB driver. Executes commands on specified databases.

### Redis Proxy (`redis-proxy`)

Connects via go-redis. Executes Redis commands, parses responses.

### Kafka Proxy (`kafka-proxy`)

Connects via Sarama client. Lists topics, describes groups, fetches metadata.

### SSH Proxy (`ssh-proxy`)

Establishes SSH connection. Executes commands remotely.

## Credential Management

Three credential sources:

| Source | How it works |
|--------|-------------|
| `local` | Credentials in `forager.yaml` config file |
| `cloud_push` | Encrypted credentials pushed via config sync, stored locally in `{data_dir}/credentials.enc` |
| `aws_secrets_manager`, `gcp_secret_manager`, `azure_key_vault` | Fetched from cloud secret providers at configure time |

Cloud-pushed credentials are encrypted at rest using AES-GCM with a key derived from the agent's `access_secret`.

## Configuration

### forager.yaml

```yaml
relay_url: wss://relay.nudgebee.com/register
access_key: <agent-key>
access_secret: <agent-secret>
data_dir: /var/lib/nudgebee

# Local datasources (optional — cloud can also push configs)
datasources:
  - name: my-postgres
    type: postgresql
    host: localhost
    port: 5432
    database: mydb
    credentials:
      username: user
      password: pass

  - name: my-mcp
    type: mcp
    url: http://localhost:8080/mcp
    credentials:
      auth_type: bearer
      bearer_token: sk-...

# Cloud secret provider configs (optional)
aws:
  region: us-east-1
```

### Environment Variables

All config values can be set via `NB_` prefixed env vars:

```
NB_RELAY_URL=wss://relay.nudgebee.com/register
NB_ACCESS_KEY=key
NB_ACCESS_SECRET=secret
NB_DATA_DIR=/var/lib/nudgebee
```

## Concurrency Model

```
main goroutine
  └─ client.Run() — reconnect loop
       └─ connectAndServe() — per-connection
            ├─ readLoop      — reads WS messages, spawns handler goroutines
            ├─ writeLoop     — drains sendCh to WS (serialized writes)
            ├─ pingLoop      — sends WS pings every 30s
            ├─ healthReport   — sends health every 60s
            └─ sendMetadata   — one-shot on connect
```

Each incoming request is handled in its own goroutine (spawned by readLoop). Proxy modules manage their own connection pools. The WS write path is serialized through a buffered channel (capacity 64).
