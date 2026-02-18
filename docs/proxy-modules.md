# Proxy Modules

Every proxy implements the `Proxy` interface:

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

## DB Proxy (`db-proxy`)

Supports PostgreSQL, MySQL, MSSQL, ClickHouse, Oracle. Opens a connection pool, executes SQL queries, returns results as JSON.

**Config:** `host`, `port`, `database`, `db_type`
**Creds:** `username`, `password`

## HTTP Proxy (`http-proxy`)

Generic reverse proxy for any HTTP API. Forwards method, URL, headers, body. Base64-encodes response body.

**Config:** `base_url`, `auth_type`, `tls_skip_verify`
**Auth types:** `basic`, `bearer`, `custom_header`
**Creds:**
- basic: `username`, `password`
- bearer: `bearer_token`
- custom_header: `custom_header_name`, `custom_header_value`

## MCP Proxy (`mcp-proxy`)

Forwards JSON-RPC requests to MCP (Model Context Protocol) servers. Supports three transports:

| Transport | How it works |
|-----------|-------------|
| `http` (default) | POST JSON-RPC to server URL |
| `stdio` | Spawn process, write to stdin, read from stdout |
| `sse` | POST to SSE endpoint, parse `data:` lines from event stream |

**Config (http/sse):** `transport`, `url`, `auth_type`
**Config (stdio):** `transport`, `command`, `args`, `env`, `working_dir`
**Auth types:** `basic`, `bearer`, `custom_header`, `api_key`
**Creds (api_key):** `api_key_name`, `api_key_value`, `api_key_location` (`header` or `query`)

### stdio transport details

- Lazy-starts the subprocess on first request
- Requests are serialized (mutex) since stdio is single-channel
- JSON-RPC messages are newline-delimited
- Process lifecycle: SIGTERM → 5s grace → SIGKILL
- Stderr is captured and logged
- Health check: `Signal(0)` to verify process is alive

## MongoDB Proxy (`mongo-proxy`)

Connects via MongoDB driver. Executes commands on specified databases.

**Config:** `host`, `port`, `database`
**Creds:** `username`, `password`

## Redis Proxy (`redis-proxy`)

Connects via go-redis. Executes Redis commands, parses responses.

**Config:** `host`, `port`
**Creds:** `password`

## Kafka Proxy (`kafka-proxy`)

Connects via Sarama client. Lists topics, describes groups, fetches metadata.

**Config:** `brokers` (comma-separated)
**Creds:** `username`, `password`, `mechanism` (PLAIN/SCRAM)

## SSH Proxy (`ssh-proxy`)

Establishes SSH connection. Executes commands remotely.

**Config:** `host`, `port`
**Creds:** `username`, `password` or `private_key`
