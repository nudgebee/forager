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

**Config:** `base_url`, `auth_type`, `tls_skip_verify`, `follow_redirects` (same-origin only), `max_response_bytes` (default 256 MiB; larger upstream responses fail instead of exhausting memory)
**Auth types:** `basic`, `bearer`, `custom_header`
**Creds:**
- basic: `username`, `password`
- bearer: `bearer_token`
- custom_header: `custom_header_name`, `custom_header_value`
- TLS (optional, PEM): `ca_cert` to trust a private CA, `client_cert` + `client_key` for mTLS. Each also accepts a `*_file` path (e.g. `ca_cert_file`) in local YAML so Kubernetes can mount a Secret.

In local YAML, `tls_skip_verify`, `follow_redirects` and `max_response_bytes` are datasource fields next to `url`.

### Prometheus datasources

`type: prometheus` uses this proxy. Its health check requires a 2xx from `/-/ready`, falling back to `/api/v1/status/buildinfo` for Prometheus-compatible stores (Mimir, VictoriaMetrics, Thanos). A 404 or 401 from a wrong host or reverse proxy is reported as an error. Other `http` datasources keep the looser check (any status below 500).

### Customer-run metrics store

For VM metrics the customer runs the store and the agents write to it directly. The forager only carries queries:

```
node-agent (on each VM) --remote-write--> customer Prometheus <--queries-- forager <--relay-- server
```

Requirements for the store:
- Remote-write receiving enabled (Prometheus `--web.enable-remote-write-receiver`, or the equivalent in Mimir/VictoriaMetrics).
- Write authentication (basic or bearer) so only the VMs' agents can push.
- TLS on both the write and query endpoints. Use `ca_cert` / mTLS above when the certificate comes from a private CA.
- The forager host must be able to reach the query endpoint. The VMs only need to reach the write endpoint.

With more than one forager in an account the relay queue is shared, so a request can land on a forager that cannot see the store. Foragers expose what the server needs to avoid that:
- `datasource_health_update` carries `reachable`, `latency_ms` and `last_success` per datasource. Route to a forager where the datasource is reachable.
- Error responses carry `error_code`: `datasource_not_found` (this forager has no such datasource) and `upstream_unreachable` (network-level failure to the store) are safe to retry on another forager. An upstream HTTP error (including 4xx/5xx from the store) is passed through unchanged and should not be retried elsewhere.
- A health update is sent immediately after each `datasource_config_sync`, so a newly connected store reports without waiting for the next interval.
- A request without `datasource_id` is only accepted when exactly one `http-proxy` datasource exists; otherwise it fails with `ambiguous_datasource` (HTTP 400). Always send `datasource_id`.

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

### http/sse session handling

- Opens an MCP session with the `initialize` handshake (plus `notifications/initialized`) and sends `Mcp-Session-Id` on later requests; servers that return no session id are used sessionless
- One upstream session per `session_id` request param, so concurrent conversations don't share state on stateful servers (browser, shell, database); requests without `session_id` share one session
- Sessions close after 30 min idle (each use extends it) and on proxy close, via a best-effort HTTP `DELETE`
- A `404` for a sent session (server restarted or expired it) re-initializes and retries once
- Replies framed as SSE are unwrapped to the JSON-RPC payload

### stdio transport details

- Lazy-starts the subprocess on first request
- Requests are serialized (mutex) since stdio is single-channel
- JSON-RPC messages are newline-delimited
- Process lifecycle: SIGTERM → 5s grace → SIGKILL
- Stderr is captured and logged
- Health check: `Signal(0)` to verify process is alive
- One process per datasource, shared by all callers: `session_id` does not isolate state on stdio

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
