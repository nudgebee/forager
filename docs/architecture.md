# Forager Architecture

Forager is a lightweight agent that runs in customer environments (VMs, containers) and proxies requests from Nudgebee's cloud platform to customer datasources (databases, HTTP APIs, MCP servers, etc.). Customers never need to expose their datasources to the internet.

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

## Documentation

- [Connection Lifecycle](connection-lifecycle.md) — startup, WebSocket handshake, auto-reconnect, config sync
- [Request Flow](request-flow.md) — how requests route from cloud to datasource and back, message formats
- [Proxy Modules](proxy-modules.md) — all proxy types, transports, auth patterns
- [Configuration](configuration.md) — forager.yaml, environment variables, credential management
