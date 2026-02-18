# Forager Architecture

Forager is a lightweight agent that runs in customer environments (VMs, containers) and proxies requests from Nudgebee's cloud platform to customer datasources (databases, HTTP APIs, MCP servers, etc.). Customers never need to expose their datasources to the internet.

```mermaid
graph TB
    subgraph cloud["Nudgebee Cloud"]
        api["Cloud API"]
        relay["Relay Server"]
        rmq["RabbitMQ"]
        rmq_reply["RabbitMQ Reply Queue"]

        api -->|request| relay
        relay -->|publish| rmq
        rmq_reply -->|HTTP response| relay
    end

    subgraph customer["Customer Environment"]
        subgraph forager["Forager Agent"]
            ws["WS Client<br/><i>auto-reconnect</i>"]
            handler["Handler<br/><i>routes messages</i>"]
            registry["Registry<br/><i>manages proxies by datasource ID</i>"]

            ws --> handler --> registry
        end

        subgraph proxies["Proxy Modules"]
            db["db-proxy<br/><i>PostgreSQL, MySQL, MSSQL, ClickHouse, Oracle</i>"]
            http["http-proxy<br/><i>Any HTTP API</i>"]
            mcp["mcp-proxy<br/><i>HTTP, stdio, SSE transports</i>"]
            mongo["mongo-proxy<br/><i>MongoDB</i>"]
            redis["redis-proxy<br/><i>Redis</i>"]
            kafka["kafka-proxy<br/><i>Kafka</i>"]
            ssh["ssh-proxy<br/><i>SSH tunnels</i>"]
        end

        registry --> proxies
    end

    rmq -->|per-account queue| ws
    ws -->|response| rmq_reply

    style cloud fill:#e8f4fd,stroke:#1a73e8
    style customer fill:#fef7e0,stroke:#f9a825
    style forager fill:#fff,stroke:#666
    style proxies fill:#f3e8fd,stroke:#7b1fa2
```

## Documentation

- [Connection Lifecycle](connection-lifecycle.md) — startup, WebSocket handshake, auto-reconnect, config sync
- [Request Flow](request-flow.md) — how requests route from cloud to datasource and back, message formats
- [Proxy Modules](proxy-modules.md) — all proxy types, transports, auth patterns
- [Configuration](configuration.md) — forager.yaml, environment variables, credential management
