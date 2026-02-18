# Connection Lifecycle

## Startup

```mermaid
graph LR
    main["main.go"] --> config["Load config<br/><i>forager.yaml or env vars</i>"]
    main --> creds["Init credential store<br/><i>encrypted at rest</i>"]
    main --> registry["Init proxy registry"]
    main --> ds["Configure local datasources"]
    main --> ws["Create WS client + handler"]
    main --> reporters["Wire reporters<br/><i>inventory, metadata, health</i>"]
    main --> run["client.Run()<br/><i>blocks with auto-reconnect</i>"]
```

## WebSocket Connection

The agent initiates an outbound WebSocket connection to the relay server. The relay never connects inbound to the agent.

```mermaid
sequenceDiagram
    participant Agent
    participant Relay as Relay Server

    Agent->>Relay: WS connect (Authorization: Basic base64(key:secret))
    Agent->>Relay: Greeting {"action":"auth","agent_type":"proxy","version":"1.0.0"}
    Agent->>Relay: Inventory {"action":"datasource_inventory","datasources":[...]}
    Agent-->>Relay: Metadata (async) {"action":"datasource_metadata","metadata":{...}}

    loop Every 30s
        Agent->>Relay: Ping
        Relay->>Agent: Pong
    end

    loop Every 60s
        Agent->>Relay: Health {"action":"datasource_health_update","datasources":{...}}
    end
```

**Auto-reconnect:** On disconnect, the agent reconnects with exponential backoff (3s → 6s → 12s → ... → 30s max).

## Config Sync

The cloud can push datasource configurations at any time via WebSocket:

```mermaid
sequenceDiagram
    Relay->>Agent: {"action":"datasource_config_sync", "datasources":[...]}
    Agent->>Relay: {"action":"datasource_config_sync_ack", "status":"ok"}
```

Each datasource in the sync includes:
- `id`, `type`, `proxy_type`, `name`
- `config` — transport-specific settings (host, port, URL, etc.)
- `credentials` — auth credentials (or reference to secret provider)
- `credential_source` — where creds come from: `cloud_push`, `local`, `aws_secrets_manager`, etc.

The handler creates/reconfigures proxy instances and removes any datasources not in the new config.

## Concurrency Model

```mermaid
graph TB
    main["main goroutine"] --> run["client.Run()<br/><i>reconnect loop</i>"]
    run --> cas["connectAndServe()<br/><i>per-connection</i>"]
    cas --> read["readLoop<br/><i>reads WS messages, spawns handler goroutines</i>"]
    cas --> write["writeLoop<br/><i>drains sendCh to WS (serialized writes)</i>"]
    cas --> ping["pingLoop<br/><i>sends WS pings every 30s</i>"]
    cas --> health["healthReport<br/><i>sends health every 60s</i>"]
    cas --> meta["sendMetadata<br/><i>one-shot on connect</i>"]
```

Each incoming request is handled in its own goroutine (spawned by readLoop). Proxy modules manage their own connection pools. The WS write path is serialized through a buffered channel (capacity 64).
