# Connection Lifecycle

## Startup

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

## WebSocket Connection

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

## Config Sync

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
