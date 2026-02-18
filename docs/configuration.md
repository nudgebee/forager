# Configuration

## forager.yaml

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

  - name: my-grafana
    type: http
    url: http://localhost:3000
    credentials:
      auth_type: bearer
      bearer_token: glsa_...

  - name: my-mcp
    type: mcp
    url: http://localhost:8080/mcp
    credentials:
      auth_type: bearer
      bearer_token: sk-...

# Cloud secret provider configs (optional)
aws:
  region: us-east-1
gcp:
  project_id: my-project
  credentials_file: /path/to/creds.json
azure:
  vault_url: https://my-vault.vault.azure.net
  tenant_id: ...
  client_id: ...
```

## Environment Variables

All config values can be set via `NB_` prefixed env vars:

```
NB_RELAY_URL=wss://relay.nudgebee.com/register
NB_ACCESS_KEY=key
NB_ACCESS_SECRET=secret
NB_DATA_DIR=/var/lib/nudgebee
```

## Credential Management

Three credential sources:

| Source | How it works |
|--------|-------------|
| `local` | Credentials in `forager.yaml` config file |
| `cloud_push` | Encrypted credentials pushed via config sync, stored locally in `{data_dir}/credentials.enc` |
| `aws_secrets_manager`, `gcp_secret_manager`, `azure_key_vault` | Fetched from cloud secret providers at configure time |

Cloud-pushed credentials are encrypted at rest using AES-GCM with a key derived from the agent's `access_secret`.

## Config File Lookup Order

1. Path specified via `--config` flag
2. `forager.yaml` in `/etc/nudgebee/`
3. `forager.yaml` in current working directory
