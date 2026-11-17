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

## Message Signing

Relay messages are signed with Ed25519. With a public key configured the forager
rejects unsigned or badly signed messages; without one it only warns, and reports
`signing_enforced: false` to the relay, which then refuses to push credentials for
integrations that require enforcement.

```yaml
# One key (no key id): checked for every message
signing_public_key: ssh-ed25519 AAAA...

# Several keys, for rotation. A message that names a key_id is checked against
# that key; one that does not is checked against every key.
signing_public_keys:
  - key_id: k-2026-11
    key: ssh-ed25519 AAAA...
  - key_id: k-2026-05
    key: ssh-ed25519 AAAA...
```

To rotate the relay's key: add the new public key here (keep the old one), switch
the relay to the new private key, then remove the old entry.

## Credential Management

Three credential sources:

| Source | How it works |
|--------|-------------|
| `local` | Credentials in `forager.yaml` config file |
| `cloud_push` | Credentials pushed via config sync, stored locally in `{data_dir}/credentials.enc` |
| `aws_secrets_manager`, `gcp_secret_manager`, `azure_key_vault` | Fetched from cloud secret providers at configure time |

Cloud-pushed credentials are encrypted at rest using AES-GCM with a key derived from the agent's `access_secret`.

### End-to-end encryption of pushed credentials

On first start the forager creates an X25519 keypair in `{data_dir}/enc_key` (mode
0600) and sends the public key in its greeting (`enc_public_key`, named by
`enc_key_id`). Nudgebee seals credentials to that key before they leave its
servers, so relay-server and the message broker carry only an opaque blob
(`credentials_enc`); only this forager can open it. A push sealed to another key
— a reinstall, or a second forager — is refused per datasource with
`key_mismatch`, and the forager keeps whatever it was serving before.

The datasource id and host are sealed together with the credentials and checked
when the blob is opened, so a blob captured from one push cannot be replayed to
point the same credentials at another datasource or host
(`sealed_for_other_datasource`). Credentials are stored only after the proxy has
accepted them, never for a datasource that failed to configure.

Back up `enc_key` with `credentials.enc`; a lost key means Nudgebee must re-push
every credential (it does so automatically after the forager reconnects with its
new key).

### Host binding

Stored credentials remember the host they were pushed for, in
`{data_dir}/credential_hosts.enc` beside `credentials.enc` (whose format is
unchanged, so an older forager still starts from the same data dir). A later config sync
that moves a datasource to a different host without carrying its credentials is
refused (`host_changed`), so a stored token can never be redirected to another
server. A change of host must come with the credentials — Nudgebee always sends
them on save.

### Removal

When a datasource leaves the account's configuration, its stored credentials are
deleted from `credentials.enc` in the same sync.

### Secret-manager references for HTTP datasources

An http-proxy datasource pushed from Nudgebee may name a secret in AWS Secrets
Manager, GCP Secret Manager or Azure Key Vault instead of carrying its
credentials. Because whoever edits the integration chooses both the URL and the
secret, set this list to restrict which secrets an HTTP datasource may read:
once it is set, a reference that does not start with one of the prefixes is
refused (`secret_ref_not_allowed`). Matching is a plain prefix match, so end
each prefix with a separator (`/`, `-`): `secret:nudgebee` would also match
`secret:nudgebee-prod-db-admin`.

With no list, any reference resolves as before and the forager logs a warning,
so an upgrade does not break an existing HTTP Proxy integration. Database, SSH
and other proxy types are not restricted.

```yaml
secret_ref_allowlist:
  - arn:aws:secretsmanager:eu-west-1:123456789012:secret:nudgebee/
  - projects/my-project/secrets/nudgebee-
```

### Credential probe

Nudgebee may send an http-proxy datasource with a `probe`: one authenticated
request to a fixed API endpoint of that provider (for Grafana Tempo,
`/api/v2/search/tags`). The forager runs it with the datasource's credentials in
the pre-save connection test, so a wrong key is refused before it is saved
(`bad_credentials` on 401 or 403), and in the health report. A datasource
without a probe keeps the previous checks.

### Cloud metadata endpoints

The HTTP proxy refuses to connect to link-local addresses (`169.254.0.0/16`,
`fe80::/10`), AWS's `fd00:ec2::254`, Azure's `168.63.129.16` and Alibaba
Cloud's `100.100.100.200`, checked on the resolved address of every
connection. The forager's own cloud credentials are served from those
addresses, so no datasource URL can reach them.

When `HTTP_PROXY`/`HTTPS_PROXY` is set, the outbound proxy resolves the target
and the forager only sees the proxy's address. A `base_url` that names a
metadata address or `metadata.google.internal` is still refused when the
datasource is configured, but a name that only resolves to one is not: block
those addresses on the outbound proxy too. The MCP proxy is not covered yet.

### Config sync acknowledgements

Each `datasource_config_sync` is answered per datasource:

```json
{"action": "datasource_config_sync_ack", "status": "partial",
 "datasources": [
   {"id": "…", "status": "ok"},
   {"id": "…", "status": "error", "error_code": "key_mismatch", "error": "…"}
 ]}
```

`status` is `ok` when every datasource applied, `partial` otherwise. Error codes:
`no_encryption_key`, `key_mismatch`, `decrypt_failed`, `sealed_for_other_datasource`,
`host_changed`, `store_failed`, `credential_resolve_failed`, `unknown_proxy_type`,
`configure_failed`, `secret_ref_not_allowed`. An `ok` result may carry a `warning` when a secondary part was
not applied (a discovery scope whose ssh access could not be enabled).

Host binding applies to the key each proxy type dials: `base_url` for the HTTP
proxy, `url` for MCP, `host` for the database, Redis, MongoDB and SSH proxies,
`brokers` for Kafka. A stored entry from before host binding is bound to the host
of its first reuse.

## Config File Lookup Order

1. Path specified via `--config` flag
2. `forager.yaml` in `/etc/nudgebee/`
3. `forager.yaml` in current working directory
