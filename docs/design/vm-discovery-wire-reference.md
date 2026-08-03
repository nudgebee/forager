# VM Discovery — action and relay wire reference

Status: REFERENCE, from the AWS testbed run 2026-08-03
Audience: whoever builds the server side (nudgebee-enterprise#35405) and
needs to know exactly what to send and what comes back.

Everything below is either what was actually run, or the envelope the
relay produces — both marked as such, because the distinction matters:
**the actions were exercised, the relay envelope around them was not.**

## What was actually run

Driven through the discovery proxy's exported Go API by a throwaway
harness on the forager host, because nothing can dispatch a discovery
action through the relay yet.

### Datasource configuration

```go
p.Configure(map[string]any{
    "allowed_cidrs":   []any{"172.31.0.0/28"},
    "max_rate_pps":    float64(50),
    // inventory additionally needed:
    "pack_public_key": "<base64 ed25519>",
    "pack_dir":        "/etc/nudgebee/packs",
}, map[string]string{
    "username":    "nudgebee-ro",
    "private_key": "<key material>",
})
```

### discovery_sweep

```go
&proxy.ActionRequest{
    Action: "discovery_sweep",
    Params: map[string]any{
        "cidrs":      []any{"172.31.0.0/28"},
        "ports":      []any{float64(22)},
        "rate_pps":   float64(50),
        "timeout_ms": float64(1000),
    },
}
```

Response (`ActionResponse.Data`, verbatim):

```json
{
  "cidrs": ["172.31.0.0/28"],
  "addresses_scanned": 14,
  "addresses_excluded": 0,
  "rate_pps": 50,
  "duration_seconds": 1.184975093,
  "hosts": [
    {"ip": "172.31.0.10", "open_ports": [22],
     "rdns": "ip-172-31-0-10.ec2.internal", "sources": ["tcp"]},
    {"ip": "172.31.0.11", "mac": "02:4d:07:48:c4:87", "open_ports": [22],
     "rdns": "ip-172-31-0-11.ec2.internal", "sources": ["tcp","arp"]},
    {"ip": "172.31.0.12", "mac": "02:16:a7:ae:cb:8b", "open_ports": [22],
     "rdns": "ip-172-31-0-12.ec2.internal", "sources": ["tcp","arp"]}
  ]
}
```

`172.31.0.10` has no MAC because it is the forager itself — a host does
not ARP for its own address. Do not treat a missing MAC as an error;
it is also normal for anything reached through a router.

`addresses_scanned` is 14, not 16: network and broadcast are skipped.

### discovery_inventory

```go
&proxy.ActionRequest{
    Action: "discovery_inventory",
    Params: map[string]any{
        "targets":              []any{"172.31.0.11", "172.31.0.12"},
        "content_pack_version": float64(1),
    },
}
```

Response shape, with the fields that matter to ingest:

```json
{
  "content_pack_version": 1,
  "targets": [
    {
      "host": "172.31.0.11",
      "status": "ok",
      "duration_seconds": 1.5,
      "facts": {"os_family":"debian","os_id":"ubuntu","os_major":"22","arch":"x86_64"},
      "collectors": {
        "os-release": "NAME=\"Ubuntu\"\nID=ubuntu\n...",
        "pkgs-dpkg":  "acpid\t1:2.0.33-1ubuntu1\tamd64\tinstalled\n...",
        "machine-id": "ec2403e319a2f3f0ae53a05e3daf084b\n",
        "smbios-uuid": ""
      },
      "collector_errors": {},
      "skipped_collectors": []
    }
  ]
}
```

Per-target `status` is one of `ok`, `ssh-refused`, `ssh-auth-failed`,
`timeout`, `error`. **A failed target is a result, not an error** — the
batch still returns 200. These map onto coverage gap reasons.

## Parsing notes from real output

Taken from the actual runs, not from the collector definitions.

- **`rpm` prints `(none)` for a missing epoch**, not `0` or empty:
  `publicsuffix-list-dafsa\t(none)\t2026...`. `(none)` and `0` are not
  equivalent for version comparison and must not be collapsed.
- **Epoch and release survive intact** and must stay that way:
  `openssl\t1\t3.5.5\t1.amzn2023.0.5\tx86_64\t1784931981`, and Debian's
  `acpid\t1:2.0.33-1ubuntu1` keeps its `1:` prefix.
- **`smbios-uuid` comes back empty** under the unprivileged credential —
  `/sys/class/dmi/id/product_uuid` is mode `-r--------`. Plan for
  machine-id as the only strong identifier on-prem.
- Collector output is raw text exactly as the command emitted it,
  including a trailing newline. Where a collector wrote to stderr, it
  is appended after a `\n[stderr]\n` marker.

Real output from both distro families is available on the testbed for
capturing golden files rather than hand-writing them.

## The relay envelope — shape only, NOT yet exercised

What the relay wraps an action in. Reproduced here from the relay's
signer and pinned by tests in `pkg/ws/discovery_wire_test.go`, but no
discovery action has actually travelled this path: the relay's dispatch
endpoint is hardcoded for `http_request`, so sending one means
publishing to the agent's queue, which is server-side work.

```json
{
  "request_id": "<uuid>",
  "datasource_id": "local:aws-testbed",
  "action": "discovery_sweep",
  "params": { "cidrs": ["172.31.0.0/28"], "ports": [22] },

  "signed_payload": "{\"action\":\"discovery_sweep\",\"datasource_id\":\"local:aws-testbed\",\"params\":{...}}",
  "signature": "<base64 ed25519 over signed_payload>",
  "signed_at": "<RFC3339, within ±5 min>",
  "nonce": "<unique, replay-checked>"
}
```

Two things to get right:

1. **Discovery actions are not in the relay's explicit `SigningFields`
   map**, so they fall through to `DefaultSigningFields` —
   `action`, `datasource_id`, `params`. That is correct for all three,
   and is now pinned by a test rather than assumed.
2. **All three require a signature.** They were absent from the
   forager's `signedActions` allowlist and therefore unverified; fixed
   in forager#122. An unsigned or tampered discovery action is now
   rejected with 403.

`datasource_id` is `local:<name>` for a locally configured datasource.
