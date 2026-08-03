# discovery proxy

Finds VMs in the forager's network segment and collects their OS and package
inventory over SSH. Nothing is installed on the target hosts: their "agent" is
the sshd and package manager the OS already ships.

Part of Phase 0 VM discovery — see `docs/design/vm-discovery-phase0.md`.

Three actions, deliberately separate:

| Action | Answers | Needs credentials |
|---|---|---|
| `discovery_sweep` | what is on this network | no |
| `discovery_ldap` | what does the directory know exists | directory bind |
| `discovery_inventory` | what is installed on this host | SSH |

Sweeps find, they do not inventory — package data always requires
credentials. Nothing here decides *when* to run: the server schedules
everything and the forager holds no state between actions.

## Why the commands live outside the binary

The forager carries no per-distro logic. Collection commands ship as a
versioned, Ed25519-signed **content pack**; the binary verifies the signature,
evaluates each collector's `when` guard against facts probed from the host,
and runs the surviving commands verbatim. Adding a distro or fixing a command
is a new pack version, not an agent release — which is the whole point, since
fleet-wide agent upgrades are exactly what customers refuse to sign up for.

Output is returned raw. Parsing happens server-side, so a parser bug is fixed
by deploying the server, never by touching hosts.

## Actions

### `discovery_sweep`

Finds hosts that are up, by plain TCP connect across the requested CIDRs.

| Param | Type | Notes |
|---|---|---|
| `cidrs` | `[]string` | IPv4 CIDRs to sweep. Must fall within `allowed_cidrs`. |
| `ports` | `[]int` | Defaults to 22, 3389, 5985. |
| `exclusions` | `[]string` | CIDRs or bare addresses, removed before any packet is sent. |
| `rate_pps` | `int` | Probes/second, default 100, clamped to `max_rate_pps`. |
| `workers` | `int` | Probes in flight, default 64, max 512. Governs concurrency, not rate — raising it helps when a scope is mostly dead addresses. |
| `timeout_ms` | `int` | Per-probe connect timeout, default 1000. |

Returns per responder: IP, open ports, MAC (local segment only), reverse DNS.

Discovery actions return their payload in `result` as structured JSON,
parsed once. Older actions use `data`, a string holding double-encoded
JSON — that field exists because some actions return things that are not
JSON at all (HTTP bodies, raw MCP bytes) and because every existing
consumer decodes it as a string. An action populates exactly one of the
two: setting both would double a payload that reaches megabytes for a
real package inventory.

Safety properties, which are requirements rather than tuning:

- **Only well-formed TCP connects.** No raw or crafted packets — the malformed
  probes port scanners emit are what destabilize embedded and OT gear.
- **Rate cap enforced in the forager.** The server asks for a rate; the
  forager still refuses to exceed its own `max_rate_pps`.
- **Exclusions applied during address expansion**, so an excluded host is
  never handed to a prober at all.
- **Scope enforced twice** — a requested CIDR outside `allowed_cidrs` is
  refused, so one bad request cannot turn a segment collector into a
  general-purpose scanner.
- Small burst relative to the rate, so a sweep does not open with a spike.

MACs come from reading the kernel's neighbour cache after probing, not from
sending ARP frames — so no raw sockets and no `CAP_NET_RAW`. A host reached
through a router has no MAC here, which is expected.

The honest limit: a host with none of the probed ports open is invisible to a
sweep. That is why the directory and hypervisor sources exist.

### `discovery_ldap`

Lists computer objects from the configured directory.

| Param | Type | Notes |
|---|---|---|
| `base_dn` | `string` | Overrides the datasource's configured base DN. |
| `active_within_days` | `int` | Skip objects whose last logon is older, default 90. |

Returns name, DNS name, OS, `objectGUID` (a STRONG merge identifier), last
logon, and whether the account is enabled.

The staleness filter is not an optimization: AD accumulates tombstones of
machines decommissioned years ago, and importing them would report permanent
phantom gaps in the coverage report. A machine that has *never* logged on is
kept — that is a new host, not a stale one.

### `discovery_inventory`

| Param | Type | Notes |
|---|---|---|
| `targets` | `[]string` | Hosts to inventory. Must fall within `allowed_cidrs`. |
| `content_pack_version` | `int` | Which pack to run. Loaded from `pack_dir`, verified, then cached. |
| `concurrency` | `int` | Optional per-request override, clamped to the module max. |

A request **selects** a pack by version; it cannot carry one. Pack bodies
reach `pack_dir` through the distribution pipeline, never through an action —
so no part of an action payload is ever executed. A pack whose declared
version differs from the one requested is refused, since mislabelled results
would corrupt server-side correlation.

Response:

```json
{"content_pack_version": 3,
 "targets": [
   {"host": "10.0.1.15", "status": "ok",
    "facts": {"os_family": "debian", "os_major": "22", "arch": "x86_64"},
    "collectors": {"pkgs-dpkg": "acl\t2.3.1-1\tamd64\n..."},
    "duration_seconds": 1.4},
   {"host": "10.0.1.16", "status": "ssh-auth-failed", "error": "..."}
 ]}
```

Per-target statuses (`ok`, `ssh-refused`, `ssh-auth-failed`, `timeout`,
`error`) map onto the server's coverage states and gap reasons. **One host
failing never fails the batch** — "which hosts could we not reach, and why"
is the product question Phase 0 answers, so failures are data, not errors.

## Configuration

Pushed from the server alongside credentials; the forager holds no schedule
and no target list of its own.

| Key | Default | Notes |
|---|---|---|
| `port` | 22 | |
| `concurrency` | 25 | Clamped to 200. |
| `host_timeout_seconds` | 120 | Whole-host budget. |
| `command_timeout_seconds` | 60 | Per collector. |
| `dial_timeout_seconds` | 10 | |
| `max_output_bytes` | 4 MiB | Per command, stdout and stderr each. |
| `allowed_cidrs` | none | Segment scope for both sweep and inventory. Empty means unrestricted. |
| `max_rate_pps` | 1000 | Ceiling on sweep probe rate, whatever a request asks for. |
| `ldap` | — | Directory connection: `host`, `port`, `tls`/`start_tls`, `base_dn`, `page_size`. Absent host disables `discovery_ldap`. |
| `pack_public_key` | — | Required; without it no pack can be trusted, so nothing runs. |
| `pack_dir` | — | Directory holding signed packs, named `linux-inventory-v<N>.yaml`. Required to run inventory. |
| `known_hosts_file` | — | OpenSSH known_hosts path. When set, host keys are verified and unknown/changed keys are refused. |

Credentials arrive through `pkg/secrets`, local or cloud-push, and never
appear in logs or responses: `username` plus `private_key` or `password` for
SSH, and `ldap_bind_dn` / `ldap_bind_password` for the directory. LDAP bind
failures echo the DN back, so those errors are redacted before they leave.

## Pack format

See `docs/content-packs/linux-inventory-example.yaml` for a documented
example. Guard facts are `os_family`, `os_id`, `os_major`, `arch`; guards
support `==`/`!=` against a quoted literal, joined by `&&`/`||`.

The guard language is deliberately minimal and must stay that way. It is not
an expression evaluator: anything richer becomes a sandbox-escape surface in
a binary whose job is running signed content against production hosts.

## Known gaps

- **Host keys are unverified unless `known_hosts_file` is set.** Discovery
  finds hosts nobody has catalogued, so their keys are unknown on first
  contact and change when a VM is re-imaged — strict verification by default
  would break the one thing this module exists to do. Customers who can
  supply host keys should set `known_hosts_file` and get real verification.
  Recording keys on the server-side asset record and pinning on later runs is
  the fix that removes the tradeoff, and belongs with that work.
- IPv6 sweeps are unsupported: enumerating a v6 prefix by address is not
  viable, so v6 discovery needs the directory or hypervisor sources instead.
- The hypervisor connector (nudgebee/forager#115) is not here yet. Until it
  lands, powered-off VMs are invisible — neither a sweep nor a reachability
  check can see a machine that is switched off.
- The production pack, its CI signing, and pin/ring rollout are #116.
