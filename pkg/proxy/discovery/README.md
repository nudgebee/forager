# discovery proxy

Collects OS and package inventory from VMs in the forager's network segment
over SSH. Nothing is installed on the target hosts: their "agent" is the sshd
and package manager the OS already ships.

Part of Phase 0 VM discovery — see `docs/design/vm-discovery-phase0.md`.

## Why the commands live outside the binary

The forager carries no per-distro logic. Collection commands ship as a
versioned, Ed25519-signed **content pack**; the binary verifies the signature,
evaluates each collector's `when` guard against facts probed from the host,
and runs the surviving commands verbatim. Adding a distro or fixing a command
is a new pack version, not an agent release — which is the whole point, since
fleet-wide agent upgrades are exactly what customers refuse to sign up for.

Output is returned raw. Parsing happens server-side, so a parser bug is fixed
by deploying the server, never by touching hosts.

## Action

`discovery_inventory`

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
| `allowed_cidrs` | none | Segment scope. Empty means unrestricted. |
| `pack_public_key` | — | Required; without it no pack can be trusted, so nothing runs. |
| `pack_dir` | — | Directory holding signed packs, named `linux-inventory-v<N>.yaml`. Required to run inventory. |
| `known_hosts_file` | — | OpenSSH known_hosts path. When set, host keys are verified and unknown/changed keys are refused. |

Credentials (`username` plus `private_key` or `password`) arrive through
`pkg/secrets`, local or cloud-push. They never appear in logs or responses.

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
- Sweep, LDAP, and hypervisor discovery actions are separate tickets
  (nudgebee/forager#114, #115); this module currently implements inventory only.
- The production pack, its CI signing, and pin/ring rollout are #116.
