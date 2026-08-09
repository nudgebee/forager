# VM Discovery — Deployment Plan

Status: DRAFT
Covers: getting the merged discovery module (forager#118) into an
environment where it can actually run.

## Where things stand

Merged to `main` as c2ad9c7. **Not released** — `v0.1.3` is the latest
tag and discovery is one commit ahead of it. The release workflow fires
on a `v*.*.*` tag and publishes `ghcr.io/nudgebee/forager` plus the
chart to `oci://ghcr.io/nudgebee/charts`.

Deploying the new image is safe on its own: nothing about existing
datasource types changed, so current foragers keep working. But
**end-to-end discovery cannot run yet** — four gaps, listed below with
what each one blocks.

## Existing deployment pattern (what we build on)

`nudgebee-infra/deploy/customers/rackspace/agents/forager-values-dev.yaml`
is the working precedent:

- Chart `deploy/helm/forager` from this repo, release
  `nudgebee-forager-dev`, namespace `nudgebee-agent-dev`.
- Points at `wss://relay.dev.nudgebee.pollux.in/register`.
- Secrets SOPS-encrypted with AWS KMS; `encrypted_regex` already
  covers `accessKey|accessSecret|password|username`.
- Deployed via `installation.sh -f values.yaml -k`.

The chart takes us most of the way: `forager.datasources` is passed
through with `toYaml`, so arbitrary datasource fields reach
`forager.yaml`, and `extraVolumes`/`extraVolumeMounts` exist for
mounting a pack directory. No chart changes are strictly required.

## Blockers

### 1. Local config cannot configure a discovery datasource

`cmd/app.go` maps only `allowed_hosts` → `allowed_cidrs`. There is no
path from `forager.yaml` to `pack_public_key`, `pack_dir`, `ldap`,
`known_hosts_file`, `max_rate_pps`, or the port/concurrency/timeout
settings — `config.LocalDatasource` has no fields for them.

Consequence per action:

| Action | Works from local YAML today |
|---|---|
| `discovery_sweep` | yes — only needs `allowed_cidrs` |
| `discovery_ldap` | no — directory config unreachable |
| `discovery_inventory` | no — without a pack key nothing runs |

The production intent (design §9) is that the server pushes datasource
config, which would sidestep this. But that path needs the server-side
work that does not exist yet, so local config is what we have.

**Fix:** add the discovery fields to `config.LocalDatasource` and map
them in `app.go`. Small, self-contained.

### 2. A sweep-only datasource still demands SSH credentials

`Configure` returns `ssh username is required` before it looks at
anything else. A datasource intended purely for sweeping — which needs
no credentials at all — cannot be configured without inventing dummy
ones.

**Fix:** only require SSH credentials when they are needed, and let
`HealthCheck` report which actions a given datasource can serve.
Otherwise the first thing an operator does is put fake credentials in
a values file, which is a bad habit to teach.

### 3. No signed content pack exists

`docs/content-packs/linux-inventory-example.yaml` is deliberately
unsigned and is a format reference, not a shippable pack. The real
pack, CI signing, and pin/ring rollout are #116.

`discovery_inventory` refuses to run without a verified pack, so this
blocks inventory entirely — by design.

**Fix for a first deployment:** generate a keypair, sign the example
pack by hand, mount it via `extraVolumes`, set `pack_public_key`. Not
a substitute for #116.

### 4. Nothing triggers discovery

There is no scheduler and no UI: the server never sends
`discovery_sweep`, `discovery_ldap`, or `discovery_inventory`. A
deployed forager would connect and sit idle. That is
nudgebee-enterprise#35405 plus the scheduling decision.

Relay signing is *not* a blocker — `DefaultSigningFields`
(`action`, `datasource_id`, `params`) already matches all three
actions. Adding them explicitly to `SigningFields` in
`relay-server/pkg/signing/signer.go` is worth doing for clarity, but
nothing breaks without it.

## Plan

### Phase A — ship a release candidate (no dependencies)

Cut `v0.1.4-rc.1`, not `v0.1.4`. The workflow already treats a tag
containing `-` as a prerelease, and the precedent exists (`v0.1.2-rc.1`).

What an rc tag does and does not touch:

| | rc tag | final tag |
|---|---|---|
| `ghcr.io/nudgebee/forager:0.1.4-rc.1` | pushed | — |
| `ghcr.io/nudgebee/forager:latest` | **untouched** (`latest=auto` skips prereleases) | moves |
| `0.1` shorthand tag | not applied to prereleases | moves |
| GitHub Release | marked prerelease | full release |
| `registry.nudgebee.com` mirror (ECR + S3) | **skipped** — the mirror jobs are gated on `!contains(github.ref, '-')` | synced |
| Chart `oci://ghcr.io/nudgebee/charts/forager:0.1.4-rc.1` | new version, does not overwrite 0.1.3 | new version |

So no customer-facing pointer moves. Existing installs consuming
`:latest` or the mirror stay on 0.1.3 until we cut a final tag.

1. Tag `v0.1.4-rc.1` on `main`.
2. Roll the Rackspace **dev** forager onto it by bumping `image.tag`
   in `forager-values-dev.yaml`.
3. Confirm the existing `rackspace-pg` datasource still works — a pure
   regression check, no discovery involved.

Value: the binary is available and exercised without committing to a
release, and any discovery rollout afterwards is a config change
rather than an image change. Phases B–D can iterate through
`-rc.2`, `-rc.3` at no cost to anyone downstream.

### Phase B — make discovery configurable (blockers 1 and 2)

One forager PR:

- Add discovery fields to `config.LocalDatasource` and map them in
  `app.go`.
- Require SSH credentials only when the datasource will serve
  inventory.
- Extend `values-enterprise.yaml.example` with a documented discovery
  datasource.

### Phase C — first real sweep (needs A + B)

Deploy a second forager release scoped to sweeping only, in the
Rackspace cluster:

- `allowed_cidrs` limited to a **known-safe range** — the cluster's own
  pod/service CIDR, not a customer network.
- Exclusions for anything that should never be probed.
- `ports: [22]` to start, so no RDP/WinRM probes appear in security
  monitoring.
- Rate left at the default 100 pps.

Because nothing schedules actions yet, trigger one by hand through the
relay and read the response. That is the smallest thing that proves the
network path, signing, and scope enforcement all work together.

Before this runs anywhere near a customer network, the forager's IP
needs allowlisting in their IDS — an unannounced sweep looks exactly
like an attacker, and a bare TCP connect still makes `sshd` log
`Did not receive identification string`, which some fail2ban configs
act on.

### Phase D — inventory (needs C + a pack)

- Generate a pack signing keypair; store the private key where CI can
  reach it for #116, and put the public key in the values file.
- Sign the example pack, mount it read-only at `pack_dir` via
  `extraVolumes`.
- Create a `nudgebee-ro` user on one or two test VMs.
- Run `discovery_inventory` by hand against those hosts and check the
  raw collector output.

### Phase E — scheduled and server-driven

Everything above is manual. Real operation needs
nudgebee-enterprise#35405 (asset storage and ingest) plus the
scheduler, at which point datasource config moves to server-push and
local YAML becomes a bootstrap detail.

## Open questions

1. Which cluster for the first sweep — Rackspace dev, or a dedicated
   test environment? Rackspace is real customer infrastructure, so the
   CIDR scope needs deciding with care.
2. Where does the pack signing private key live? CI secret for #116 is
   the obvious answer, but it should be settled before we hand-sign
   anything, so the throwaway key does not become load-bearing.
3. Do we reuse the existing `nudgebee-forager-dev` release for
   discovery, or run a separate one? Separate is cleaner — different
   blast radius, different credentials, and a sweep misconfiguration
   should not be able to disturb the working pg datasource.
