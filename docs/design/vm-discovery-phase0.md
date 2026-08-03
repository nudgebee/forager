# Design: VM Discovery & Package Inventory (Phase 0)

Status: DRAFT
Scope: Phase 0 — VM discovery, package inventory, reconciliation,
coverage reporting. Discovery makes VMs first-class Nudgebee
resources; patch & vulnerability management is the first consumer.
Out of scope (later phases): CVE matching, escalation policy, patching,
CIS benchmarking, application (non-OS-package) inventory, Windows.

---

## 1. Problem

Customers need patch & vulnerability management for VMs, starting with
on-premise / self-hosted fleets where no cloud control plane exists.
Before anything else can ship, we must answer:

> How many VMs exist, which packages are installed on each, and for
> every VM we can't inventory — why not?

Constraints:

- **No agent on target VMs.** Rollout friction kills adoption; agent
  upgrade management is a liability (post-CrowdStrike, staged rollout
  and version pinning are procurement questions).
- **Minimal, rarely-upgraded footprint.** The only installed software
  is one forager node per network segment.
- **On-prem first.** Cloud APIs (EC2/Azure/GCE) are optional
  enrichment, not a dependency.

Product framing: a discovered VM becomes a first-class Nudgebee
resource — the same status cloud resources and Kubernetes workloads
have today. Discovery is the foundation; independent capability
tracks build on the VM resource:

1. **Observability** — node health, metrics, logs, service state.
2. **Security** — package inventory → CVE matching, patching, CIS
   benchmarking (the initiative's first deliverable).
3. **Automation** — signed, audited command execution on VMs through
   the per-segment forager; patching is one instance of it.

Phase 0 therefore avoids patch-specific shortcuts: the asset tables
are a general resource catalog (packages are one satellite dataset),
and signed content packs are the generic execution vehicle all three
tracks reuse.

## 2. Industry research summary

Surveyed: Qualys, Tenable, Rapid7, Tanium, osquery/Fleet, AWS SSM,
Red Hat Satellite, WSUS, Ansible, Lansweeper, runZero, Wiz/Orca,
Axonius, PatchMon, CrowdStrike, JFrog, and the dedicated
patch-management pack (Automox, Action1, NinjaOne, ManageEngine,
Ivanti). Findings that drive this design:

1. **Every mature tool runs the same four-stage pipeline:** seed from
   authoritative sources (hypervisor/AD/cloud) → unauthenticated sweep
   → authenticated inventory → continuous reconciliation. Tools differ
   only in how stage 3 reaches the box.
2. **Sweeps find, they don't inventory.** Unauthenticated scanning
   tops out at fingerprints. Package data requires credentials or a
   resident channel — no exceptions in the industry.
3. **Only control planes see powered-off machines** (hypervisor,
   cloud, AD last-logon). Scanning can't; tools handle absence with
   staleness decay.
4. **Reconciliation is the product; collection is commodity.** Asset
   duplication is the #1 operational complaint against Qualys/Tenable;
   Axonius built a company purely on reconciling other tools'
   inventories.
5. **Nobody serious ships a full-logic agent per VM anymore.** Red Hat
   deprecated and removed katello-agent in favor of OS-native
   reporting (`subscription-manager` package-profile upload).
6. **The converged answer to "minimal agent, no upgrades" is three
   layers:** a per-segment node (Nessus scanner model) + agentless
   push over SSH (Ansible model) + **signed content-driven execution**
   (Qualys manifests, Tanium sensors, osquery query packs) — the agent
   binary is a frozen interpreter; capability changes ship as signed
   content.
7. **Updates need pinning + staged rollout as first-class features** —
   even content updates, post-CrowdStrike. The Channel File 291 RCA is
   the proof: content updates **bypassed** the N-1/N-2 pinning
   customers had on sensor binaries; the post-incident fixes were
   staged/canary content rollout and customer control over content
   scheduling — exactly the pack pinning + ring rollout in §7 of this
   doc. The split is industry consensus: Rapid7's Insight Agent keeps
   shipping content when binary updates are disabled; Ivanti moved
   Linux to "contentless" detection (query the distro's own repos);
   ManageEngine syncs a central patch DB independent of agent
   versions.
8. **Dedicated patch vendors don't solve discovery.** Automox,
   Action1, NinjaOne, and ManageEngine are per-endpoint agent +
   enrollment; their answer to "machines we don't know about" is
   scanning AD in order to push more agents. Ivanti Security Controls
   is the only central-node agentless inventory — Windows-only, over
   admin shares/remote registry. **No vendor ships agentless SSH
   Linux inventory from a per-segment collector** — the exact
   combination this design proposes is open ground.
9. **Rapid7 validates the per-segment model and flags its two
   hazards.** "Assigning a Scan Engine to each subnetwork is a best
   practice" (stateless engines, hub-and-spoke to the console). But:
   (a) remote credential management hurt enough that they shipped
   Scan Assistant, a tiny cert-authenticated on-host helper — expect
   credentials to be the operational cost center and design the vault
   integration well; (b) their agent/engine asset correlation relies
   on a UDP-31400 probe plus hostname/IP/MAC/UUID matching, and
   produces duplicates when it fails — deterministic identity
   (machine-id/SMBIOS first) must be built in up front, which §8.2
   does.
10. **Confirmed dead ends.** Snapshot side-scanning (Wiz/Orca) does
    not extend on-prem: Wiz's vSphere support is vCenter-API-only
    with guest package scanning unshipped, and Orca covered on-prem
    by introducing a runtime agent — abandoning agentless. JFrog has
    no machine discovery anywhere in its portfolio (Xray scans
    artifacts in Artifactory; Runtime is a Helm-installed K8s eBPF
    sensor; Connect is per-device token enrollment) — it is an
    artifact-layer product, not a VM-discovery comparable.

Forager already implements the per-segment-node and SSH-push layers
(outbound-only WSS, Ed25519-signed actions, SSH executor, datasource
auto-registration). The missing pattern is signed-content collection.

## 3. Build vs fork: why not adopt an existing OSS scanner

Evaluated forking/adopting an open-source project instead of extending
forager. Conclusion: **no fork; reuse at the library and server
layers.**

### Candidates

| Project | What it does | Why not a fork base |
|---|---|---|
| **Vuls** (future-architect) | Closest match: Go, agentless SSH scan, package collection + CVE matching for CentOS/Ubuntu/RHEL/Debian/SUSE/Alpine/Amazon | **GPL-3.0** — forking into our agent makes the combined work GPL. Local TOML config model (ours is cloud-pushed), no relay/transport, per-distro logic baked into the binary — the exact thing we're avoiding |
| **cnquery** (Mondoo) | Agentless SSH inventory, polished | **BUSL-1.1** — source-available license that prohibits building a competing commercial product on it. We are the prohibited use |
| **Wazuh** | Inventory + vuln detection | Per-VM agent (violates constraint), GPLv2, huge |
| **OpenVAS/GVM** | Full scanner appliance | GPL, C, enormous; a second heavyweight deployable in the customer env kills the "one small thing per segment" story |
| **osquery/Fleet** | Best-in-class inventory | Per-VM agent — wrong model |
| **Ansible** | Agentless push | GPLv3, Python runtime dependency on the node, we'd use 2% of it |
| **PatchMon** | Patch monitoring/automation: pending updates, patch policies with windows + dry-run, approval-gated execution, OpenSCAP CIS | **AGPL-3.0** — network copyleft, binds on SaaS use, worst license in the survey. Per-host agent (10 binary variants to maintain fleet-wide) — the rejected model. And **no discovery at all**: hosts exist only once the agent is installed; coverage accounting is impossible in its model |

### Why fork economics are bad here

1. **A fork saves the cheap part.** The collection layer is
   `rpm -qa` / `dpkg-query -W` / `cat /etc/os-release` over SSH — a
   few hundred lines against forager's existing SSH client.
2. **A fork doesn't help with the hard part.** Reconciliation +
   coverage accounting is the product (finding #4), it's server-side,
   and no OSS project ships it in reusable form.
3. **We'd port the fork onto forager anyway.** Transport, signing,
   secrets, outbound-only WSS, datasource registration — the fork has
   none of it; forager has all of it. Integration work exceeds the
   collection code saved.
4. **A fork works against the no-upgrade goal.** Vuls' per-distro
   logic lives in the binary — every distro quirk is a binary release.
   The content-pack architecture (§7) is strictly better.
5. **Forks rot.** We would own the divergence forever; upstream fixes
   conflict with our patches.

### Where OSS reuse is right

- **Libraries in forager** (license-clean): `govmomi` (Apache-2.0)
  for vCenter, `go-ldap` (MIT) for AD, `naabu` (MIT) or ~300
  hand-rolled lines for the sweep. Do **not** shell out to nmap — its
  NPSL license is a known problem for commercial redistribution.
- **Server-side, Phase 1:** Trivy or Grype (both Apache-2.0) for CVE
  matching against the package cache — Trivy is already in
  scan_orchestrator. Biggest genuine reuse win; zero agent impact.
- **Vuls as a reference, not a dependency:** its code encodes years of
  per-distro edge cases (epoch handling, CentOS vault, backport
  version formats). Read to design content packs; don't copy code.
- **SBOM output** (CycloneDX/SPDX) for the package cache so
  third-party tools interop for free.
- Acceptable one-off: running Vuls standalone for a pre-sales demo.
  Throwaway only, not a foundation.
- **PatchMon as a phases-1–3 UX reference** (same status as Vuls —
  read, don't reuse): its policy model (immediate/delayed/maintenance
  window), dry-run → approval → full-shell-output audit flow, and
  per-package-manager pending-update handling are a good benchmark.
  Also a competitor to track.

## 4. Architecture summary

```
┌─────────────────────────┐          ┌────────────────────────────────────┐
│     Nudgebee Cloud      │          │   Customer Site / Segment          │
│                         │   wss    │                                    │
│  Scheduler ─► Relay ◄───┼──────────┼─► Forager (1 per segment)          │
│      │          ▲       │          │     │                              │
│  Reconciler     │       │          │     ├─ sweep: ARP/ICMP/TCP probe   │
│      │     asset_       │          │     ├─ hypervisor: vCenter/Proxmox │
│  assets DB  inventory   │          │     ├─ ldap: AD computer objects   │
│                         │          │     └─ inventory: SSH push ──► VMs │
└─────────────────────────┘          │              (nothing installed)   │
                                     └────────────────────────────────────┘
```

- **Forager = per-segment discovery node.** Sweeps its segment,
  queries the hypervisor/directory, collects per-VM inventory over
  SSH (run commands, capture output, leave nothing behind).
- **Target VMs get nothing installed.** Their "agent" is sshd + the
  package manager the OS already has.
- **Collection logic ships as signed content packs** (§7); the forager
  binary stays frozen.
- **All policy lives server-side:** schedules, CIDR scopes, rate
  limits, reconciliation. Forager initiates nothing on its own.
- Per-VM forager install remains a *fallback* for hosts where SSH is
  blocked by policy — an option, not the model.

## 5. Discovery sources (authority ladder)

Reconciled, not either/or. Ordered by authority:

| # | Source | Sees | Identifier quality | Notes |
|---|--------|------|--------------------|-------|
| 1 | Hypervisor API — vCenter, Proxmox, libvirt-via-SSH | All VMs incl. **powered-off** | Strong (instance/SMBIOS UUID) | The on-prem "control plane"; only true denominator |
| 2 | Directory/inventory — AD LDAP, DNS zones, DHCP leases, Ansible inventory, node_exporter targets | Recorded hosts | Weak (FQDN/IP/MAC) | Cheap, high yield; corroboration only |
| 3 | Network sweep — ARP (local L2), ICMP + TCP 22/3389/5985 across configured CIDRs | Live, reachable hosts | Weak until inventoried | Finds the unrecorded box; noisiest source |
| 4 | Cloud APIs — existing cloud-collector (EC2/Azure/GCE) | Cloud VMs | Strong (instance-id) | Optional enrichment where accounts exist |
| 5 | Authenticated inventory (SSH) | Everything about a reachable host | **Strong (machine-id, SMBIOS UUID)** | The only source of package data |

Sweep safety (product requirements, not niceties):

- Opt-in per CIDR; explicit exclusion lists.
- Hard rate cap (default ≤100 pps); well-formed packets only —
  malformed nmap-style probes destabilize embedded/OT gear.
- Configurable scan windows.
- Onboarding docs must tell customers to whitelist the forager IP in
  their IDS — an unannounced sweep trips Darktrace/Suricata and
  generates a security incident.

**Powered-off VMs:** only source 1 sees them. Without a hypervisor
integration, an off host does not exist to us. Model this honestly
with staleness decay: `last_seen` ages → `stale` after N days →
`presumed-retired` after M, surfaced in the coverage report. The claim
is "not observed since X," never a false "doesn't exist."

## 6. Targeted OS matrix (v1)

Linux only. Windows (WinRM/WMI) explicitly deferred.

| Family | Distros | Package query | Patch channel binding |
|--------|---------|---------------|----------------------|
| RHEL-like | CentOS 7/Stream, RHEL 7–9, Rocky, Alma, Oracle, Amazon Linux 2/2023 | `rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\n'` | `subscription-manager status` + `identity` (RHEL); `yum repolist -q` / `dnf repolist` |
| Debian-like | Ubuntu 18.04–24.04, Debian 10–12 | `dpkg-query -W -f '${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'` | `pro status --format json` (Ubuntu ESM); `/etc/apt/sources.list{,.d/}` |
| SUSE | SLES 12/15, openSUSE Leap | `rpm -qa` (as RHEL-like) | `SUSEConnect --status-text`; `zypper lr -u` |
| Alpine | 3.x | `apk info -v` | `/etc/apk/repositories` |

Full per-host collection set (one SSH session, one batched script from
the content pack):

- **Identity:** `/etc/machine-id`; SMBIOS UUID via
  `/sys/class/dmi/id/product_uuid` (root) with `dmidecode -s
  system-uuid` fallback if sudo-permitted — degrade gracefully to
  machine-id only; hostname/FQDN; MACs (`ip -o link`).

  **Verified on the AWS testbed (2026-08-03):** `product_uuid` is mode
  `-r--------` root-only on stock Linux, so an unprivileged
  `nudgebee-ro` gets **nothing** — SMBIOS UUID is unavailable in the
  default credential model, not merely sometimes. `product_serial` is
  root-only too. `board_asset_tag` *is* world-readable and on EC2
  carries the instance id, so cloud VMs still yield a strong
  identifier.

  This has a consequence for §8.2 that is easy to miss: a hypervisor
  record (source 1) knows a VM's SMBIOS UUID, and an SSH record
  (source 5) knows its machine-id. On-prem, with no sudo, **they share
  no strong identifier** — so the two sources cannot be merged on one,
  and every VM would appear twice. The narrow sudoers entry for
  `dmidecode` is therefore not the optional nicety §10 implies; it is
  what makes hypervisor↔SSH reconciliation possible at all. Either
  require it, or accept that on-prem merging leans on corroborated
  weak identifiers, which §8.2 currently forbids. Decide before P4.
- **OS:** `/etc/os-release` (ID, VERSION_ID, PRETTY_NAME),
  `uname -r -m`.
- **Packages:** per family above. Version strings kept **verbatim**
  incl. epoch and release — required for backport-aware CVE matching
  in Phase 1 (vendor OVAL, not NVD CPE); never normalize away the
  distro release suffix.
- **Subscription/repo binding:** per family above. Captured now
  because a lapsed subscription or dead repo means the host **cannot
  be patched** — that surfaces in Phase 0's gap report, not at patch
  time in Phase 2.
- **Reboot-pending signal:** `/var/run/reboot-required` (Debian-like),
  `dnf needs-restarting -r` exit code (RHEL-like, if present). Cheap
  now, needed by Phase 2.

Requirements on targets: reachable sshd + one scoped credential (§9).
No python dependency (unlike Ansible), no temp files — commands run
directly, output streams back.

**EOL reality check:** CentOS 7 (EOL June 2024) and CentOS 8 are
common in exactly the fleets that buy this. Inventory works
identically; Phase 0 records `os_eol: true` from a small static EOL
table so the coverage report can say "N hosts are EOL — no vendor
patches exist for anything on them."

## 7. Signed content packs (the no-upgrade mechanism)

The per-OS collection commands in §6 do **not** live in the forager
binary. They ship as a versioned, Ed25519-signed content pack fetched
from the cloud (same trust root as action signing). Format below is
illustrative — the actual schema is the P1 spike's output, reviewed
by the team:

```yaml
# content-pack: linux-inventory v3
version: 3
signature: <ed25519>
collectors:
  - id: os-release          # every host
    cmd: cat /etc/os-release
  - id: pkgs-rpm
    when: os_family == "rhel"
    cmd: rpm -qa --qf '...'
  - id: pkgs-dpkg
    when: os_family == "debian"
    cmd: dpkg-query -W -f '...'
  # ...
```

Rules:

- Forager validates the signature, then executes collectors verbatim;
  it contains **no per-distro logic** beyond a tiny `when`-expression
  evaluator and output framing.
- Adding a distro, fixing a collector, adding a fact = publish a new
  pack version. No binary release.
- **Pinning + staged rollout are first-class:** tenants can pin a pack
  version; new versions roll out by ring. Content is an update surface
  too — treat it with the same care as binaries.
- **Output parsing happens server-side.** The agent returns raw framed
  output per collector. Parsers (the code that actually churns) never
  ship in the agent.

## 8. Server side

### 8.1 Data model (OPEN — for discussion, not final)

Two directions; decide at P2 kickoff, not in this doc:

- **Option A — reuse the existing resource model.** VMs become
  another resource kind in `cloud_resources` and the existing
  datasource/inventory plumbing, the way other resource types
  already work. Big advantage: everything that already consumes
  resources — troubleshooting, automation, UI listing — infers VMs
  with little or no new plumbing.
- **Option B — dedicated asset tables.** The sketch below. Cleaner
  for identity reconciliation and package data, but new plumbing
  everywhere.

Likely landing point: A for the VM resource itself, with new
satellite tables only where nothing exists today (identities for
merge logic, packages, subscriptions). The sketch below shows the
data we must hold, not a schema decision.

```
assets                -- one row per real machine
  id, tenant_id, cloud_account_id?
  hostname, fqdn, os_family, os_version, os_eol, kernel, arch
  env, criticality, owner            -- from tags/CMDB when known
  power_state, first_seen, last_seen
  coverage_state, gap_reason         -- denormalized for the report

asset_identities      -- merge keys; many per asset
  asset_id, kind, value, source, observed_at
  -- kinds: machine_id | smbios_uuid | instance_id | ad_objectguid   (STRONG)
  --        fqdn | ip | mac                                          (WEAK)
  -- unique (tenant_id, kind, value) enforced for STRONG kinds only

asset_observations    -- raw per-source records, never merged/edited
  asset_id?, tenant_id, source, source_ref, observed_at, payload jsonb

asset_packages        -- the package cache
  asset_id, name, epoch, version, release, arch, pkg_type, repo, installed_at
  pk (asset_id, name, arch)

asset_subscriptions   -- patch-channel binding (used by Phase 2)
  asset_id, kind (rhsm|pro|scc|apt|yum), status, channels jsonb
```

### 8.2 Reconciliation rules

The hard part (research finding #4).

- **Strong identifiers may merge on their own:** machine-id,
  SMBIOS/instance UUID, AD objectGUID.
- **Weak identifiers never merge alone** (FQDN, IP, MAC) — they
  corroborate. Merging on a recycled DHCP lease silently fuses two
  hosts and is nearly undetectable afterwards. Enforced by schema,
  not convention.
- Observations are immutable; `assets` is a projection. Bad merge →
  fix rule → re-project. No data loss.
- Reaping: full-snapshot semantics per (agent, source) with staleness
  decay — same pattern as the existing `removeStaleAgentDatasources`.

### 8.3 Ingest path

New upward action `asset_inventory` (do not overload the existing
`datasource_inventory`, which means "what datasources does this agent
have"):

```json
{"action": "asset_inventory",
 "source": "sweep|vcenter|ldap|libvirt|host_inventory",
 "content_pack_version": 3,
 "observations": [{"identities": {...}, "facts": {...},
                   "collectors": {"pkgs-rpm": "<raw output>"}}]}
```

Relay handler → insert `asset_observations` → reconciler projects into
`assets`/`asset_packages`. Collector-output parsers live here.

### 8.4 Scheduler

Server-side cron pushing actions to forager (same pattern as
scan_orchestrator job scheduling): sweep cadence per CIDR, hypervisor
poll cadence, inventory cadence per asset, scan windows, concurrency
caps. Forager holds zero schedule state.

## 9. Forager changes

New proxy module `pkg/proxy/discovery`, registered like existing
modules.

**Datasource configuration: from the Nudgebee UI, pushed down**
(recommendation — matches every surveyed tool: Rapid7 discovery
connections live in the console and are assigned to engines; Qualys
and Tenable manage scanners centrally; the per-segment node only
enrolls). Two reasons beyond precedent: the coverage report needs the
server to know *intended* scope (CIDRs, datasources) or gaps can't be
computed; and the existing integrations config-push path
(`integration_config.go` / `proxy_config_push.go`) plus `pkg/secrets`
cloud-push already deliver exactly this. Forager keeps only bootstrap
config (relay URL, pairing) locally.

Open point — credential residency: datasource *existence and scope*
is always UI-configured, but the credential *value* is either
UI-entered (cloud-push, default) or a local/vault reference on the
forager for customers who won't let credentials transit our cloud
(`pkg/secrets` local mode exists for this).

New datasource types (credentials via existing `pkg/secrets`
local/cloud-push):

- `vcenter` (govmomi, read-only role)
- `proxmox` (REST `/cluster/resources`)
- `libvirt` (over SSH to the KVM host: `virsh list --all --uuid`)
- `ldap` (AD computer objects; filter `lastLogonTimestamp` to skip
  tombstones)

Actions (existing signed `ActionRequest` scheme):

| Action | Params | Returns |
|--------|--------|---------|
| `discovery_sweep` | cidrs, ports, rate_pps, timeout, exclusions | live hosts: IP, MAC (L2), rDNS, open ports |
| `discovery_hypervisor` | datasource_id | VM list: UUID, name, power state, guest OS, IPs |
| `discovery_ldap` | datasource_id, active_within | computer objects: name, DNS name, lastLogon, objectGUID |
| `discovery_inventory` | targets[], credential_ref, content_pack_ref | per-host facts + raw collector output (§6) |

SSH execution reuses `pkg/proxy/ssh` client plumbing (connection,
auth, timeouts); the discovery module owns target iteration,
concurrency caps, and content-pack execution.

## 10. Credentials & security

- One **read-only inventory credential** per segment: SSH key for a
  dedicated `nudgebee-ro` user. None of the §6 commands require root
  except SMBIOS UUID (graceful fallback; optional narrow sudoers entry
  for `dmidecode` if the customer wants it).
- Delivered via existing `pkg/secrets` (local or cloud-push); never
  logged, never included in action responses.
- Hypervisor/LDAP credentials: read-only roles (vCenter read-only,
  unprivileged AD bind).
- All actions Ed25519-signed; content packs signed with the same trust
  root.
- No new inbound ports on forager; no new ports on targets beyond
  existing sshd.

## 11. Coverage report — the Phase 0 deliverable

One screen, per tenant:

```
Discovered: 412   Reachable: 391   Inventoried: 380
Gaps (32):
  11  ssh-refused          (no credential / firewall)
   8  ssh-auth-failed      (bad credential)
   6  stale                (not observed in 14d)
   4  powered-off          (per vCenter)
   2  unsupported-os       (fingerprint: FreeBSD)
   1  eol-no-repo          (CentOS 7, vault not configured)
```

Coverage states per asset, tracked independently: `discovered` (exists
per any source) → `reachable` (SSH auth ok) → `inventoried` (package
list collected). `discovered − inventoried` is a feature, not an error
state. Nothing else in Phase 0 ships until this screen is correct.

## 12. Build list

1. Migrations: `assets`, `asset_identities`, `asset_observations`,
   `asset_packages`, `asset_subscriptions` + static EOL table.
2. Forager `pkg/proxy/discovery`: sweep, hypervisor (first connector
   per open question 1), ldap, SSH inventory executor; content-pack
   fetch/verify.
3. Content pack v1: linux-inventory (RHEL-like, Debian-like, SUSE,
   Alpine collectors).
4. Relay: `asset_inventory` handler; server-side collector parsers;
   reconciler.
5. Scheduler: per-tenant CIDRs/cadences/windows/rate caps.
6. UI: asset list + coverage report.
7. Cloud-collector VM resources wired in as observer source (existing
   data, new projection).

## 13. Open questions

1. **Customer hypervisor stack** — VMware, Proxmox, Hyper-V, or
   unmanaged KVM/bare metal? Sizes item 2; build only that connector
   first.
2. Approximate fleet size and segment count — sets sweep/inventory
   cadence defaults and forager concurrency caps.
3. Shared SSH credential per segment, per-host credentials, or an
   existing vault (CyberArk etc.)?
4. Windows timeline — deferred from v1, but if the fleet is >30%
   Windows, WinRM support moves up.
5. Content-pack distribution: piggyback on the relay WSS channel vs
   HTTPS fetch from cloud API (relay keeps one channel; HTTPS is
   simpler to cache/CDN).
