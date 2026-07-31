# Ticket Plan: VM Discovery & Package Inventory (Phase 0)

Derived from `vm-discovery-phase0.md`. One epic, 8 tickets. Boundary
rule: one ticket = one owner + one repo/service + one demoable
deliverable. Spikes are the first tasks inside a ticket, not tickets.

**Epic: VMs as first-class Nudgebee resources — Phase 0 discovery &
package inventory.** Done when the coverage report (§11) is correct
against a real fleet: every VM is `discovered`, `reachable`, or
`inventoried`, and every gap has a reason.

**Prerequisite action (not a ticket):** customer answers to §13 —
hypervisor stack (hard-blocks P4), fleet size, credential model,
Windows %, pack distribution channel. Send immediately; only P4
waits on the answers.

**Open decisions — explore inside the ticket, nothing pre-decided:**

- Storage model: extend `cloud_resources`/resource model vs new
  tables (P2, design doc §8.1).
- Content-pack format & schema: the P1 spike *proposes* a format for
  team review; the YAML sketch in §7 is illustrative only.
- Pack distribution channel: HTTPS vs existing relay WSS (P6 +
  customer question 5).
- Sweep implementation: plain TCP-connect vs a library like naabu;
  safe-scan defaults (P3).
- Hypervisor connector: which one first (P4, customer answer).
- Scheduler: reuse the scan_orchestrator pattern vs something new
  (P5).
- Concurrency/cadence/staleness defaults: tune from customer fleet
  size, not fixed in this doc.

Non-negotiable invariants (correctness, not approach — these hold
whatever we pick): weak identifiers never merge assets alone; raw
observations stay immutable/replayable; package versions stored
verbatim incl. epoch/release; content packs signed + pinnable; no
software installed on target VMs.

---

## P1 — Forager: discovery module + content-pack runner + SSH inventory
Repo: forager. New `pkg/proxy/discovery` module, registered like
existing proxies.

Tasks: (a) spike the content-pack design — output is a *proposed*
format for team review (candidate fields: version, signature,
collectors, `when` exprs, a `kind` axis so observability/automation
can reuse the runner later); signing reuses the existing Ed25519
trust root; verbatim execution, framed per-collector output;
(b) spike SSH executor concurrency on `pkg/proxy/ssh` plumbing —
target iteration, per-target timeout, output caps, bounded
concurrency; (c) `discovery_inventory` action (targets[],
credential_ref, content_pack_ref) wiring both; credentials via
`pkg/secrets`.

AC: tampered pack rejected, unknown `when` var fails closed; 50–100
concurrent targets without fd/memory blowup, per-target status on
partial failure; a signed action from relay inventories a static
target list on ≥2 distro families; credentials never in logs or
responses.

## P2 — Server: asset model, ingest, parsers, reconciler
Repo: nudgebee (api-server + relay-server).

Tasks: (a) storage decision first (design doc §8.1 is OPEN): extend
the existing `cloud_resources`/resource model so existing features
(troubleshooting, automation, UI) pick VMs up automatically, vs new
dedicated tables — then migrations only for what has no home today
(identities for merge logic, raw observations, packages,
subscriptions, static EOL data);
(b) relay `asset_inventory` handler (new upward action, not
`datasource_inventory`) — batch insert, size limits; (c) parsers:
os-release, rpm (epoch/release verbatim), dpkg, apk,
subscription/repo, reboot-pending, identity — golden-file tests from
real distro output (CentOS 7, RHEL 9, Ubuntu 20.04/22.04/24.04,
Debian 12, SLES 15, Alpine); (d) reconciler v1 — strong-id merge,
weak-id corroborate only, staleness decay, replay from observations.

AC: weak identifiers cannot merge alone (schema-enforced); two
observations sharing machine-id merge, two sharing only IP don't;
rule fix + replay loses no data; epoch/release survive round-trip;
malformed observation rejected without dropping its batch.

**M0 exit = P1 + P2 demo:** one host end-to-end — signed pack, SSH
collection, relay ingest, parsed packages in Postgres.

## P3 — Forager: discovery sources — sweep + LDAP
Repo: forager.

Tasks: (a) `discovery_sweep` — ARP local L2, ICMP, TCP 22/3389/5985
over configured CIDRs; opt-in per CIDR, exclusions, hard rate cap
(default ≤100 pps), well-formed packets, windows honored; decide
TCP-connect vs naabu inside the ticket; (b) `discovery_ldap` —
read-only AD bind (go-ldap), filter `lastLogonTimestamp` tombstones.

AC: /24 sweep returns IP/MAC/rDNS/open-ports; rate cap verified by
packet capture; exclusions honored; objectGUID lands as STRONG
identity.

## P4 — Forager: hypervisor connector (first one only)
Repo: forager. **Blocked on customer answer.** Build exactly one of:
vcenter (govmomi) | proxmox (REST) | libvirt-over-SSH. Datasource
type + read-only credential via `pkg/secrets`.

AC: returns UUID, name, power state, guest OS, IPs **including
powered-off VMs**; powered-off reaches `assets.power_state`.

## P5 — removed (folded into P2 and kickoff decisions)
Coverage states + gap-reason taxonomy and the cloud-VM merge
(instance-id as STRONG identity) moved into P2 — they're part of the
same projection logic. Scheduling of recurring runs is a kickoff
decision (candidate: reuse the scan_orchestrator pattern — see
`RunOne`/`ScanAccount` usage in recommendation/service.go); forager
still holds zero schedule state either way.

## P6 — Content pack v1 + publish pipeline
Repo: content (+ server config). `linux-inventory` covering the §6
matrix (RHEL-like, Debian-like, SUSE, Alpine); CI signing;
distribution channel (default HTTPS unless customer answer says
otherwise); tenant pinning + ring rollout server-side.

AC: pack version visible per tenant; pinned tenant never receives a
newer pack; new version reaches ring 0 before ring 1.

## P7 — UI: asset list + coverage report
Repo: nudgebee (UI). The §11 screen: totals, per-state counts, gap
breakdown, per-asset drill-down (identities, packages, subscription
binding, sources, last_seen), EOL flags.

AC: numbers reconcile with DB counts; gap rows link to affected
assets.

## P8 — Onboarding docs
Repo: nudgebee-docs. `nudgebee-ro` user + SSH key setup (optional
narrow sudoers for dmidecode), hypervisor read-only role, IDS
whitelisting of forager IP, CIDR opt-in guidance.

AC: a customer goes from zero to first coverage report using only
this doc. Not an afterthought — Rapid7's lesson (§2 finding 9) is
that credential management is the operational cost center.

---

## Dependencies

```
P1 ─┬─► M0 exit ─► P3 ─► P6, P7
P2 ─┘               │
customer answer ─► P4        P8 alongside P6/P7
```

P1 and P2 have no dependencies and run in parallel. P4 is the only
customer-blocked ticket. P8 can start once P1's credential model is
settled.
