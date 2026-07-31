# Epic 1: VM Discovery & Package Inventory

First epic of the **VM Patch & Vulnerability Management** initiative:

| Epic | What ships | Customer's naming |
|------|-----------|-------------------|
| **1. Discovery & package inventory (this one)** | Every VM found, packages cached, coverage report | first half of their "Phase 1" |
| 2. Vulnerability matching | Packages → CVEs (vendor advisories), escalation policy (CVSS/urgency config) | second half of their "Phase 1" |
| 3. Patching | Subscription-based patch apply, approval flow, maintenance windows | their "Phase 2" |
| 4. Hardening & insight | CIS benchmarking, AI impact analysis of vulns on applications | later asks |

Epics 2–4 are sequenced, not speculative — 2 needs 1's package data,
3 needs 2's vuln data. We only break tickets down for epic 1 now.

## Summary

Make VMs first-class resources in Nudgebee — the same way we treat
cloud resources and Kubernetes workloads today. This epic answers
three questions for every customer:

1. How many VMs do you have?
2. What packages are installed on each one?
3. For every VM we couldn't inventory — why not?

This is the foundation for patch & vulnerability management (the
customer ask), and later for observability and automation on VMs.

## Why

A customer wants patch and vulnerability management for their VMs,
including on-premise machines where no cloud API exists. Nothing else
in that product can ship until we reliably know which VMs exist and
what's installed on them. No vendor today does this for Linux without
installing an agent on every VM — that gap is our opening.

## How (in one paragraph)

We install nothing on the VMs. One forager node per network segment
does all the work: it pings the network to find machines, asks the
hypervisor and Active Directory for their lists, and logs into each VM
over SSH with a read-only user to collect the OS and package list.
The commands it runs come from a signed, versioned "content pack"
downloaded from our server — so changing what we collect never
requires a new forager release. All data flows to the server, which
merges the different sightings into one asset list and shows a
coverage report.

## Definition of done

The coverage report is live and correct for a real fleet:

- Every VM appears with a state: **discovered** (we know it exists),
  **reachable** (SSH login works), or **inventoried** (package list
  collected).
- Every gap has a reason (no credential, powered off, EOL OS, stale…).
- Works on CentOS/RHEL, Ubuntu/Debian, SUSE, Alpine. Windows is out
  of scope for now.

## Out of scope (later phases)

CVE matching, patching, escalation policy, CIS benchmarking, Windows,
application-level (non-OS) packages.

## Tickets

| # | Ticket | Where | Note |
|---|--------|-------|------|
| P1 | Forager: SSH inventory + signed content-pack runner | forager | no dependencies |
| P2 | Server: asset storage + ingest + parsers + dedup logic | nudgebee | no dependencies |
| P3 | Forager: network sweep + Active Directory lookup | forager | after P1+P2 demo |
| P4 | Forager: hypervisor connector (vCenter/Proxmox/libvirt) | forager | **blocked: customer must tell us their hypervisor** |
| P5 | Server: scheduler + coverage states + merge cloud VMs | nudgebee | after P1+P2 demo |
| P6 | Content pack v1 + signing/publish pipeline | content | with P5 |
| P7 | UI: asset list + coverage report screen | nudgebee | last |
| P8 | Customer setup docs (SSH user, firewall/IDS allowlist) | nudgebee-docs | alongside P6/P7 |

Milestone 0 = P1 + P2 together: one VM inventoried end-to-end
(signed pack → SSH collection → server → package list in the DB).
Prove the pipe before building breadth.

Storage is an open discussion, not decided: prefer extending the
existing resource model (`cloud_resources` etc.) so features that
already work on resources — troubleshooting, automation, UI —
pick up VMs automatically; add new tables only for data that has no
home today (package cache, identity merge keys).

## Open questions for the customer (send now)

1. Which hypervisor do you run — VMware, Proxmox, Hyper-V, plain KVM?
   (blocks P4)
2. Roughly how many VMs and network segments?
3. Can we get one read-only SSH credential per segment, or do you use
   a vault (CyberArk etc.)?
4. What share of the fleet is Windows?
5. Any restriction on how the forager downloads content packs
   (HTTPS out, or must everything ride the existing relay channel)?

Details behind this epic: `vm-discovery-phase0.md` (design),
`vm-discovery-phase0-tickets.md` (full ticket breakdown with
acceptance criteria).
