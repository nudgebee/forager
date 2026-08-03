# VM Discovery — what's next

Status: PLAN, 2026-08-03
Written after the AWS testbed run, which changed the picture in two ways.

## Where we are

The agent half is done and proven on real hosts. #113 and #114 are
merged and closed; `v0.1.4-rc.2` is released with a green pipeline; a
forager is deployed on EC2, registered as `aws-dev-proxy`, and both
sweep and inventory were validated against Ubuntu and Amazon Linux
targets (609 and 494 packages, correct per-family collectors, epoch and
release intact).

**And it does nothing.** The agent is registered and idle, because
nothing can send it a discovery action. Everything user-visible is
behind the server side.

That is the honest summary: we have a working collector and no product.

## The one decision that blocks design, not code

**SMBIOS UUID is unreadable by the unprivileged credential.** Verified
on the testbed: `/sys/class/dmi/id/product_uuid` is mode `-r--------`.

The consequence is not obvious and is easy to build straight past. A
hypervisor knows a VM by its SMBIOS UUID. An SSH inventory knows the
same VM by its machine-id. On-prem, with no sudo, **those two sources
share no strong identifier** — so §8.2's rule that only strong
identifiers may merge means the same VM lands in the asset list twice,
once from each source, forever.

Three ways out, and someone has to pick before #115 or the #35405
schema hardens:

1. **Require the narrow `dmidecode` sudoers entry.** Cleanest data
   model; costs a privilege we currently advertise as unnecessary, and
   it is a per-host change customers must roll out.
2. **Merge hypervisor↔SSH on corroborated weak identifiers** (hostname
   plus IP, say). Keeps the credential unprivileged; weakens the rule
   that exists precisely because DHCP recycles IPs. If we do this, the
   corroboration threshold needs writing down, not left to judgement.
3. **Accept the duplication** and reconcile in the UI. Cheapest now,
   worst to live with — "how many VMs do I have" is the question this
   epic exists to answer, and it would answer it wrong.

Cloud VMs are unaffected: `board_asset_tag` is world-readable and
carries the instance id, so the cloud↔SSH merge works today.

## Critical path

### 1. Server side — nudgebee-enterprise#35405

The only thing between us and something demoable. Nothing else on this
list changes what a user can see.

Carries two testbed findings already reported on the ticket:
`rpm` prints `(none)` for a missing epoch (and `(none)` ≠ `0` for
version comparison), and golden files for the parsers can be captured
from the testbed rather than hand-written.

Also needs the identity decision above, since it determines what the
merge logic is allowed to do.

### 2. Scheduling

Deliberately left undecided in the ticket breakdown. Now it is the
thing standing between a deployed agent and a running one. Candidate
remains reusing `scan_orchestrator`; confirm or reject at #35405
kickoff rather than carrying it as an open question indefinitely.

### 3. Content pack pipeline — forager#116

Required before any customer deployment. The testbed runs on a
hand-signed pack and a throwaway key that must not become
load-bearing. Where the real signing key lives is still unanswered and
should be settled as part of this.

### 4. Hypervisor connector — forager#115

Still blocked on which hypervisor the customer runs, and now also on
the identity decision. Worth noting it is the only source that sees
powered-off VMs, so the coverage report's denominator is wrong without
it.

## Small fixes worth doing while the above runs

- **`install.sh` fails cryptically on a stale `/tmp` file.** It
  downloads to `/tmp/nudgebee-forager`; if that path exists owned by
  another user, `fs.protected_regular=1` (default on AL2023 and most
  modern distros) stops root writing it and curl reports a bare error
  23. Download to `mktemp -d` instead. Cost us two failed installs.
- **No `private_key_file` credential option.** SSH keys must be inlined
  into config, so key material sits in values files. Supporting a path
  would let Kubernetes mount a secret directly.
- **Agent credentials are plaintext in the infra repo.** All four
  `proxy-agent/values-*.yaml` carry `accessKey`/`accessSecret` in
  clear, while the Rackspace file is properly SOPS-encrypted with an
  `encrypted_regex` that already covers those fields. Same pattern,
  applied to the customer and not to us. Worth encrypting and rotating.
- **Stale IP allowances in the AWS default security group.** Two
  `/32` rules for addresses nobody is using, plus one granting all TCP
  ports. Worth pruning.

## Testbed

Three `t3.micro` in account 864186153326, tagged
`Purpose=vm-discovery-testbed`, `Disposable=true`. A few dollars a
month. Keep while #115 and #35405 are in flight — rebuilding costs
more than running them — and terminate once the coverage report is
correct.

Note the security group pins SSH to specific source IPs, so access
breaks whenever someone's address changes.
