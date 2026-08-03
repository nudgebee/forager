# VM Discovery — AWS testbed setup

Status: RUNBOOK — executed 2026-08-03, results inline
Goal: first real sweep and inventory, on our own AWS, with a locally built
binary. No dependency on releases or on the server side.

## What runs where

Three EC2 instances in one small subnet:

```
subnet 10.x.y.0/28  (isolated, us-east-1)
┌──────────────────────────────────────────────┐
│  forager-discovery   ← runs the forager      │
│      │ sweeps the subnet, SSHes into targets │
│      ├──► target-ubuntu    (Debian-like)     │
│      └──► target-al2023    (RHEL-like)       │
└──────────────────────────────────────────────┘
```

**The forager runs on its own EC2 instance, not as a pod on EKS.** Two
reasons, and the second is the one that matters:

1. It matches how this is actually deployed — one node per network segment.
   Testing a different topology than the product ships would prove less than
   it appears to.
2. MAC enrichment reads the kernel neighbour cache after probing. On EKS with
   the VPC CNI, a pod's neighbour cache does not see other instances' L2
   entries, so MACs would come back empty and we would not know whether that
   is a bug or the environment.

Targets are two distros on purpose: `dpkg-query` and `rpm -qa` are different
collectors in the pack, and a run that only exercises one proves half the
matrix. Amazon Linux 2023 is RHEL-like (dnf/rpm), so it covers that family
without needing a RHEL subscription.

## 1. Create the instances

Anything small is fine — `t3.micro` throughout. Requirements:

- All three in the **same subnet**, so the sweep's L2 neighbour lookup works.
- Security group allowing `forager-discovery` → targets on TCP 22.
- The forager host needs outbound 443 to reach the relay. It needs **no
  inbound** at all.
- Tag them so they are obviously disposable.

A `/28` gives 11 usable addresses — enough to see the sweep correctly report
"3 responded out of 11 scanned", which is the result that tells you the
address expansion and exclusion logic are right.

## 2. Build and copy the binary

```bash
# from the forager repo
make build-all            # or: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
                          #       go build -o build/nudgebee-forager-linux-amd64 ./cmd
scp build/nudgebee-forager-linux-amd64 ec2-user@<forager-host>:/tmp/
```

Use `-linux-arm64` instead if you pick Graviton instances.

```bash
sudo install -m 0755 /tmp/nudgebee-forager-linux-amd64 /usr/local/bin/nudgebee-forager
sudo mkdir -p /etc/nudgebee /var/lib/nudgebee
```

## 3. Configure

`/etc/nudgebee/forager.yaml` on the forager host:

```yaml
relay_url: wss://relay.dev.nudgebee.pollux.in/register
access_key: REPLACE_ME
access_secret: REPLACE_ME
data_dir: /var/lib/nudgebee
signing_public_key: 'fA+zl69KzfyYZ8+f722PGR8h8TUP/u76nngOGKUUpYo='

datasources:
  - name: aws-testbed
    type: discovery

    # Scope ceiling. The subnet and nothing else.
    allowed_hosts:
      - 10.x.y.0/28

    discovery:
      max_rate_pps: 50
      concurrency: 10

    # Omit credentials entirely for the sweep-only stage. The node will
    # report it can serve discovery_sweep and not discovery_inventory,
    # which is the honest state — and is only possible from rc.2 onward.
```

Point it at the **dev** relay, not prod: a half-configured node should not
appear in the prod account while we are shaking it out.

Run it in the foreground first rather than as a service — the startup logs
say whether the datasource configured, and that is most of what stage 1 is
checking:

```bash
sudo nudgebee-forager --config /etc/nudgebee/forager.yaml
```

Expect `discovery proxy configured` with `allowed_cidrs=1`, and
`ssh host key verification disabled` (correct — no known_hosts yet).

## 4. Sweep

Nothing schedules discovery yet, so trigger it by hand through the relay:

```json
{"action": "discovery_sweep",
 "datasource_id": "local:aws-testbed",
 "params": {"cidrs": ["10.x.y.0/28"], "ports": [22], "rate_pps": 50}}
```

`ports: [22]` deliberately — the default also probes 3389/5985, which on a
Linux-only testbed generates RDP/WinRM probes for no benefit.

What a correct result looks like: `addresses_scanned` of 11 for a /28 (16
minus network, broadcast, and AWS's three reserved addresses will still be
scanned — AWS reserves them but they simply will not answer), three hosts
returned with `open_ports: [22]`, and MACs present since everything is on the
same L2.

If MACs come back empty, that is the finding — it means the neighbour-cache
read is not working in this environment, which is exactly what running on EC2
rather than EKS was meant to establish.

## 5. Inventory

Needs a signed pack, which does not exist yet (#116). For the testbed,
generate a throwaway keypair and sign the example pack:

```bash
# keypair
go run ./cmd/... # no helper yet — see pkg/signing.GenerateKeypair
```

Then on each target:

```bash
sudo useradd --system --create-home --shell /bin/sh nudgebee-ro
sudo install -d -m 700 -o nudgebee-ro ~nudgebee-ro/.ssh
echo '<forager public key>' | sudo tee ~nudgebee-ro/.ssh/authorized_keys
sudo chmod 600 ~nudgebee-ro/.ssh/authorized_keys
sudo chown nudgebee-ro: ~nudgebee-ro/.ssh/authorized_keys
```

Add to the datasource: `pack_public_key`, `pack_dir`, and the SSH credential.
Then:

```json
{"action": "discovery_inventory",
 "datasource_id": "local:aws-testbed",
 "params": {"targets": ["10.x.y.4", "10.x.y.5"], "content_pack_version": 1}}
```

The check that matters is not "did it return data" but **whether the two
distros ran different collectors** — `pkgs-dpkg` on Ubuntu, `pkgs-rpm` on
AL2023 — and whether version strings came back with epoch and release intact
(`5.14.0-362.8.1.el9_3`, not `5.14.0`). Backport-aware CVE matching in epic 2
depends on that, and it is the thing most likely to be silently wrong.

**The throwaway signing key must not become load-bearing.** Where the real
key lives is an open question on #116; generate this one, use it, and do not
put it anywhere durable.

## What actually happened (2026-08-03)

Built on account 864186153326 (sandbox, not the prod 740395098545),
default VPC, subnet `subnet-0e08ebf5c41c11e4d`, instances pinned to
`172.31.0.10/.11/.12`. The default security group needed one added
rule — its self-referencing rule covered only 5432, so nothing could
reach port 22 and the sweep would have returned zero hosts for reasons
having nothing to do with the code.

**Sweep** — 14 addresses scanned, 3 found, 1.2s. `172.31.0.10` came
back without a MAC while the other two had one: a host does not ARP
for its own address, so it is absent from its own neighbour cache.
That is the result that shows the MAC enrichment reads the kernel
cache rather than inventing values — and is precisely what running on
EKS would have obscured.

**Inventory** — both hosts in 1.6s, 609 and 494 packages. The right
collectors ran on each family and neither ran the other's. Epoch and
release survived intact (`openssl 1 3.5.5 1.amzn2023.0.5`; Debian's
`acpid 1:2.0.33-1ubuntu1` kept its `1:`).

**Findings worth carrying forward:**

1. `/sys/class/dmi/id/product_uuid` is `-r--------` root-only, so the
   unprivileged credential never reads an SMBIOS UUID. See §6 of the
   design doc — this breaks hypervisor↔SSH merging on-prem.
2. `rpm` prints `(none)` for a missing epoch, not `0` or empty, and
   the two are not equivalent for version comparison. Reported on
   nudgebee-enterprise#35405.
3. `board_asset_tag` is world-readable and carries the EC2 instance
   id, so the cloud-VM merge path works unprivileged.

Nothing schedules discovery yet, so both stages were driven through
the exported proxy API by throwaway harnesses rather than the relay.

## Cost and teardown

Three t3.micro instances are a few dollars a month. They are disposable —
terminate them once the coverage report reads correctly, and rebuild from
this document if needed.
