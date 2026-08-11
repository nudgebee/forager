# Running discovery from the command line

Discovery can be run directly from the binary, with no account, no relay and
no config file. This is how to evaluate it, reproduce a customer's result on
their own machine, or work on it from a clone of this repo.

These subcommands call the same code the agent calls, so what you see here is
what the agent does.

## Getting the binary

Download from the [releases page](https://github.com/nudgebee/forager/releases)
— pick the file matching your platform:

```bash
curl -fsSL -o forager \
  https://github.com/nudgebee/forager/releases/download/v0.1.4-rc.5/nudgebee-forager-darwin-arm64
chmod +x forager
./forager --version
```

Or build it:

```bash
go build -o forager ./cmd
```

Results print to stdout as JSON, logs to stderr, so output pipes into `jq`.

---

## sweep — what is on this network

Probes every address in a range and reports what answered. No credentials
needed, and nothing is read from the machines themselves — unless `--user`
is paired with `--key`/`--password-env`, in which case each host that
answers on the SSH port also gets a cloud-instance-identity probe (AWS/GCP/
Azure instance metadata, read over SSH — see `pkg/proxy/discovery/cloud_identity.go`).

```bash
./forager sweep --cidr 192.168.1.0/24 --ports 22
./forager sweep --cidr 192.168.1.0/24 --user nudgebee-ro --key ~/.ssh/id_ed25519
```

| Flag | Default | |
|---|---|---|
| `--cidr` | *required* | IPv4 range to sweep |
| `--ports` | `22` | Comma-separated ports to probe |
| `--rate-pps` | `100` | Probes per second |
| `--timeout-ms` | `1000` | Per-probe timeout |
| `--exclude` | | Addresses or CIDRs to skip entirely |
| `--user` | `nudgebee-ro` | SSH username for the cloud-identity probe |
| `--key` | | Path to SSH private key — enables the cloud-identity probe |
| `--password-env` | | Env var holding the SSH password, instead of `--key` — enables the cloud-identity probe |
| `--ssh-port` | `22` | Port the cloud-identity probe connects on |
| `-v` | | Log progress to stderr |

```json
{
  "cidrs": ["192.168.1.0/24"],
  "addresses_scanned": 254,
  "addresses_excluded": 0,
  "rate_pps": 100,
  "duration_seconds": 3.2,
  "hosts": [
    {"ip": "192.168.1.50", "open_ports": [22], "mac": "aa:bb:cc:dd:ee:ff",
     "rdns": "web-01.lan", "sources": ["tcp", "arp"],
     "cloud_identity": "provider=aws\ninstance_id=i-0aab26d051729d673\nregion=us-east-1\npublic_ip=54.1.2.3\n"}
  ]
}
```

`mac` appears only for hosts on the same network segment — anything reached
through a router will not have one, and neither will the machine you are
running from, since a host does not ARP for its own address. `rdns` appears
only when reverse DNS resolves. `cloud_identity` appears only when SSH
credentials were supplied, the host answered on the SSH port, and it's
actually running on a cloud whose metadata service answered — a bare-metal
host, a non-SSH host, or a run with no `--user`/`--key` all leave it absent.
None of these are errors.

`addresses_scanned` excludes the network and broadcast addresses, so a `/24`
scans 254 rather than 256.

### Excluding things you must not touch

```bash
./forager sweep --cidr 10.0.0.0/24 --exclude 10.0.0.5,10.0.0.100/30
```

Exclusions are applied while building the address list, so an excluded host is
never sent a packet at all.

---

## inventory — what is installed on those machines

Logs in over SSH and runs read-only commands. Needs two things sweep does not:
an SSH login on the target, and a signed content pack.

```bash
./forager inventory \
  --cidr 192.168.1.0/24 \
  --targets 192.168.1.50,192.168.1.51 \
  --user nudgebee-ro --key ~/.ssh/id_ed25519 \
  --pack ./linux-inventory-example.yaml \
  --pack-key '<base64 public key>'
```

| Flag | Default | |
|---|---|---|
| `--cidr` | *required* | Scope the targets must fall within |
| `--targets` | *required* | Comma-separated hosts |
| `--pack` | *required* | Signed content pack |
| `--pack-key` | *required* | Base64 Ed25519 public key the pack is signed with |
| `--user` | `nudgebee-ro` | SSH username |
| `--key` | | Path to SSH private key |
| `--password-env` | | Env var holding the SSH password, instead of a key |
| `--port` | `22` | SSH port |
| `--concurrency` | `25` | Hosts inventoried in parallel |
| `--known-hosts` | | known_hosts file; without it host keys are not verified |
| `-v` | | Log progress to stderr |

`--cidr` is required here too. It bounds what can be contacted, so a mistyped
target is refused rather than reached.

### 1. Create the read-only user on each target

```bash
sudo useradd --system --create-home --shell /bin/sh nudgebee-ro
sudo install -d -m700 -o nudgebee-ro -g nudgebee-ro /home/nudgebee-ro/.ssh
echo '<your public key>' | sudo tee /home/nudgebee-ro/.ssh/authorized_keys
sudo chmod 600 /home/nudgebee-ro/.ssh/authorized_keys
sudo chown nudgebee-ro:nudgebee-ro /home/nudgebee-ro/.ssh/authorized_keys
```

No sudo rights are needed. Every command the pack runs is read-only.

### 2. Sign a content pack

```bash
PRIV=$(./forager pack keygen)        # public key is printed to stderr
./forager pack sign ./linux-inventory-example.yaml --key "$PRIV"
```

The example pack lives at `docs/content-packs/linux-inventory-example.yaml`.

### 3. Run it

```json
{
  "content_pack_version": 2,
  "targets": [
    {
      "host": "192.168.1.50",
      "status": "ok",
      "duration_seconds": 1.4,
      "facts": {"os_family": "debian", "os_id": "ubuntu",
                "os_major": "22", "arch": "x86_64"},
      "collectors": {
        "pkgs-dpkg": "acpid\t1:2.0.33-1ubuntu1\tamd64\tinstalled\n...",
        "machine-id": "ec2403e319a2f3f0ae53a05e3daf084b\n",
        "os-release": "NAME=\"Ubuntu\"\nID=ubuntu\n..."
      }
    },
    {"host": "192.168.1.51", "status": "ssh-auth-failed", "error": "..."}
  ]
}
```

The right collectors run per OS family automatically — `dpkg-query` on
Debian-like, `rpm -qa` on RHEL-like. You do not tell it what the target runs.

**A host that fails is a result, not an error.** Ask for ten targets and one
refuses the connection, and you get nine inventories plus one entry saying
why the tenth did not work. Per-host `status` is one of:

| Status | Means |
|---|---|
| `ok` | Collected |
| `ssh-refused` | Port closed or filtered — usually a firewall |
| `ssh-auth-failed` | Reached sshd, credentials rejected |
| `timeout` | Reachable but did not finish in time |
| `error` | Anything else, including a target outside `--cidr` |

Collector output is returned raw, exactly as the command printed it. Parsing
happens server-side, which is why fixing a parser never requires touching a
single machine.

---

## pack — managing content packs

A content pack is the file listing which commands to run. It is signed, and
the signature is checked before anything executes, so the agent never runs
collection commands it cannot attribute. There is deliberately no flag to skip
verification — it would end up in a production config eventually.

```bash
./forager pack keygen                       # new keypair
./forager pack sign <file> --key <private>  # sign, or re-sign, in place
./forager pack verify <file> --key <public> # check without running anything
```

`keygen` prints the private key to stdout and the public key to stderr, so
`PRIV=$(./forager pack keygen)` captures the secret while leaving the public
key visible.

For signing in CI, prefer `--key-env` over `--key`: a key on the command line
lands in shell history and in the process list.

```bash
./forager pack sign ./pack.yaml --key-env PACK_SIGNING_KEY
```

`pack sign` also accepts `--out` to write elsewhere instead of overwriting.

---

## Before you scan someone else's network

Scanning looks like an attack to security tooling, because it is the same
activity. On anything you do not own:

- Tell whoever runs intrusion detection, and get the machine you are running
  from allowlisted. Otherwise the first sweep becomes a security incident.
- Agree which ranges are in scope and which must not be touched. Printers,
  industrial controllers and medical devices are the usual exclusions.
- Lower `--rate-pps` if the network is monitored or fragile. Sweeps use
  ordinary TCP connections, not crafted packets, but volume is still visible.

One side effect worth knowing: a bare TCP connect to port 22 makes `sshd` log
`Did not receive identification string`. It is harmless, but some `fail2ban`
configurations act on it and will ban the scanning host — which then shows up
as `ssh-refused` and looks like a firewall problem.

---

## When something does not work

| What you see | What it usually is |
|---|---|
| `pack signature verification failed` | The pack was signed with a different key than `--pack-key`. Re-sign it, or pass the matching key |
| `loading content pack version N: no such file` | The pack file declares a different version than the one being requested. The version comes from inside the file |
| Every host `ssh-refused` | A firewall between you and the targets, or sshd not listening on `--port` |
| Every host `ssh-auth-failed` | Wrong `--user`, or the key is not in that user's `authorized_keys` |
| Sweep finds nothing | Check `--ports` — the default is only 22. Also check that a firewall is not dropping the probes |
| No `mac` on any host | The targets are not on the same network segment as the machine you are running from. Expected, not a fault |
| `no ssh auth method provided` | Neither `--key` nor `--password-env` was given, or the password env var is empty |
| Sweep is slower than expected | Dead addresses each cost a full `--timeout-ms`. Lower it, or raise `--rate-pps` if the network can take it |

---

## What this does not do

- **Windows.** Sweep will find Windows machines and report their open ports,
  but inventory is SSH-only and the content pack knows only Linux package
  managers. A Windows host comes back as `unsupported-os`.
- **Machines that are switched off.** Nothing that looks at a network can see
  them. The agent can read a hypervisor to find those; the CLI cannot.
- **Active Directory.** The agent supports it; the CLI does not expose it yet.
- **Storing anything.** Results print and are gone. Persisting them, tracking
  changes over time and reporting coverage is what the full product does.
