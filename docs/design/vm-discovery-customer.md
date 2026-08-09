# VM Discovery

Draft for discussion. Some of this we build, some of it only you can
set up, and there's one choice we'd like your opinion on.

## What it does

Finds the machines on your network and lists the software installed on
each one, so that patching has something accurate to work from.

For any machine it can't check, it says which machine and why. That
part is deliberate. An inventory that silently skips 50 machines is
harder to trust than one that reports 50 gaps.

## How it works

You run one small program on a single machine in each network. We call
it the collector. Nothing gets installed on the machines being
inventoried.

```
        ┌── collector (one per network) ──┐
        │  finds machines                 │
        │  logs in over SSH               │
        └──────────┬──────────────────────┘
                   │  SSH, read-only
       ┌───────────┼───────────┐
       ▼           ▼           ▼
    your VM     your VM     your VM
```

The collector does three things:

1. Probes the network to see which addresses respond.
2. Asks your virtualisation platform what machines exist, including ones
   that are switched off. If your Linux servers are joined to an Active
   Directory domain, it can ask that too.
3. Logs into each machine over SSH with a read-only account you create,
   and runs read-only commands: list installed packages, read the OS
   version, check whether a reboot is pending.

Nothing is written, changed or restarted on your machines.

## What you get

A per-network summary:

```
Found: 412 machines
  Reachable: 391    (we can log in)
  Inventoried: 380  (we have the software list)

Cannot inventory 32:
  11  no credentials or blocked by firewall
   8  login rejected
   6  not seen for two weeks
   4  powered off
   2  operating system we don't support yet
   1  no security updates available for this OS
```

And per machine: name, operating system, every installed package with
its exact version, and whether the machine is still entitled to
security updates.

That last one is easy to overlook. If a machine's vendor subscription
has lapsed, or it runs an OS past end of life, no patch exists for it.
You want to find that out during an inventory, not during an incident.

## What we need from you

### Questions

- Which virtualisation platform do you run: VMware, Proxmox, Hyper-V,
  plain KVM, or a mix? We'll build support for yours first. It also
  affects one of the limitations below.
- Roughly how many machines, and how many separate networks? This sets
  how fast we scan and how many collectors you need.
- Are your Linux servers joined to an Active Directory domain? Most
  aren't, and if yours aren't, AD won't help here. AD holds a record
  for each domain-joined machine, which is useful when it applies, but
  it is normally Windows machines that are joined rather than Linux.
- Roughly what proportion is Windows? We're doing Linux first, but a
  large Windows estate would change that.
- Which Linux distributions, and are any of them old? See the note on
  end of life above.

### Access you'd need to set up

1. A read-only user on each machine (we suggest `nudgebee-ro`) with an
   SSH key. It only needs to run read-only commands. You'd normally
   push this with whatever you already use to manage machines. We'll
   give you the commands.
2. A read-only account on your virtualisation platform. View
   permissions only.
3. A read-only Active Directory account, but only if your Linux
   machines are domain-joined. An ordinary user account, no group
   memberships.
4. One small VM per network to run the collector on. It needs outbound
   internet on port 443. It needs no inbound access at all.

### Before we scan anything

Network scanning looks like an attack to security tooling, so:

- Your security team needs to know, and to allow the collector's
  address in your intrusion detection. Otherwise the first scan
  becomes an incident.
- We need to agree which address ranges are in scope, and which are
  off limits. Printers, industrial controllers and medical devices are
  the usual exclusions.
- We can restrict scanning to particular hours if you'd prefer.

The scan itself uses ordinary connections at a rate you set, not the
sort of traffic that upsets older equipment.

## The choice we'd like your opinion on

The same machine can be seen twice: once by your virtualisation
platform, and once when we log into it. To show it once, we need
something that tells us both sightings are the same box.

Three identifiers are in play, and they are not the same thing:

- **Machine ID.** A random string written when the OS was installed,
  for example `ec2403e319a2f3f0ae53a05e3daf084b`. Any user can read
  it. Your virtualisation platform has never heard of it.
- **Hardware ID.** The virtual BIOS serial number, set when the VM was
  created. Your virtualisation platform knows every VM by this. On
  Linux only an administrator can read it, so our read-only login
  cannot.
- **MAC address.** The hardware address of a network card, for example
  `02:4d:07:48:c4:87`. Both sides can see this one.

So the platform knows the hardware ID, we know the machine ID, and
neither recognises the other's. Three ways to bridge that:

1. Let the read-only user run one extra command that reads the hardware
   ID. Exact match, no guessing. Costs one narrow permission on each
   machine.
2. Match on MAC address, plus hostname and IP as a cross-check. Nothing
   to set up. Usually right, but not guaranteed: a machine can have
   several network cards, and a cloned VM can end up sharing a MAC with
   the machine it was cloned from.
3. Live with duplicates and merge them in the interface. Nothing to set
   up, but the machine count is approximate.

We'd pick the first, but it depends how much work that permission is in
your environment, which you'd know better than us.

Two smaller things, both defaults you can change: how often we look
(daily for new machines, weekly for software), and whether any of this
data shouldn't leave your network. The collector reads machine names,
OS versions and package lists. It doesn't read files, databases or
application data.

## Where this actually is

Working, and tested against real machines:

- Finding machines on a network
- Reading the full package list over SSH on both major Linux families
- Reading Active Directory, for domain-joined machines
- Running as a service, talking to us securely

Not built yet:

- Storing the results and showing them to you. This is the next piece
  of work and the largest.
- Reading your virtualisation platform. We build this once you tell us
  which one you have.
- Scheduling, so it runs on its own rather than on request.
- Windows.
- Matching packages against known vulnerabilities. That's the next
  phase and it depends on this one being right.

## What it can't do

- A machine that's switched off can't be found by anything that looks
  at a network. It stays invisible until we can read your
  virtualisation platform, which is the only thing that knows about it.
- A machine we can't log into gets found and counted, but not
  inventoried. It shows in the report with the reason.

## Suggested next step

Pick one network to start with, ideally a small one where you already
know roughly what's there. The first run is only useful if you can
check the answer against something.
