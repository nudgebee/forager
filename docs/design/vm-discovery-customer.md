# VM Discovery — how it works, and what we need from you

Draft for discussion. This is a joint build: some of it is ours, some
only you can do, and one choice we should make together.

---

## 1. What this solves

Before you can patch anything, you have to know what you have. Most
teams have a list somewhere, and most of those lists are wrong.

We want to answer three questions honestly: how many machines you have,
what is installed on each, and — for anything we could not check — why
not. The third matters as much as the others. A tool reporting "400
machines, all healthy" while quietly missing 50 is worse than one that
says "we found 450, we could not get into 50, here is why."

## 2. How it works

**Nothing is installed on your machines.**

You run one small program — the collector — on a single machine in each
network. It looks around the network to see what is there, asks your
virtualisation platform and Active Directory what they know about, and
logs into each machine over SSH using a read-only account you create.

```
        ┌── one collector per network ──┐
        │  · finds machines             │
        │  · logs in over SSH           │
        └──────────┬────────────────────┘
                   │  SSH, read-only
       ┌───────────┼───────────┐
       ▼           ▼           ▼
    your VM     your VM     your VM
```

The commands it runs are ones your own administrators would type — list
the installed packages, read the OS version. Nothing is changed,
written, or restarted.

Installing software on hundreds of machines is a project in itself, and
keeping it updated is a permanent cost. One collector per network is
something you can approve, place, and watch.

## 3. What you get

```
Found: 412 machines
  Reachable: 391    (we can log in)
  Inventoried: 380  (we have the software list)

Cannot inventory 32:
  11  no credentials or blocked by firewall
   8  login rejected
   6  not seen for two weeks
   4  powered off
   2  operating system we do not support yet
   1  running an OS with no security updates available
```

Plus, per machine: name, operating system, the full list of installed
software with exact versions, and whether it is still receiving
security updates from its vendor.

That last field is worth the attention. A machine whose vendor
subscription has lapsed, or which runs an OS past end-of-life, **cannot
be patched at all** — better to know now than while trying to fix an
urgent vulnerability.

## 4. What we need from you

### Answers

| Question | Why it matters |
|---|---|
| Which virtualisation platform — VMware, Proxmox, Hyper-V, plain KVM, or a mix? | We build support for yours first; see the first limit in section 6 |
| Roughly how many machines, across how many networks? | Sets scanning pace and how many collectors you need |
| Do you use Active Directory? | It knows machines exist even when they are unreachable |
| Roughly what share is Windows? | We support Linux first; a large Windows estate changes our order of work |
| Which Linux distributions, and any very old ones? | Changes what we can promise — see section 3 |

### Access

1. **A read-only login on the machines** — a user (we suggest
   `nudgebee-ro`) with an SSH key, able to run read-only commands and
   nothing else. Normally pushed with whatever tool you already use to
   manage machines. We will give you the exact commands.
2. **A read-only account on your virtualisation platform** — view
   permissions only.
3. **A read-only Active Directory account**, if you want us to use it.
   An ordinary user, no special groups.
4. **One small VM per network** to run the collector. Outbound internet
   on port 443, no incoming access at all.

### Permission to look

Scanning a network looks exactly like an attack, because technically it
is the same activity. Before we start:

- **Your security team needs to expect it**, and to allow the
  collector's address in your intrusion detection. Without this, the
  first scan becomes a security incident.
- **Agree which address ranges** we may look at, and which we must not
  touch — printers, industrial controllers, medical devices, anything
  fragile.
- **Agree when.** Scanning can be restricted to specific hours.

We scan gently by design: ordinary connections only, at a slow rate you
control, with none of the unusual traffic that can upset older
equipment.

## 5. The decision we need from you

To avoid listing a machine twice, we need something that uniquely
identifies it. There are two candidates: a **machine ID** file, readable
by an ordinary user, and a **hardware ID** from the virtual BIOS, which
on Linux only an administrator can read.

Your virtualisation platform reports the hardware ID. Our read-only
login can only read the machine ID. With just those two, we cannot tell
that "the machine VMware calls X" and "the machine we logged into" are
the same box — so it appears twice.

| Option | Result | Cost |
|---|---|---|
| Allow the read-only user to run one extra command that reads the hardware ID | Accurate count | One small permission per machine |
| Match on name and network address instead | No setup | Less reliable; addresses get reused and we would occasionally be wrong |
| Accept duplicates, merge them in the interface | No setup | The machine count is approximate |

We lean towards the first, but your estimate of the effort should
decide it.

Two smaller ones, both with sensible defaults you can change: how often
we look (daily for new machines, weekly for software), and whether any
categories of data must not leave your network. The collector reads
machine names, operating systems and software lists — not your files,
databases, or application data.

## 6. Where we actually are

**Working now, tested on real machines:** finding machines on a
network; reading the full installed-software list over SSH on both
major Linux families; reading Active Directory; running as a service
and communicating securely.

**Not built yet:** storing the results and showing them to you — the
next and largest piece; reading your virtualisation platform, which we
build once you tell us which one; automatic scheduling, so it runs by
itself; Windows; and matching software against known vulnerabilities,
which is the following phase and needs this one to be right first.

**Limits we are not hiding:**

- A machine that is switched off cannot be seen by anything that looks
  at a network. It stays invisible until we connect to your
  virtualisation platform.
- A machine we cannot log into can still be found and counted, but not
  inventoried. It appears in the report with the reason.

## 7. Next step

Pick one network to try — ideally a small one whose contents you
already know. The first run is only useful if you can check the result
against what you believe is there.
