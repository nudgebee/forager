# VM Discovery — how it works, and what we need from you

Draft for discussion. This is a joint build: some of it is ours, some
of it only you can do, and a few choices we should make together.

---

## 1. The problem this solves

Before you can patch anything, you have to know what you have. Most
teams have a list somewhere, and most of those lists are wrong — a
spreadsheet, a CMDB nobody updates, a monitoring tool that only sees
what someone installed an agent on.

We want to answer three questions honestly:

1. **How many machines do you actually have?**
2. **What software is installed on each one?**
3. **For anything we could not check — why not?**

The third one matters as much as the first two. A tool that reports
"400 machines, all healthy" while quietly missing 50 is worse than one
that says "we found 450, we could not get into 50, here is why."

## 2. How it works

**We do not install anything on your machines.**

Instead, you run one small program — we call it the collector — on a
single machine in each network. That collector:

- looks around the network to see what is there,
- asks your virtualisation platform and Active Directory what they
  know about,
- logs into each machine over SSH using a read-only account you
  create, runs a few read-only commands, and reads the answers.

```
        ┌── one collector per network ──┐
        │  · finds machines             │
        │  · logs in over SSH           │
        └──────────┬────────────────────┘
                   │  SSH, read-only
       ┌───────────┼───────────┐
       ▼           ▼           ▼
    your VM     your VM     your VM      ← nothing installed here
```

The commands it runs are things like "list the installed packages" —
the same commands your own administrators would type. Nothing is
changed, nothing is written, nothing is restarted.

**Why no agent on each machine?** Because installing software on
hundreds of machines is a project in itself, and keeping it updated is
a permanent cost. One collector per network is something you can
approve, place, and watch.

## 3. What you get

A single view, per network, that looks like this:

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

Plus, for each machine: its name, operating system, the full list of
installed software with exact versions, and whether it is still
receiving security updates from its vendor.

That last point is worth calling out. A machine whose vendor
subscription has lapsed, or which runs an OS past end-of-life, **cannot
be patched at all**. Better to learn that now than when you are trying
to fix an urgent vulnerability.

## 4. What we need from you

### 4a. Answers — so we build the right thing first

| Question | Why it matters |
|---|---|
| Which virtualisation platform? VMware, Proxmox, Hyper-V, plain KVM, or a mix | It is the only thing that knows about **powered-off** machines. We will build support for yours first |
| Roughly how many machines, across how many networks? | Sets how fast we scan and how many collectors you need |
| Do you use Active Directory? | It knows machines exist even when they are switched off or firewalled |
| Roughly what share is Windows? | We support Linux first. If a large part of the fleet is Windows, we reprioritise |
| Which Linux distributions, and any very old ones? | Old systems like CentOS 7 still work for inventory, but have no vendor patches — we want to flag them clearly rather than surprise you |

### 4b. Access — things only you can set up

1. **A read-only login on the machines.** A user (we suggest
   `nudgebee-ro`) with an SSH key, which can run read-only commands and
   nothing else. You would normally push this with whatever tool you
   already use to manage machines. We will give you the exact commands.

2. **A read-only account on your virtualisation platform.** View
   permissions only — enough to list machines and see whether they are
   on or off.

3. **A read-only Active Directory account**, if you want us to use it.
   An ordinary user with no special group membership.

4. **A place to run the collector** — one small VM per network. It
   needs outbound internet access on port 443 and no incoming access
   at all.

### 4c. Permission to look — the bit people forget

Scanning a network looks exactly like an attack, because technically it
is the same activity. Before we start we need:

- **Your security team to expect it**, and to allow the collector's
  address in whatever intrusion detection you run. Without this, the
  first scan generates a security incident.
- **Agreement on which address ranges** we may look at, and which we
  must not touch — printers, industrial controllers, medical devices,
  anything fragile.
- **Agreement on when.** We can restrict scanning to specific hours.

We deliberately scan gently: normal connections only, at a slow rate
you control, with no unusual traffic of the sort that can upset older
equipment.

## 5. Decisions we should make together

### 5a. Identifying a machine reliably

This one has a real trade-off and we would like your view.

To avoid listing the same machine twice, we need something that
uniquely identifies it. There are two candidates:

- A **machine ID** file, readable by an ordinary user.
- A **hardware ID** from the virtual BIOS, which on Linux can only be
  read by an administrator.

Your virtualisation platform reports the *hardware* ID. Our read-only
login can only read the *machine* ID. If we only have those two, we
cannot tell that "the machine VMware calls X" and "the machine we
logged into" are the same box — so it appears twice.

Three ways forward:

1. **Grant one narrow extra permission** — allow the read-only user to
   run a single command that reads the hardware ID, and nothing else.
   Cleanest result; costs one small permission on each machine.
2. **Match on name and address instead.** No extra permission, but less
   reliable — addresses get reused, and occasionally we would get it
   wrong.
3. **Accept some duplicates** and let you merge them in the interface.
   No setup cost, but the machine count is then approximate.

We lean towards option 1, but it is your estimate of the effort that
should decide it.

### 5b. How often, and how fast

Defaults we suggest, all adjustable: look for new machines daily,
re-check software weekly, scan slowly enough to be invisible in
network monitoring.

### 5c. What happens to the data

The collector sends what it read — machine names, operating systems,
installed software lists. It does not read your files, your databases,
or your application data. If there are categories you do not want
leaving your network, tell us now rather than later.

## 6. Where we actually are

Being straight about status, because "in progress" covers too much.

**Working now, tested on real machines:**

- Finding machines on a network
- Reading the full installed-software list over SSH, on both major
  Linux families
- Reading Active Directory
- The collector runs as a service and communicates securely

**Not built yet:**

- Storing the results and presenting them to you — this is the next
  piece of work and the biggest remaining one
- Reading your virtualisation platform — we build this once you tell
  us which one you use
- Automatic scheduling, so it runs by itself rather than on request
- Windows machines
- Matching software against known vulnerabilities. That is the next
  phase, and this one has to be right first

**Known limits we are not hiding:**

- A machine that is switched off is invisible until we connect to your
  virtualisation platform. Nothing that looks at a network can see a
  machine that is off.
- A machine with no SSH access can be found, but not inventoried. It
  will show in the report as a gap with the reason.
- Very old systems can be inventoried, but there may be no patches
  available for them. We will say so plainly.

## 7. What we would like next

1. The answers in section 4a — mainly which virtualisation platform.
2. Your view on the identification trade-off in 5a.
3. A single network to try first. Ideally a small one, with machines
   you know, so that when we show you the result you can tell whether
   it is right.

The last point is the important one. The first run is only useful if
you can check it against what you already know is there.
