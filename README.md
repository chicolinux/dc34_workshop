# DEFCON 34 — Offensive Packet Wizardry with Scapy
### From Basics to Red Team Toolkit

> **⚠️ MANDATORY — arrive with your lab already built.** The three-VM lab (Kali attacker + Ubuntu
> target + gateway) is **not provided at the venue**. Build it yourself, at home, before the
> workshop — see [`setup/README.md`](setup/README.md) for the full Vagrant setup guide. No
> pre-built lab, no exercises.

> **Note:** This repository is a work in progress and is not officially released until
> **August 1st**. Content may change before then.

**Duration:** 4 hours
**Level:** Intermediate (Python + basic TCP/IP required)
**Instructor:** Miguel Guirao
**Venue:** DEFCON 34, Las Vegas, NV

---

## What You Will Build

By the end of this workshop you will have a working red team Python toolkit that can:

- Discover live hosts and open ports without triggering common IDS signatures
- Perform ARP cache poisoning to intercept cleartext traffic
- Inject data into live TCP sessions
- Fuzz custom binary protocols and detect crashes
- Exfiltrate data over ICMP and DNS covert channels

All exercises run inside an isolated two-VM lab (Kali attacker + Ubuntu target). Nothing touches the venue network.

---

## Prerequisites

- Python 3.10+ (can write a script, understands classes and modules)
- Basic TCP/IP: you can explain what a SYN-ACK is and draw a TCP handshake
- Linux CLI: comfortable with `ip`, `ss`, `tcpdump`, `iptables`
- Scapy is **not** a prerequisite — it is what you are here to learn
- **Bring your lab ready:** the three VMs are **not** provided — build them yourself and install all
  dependencies *before* arriving (do not rely on conference Wi-Fi). See the
  [Do this before the workshop](#do-this-before-the-workshop) section below.

---

## Lab Environment

| Host | IP | Role |
|------|----|------|
| attacker | 192.168.56.1 | Kali Linux (rolling), your machine |
| target   | 192.168.56.2 | Ubuntu 24.04, your victim |
| gateway  | 192.168.56.254 | Alpine Linux, real L2 router (enables ARP MitM exercises) |

Network: isolated VirtualBox internal network `192.168.56.0/24`, no internet access required during
exercises.

**No VMs are provided** — but you don't build them by hand either. A **Vagrantfile** in the repo root
creates and fully provisions all three VMs, the isolated network, and all software with a single
`vagrant up`. See the next section.

---

## Do this before the workshop

Complete these steps **at home, before the day of the workshop**. Do not rely on conference Wi-Fi — the box downloads alone are several GB.

- **Install [VirtualBox 7.0+](https://www.virtualbox.org/wiki/Downloads)** on your laptop (macOS, Windows, or Linux).
- **Install [Vagrant 2.4+](https://developer.hashicorp.com/vagrant/install)** on your laptop.
- **Install rsync** — already present on macOS and Linux; on Windows use Git Bash or WSL.
- **Clone this repo** and enter it:
  ```bash
  git clone https://github.com/chicolinux/dc34_workshop.git ~/dc34_workshop
  cd ~/dc34_workshop
  ```
- **Build and provision all three VMs** (downloads ~4 GB of boxes on first run, then provisions — allow 15–30 min):
  ```bash
  vagrant up
  ```
- **Log into the attacker VM** and verify the environment:
  ```bash
  vagrant ssh attacker
  sudo python3 /vagrant/setup/verify_env.py
  ```
  Every check should print `[OK]`. If anything fails, see [`setup/README.md`](setup/README.md) for troubleshooting before the workshop.
- **Shut the VMs down** when you're done verifying (saves RAM/battery until workshop day):
  ```bash
  exit          # leave the attacker VM
  vagrant halt  # power off all three VMs
  ```

On workshop day, `cd ~/dc34_workshop && vagrant up && vagrant ssh attacker` and you're ready to go.

---

## Workshop Outline

| # | Module | Time | Key Technique |
|---|--------|------|---------------|
| 0 | [Setup & Orientation](setup/README.md) | 15 min | Verify lab, Scapy REPL tour |
| 1 | [Scapy Fundamentals](module1/README.md) | 35 min | Packet crafting, send/recv, PCAP I/O |
| 2 | [Active Recon & Scanning](module2/README.md) | 35 min | SYN scan, OS fingerprinting, IDS evasion |
| 3 | [ARP & ICMP Manipulation](module3/README.md) | 30 min | ARP MitM, ICMP redirect, route injection |
| — | Break | 10 min | — |
| 4 | [TCP/IP Stack Abuse](module4/README.md) | 35 min | Session hijacking, SYN flood, fragmentation |
| 5 | [Protocol Fuzzing](module5/README.md) | 30 min | `fuzz()`, custom protocol fuzzer, crash triage |
| 6 | [Covert Channels](module6/README.md) | 30 min | ICMP C2, DNS exfiltration, TCP header channels |
| 7 | [Capstone](capstone/README.md) | 20 min | Full kill chain: recon → exploit → exfil |

---

## Repository Structure

```
dc34_workshop/
├── setup/           # Environment setup and verification
├── module1/         # Scapy fundamentals
├── module2/         # Active recon and scanning
├── module3/         # ARP and ICMP manipulation
├── module4/         # TCP/IP stack abuse
├── module5/         # Protocol fuzzing
├── module6/         # Covert channels
├── capstone/        # Scenario description and scoring
├── redteam_toolkit/ # Final assembled toolkit package
└── samples/         # PCAP files and test data
```

---

## Quick Start (on workshop day)

```bash
cd ~/dc34_workshop   # the repo you cloned during pre-workshop setup
vagrant up           # resumes the VMs you already built (fast — no re-download)
vagrant ssh attacker
sudo scapy           # launch Scapy interactive shell and you're ready for Module 1
```

> First time here? Do the **"Do this before the workshop"** steps above first.
> Manual setup without Vagrant? See [`setup/README.md`](setup/README.md).

---

## Legal and Ethical Scope

All techniques taught in this workshop are to be used **only** in:
- Environments you own or have explicit written authorization to test
- The provided isolated lab VMs
- CTF competitions and authorized red team engagements

Unauthorized use against real networks is illegal under the CFAA (18 U.S.C. § 1030) and equivalent laws worldwide. The techniques are taught for defensive understanding and authorized offensive testing only.

---

## Resources

- [Protocol Headers Reference](protocol_headers.md) — Mermaid diagrams for every protocol covered in the workshop (Ethernet, ARP, IPv4, ICMP, TCP, UDP, DNS, DC34)
- [Scapy documentation](https://scapy.readthedocs.io/)
- [Scapy GitHub](https://github.com/secdev/scapy)
- RFC 793 (TCP), RFC 826 (ARP), RFC 792 (ICMP)
- *Black Hat Python* — Justin Seitz (No Starch Press)
- *The Art of Exploitation* — Jon Erickson (No Starch Press)

---

## Working with the ARP Table

The `ip neigh` command (iproute2) is the modern tool for inspecting and manipulating the ARP
cache. You will use it throughout modules 3 and 4 — to baseline the cache before an attack,
watch it change in real time during poisoning, and clean up afterwards.

### Displaying entries

```bash
ip neigh                        # full table, all interfaces
ip neigh show dev eth1          # filter to the lab interface only
ip neigh show nud reachable     # only recently confirmed entries
ip neigh show nud stale         # entries not yet reverified (common mid-attack)
```

Example output:
```
192.168.56.2   dev eth1 lladdr 08:00:27:79:be:b4 REACHABLE
192.168.56.254 dev eth1 lladdr 08:00:27:26:ea:73 STALE
```

**NUD states** (Neighbour Unreachability Detection) you will see during exercises:
`REACHABLE` → confirmed recently · `STALE` → not confirmed but still used · `DELAY` → probing
soon · `PROBE` → actively sending probes · `FAILED` → host unreachable · `PERMANENT` → static,
never expires

### Watching in real time

```bash
watch -n1 ip neigh              # refresh every second — run this on the target during 3-A
```

This is the most useful command during exercise 3-A: you can see the gateway's MAC flip to the
attacker's MAC within seconds of starting `arp_mitm.py`, and flip back when the script exits.

### Deleting and flushing entries

```bash
# Delete a single entry (force fresh ARP resolution for that host)
sudo ip neigh del 192.168.56.254 dev eth1

# Flush all dynamic entries on the lab interface (use after any attack)
sudo ip neigh flush dev eth1

# Flush the entire table on all interfaces
sudo ip neigh flush all
```

### Adding and pinning static entries

```bash
# Add a permanent entry — immune to ARP poisoning
sudo ip neigh add 192.168.56.254 lladdr 08:00:27:26:ea:73 dev eth1 nud permanent

# Change an existing entry in place
sudo ip neigh change 192.168.56.254 lladdr 08:00:27:26:ea:73 dev eth1

# Remove a static entry you added
sudo ip neigh del 192.168.56.254 dev eth1
```

Pinning the gateway's real MAC as `permanent` is a simple defence against the module 3
ARP poisoning attack — `arp_mitm.py` cannot overwrite a permanent entry.

> **Legacy alternative:** `arp -n` (display) and `arp -d <ip>` (delete) still work but are
> deprecated in favour of `ip neigh`. Prefer `ip neigh` in all workshop commands.

---

## Managing Multiple Terminals

Several exercises (ARP MitM, session hijacking, covert channels) require three or more
terminals open simultaneously. A terminal multiplexer lets you run them all inside a single
SSH session: popular options are **tmux** (pre-installed on Kali), **screen**, and **zellij**.

### tmux quick reference

```bash
# Start a new named session
tmux new -s workshop

# Inside tmux — create a new window (tab)
Ctrl-b  c

# Switch between windows
Ctrl-b  n          # next window
Ctrl-b  p          # previous window
Ctrl-b  0          # jump to window 0 (use any number)

# Split the current window into panes
Ctrl-b  %          # vertical split (side by side)
Ctrl-b  "          # horizontal split (top / bottom)

# Move between panes
Ctrl-b  arrow key

# Detach from session (leave it running in background)
Ctrl-b  d

# Re-attach later
tmux attach -t workshop
```

**Suggested layout for Module 4 session hijacking:**
- Window 0 `attacker` — run `tcp_injector.py`
- Window 1 `target` — run `nc 192.168.56.254 9999` (victim session)
- Window 2 `gateway` — watch the listener output
