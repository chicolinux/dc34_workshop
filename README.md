# DEFCON 34 — Offensive Packet Wizardry with Scapy
### From Basics to Red Team Toolkit

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
- **Bring your lab ready:** the two VMs are **not** provided — build them yourself and install all
  dependencies *before* arriving (do not rely on conference Wi-Fi). See `setup/README.md`.

---

## Lab Environment

| Host | IP | Role |
|------|----|------|
| attacker | 192.168.56.1 | Kali Linux (rolling), your machine |
| target   | 192.168.56.2 | Ubuntu 24.04, your victim |
| gateway  | 192.168.56.254 | Virtual router (simulated) |

Network: isolated VirtualBox internal network `192.168.56.0/24`, no internet access required during
exercises.

**No VMs are provided** — but you don't build them by hand either. A **Vagrantfile** in the repo root
creates and fully provisions both VMs (Kali attacker + Ubuntu target), the isolated network, and all
software with a single `vagrant up`. Do this **before** the workshop. See
[`setup/README.md`](setup/README.md) for prerequisites and details.

---

## Workshop Outline

| # | Module | Time | Key Technique |
|---|--------|------|---------------|
| 0 | Setup & Orientation | 15 min | Verify lab, Scapy REPL tour |
| 1 | Scapy Fundamentals | 35 min | Packet crafting, send/recv, PCAP I/O |
| 2 | Active Recon & Scanning | 35 min | SYN scan, OS fingerprinting, IDS evasion |
| 3 | ARP & ICMP Manipulation | 30 min | ARP MitM, ICMP redirect, route injection |
| — | Break | 10 min | — |
| 4 | TCP/IP Stack Abuse | 35 min | Session hijacking, SYN flood, fragmentation |
| 5 | Protocol Fuzzing | 30 min | `fuzz()`, custom protocol fuzzer, crash triage |
| 6 | Covert Channels | 30 min | ICMP C2, DNS exfiltration, TCP header channels |
| 7 | Capstone | 20 min | Full kill chain: recon → exploit → exfil |

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

## Quick Start

```bash
# 1. Clone the workshop repo on your host (needs VirtualBox + Vagrant installed)
git clone <repo_url> ~/workshop && cd ~/workshop

# 2. Build and provision BOTH VMs automatically (first run downloads the boxes)
vagrant up

# 3. Log into the Kali attacker VM (the repo is mounted at /vagrant)
vagrant ssh attacker

# 4. Verify your environment
sudo python3 /vagrant/setup/verify_env.py

# 5. Launch Scapy interactive shell
sudo scapy
```

> Prefer to build the VMs by hand? See the "Manual Setup" fallback in
> [`setup/README.md`](setup/README.md).

---

## Legal and Ethical Scope

All techniques taught in this workshop are to be used **only** in:
- Environments you own or have explicit written authorization to test
- The provided isolated lab VMs
- CTF competitions and authorized red team engagements

Unauthorized use against real networks is illegal under the CFAA (18 U.S.C. § 1030) and equivalent laws worldwide. The techniques are taught for defensive understanding and authorized offensive testing only.

---

## Resources

- [Scapy documentation](https://scapy.readthedocs.io/)
- [Scapy GitHub](https://github.com/secdev/scapy)
- RFC 793 (TCP), RFC 826 (ARP), RFC 792 (ICMP)
- *Black Hat Python* — Justin Seitz (No Starch Press)
- *The Art of Exploitation* — Jon Erickson (No Starch Press)
