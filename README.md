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

- [Scapy documentation](https://scapy.readthedocs.io/)
- [Scapy GitHub](https://github.com/secdev/scapy)
- RFC 793 (TCP), RFC 826 (ARP), RFC 792 (ICMP)
- *Black Hat Python* — Justin Seitz (No Starch Press)
- *The Art of Exploitation* — Jon Erickson (No Starch Press)
