# DEF CON 34 Workshop Submission
## Offensive Packet Wizardry with Scapy

---

## Introduction

Modern offensive security requires deep control over the network layer, the ability to craft,
inject, intercept, and manipulate packets at will. While tools like Nmap, Metasploit, and
Wireshark abstract that control away, understanding what happens underneath is what separates
a script kiddie from a real practitioner.

This workshop teaches attendees to build their own offensive networking tools from scratch
using **Scapy**, the Python packet crafting and manipulation library. Over four hours, students
progress from raw packet construction through active reconnaissance, man-in-the-middle attacks,
TCP/IP stack exploitation, protocol fuzzing, and covert command-and-control channels, all
implemented in Python, all running against a live isolated lab environment.

The workshop concludes with a capstone scenario called **"Silent Pivot"**: a scored, timed
attack chain that requires students to chain every technique they have learned, host discovery,
service identification, crash exploitation, ICMP C2, and DNS exfiltration, against a target
network without triggering more than five IDS alerts. An optional AI module integrates the
Claude API to provide live, streaming intelligence commentary on packets as they cross the wire,
framing each technique within the MITRE ATT&CK kill chain in real time.

---

## Workshop Outline

### Setup (0:00–0:15)
Environment verification and Scapy orientation. Students run the pre-flight checker, confirm
raw socket access, tour the Scapy interactive REPL, and build their first packets by hand.

### Module 1: Scapy Fundamentals (0:15–0:50)
Packet anatomy, the `/` stacking operator, `sr()`/`sr1()`/`sendp()`, live sniffing with
`sniff()` and `AsyncSniffer`, PCAP read/write with `rdpcap()`/`wrpcap()`, and Scapy's
built-in `fuzz()` primitive. Exercise: write a PCAP dissector that reassembles HTTP bodies
by TCP sequence number.

### Module 2: Active Recon and Scanning (0:50–1:25)
SYN port scanning with half-open connection technique, multi-method host discovery (ARP/ICMP/
TCP/UDP), and passive OS fingerprinting via TTL, TCP window size, and option ordering.
Students implement their own Nmap-style scanner and compare it against ground truth.

### Module 3: ARP and ICMP Manipulation (1:25–1:55)
Full ARP cache poisoning man-in-the-middle with automatic cache restoration on exit, live
traffic interception (HTTP credential harvesting, DNS query inspection), and ICMP Redirect
injection to silently reroute victim traffic without ARP poisoning.

### Break (1:55–2:05)

### Module 4: TCP/IP Stack Abuse (2:05–2:40)
TCP session injection into live Telnet sessions, SYN flood with spoofed sources, RST injection
to terminate arbitrary TCP connections, and IP options exploitation (Loose Source Routing,
Record Route, IP fragmentation for IDS evasion).

### Module 5: Protocol Fuzzing (2:40–3:10)
DNS fuzzer targeting boundary conditions (ID wraparound, opcode/qtype abuse, malformed
qdcount), a custom binary protocol fuzzer against an intentionally vulnerable server with four
planted bugs, and an introduction to stateful fuzzing. Students find and trigger a buffer
overflow on opcode `0xFF`.

### Module 6: Covert Channels (3:10–3:40)
ICMP command-and-control with a full interactive shell (encoded in ICMP echo payload),
DNS exfiltration of arbitrary files via base32-encoded subdomain queries, and TCP header
steganography using IP ID, ToS/DSCP, TCP Urgent Pointer, and inter-packet timing channels.

### Capstone: "Silent Pivot" (3:40–4:00)
Scored, timed full kill chain: stealth host discovery → service identification → crash the
custom protocol server via fuzzing → execute commands via ICMP C2 → exfiltrate `/etc/shadow`
over DNS → clean exit. Teams compete on a live Streamlit scoreboard projected on screen.

### Module 7: AI Lab: PacketSage (Optional / Self-Paced)
Integrates the Anthropic Claude API with Scapy to stream live narrative explanations of
network events, attacker intent, defender visibility, and MITRE ATT&CK context, directly
alongside packet capture in a browser-based Streamlit UI.

---

## What Students Will Learn

- **Packet construction**: Build any Ethernet/IP/TCP/UDP/ICMP/ARP/DNS frame from scratch
  in Python without third-party abstractions.
- **Active reconnaissance**: Implement a SYN port scanner, multi-method host discovery, and
  passive OS fingerprinting using only raw sockets.
- **Man-in-the-middle attacks**: Execute a full ARP cache poisoning attack, intercept live
  credentials and DNS queries, and restore the network state on exit.
- **TCP/IP exploitation**: Inject data into live TCP sessions, flood SYN backlogs with spoofed
  sources, kill arbitrary connections via RST injection, and abuse IP options for IDS evasion.
- **Protocol fuzzing**: Write boundary-value and mutation fuzzers, define custom Scapy packet
  layers for proprietary protocols, detect crashes via canary probes, and save crashing inputs
  to PCAP for reproduction.
- **Covert channels**: Build a functional ICMP reverse shell, exfiltrate files over DNS, and
  encode data in TCP header fields and inter-packet timing.
- **Full kill chain execution**: Chain every technique into a scored, time-pressured offensive
  scenario from initial access through exfiltration.
- **Offensive tool development**: Write importable Python modules and a unified CLI toolkit
  that can be reused across engagements.
- **AI-assisted analysis** (optional): Use the Anthropic Claude API to stream real-time threat
  intelligence and MITRE ATT&CK commentary alongside live packet capture.

---

## Why Students Should Take This Workshop

Most network security courses teach you to *use* tools. This workshop teaches you to *build*
them, and that changes everything.

When you understand how a SYN scanner works at the packet level, you can modify it to evade
a specific IDS signature. When you understand how DNS exfiltration is assembled byte by byte,
you can write a detector for it. When you can forge any packet from scratch, you are no longer
limited by what your tools support.

Scapy is the Swiss Army knife of offensive networking and is used daily by professional red
teams, vulnerability researchers, and malware analysts. Yet it is rarely taught in depth.
This workshop closes that gap, in four hours, students go from `from scapy.all import *` to
a working, modular offensive toolkit they built themselves and can carry into real engagements.

The capstone scenario enforces operational discipline: stealth, clean-up, and staying under
the IDS alert threshold are scored equally alongside technical completion. This mirrors the
pressure of real red team work in a way that a series of isolated exercises cannot.

---

## Keywords

`Scapy` · `packet crafting` · `offensive networking` · `red team` · `Python` ·
`ARP spoofing` · `man-in-the-middle` · `SYN scanning` · `OS fingerprinting` ·
`TCP session hijacking` · `SYN flood` · `RST injection` · `protocol fuzzing` ·
`covert channels` · `ICMP C2` · `DNS exfiltration` · `TCP steganography` ·
`IDS evasion` · `MITRE ATT&CK` · `kill chain` · `network security` ·
`raw sockets` · `live packet analysis` · `AI-assisted security` · `Streamlit`

---

## Abstract

**Offensive Packet Wizardry with Scapy** is a four-hour, 100% hands-on workshop that teaches
attendees to build offensive networking tools from scratch in Python using Scapy, the packet
crafting library used by red teams, malware analysts, and vulnerability researchers worldwide.

Starting from first principles, raw packet construction, layer stacking, and send/receive
mechanics, the workshop moves progressively through active reconnaissance, ARP cache poisoning
with live credential interception, TCP/IP stack abuse (session injection, SYN flood, RST
killing), protocol fuzzing against an intentionally vulnerable binary service, and full covert
channel implementation (ICMP C2 shell, DNS file exfiltration, TCP header steganography).

Every technique is implemented live in Python against an isolated lab network. Students leave
with a working, importable red team toolkit, a Python package with a unified CLI, that they
built themselves and can adapt for future engagements.

The workshop concludes with **"Silent Pivot"**, a scored capstone scenario that chains all
techniques into a realistic kill chain: stealth discovery, service identification, fuzzer-
triggered crash, ICMP command execution, DNS exfiltration of `/etc/shadow`, and network
cleanup, all subject to an IDS alert budget. A live Streamlit scoreboard projects team
rankings in real time.

An optional AI module integrates the Anthropic Claude API to provide streaming narrative
commentary on packets as they cross the wire, explaining attacker intent, defender visibility,
and MITRE ATT&CK kill chain context alongside live Scapy output.

---

## Interactive Engagement

**How will your workshop engage student attendees interactively?**

Every module is structured as a short concept introduction (5–8 minutes) followed by
hands-on implementation time. Students are not watching the instructor, they are writing
and running code on their own lab VMs throughout.

Specific interactive elements:

- **Live exercises in every module**: Each module contains at least one exercise where
  students implement a component themselves (e.g., write the PCAP reassembler, build the
  SYN scanner, implement the DNS exfiltration sender) before seeing the reference solution.
- **Intentionally broken target**: Module 5 includes a custom TCP server with four planted
  bugs. Students discover and trigger these bugs using their own fuzzer, the instructor does
  not tell them which inputs cause crashes.
- **Competitive capstone**: The "Silent Pivot" capstone is scored and projected on a live
  Streamlit leaderboard visible to all attendees, creating healthy competition and a shared
  social experience for the final 20 minutes.
- **Streamlit visual dashboards**: Module 2 offers a real-time network graph that shows
  discovered hosts popping onto the map as Scapy probes the segment, a compelling visual
  that makes the recon phase concrete and immediately readable.
- **AI chat interface** (optional Module 7): Students can ask PacketSage (Claude API) any
  question about what they are seeing in real time and receive streaming, expert-level
  explanations tailored to the current attack context.
- **Pair/group debugging**: Students are encouraged to work in pairs during fuzzing and
  the capstone, mirroring real red team collaboration dynamics.

---

## Contribution to DEFCON Content Diversity

**How will your workshop contribute to diversifying the content provided by DEFCON?**

This workshop occupies a gap that few DEFCON offerings address: the space *between* using
security tools and understanding the network protocols they exploit.

It teaches **tool construction** at the network layer, a skill that makes every other offensive
technique more powerful and more adaptable but that is rarely taught explicitly.

Several elements of the workshop contribute to content diversity:

1. **Python-first offensive networking**: The entire workshop uses Python and Scapy. No GUI
   tools, no commercial software. Attendees who primarily work in application security,
   malware analysis, or defensive roles gain a hands-on understanding of the raw network
   layer that translates directly to those domains.

2. **AI integration in security education**: The optional Module 7 is one of the first
   workshop modules at DEFCON to demonstrate live, streaming AI narration of offensive
   network activity mapped to MITRE ATT&CK, introducing a new paradigm for security
   education and tool-assisted analysis.

3. **Accessible to non-specialists**: The workshop is designed to be completed by anyone
   with solid Python skills and basic networking knowledge. It does not require prior
   experience with any specific security tool, making it accessible to developers,
   sysadmins, and early-career security practitioners who have not yet specialized in
   offensive work.

4. **Protocol fuzzing curriculum**: Dedicated fuzzing content (Module 5) is rare in
   conference workshops outside of specialized vulnerability research tracks. Pairing it
   with a custom vulnerable server that students actually crash provides concrete,
   reproducible results within a workshop timeframe.

---

## Prerequisites

**What knowledge, skills, or experience should the students have prior to the workshop?**

**Required:**

- **Python** Comfortable writing Python scripts (functions, classes, loops, file I/O,
  importing modules). Students will write Python throughout. No advanced Python required,
  but students who struggle with basic syntax will fall behind.
- **Networking fundamentals** Must understand the OSI model through layer 4, IP
  addressing and subnetting, the purpose of ARP, TCP three-way handshake, UDP, ICMP, and
  DNS. Students should be able to read a Wireshark capture and identify what they see.
- **Linux command line** Comfortable running commands in a terminal: `sudo`, file
  navigation, `ip`/`ifconfig`, `ping`, basic text editing. All lab work is done on Linux VMs.

**Helpful but not required:**

- Prior exposure to any packet capture tool (Wireshark, tcpdump)
- Basic familiarity with network security concepts (scanning, sniffing, spoofing)
- Any prior red team or CTF experience

**Not required:**

- Prior Scapy experience (it is taught from scratch)
- C/C++ or assembly knowledge
- Experience with commercial pentesting tools (Metasploit, Burp, Cobalt Strike)

---

## Experience / Skill Level Required

**What is the experience / skill level required for a student to be successful in your workshop?**

**Intermediate** — Students should be comfortable writing Python from scratch (not just
modifying existing scripts) and should understand TCP/IP at the conceptual level (what a
three-way handshake is, what ARP does, what DNS resolves).

Students with only introductory Python or only theoretical network knowledge will struggle
to complete the hands-on exercises without significant assistance. Students with strong
Python and networking backgrounds will find the early modules fast and the later modules
(fuzzing, covert channels, capstone) appropriately challenging.

There is no ceiling, students who finish early have extra exercises and the optional AI
module to explore. The pacing is designed so that the majority of the class reaches the
capstone, but not every student needs to complete every exercise to take value from the day.

---

## VM Requirements

**What are the requirements to RUN the lab VMs?**

**No VMs are distributed.** Students build their own two-VM lab on their own laptop using a
**Vagrantfile** in the workshop repository. A single `vagrant up` downloads the base boxes from
Vagrant Cloud, builds both VMs, configures the isolated network, and installs/configures all software
automatically. Students run this **before** the workshop (per `setup/README.md`).

**Required host software:**
- VirtualBox 7.0+ and Vagrant 2.4+ (the only things a student installs by hand)
- VMware Workstation Pro 17+ / Fusion 13+ also works as the hypervisor

**Minimum hardware:**
- CPU: 4 physical cores (8 logical threads), the two VMs share resources.
- RAM: 8 GB total system RAM (4 GB allocated to attacker VM, 2 GB to target VM).
- Disk: 25 GB free space for both VMs.
- Network: VirtualBox internal network for the isolated lab (no external access required)

**Recommended hardware:**
- CPU: 6+ cores
- RAM: 16 GB
- SSD storage (noticeably faster VM boot and Scapy I/O)

**VMs Vagrant builds automatically:**
- Attacker VM: `kalilinux/rolling` (official Kali box), Python 3, the **latest Scapy installed from
  source** (`github.com/secdev/scapy`), plus all workshop dependencies and the repo (mounted at
  `/vagrant`). Headless/CLI — dashboards are reached from the host browser via a forwarded port.
- Target VM: `bento/ubuntu-24.04` minimal, the vulnerable fuzz server and lab services configured
  and started on boot per `setup/README.md`.

**Network configuration:**
- Both VMs on an isolated VirtualBox internal network (`192.168.56.0/24`)
- Attacker: `192.168.56.1` | Target: `192.168.56.2` | Gateway: `192.168.56.254` (simulated)
- No external internet access required during the workshop (all dependencies installed beforehand)

---

## VM Setup Instructions

**Where do students get the VMs?**

No VMs are distributed as files. Students build the lab themselves with one command — `vagrant up`
from the workshop repository — which provisions both VMs end to end. Full instructions:

> **`setup/README.md`** in the workshop repo — Vagrant/VirtualBox prerequisites, `vagrant up`,
> the isolated-network layout, and per-VM software (including Scapy from source).

---

## Required Hardware and Software

**What other hardware and software are students required to bring?**

### Laptop (required)
- Any laptop capable of running the VMs described above (4-core CPU, 8 GB RAM minimum).
- Operating system: Windows 10/11, macOS 12+, or any modern Linux distribution.
- At least 25 GB of free disk space before the workshop.

### Software and VMs to prepare before arriving (required)
Students must do the following **before** arriving at DEFCON — do not rely on conference Wi-Fi for
downloads:

| Item | Version / Source | Notes |
|------|------------------|-------|
| VirtualBox | 7.0+ — virtualbox.org | Supported hypervisor (VMware 17+/13+ also works) |
| Vagrant | 2.4+ — developer.hashicorp.com/vagrant | Provisions both VMs via `vagrant up` |
| Lab VMs | built by `vagrant up` per `setup/README.md` | Run once before arriving; downloads boxes + all deps |

### Software to install before arriving (recommended)
| Software | Purpose |
|----------|---------|
| Wireshark | PCAP inspection alongside Scapy output |
| Python 3.11+ (host) | Optional: run non-root exercises on host OS |
| VS Code or PyCharm | Code editing inside the VM |

### Optional (Module 7 — AI Lab)
Students who wish to participate in the optional AI module must:
- Create a free account at `console.anthropic.com`
- Generate an Anthropic API key (`ANTHROPIC_API_KEY`)
- Note: Module 7 incurs small API costs (~$0.05–$0.40/hour depending on usage). Students
  are responsible for their own API usage charges. The module is fully optional and all
  core workshop content is accessible without it.

### Not required
- Physical network hardware (all networking is simulated within the VM bridge)
- External USB network adapters
- Any commercial security tool licenses
