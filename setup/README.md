# Lab Environment Setup

> **No VMs or OVA files are provided.** The entire two-VM lab is built and provisioned automatically
> on **your own machine** with **Vagrant + VirtualBox** — both VMs, the isolated network, and all
> software are configured for you. Do this **before** the workshop; do not rely on conference Wi-Fi.

## Prerequisites (install on your host)

| Tool | Version | Download |
|------|---------|----------|
| VirtualBox | 7.0+ | <https://www.virtualbox.org/wiki/Downloads> |
| Vagrant | 2.4+ | <https://developer.hashicorp.com/vagrant/install> |
| rsync | any | preinstalled on macOS/Linux; on Windows use Git Bash or WSL |

You need ~25 GB free disk, 8 GB RAM (4 GB attacker + 2 GB target), and a 4-core CPU.

## Quick Start

```bash
# From the workshop repo root (the directory containing the Vagrantfile)
vagrant up                 # downloads boxes, builds + provisions BOTH VMs (10-20 min first run)
vagrant ssh attacker       # log into the Kali attacker VM
sudo python3 /vagrant/setup/verify_env.py   # confirm the lab is healthy
```

That's it — the target VM is already running its vulnerable services. When you're done:

```bash
vagrant halt        # power both VMs off (keeps them)
vagrant destroy -f  # delete both VMs entirely
```

## What `vagrant up` builds for you

| VM | Box (Vagrant Cloud) | Lab IP | Resources | Installed automatically |
|----|---------------------|--------|-----------|-------------------------|
| attacker | `kalilinux/rolling` (2025.2.1) | `192.168.56.1` | 2 vCPU / 4 GB | git, tcpdump, nmap, tshark, python3-pip, **Scapy (latest, from source)**, all `requirements.txt` deps |
| target | `bento/ubuntu-24.04` | `192.168.56.2` | 1 vCPU / 2 GB | python3, **Scapy from source** (for the Module 6 victim-side tools), dnsmasq, netcat-openbsd, inetutils-telnetd, IP forwarding, vulnerable fuzz server on `:9000` |

The Kali box is **command-line only** (headless). You run everything from `vagrant ssh`. The Streamlit
dashboards run inside the attacker VM and are reachable from **your host browser** at
`http://localhost:8501` (port 8501 is forwarded for you). Packet capture uses **tshark/tcpdump** on the
CLI rather than the Wireshark GUI.

The workshop repository is mounted inside the attacker VM at **`/vagrant`**, so run scripts as
`sudo python3 /vagrant/module2/syn_scanner.py ...`. After editing files on your host, run
`vagrant rsync` (or `vagrant reload`) to push changes into the VM.

## Network Topology

```
┌────────────────────┐                          ┌────────────────────┐
│  attacker (Kali)   │                          │  target (Ubuntu)   │
│  192.168.56.1/24   │─────────────────────────▶│  192.168.56.2/24   │
│  eth1 (lab)        │  VirtualBox internal net │  eth1 (lab)        │
└────────────────────┘  "dc34lab" 192.168.56.0/24 └──────────────────┘
          │                                                │
          └───────────────────┬────────────────────────────┘
                              │
                        192.168.56.254
                     (simulated gateway)
```

> **Internal network:** the lab is a VirtualBox *internal* network — fully isolated, with **no host
> adapter**. The two VMs talk only to each other. You reach them from your host via `vagrant ssh` and
> the forwarded port (Streamlit at `localhost:8501`), not by pinging `192.168.56.x` from the host.
> `192.168.56.254` is a simulated gateway — nothing answers there, which is fine for the exercises.
>
> **Interface note:** Vagrant puts its NAT/SSH link on **`eth0`** and the lab network on the **second
> NIC (`eth1`)** — the one holding a `192.168.56.x` address. The workshop scripts auto-select the lab
> NIC (they set `conf.iface` to the interface that routes to `192.168.56.0/24`), so no `--iface` flag
> is normally needed. The attacker's `.1` is pinned by the provisioner (Kali's NetworkManager would
> otherwise DHCP it).

> **Two-VM limitation (ARP MitM / TCP injection):** `192.168.56.254` is a *simulated* gateway with no
> host behind it, so `module3/arp_mitm.py` and `module4/tcp_injector.py` — which need to resolve and
> poison a real victim↔gateway pair — cannot run a full intercept against `.254`. Everything that acts
> directly against the target works (recon, scanning, fuzzing, ICMP/DNS covert channels). For a true
> three-party MitM you would add a third "gateway" VM on the lab network.

## Credentials

Vagrant boxes use **`vagrant` / `vagrant`**, but you should always connect with `vagrant ssh attacker`
or `vagrant ssh target` — no password needed. From the attacker you can reach the target directly,
e.g. `ssh vagrant@192.168.56.2`.

## Manual Setup (without Vagrant — fallback only)

If you cannot use Vagrant, build two VMs by hand (Kali attacker, Ubuntu 24.04 target) on a shared
host-only `192.168.56.0/24` network, then install the software yourself.

On the **attacker** VM:

```bash
sudo apt update
sudo apt install -y python3 python3-pip git tcpdump nmap tshark

# Install the latest Scapy from source
git clone https://github.com/secdev/scapy.git
cd scapy && sudo pip3 install . --break-system-packages --ignore-installed && cd ..

# Install the remaining Python dependencies (Scapy is NOT in this file)
pip3 install -r requirements.txt --break-system-packages --ignore-installed

# Enable promiscuous mode on your lab interface (the 192.168.56.x NIC)
sudo ip link set eth1 promisc on
```

On the **target** Ubuntu VM:

```bash
sudo apt update
sudo apt install -y python3 dnsmasq netcat-openbsd inetutils-telnetd
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
# Start the vulnerable fuzz target (Module 5)
sudo python3 module5/target_server.py --port 9000
```

> On Kali and Ubuntu 24.04, pip is "externally managed" (PEP 668), so the `--break-system-packages`
> flag is required (or use a virtualenv).

## Run Verification Script

```bash
# Inside the attacker VM
sudo python3 /vagrant/setup/verify_env.py
```

All checks should print `[OK]`. If any check fails, see troubleshooting below.

## Troubleshooting

**`vagrant up` can't find/download a box:**
Check connectivity and retry; pin/refresh with `vagrant box update`. First boot downloads several GB.

**Synced folder / `/vagrant` empty on the attacker:**
The Kali box has no guest additions, so the repo syncs via rsync. Run `vagrant rsync` (or
`vagrant reload`) after host-side edits; ensure `rsync` is installed on your host.

**"Operation not permitted" on raw socket:**
Run as root or add capabilities: `sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)`

**Target not reachable:**
Confirm IPs with `ip addr` on both VMs and `ping 192.168.56.2` from the attacker.

**Scapy version too old:**
Re-install the latest from source: `cd /opt/scapy && sudo git pull && sudo pip3 install . --break-system-packages --ignore-installed`

> **Why `--ignore-installed`:** Kali ships an apt-managed Scapy (and deps like `typing_extensions`)
> with no pip `RECORD` file, so pip cannot uninstall them. `--ignore-installed` installs over the top
> into `/usr/local` instead of failing on the uninstall step.

**`conf.iface` shows the wrong interface (picks `eth0`/NAT instead of the lab):**
Set it explicitly to the lab NIC: `conf.iface = "eth1"` (or whichever interface holds the `192.168.56.x`
address from `ip addr`). Most scripts also accept an `--iface eth1` flag.
