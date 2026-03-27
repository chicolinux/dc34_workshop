# Lab Environment Setup

## VM Download

Download the pre-configured OVA files from the USB drives distributed at the workshop registration desk.

| File | Size | SHA256 |
|------|------|--------|
| `dc34_attacker_kali.ova` | ~4 GB | (printed on USB label) |
| `dc34_target_ubuntu.ova` | ~2 GB | (printed on USB label) |

## Import into VirtualBox or VMware

### VirtualBox
```bash
VBoxManage import dc34_attacker_kali.ova --vsys 0 --vmname attacker
VBoxManage import dc34_target_ubuntu.ova  --vsys 0 --vmname target

# Create isolated host-only network
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 10.0.0.254 --netmask 255.255.255.0

# Attach both VMs to the network
VBoxManage modifyvm attacker --nic1 hostonly --hostonlyadapter1 vboxnet0
VBoxManage modifyvm target   --nic1 hostonly --hostonlyadapter1 vboxnet0
```

### VMware Workstation / Fusion
Import both OVA files via `File > Open`. In VM Settings > Network Adapter, select **Custom: VMnet2** for both VMs. Set VMnet2 to Host-only, `10.0.0.0/24`.

## Network Topology

```
┌──────────────────┐           ┌──────────────────┐
│  attacker (Kali) │           │  target (Ubuntu)  │
│   10.0.0.1/24    │──────────▶│   10.0.0.2/24    │
│   eth0           │  virbr1   │   eth0            │
└──────────────────┘           └──────────────────┘
         │                              │
         └──────────┬───────────────────┘
                    │
               10.0.0.254
              (virtual GW)
```

## Credentials

| VM | Username | Password |
|----|----------|----------|
| attacker | kali | dc34workshop |
| target | ubuntu | dc34workshop |

SSH from attacker to target: `ssh ubuntu@10.0.0.2`

## Manual Setup (if not using the OVA)

If you want to use your own machines, install the following on the attacker:

```bash
# Kali / Debian
sudo apt update
sudo apt install -y python3 python3-pip scapy tcpdump nmap wireshark-qt

pip3 install scapy netaddr tabulate cryptography

# Enable promiscuous mode on your lab interface
sudo ip link set eth0 promisc on
```

On the target Ubuntu VM, install services used in the exercises:

```bash
sudo apt update
sudo apt install -y python3 dnsmasq netcat-openbsd telnetd
# Enable IP forwarding for certain exercises
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

## Run Verification Script

```bash
# On the attacker VM
cd ~/workshop
sudo python3 setup/verify_env.py
```

All checks should print `[OK]`. If any check fails, see the troubleshooting section below.

## Troubleshooting

**"Operation not permitted" on raw socket:**
Run as root or add capabilities: `sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)`

**Target not reachable:**
Check `ip addr` on both VMs confirm IPs, and `ping 10.0.0.2` from attacker.

**Scapy version too old:**
`pip3 install --upgrade scapy`

**`conf.iface` shows wrong interface:**
Set it explicitly: `conf.iface = "eth0"` (replace with your interface name from `ip addr`).
