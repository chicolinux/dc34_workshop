# Module 3 — ARP and ICMP Manipulation

## Goals for this Module

- Understand why ARP has no authentication and how that enables poisoning attacks
- Perform ARP cache poisoning to become an on-path attacker between victim and gateway
- Craft gratuitous ARP and unicast ARP replies with Scapy
- Intercept and inspect cleartext traffic flowing through the attacker machine
- Restore ARP caches cleanly after an attack to avoid detection
- Understand when ICMP Redirect can reroute traffic and how to send one

---

## Checking the ARP Cache

Run these on both the attacker and target VMs to observe cache state before and after poisoning:

```bash
ip neigh        # modern iproute2 — preferred
arp -n          # classic utility (-n skips DNS reverse lookup)
```

Example output:
```
192.168.56.2   dev eth1 lladdr 08:00:27:ab:cd:ef REACHABLE
192.168.56.254 dev eth1 lladdr 08:00:27:11:22:33 STALE
```

Watch the cache update in real time during a poisoning exercise:
```bash
watch -n1 ip neigh
```

Flush entries to force fresh ARP resolution before a test:
```bash
sudo ip neigh flush dev eth1
```

---

## Why ARP Attacks Still Work

ARP was designed in 1982 (RFC 826) for a trusted LAN. There is no authentication —
any host can reply to an ARP request, or send an unsolicited "gratuitous" ARP reply
claiming any IP address. Modern enterprise networks are full of flat VLANs where
every host is on the same Layer 2 segment. ARP poisoning works there today.

## ARP Cache Poisoning — How It Works

```
Normal state:
  Victim ARP cache:  192.168.56.254 → aa:bb:cc:dd:ee:ff  (real gateway MAC)
  Gateway ARP cache: 192.168.56.2   → 11:22:33:44:55:66  (real victim MAC)

After poisoning:
  Victim ARP cache:  192.168.56.254 → attacker_mac  (traffic to GW goes to attacker)
  Gateway ARP cache: 192.168.56.2   → attacker_mac  (traffic to victim goes to attacker)

With IP forwarding on attacker:
  victim → attacker → gateway → internet
  internet → gateway → attacker → victim
```

The attacker sees all cleartext traffic in both directions. HTTPS is still
protected (TLS), but DNS queries, HTTP, Telnet, FTP, and many application
protocols are exposed.

## IP Forwarding Requirement

Without IP forwarding, the attacker machine drops relayed traffic and the victim
loses internet access — quickly noticed. Always enable forwarding first:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

## Gratuitous ARP

A gratuitous ARP is an ARP reply that nobody asked for — sent without a preceding request.

Normal ARP exchange:
```
Host A → broadcast:  "Who has 192.168.56.2?"
Host B → Host A:     "192.168.56.2 is at 08:00:27:ab:cd:ef"
```

Gratuitous ARP skips the question:
```
Host B → broadcast:  "192.168.56.2 is at 08:00:27:ab:cd:ef"  (unsolicited)
```

**Legitimate uses:** a host announces itself on boot, detects duplicate IPs, or a failover
device (HSRP/VRRP) takes over an IP and updates the whole segment at once.

**Why it is dangerous:** every host on the segment accepts it and updates their ARP cache with
no validation. An attacker broadcasts "192.168.56.254 (gateway) is at *attacker_mac*" and every
host immediately starts sending gateway-bound traffic to the attacker.

In Scapy:
```python
sendp(
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    ARP(op=2, pdst="192.168.56.254", psrc="192.168.56.254", hwsrc=attacker_mac),
    iface="eth1"
)
```

`op=2` is an ARP reply, `dst` is broadcast — that is the gratuitous ARP pattern.

## Gratuitous ARP vs. Targeted Reply

| Method | Target | Visibility |
|--------|--------|------------|
| Gratuitous ARP (broadcast) | All hosts on segment | Very visible in logs |
| Unicast ARP reply | Specific victim only | Less visible |

Prefer unicast replies for stealth. The `arp_mitm.py` tool uses unicast.

## ICMP Redirect — When It Works

ICMP Redirect (type 5) tells a host "for traffic to X, use router Y instead of me."
A spoofed redirect from the gateway's IP can reroute a victim's traffic.

**Condition:** `net.ipv4.conf.all.accept_redirects` must be 1.
Modern Linux defaults this to 0. Windows and older kernels may accept them.

Check target setting:
```bash
# On victim:
sysctl net.ipv4.conf.all.accept_redirects   # 0 = ignores redirects
```

Enable for testing:
```bash
sudo sysctl -w net.ipv4.conf.all.accept_redirects=1
```

## Countermeasures (Know the Defense)

| Defense | How it works | Bypassed by |
|---------|-------------|-------------|
| Dynamic ARP Inspection (DAI) | Switch validates ARP against DHCP binding table | ARP from static IP or authorized MAC |
| Static ARP entries | `arp -s IP MAC` — pinned, ignores updates | n/a (no bypass) |
| 802.1X port security | Port bound to authenticated identity | Compromised authenticated device |
| VLAN segmentation | Different L2 domain per VLAN | Cross-VLAN if routing exists |
| ArpWatch / XArp | Alert on new MAC-IP associations | Low-and-slow poisoning |

Most flat enterprise networks have none of these. DAI requires managed switches
and correct DHCP snooping configuration — rarely deployed consistently.

## Exercises

| Exercise | File | Objective |
|----------|------|-----------|
| 3-A | `arp_mitm.py` | Full MitM with traffic interception and cache restore |
| 3-B | `icmp_redirect.py` | Route hijack via ICMP Redirect |
| 3-X (extra) | manual | Passive traceroute via TTL-limited probes to map internal topology |
| passive | `arp_scanner.py` | Passive MAC/IP discovery from observed ARP traffic |
