# Module 6 — Covert Channels

## What is a Covert Channel?

A covert channel is a communication path that uses a mechanism not designed for
data transfer to convey information, usually to bypass monitoring or access controls.

Two types:
- **Storage channel**: data encoded in a field value (IP ID, DNS subdomain)
- **Timing channel**: data encoded in the interval between events (packet timing)

## Why These Channels Matter

ICMP and DNS exfiltration are not academic — they appear in real-world APT campaigns:

| Group | Technique | Reference |
|-------|-----------|-----------|
| OilRig | DNS tunneling via TXT records | Palo Alto Unit42, 2017 |
| Carbanak | DNS subdomains for C2 | Kaspersky GReAT, 2015 |
| APT32 | ICMP C2 with commands in echo payload | FireEye, 2017 |
| Equation Group | TCP ISN covert channel | Kaspersky, 2015 |

Understanding how these work is essential for both building detections and
for simulating attacker TTPs in red team engagements.

## ICMP Tunnel — Why It Works

Most corporate perimeter firewalls apply this policy:
```
ALLOW outbound: TCP/80, TCP/443, UDP/53, ICMP echo
BLOCK inbound:  anything not in ESTABLISHED/RELATED state
```

ICMP echo is allowed because `ping` is a standard diagnostic tool.
The echo request payload field (8+ bytes, arbitrary) passes through
the firewall completely unexamined by most default configurations.

Detection: ICMP payload analysis (most SIEM tools ignore payload),
excessive ICMP volume, ICMP to unusual destinations, non-standard
payload sizes (real pings = 56 bytes, tools like hping3 = variable).

## DNS Tunnel — Why It Works

DNS queries must reach the authoritative server for the queried domain.
If the attacker controls `attacker.lab`, all queries for `*.attacker.lab`
eventually reach the attacker's server — even through a forward-only proxy.

Rate and entropy detection:
- Normal DNS: < 100 queries/minute, short labels
- DNS tunnel: 100s-1000s/minute, long high-entropy labels
- Tools: Zeek/Bro `dns_query` logs, PassiveDNS anomaly detection, JA3

## TCP Header Channels — Bandwidth vs. Stealth

| Channel | Bits/packet | Typical pkt rate | Effective BW | Detection method |
|---------|------------|-----------------|--------------|-----------------|
| IP ID (16 bit) | 16 | 10/s | ~160 bps | IP ID monotonicity check |
| ToS/DSCP (6 bit) | 6 | 10/s | ~60 bps | DSCP anomaly (nearly never nonzero) |
| TCP Urgent Ptr | 16 | 10/s | ~160 bps | URG flag absent but urgptr nonzero |
| Timing (1 bit) | 1 | 10/s | ~10 bps | Statistical timing analysis |

## Exercises

| Exercise | Files | Objective |
|----------|-------|-----------|
| 6-A | `icmp_tunnel.py` + `icmp_agent.py` | Two-way ICMP command execution |
| 6-B | `dns_exfil.py` + `dns_collector.py` | Exfiltrate /etc/passwd over DNS |
| demo | `tcp_covert.py` | IP ID, ToS, urgent pointer, timing channels |
| 6-X (extra) | manual + iptables | Implement full C2 within firewall rules allowing only ICMP + DNS |

## Detection Signatures

ICMP covert channel:
```
# Snort
alert icmp any any -> $HOME_NET any (msg:"ICMP payload covert channel"; dsize:>56; sid:1000001;)
alert icmp any any -> $HOME_NET any (msg:"High ICMP rate"; detection_filter:track by_src, count 50, seconds 10; sid:1000002;)
```

DNS exfiltration:
```
# Snort
alert dns any any -> any 53 (msg:"Long DNS label (possible tunnel)"; dns.query; content:!"."; pcre:"/[a-z2-7]{30,}/i"; sid:1000003;)
```

## OpSec Considerations

For authorized red team engagements using these techniques:
- Use `--delay` to stay under baseline DNS/ICMP rate thresholds
- Rotate session IDs to avoid pattern matching
- Use plausible ICMP payload sizes (48-64 bytes matches real OS pings)
- Ensure DNS traffic goes to your controlled domain, not an ISP resolver
- Clean up: stop agents, flush DNS resolver cache, restore iptables rules
