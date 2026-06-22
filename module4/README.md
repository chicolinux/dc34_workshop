# Module 4 — TCP/IP Stack Abuse

## Goals for this Module

- Understand the TCP state machine and identify where each attack fits within it
- Inject a payload into an established TCP session by calculating the correct seq/ack numbers
- Kill arbitrary TCP connections with RST injection
- Perform a SYN flood and observe its effect on the target's connection table
- Craft packets with IP options (LSRR, Record Route) and manually fragment IP datagrams

---

## TCP State Machine

```
              CLOSED
                |
           SYN sent
                |
           SYN-SENT ──────────────────────────┐
                |                             |
          SYN-ACK received              RST received
                |                             |
          SYN-RECEIVED                     CLOSED
                |
            ACK sent
                |
          ESTABLISHED  ◄──── This is where session hijacking happens
           /       \
      FIN sent   RST received
          |            |
      FIN-WAIT      CLOSED
```

| Step | State | What happened |
|------|-------|---------------|
| 1 | `CLOSED` → `SYN-SENT` | Client sends a SYN packet to initiate a connection |
| 2 | `SYN-SENT` → `SYN-RECEIVED` | Server replies with SYN-ACK; client records the server's ISN |
| 3 | `SYN-SENT` → `CLOSED` | Server sent RST instead of SYN-ACK — port closed or filtered |
| 4 | `SYN-RECEIVED` → `ESTABLISHED` | Client sends the final ACK; three-way handshake complete |
| 5 | `ESTABLISHED` | Data flows in both directions; seq/ack numbers increment with every byte sent |
| 6 | `ESTABLISHED` → `FIN-WAIT` | Either side sends FIN to begin graceful teardown |
| 7 | `ESTABLISHED` → `CLOSED` | Either side sends RST — immediate, ungraceful teardown |

**Why ESTABLISHED is the hijacking target:** both sides have agreed on seq/ack numbers and
the application is actively exchanging data. An attacker who can observe the traffic knows
the current seq and ack values and can inject a forged packet that the server accepts as
coming from the legitimate client.

## Session Hijacking Requirements

To inject into an existing TCP session you need:
1. **Correct source IP and port** (the victim's IP:port)
2. **Correct destination IP and port** (the server's IP:port)
3. **Sequence number within the receiver's window** — the server accepts packets
   where `expected_seq <= seq <= expected_seq + window_size`
4. **Correct ACK number** — must acknowledge what the server has sent

Getting seq/ack: you must observe the traffic. This requires being on-path (ARP MitM),
on the same hub/mirror port, or having compromised a network device.

## Sequence Number Math

When you observe a packet from victim to server:
```
  victim sends: seq=1000, len=50 bytes of data
  server will next expect: seq=1050

  To inject AFTER this packet:
    your_seq = 1050
    your_ack = server_seq + server_data_len
```

The ACK storm problem: when you inject, both sides get confused about seq numbers
and start sending ACKs that the other side rejects with more ACKs. Solution: kill
the session with RSTs immediately after injection, or stay on-path and suppress the
victim's RSTs via ARP poisoning.

## SYN Flood and SYN Cookies

### The SYN flood problem

Every incoming SYN causes the server to allocate a `SYN_RECV` entry in the backlog table and
send a SYN-ACK. A flood with randomized spoofed source IPs means the SYN-ACKs go to
nonexistent hosts — no ACK ever arrives — but the table entries stay until they time out:

```
Default Linux backlog:  128–1024 entries
Flood with spoofed SYNs → table fills → legitimate connections refused
```

### What SYN cookies do

Instead of allocating a table entry on SYN, the server encodes all connection state into the
**ISN (Initial Sequence Number)** of the SYN-ACK:

```
ISN = hash(src_ip, src_port, dst_ip, dst_port, timestamp) + MSS encoding
```

```
Client → Server:  SYN
Server → Client:  SYN-ACK  (ISN carries encoded state — no table entry allocated)
Client → Server:  ACK       ← server decodes state from ACK number, creates entry now
```

Spoofed SYNs never produce a real ACK, so no memory is ever allocated for them. The backlog
stays empty regardless of flood volume.

**The trade-off:** SYN cookies cannot carry TCP options (window scale, SACK) because there is
no stored SYN to refer back to. Legitimate connections established during a flood see slightly
reduced throughput.

SYN cookies are on by default and activate automatically when the backlog fills:
```bash
sysctl net.ipv4.tcp_syncookies   # 1 = enabled (default)
```

### Monitor during a flood

```bash
ss -s                                         # shows SYN_RECV count in real time
cat /proc/net/tcp | grep " 06 " | wc -l      # count SYN_RECV entries directly
```

## IP Fragmentation Attack History

| Attack | Description | Modern status |
|--------|-------------|---------------|
| Teardrop (1997) | Overlapping fragments crashed BSD IP stack | Patched |
| Tiny fragment | TCP header split across fragments, evades ACL port checks | Works on some firewalls |
| Fragment evasion | IDS misses TCP flags in later fragments | Still works on many IDS |
| Ping of Death | Oversized reassembled ICMP | Patched universally |

Modern Linux: `ip_defrag_timeout` reassembles properly and discards overlapping fragments.
Some edge routers and embedded devices still mishandle edge cases.

## Exercises

| Exercise | File | Objective |
|----------|------|-----------|
| 4-A | `tcp_injector.py` | Inject payload into live netcat session (see walkthrough below) |
| 4-B | `syn_flood.py` | SYN flood with randomized spoofed IPs |
| standalone | `rst_injector.py` | Kill sessions by injecting RST |
| demo | `ip_options.py` | LSRR, Record Route, fragmentation demo |
| 4-X (extra) | manual | Route through LSRR waypoint to reach normally-blocked host |

### Exercise 4-A Walkthrough — Session Hijacking

The gateway VM runs a persistent plaintext TCP listener on port 9999. The target connects to
it as the "victim user." The attacker ARP-poisons both ends, sniffs the live session, and
injects a command into the stream.

**Open three terminals before starting:**

| Terminal | VM | Command |
|----------|----|---------|
| T1 (attacker) | `vagrant ssh attacker` | run the injector (step 3) |
| T2 (victim) | `vagrant ssh target` | open the nc session (step 1) |
| T3 (gateway) | `vagrant ssh gateway` | optional — watch gateway side |

**Step 1 — Victim opens a plaintext session (T2):**
```bash
nc 192.168.56.254 9999
```
Type a few messages and press Enter so there is live traffic on the wire.

**Step 2 — Keep T2 active and switch to T1.**

**Step 3 — Attacker hijacks the session (T1):**
```bash
sudo python3 /vagrant/module4/tcp_injector.py \
    --victim 192.168.56.2 \
    --gateway 192.168.56.254 \
    --port 9999
```

The injector will:
1. ARP-poison both ends (target thinks gateway is at attacker's MAC, and vice versa)
2. Sniff the wire for a data packet carrying live seq/ack numbers
3. Forge a TCP packet with the correct 5-tuple, seq, ack and inject the payload
4. Send RST to both sides to tear down the session
5. Restore both ARP caches on exit

**What you will see:**
- T1: `[*] ARP poisoning ... [+] injected payload ... [*] RST sent`
- T2: the injected text appears in the nc session, then the connection closes

**Why TLS stops this attack:**
SSH and HTTPS sessions cannot be hijacked this way. The injected bytes would fail the MAC
verification on the encrypted channel and the session would terminate with an error — the
payload is never interpreted as input. Session hijacking only works against cleartext
protocols (Telnet, plain HTTP, unencrypted netcat, FTP).

---

### Exercise 4-B Walkthrough — SYN Flood

**Terminals needed: 2** — T1 attacker (flood), T2 target (watch the connection table)

| Terminal | VM | Purpose |
|----------|----|---------|
| T1 | `vagrant ssh attacker` | run the flood |
| T2 | `vagrant ssh target` | monitor `SYN_RECV` entries in real time |

**Step 1 — Start monitoring the connection table on the target (T2):**
```bash
watch -n1 'ss -s'
```

**Step 2 — Start the SYN flood from the attacker (T1):**
```bash
sudo python3 /vagrant/module4/syn_flood.py --target 192.168.56.2 --port 9000 --duration 15
```

**Step 3 — Observe the effect on T2:** `SYN_RECV` entries accumulate during the flood, then
drop back to zero after the 15-second duration ends.

**What you will see:** T1 prints pre-flight responsiveness check, live packets-per-second rate,
and a post-flight check. T2's `ss -s` shows `SYN_RECV` entries building up. Because Ubuntu
enables SYN cookies by default, the count stays bounded and the service remains reachable —
the script's post-flight check will confirm the target is still responsive.

---

### Standalone Walkthrough — `rst_injector.py` (Connection Killer)

**Terminals needed: 3** — T1 attacker (ARP MitM to get on-path), T2 attacker (RST injector), T3 target (victim's connection)

| Terminal | VM | Purpose |
|----------|----|---------|
| T1 | `vagrant ssh attacker` | ARP MitM — puts attacker on-path so it sees target traffic |
| T2 | `vagrant ssh attacker` | run `rst_injector.py` |
| T3 | `vagrant ssh target` | hold the TCP session that will be killed |

**Step 1 — Open a persistent connection from the target to the gateway (T3):**
```bash
nc 192.168.56.254 9999
# type a few messages so there is live traffic on the wire
```

**Step 2 — Start ARP poisoning so the attacker sees the traffic (T1):**
```bash
sudo python3 /vagrant/module3/arp_mitm.py --victim 192.168.56.2 --gateway 192.168.56.254
```

**Step 3 — Run the RST injector in a second attacker terminal (T2):**
```bash
sudo python3 /vagrant/module4/rst_injector.py --target 192.168.56.2 --port 9999
```

**Step 4 — Type anything in T3's nc session.** The injector detects the packet and immediately
kills the connection.

**What you will see:** T2 prints the detected session and `[+] RST injected — session killed`.
T3's nc session closes with "broken pipe" or simply exits — the victim loses the connection
with no graceful teardown.

---

### Demo Walkthrough — `ip_options.py` (IP Options and Fragmentation)

**Terminals needed: 2** — T1 attacker (runs the demos), T2 target (optional — observe with tcpdump)

**Step 1 — Optional: start tcpdump on the target to observe incoming packets (T2):**
```bash
sudo tcpdump -i eth1 -n 'src host 192.168.56.1' -v
```

**Step 2 — Run all demos in sequence (T1):**
```bash
sudo python3 /vagrant/module4/ip_options.py --demo all --target 192.168.56.2
```

**Step 3 — Run just the fragmentation demo to focus on IDS evasion (T1):**
```bash
sudo python3 /vagrant/module4/ip_options.py --demo frag --target 192.168.56.2
```

**What you will see:** T1 prints the full Scapy packet structure for each IP option (LSRR,
Record Route, Timestamp) and the fragment list for the frag demo. T2's tcpdump shows individual
IP fragments arriving with the `MF` (More Fragments) flag set, then the final fragment with
`MF=0`. The kernel reassembles them and processes the packet normally — while a stateless IDS
inspecting only the first fragment would miss the TCP flags.
