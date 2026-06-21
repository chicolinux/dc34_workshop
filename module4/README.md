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

Without SYN cookies:
- Each SYN allocates a "SYN_RECV" entry in the connection table
- Default Linux backlog: 128-1024 entries
- Flood with spoofed SYNs → table fills → legitimate connections refused

With SYN cookies (default on modern Linux):
- Server encodes connection state in the ISN (initial sequence number)
- No table entry allocated until the client sends ACK
- Flood impact is reduced but not eliminated: server still processes SYN-ACK generation

Monitor during flood:
```bash
ss -s           # shows SYN_RECV count in real time
cat /proc/net/tcp | grep " 06 " | wc -l   # count SYN_RECV entries
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
| 4-A | `tcp_injector.py` | Inject payload into live Telnet/netcat session |
| 4-B | `syn_flood.py` | SYN flood with randomized spoofed IPs |
| standalone | `rst_injector.py` | Kill sessions by injecting RST |
| demo | `ip_options.py` | LSRR, Record Route, fragmentation demo |
| 4-X (extra) | manual | Route through LSRR waypoint to reach normally-blocked host |
