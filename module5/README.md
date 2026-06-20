# Module 5 — Protocol Fuzzing

## What is Network Protocol Fuzzing?

Fuzzing sends unexpected, malformed, or random data to a program and
watches for crashes, hangs, or incorrect behavior. Network protocol
fuzzing targets the parsing code in daemons, embedded devices, and
network stacks — the attack surface that never gets unit-tested with
adversarial inputs.

## Why Scapy for Fuzzing?

Scapy gives you complete control over every field in every layer.
You can express things no other tool allows:
- Set TCP length=0 while including a payload
- Send DNS with qdcount=1000 but only one question record
- Craft ICMP with a type that doesn't exist
- Split the protocol header across IP fragments

**Scapy is not fast.** For production fuzzing use Boofuzz, AFLNet,
or purpose-built network fuzzers. Scapy is ideal for:
- Learning how the protocol works under adversarial conditions
- Crafting specific, targeted test cases
- Quick one-off verification of a hypothesis

## Scapy's `fuzz()` Function

`fuzz(layer)` returns a copy of the layer with every field set to a
random value of the correct type. Useful fields remain the correct
Python type (e.g., IP addresses stay 4-byte strings), so the packet
is syntactically valid but semantically wrong.

```python
from scapy.all import fuzz, IP, TCP, DNS, DNSQR

# Randomize all IP fields
fuzz(IP())

# Fix destination, randomize everything else
fuzz(IP(dst="192.168.56.2"))

# Fully random DNS query
fuzz(DNS(rd=1, qd=DNSQR(qname="test.com")))

# Combine layers: fixed IP, fuzzed TCP header
IP(dst="192.168.56.2") / fuzz(TCP(dport=80))
```

## Boundary Value Strategy

The most effective network fuzzing inputs are boundary values:
values at the edges of valid ranges that parsers frequently mishandle.

| Field Type | Boundary Values |
|-----------|-----------------|
| 1-byte    | 0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF |
| 2-byte    | 0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF |
| Length    | 0, 1, max-1, max, max+1 |
| String    | empty, 1 char, max-length, max+1, null bytes, format strings |

## Crash Detection and Triage

A crash is only useful if you can reproduce it. Workflow:

1. Send fuzz packet
2. Send canary probe (known-good request)
3. If canary fails → server crashed → save the fuzz packet to PCAP
4. Restart server, replay saved packet to confirm reproducibility
5. Minimize: binary search the payload to find the minimum trigger
   - Is it the length field alone?
   - Is it the opcode?
   - Is it a specific byte value in the payload?

## The DC34 Protocol Vulnerabilities

`target_server.py` contains four intentional bugs:

| Bug | Trigger | Effect |
|-----|---------|--------|
| Buffer overflow | opcode=0xFF, length > 64 | `RuntimeError` crash |
| OOM-like behavior | opcode=0x03, length=65535 | Large allocation |
| Magic bypass | magic=0x0000 | Skips magic validation |
| Partial read hang | length > actual payload bytes | Server hangs on `recv()` |

Your fuzzer should find Bug #1 (overflow) quickly with boundary length values,
and Bug #3 with boundary magic values.

## Exercises

| Exercise | File | Objective |
|----------|------|-----------|
| 5-A | `dns_fuzzer.py` | Fuzz DNS header fields with canary monitoring |
| 5-B | `custom_fuzzer.py` + `custom_proto.py` | Find the crash in DC34 protocol server |
| 5-X (extra) | `custom_fuzzer.py --stateful` | Stateful fuzzer: AUTH first, then COMMAND |

## Comparison to Dedicated Fuzzers

| Tool | Speed | State-awareness | Protocol support |
|------|-------|-----------------|------------------|
| Scapy | ~1k pkt/s | Manual | Any (you define it) |
| Boofuzz | ~5k pkt/s | Built-in session | Built-in + custom |
| AFLNet | ~50k req/s | Yes | Requires source or black-box wrapper |
| Sulley | Legacy | Basic | Many |

Use Scapy to understand and prototype, then move to Boofuzz for production fuzzing.
