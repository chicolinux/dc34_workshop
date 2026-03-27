# Module 7 — AI Lab: PacketSage (Optional)

**Claude API + Scapy = live network intelligence**

PacketSage is an optional add-on that turns your terminal or browser into an AI-powered
network analyst. As packets fly by, Claude narrates what is happening — attacker intent,
defender visibility, protocol details, and MITRE ATT&CK kill chain context.

---

## Prerequisites

```bash
# Anthropic SDK (already in requirements.txt)
pip3 install anthropic>=0.40.0

# API key — get one at https://console.anthropic.com/
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Files

| File | Purpose |
|------|---------|
| `packet_narrator.py` | Core library — `PacketNarrator` class + CLI demo |
| `ai_lab.py` | Streamlit AI Lab — full browser-based UI |

---

## Quick Start

### CLI demo (terminal, live interface)

```bash
# Watch live traffic and get real-time narration per packet
sudo python3 module7/packet_narrator.py --iface eth0 --mode recon

# Ask PacketSage a question directly
python3 module7/packet_narrator.py --ask "What is the difference between a SYN scan and a connect scan?"

# Available modes
sudo python3 module7/packet_narrator.py --iface eth0 --mode arp_mitm
sudo python3 module7/packet_narrator.py --iface eth0 --mode covert_c2
```

### Streamlit AI Lab (browser)

```bash
# Requires root for Scapy raw sockets
sudo streamlit run module7/ai_lab.py

# Open: http://localhost:8501
```

---

## Attack Contexts

| Context | Description | Key TTPs |
|---------|-------------|----------|
| `recon` | Host discovery and port scanning | T1046, T1018 |
| `arp_mitm` | ARP cache poisoning MitM | T1557.002 |
| `tcp_abuse` | Session hijacking, RST injection | T1565.002 |
| `fuzzing` | Protocol fuzzing, input validation bypass | T1190 |
| `covert_c2` | Covert C2 and data exfiltration | T1095, T1071.004 |
| `general` | No specific framing — raw observation | — |

Switch context in the CLI with `--mode`. In the Streamlit UI, use the **Attack Context** sidebar selector — PacketSage will reset its conversation history to match the new phase.

---

## PacketNarrator — Library API

Use `PacketNarrator` as a library inside your own scripts or the existing workshop tools:

```python
from module7.packet_narrator import PacketNarrator

narrator = PacketNarrator(attack_context="recon")

# Narrate a single packet (returns a streaming generator)
for chunk in narrator.narrate_packet(pkt):
    print(chunk, end="", flush=True)

# Narrate a named attack step with optional packet context
for chunk in narrator.narrate_attack_step(
    "SYN Scan Complete",
    "Scanned ports 1-1024, found 3 open: 22, 80, 9000",
    packets=answered_pkts,
):
    print(chunk, end="", flush=True)

# Narrate a full sequence (e.g., sr() results)
answered, _ = sr(IP(dst="10.0.0.2")/TCP(dport=(1,1024), flags="S"), timeout=2)
for chunk in narrator.narrate_sequence([r for _, r in answered], "SYN scan results"):
    print(chunk, end="", flush=True)

# Ask a free-form question
for chunk in narrator.ask("Why didn't we get a reply to that SYN on port 443?"):
    print(chunk, end="", flush=True)

# Switch to a new attack phase (clears history)
narrator.set_context("arp_mitm")
```

### Constructor parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `attack_context` | `"general"` | Initial framing context |
| `model` | `"claude-opus-4-6"` | Claude model to use |
| `max_history` | `20` | Conversation turns to retain |

---

## Streamlit AI Lab — UI Overview

```
┌─────────────────────────────────┬──────────────────────────────────┐
│  Live Packet Feed               │  PacketSage Commentary           │
│                                 │                                  │
│  [ETH] [IP] [TCP] packets       │  Streaming AI narration per      │
│  color-coded by protocol        │  packet or attack step           │
│                                 │                                  │
├─────────────────────────────────┴──────────────────────────────────┤
│  Chat Interface — ask PacketSage anything about what you see       │
│  Quick-ask buttons: "What just happened?" / "Defender view?" / ... │
└────────────────────────────────────────────────────────────────────┘
```

### Sidebar controls

| Control | Description |
|---------|-------------|
| Interface | Network interface to sniff (e.g., `eth0`) |
| Attack Context | Frames PacketSage's narration style |
| Start / Stop Sniffer | Toggle live packet capture |
| Auto-Narrate | Automatically send each packet to PacketSage |
| Packet Filter (BPF) | Optional BPF expression (e.g., `tcp port 80`) |
| Attack Scenario Shortcuts | Pre-written scenario descriptions to narrate |

### Quick-ask buttons

- **"What just happened?"** — summarize the last few packets
- **"Defender view?"** — what would a SOC analyst see in SIEM/IDS?
- **"Kill chain?"** — map current activity to MITRE ATT&CK
- **"Evade detection?"** — how might an attacker avoid triggering alerts here?

---

## How It Works

### Architecture

```
Scapy sniff() ──► queue.Queue ──► Streamlit feed panel
                                       │
                              auto-narrate toggle
                                       │
                              PacketNarrator.narrate_packet()
                                       │
                         anthropic.Anthropic().messages.stream()
                                       │
                              streaming text chunks ──► chat panel
```

### Claude API design choices

**Prompt caching** — The large `SYSTEM_PROMPT` (PacketSage persona + format rules) is marked
with `cache_control: {"type": "ephemeral"}`. This means after the first request, Anthropic
caches the system prompt prefix and subsequent requests pay ~10× lower input token cost for
that portion. The dynamic attack context (changes when you switch modes) is appended after
the cached block so it doesn't break the cache.

**Adaptive thinking** — `thinking: {"type": "adaptive"}` lets Claude decide when deeper
reasoning is warranted. For a complex packet sequence it may think before answering; for a
simple ARP reply it won't. This balances quality and latency automatically.

**Conversation history** — `PacketNarrator` maintains a rolling window of the last 20 turns.
This means Claude remembers the packets it already narrated and can refer back to them —
"this RST is targeting the session we saw established three packets ago."

**Streaming** — All responses stream via `client.messages.stream()` / `text_stream`. You see
the first word within ~200ms even for long narrations.

---

## Integrating with Other Modules

You can drop `PacketNarrator` into any module for live commentary:

```python
# Inside module3/arp_mitm.py — narrate each intercepted packet
from module7.packet_narrator import PacketNarrator

narrator = PacketNarrator(attack_context="arp_mitm")

def intercept_callback(pkt):
    print(pkt.summary())
    for chunk in narrator.narrate_packet(pkt):
        print(chunk, end="", flush=True)
    print()
```

```python
# After a SYN scan — narrate the full result
from module7.packet_narrator import PacketNarrator
from module2.syn_scanner import syn_scan

narrator = PacketNarrator(attack_context="recon")
results = syn_scan("10.0.0.2", "1-1024")

for chunk in narrator.narrate_attack_step(
    "Port Scan Complete",
    f"Found {sum(1 for s in results.values() if s == 'open')} open ports on 10.0.0.2",
):
    print(chunk, end="", flush=True)
```

---

## Cost Estimates

Rough estimates at claude-opus-4-6 pricing with prompt caching active:

| Scenario | Approx. cost / hour |
|----------|---------------------|
| Auto-narrate every packet (busy interface) | $0.10–0.40 |
| Manual narrate (click per packet) | $0.02–0.10 |
| Chat questions only | < $0.05 |

The system prompt cache hit (after first request) reduces per-packet input cost significantly.
Use the BPF filter to narrow traffic and reduce unnecessary API calls.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `AuthenticationError` | Check `ANTHROPIC_API_KEY` is exported |
| `RateLimitError` | Lower auto-narrate frequency or add a short sleep |
| No packets in feed | Verify interface name with `ip link show` |
| Streamlit requires root | Run `sudo streamlit run module7/ai_lab.py` |
| Slow first response | Normal — first request warms the prompt cache |
