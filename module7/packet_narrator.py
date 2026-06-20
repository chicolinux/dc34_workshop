#!/usr/bin/env python3
"""
Module 7 — PacketNarrator: Claude-powered network intelligence layer

Converts raw Scapy packet objects into streaming narrative explanations.
Claude acts as a DEFCON instructor who watches packets fly by and tells
the story of what is happening — attacker intent, victim response,
defender visibility, and kill chain context.

Requirements:
    pip install anthropic>=0.40.0
    export ANTHROPIC_API_KEY=sk-ant-...

Usage (standalone):
    sudo python3 module7/packet_narrator.py --iface eth0 --mode recon

Usage (as library):
    from module7.packet_narrator import PacketNarrator
    narrator = PacketNarrator(attack_context="arp_mitm")
    for chunk in narrator.narrate_packet(pkt):
        print(chunk, end="", flush=True)
"""

import os
import sys
import time
import json
import textwrap
from typing import Generator, Iterator

import anthropic

# ── Path setup ──────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# ── System prompt (cached — stable across all requests) ─────────────────────
SYSTEM_PROMPT = textwrap.dedent("""
    You are PacketSage — the resident network intelligence expert at DEFCON 34,
    embedded inside a live Scapy-powered offensive security workshop.

    Your role is to narrate network events like a master storyteller who happens
    to have a PhD in network security. When you see a packet or a sequence of
    packets, you explain:

    1. WHAT is technically happening (be precise about protocol fields)
    2. WHY an attacker does it this way (the offensive intent and advantage)
    3. WHAT a defender would see (SIEM alerts, IDS signatures, log entries)
    4. HOW it maps to the MITRE ATT&CK kill chain (use TTP IDs when relevant)

    Tone: Engaging, educational, occasionally dramatic. You are at DEFCON —
    the audience loves both technical depth and vivid analogies.

    Format rules:
    - Individual packet narration: 3-5 sentences max. Be punchy.
    - Attack step narration: 1-3 short paragraphs. Tell the full story.
    - Always start with a one-sentence headline that captures the essence.
    - Use ATT&CK TTP IDs sparingly, only when genuinely relevant.
    - When you see defense evasion, call it out explicitly.
    - If a packet reveals something interesting about the target, highlight it.

    Attack contexts you will encounter and how to frame them:
    - recon:       Network Discovery (T1046, T1018) — mapping the battlefield
    - arp_mitm:    Adversary-in-the-Middle (T1557.002) — positioning for interception
    - tcp_abuse:   Exploitation of trusted protocol — session hijack, RST injection
    - fuzzing:     Vulnerability discovery — probing for input validation failures
    - covert_c2:   Command and Control (T1095, T1071.004) — hiding in plain sight
    - general:     Explain what you observe without a specific attack framing
""").strip()

# ── Attack context descriptions ──────────────────────────────────────────────
ATTACK_CONTEXTS = {
    "recon":     "Active network reconnaissance — host discovery and port scanning",
    "arp_mitm":  "ARP cache poisoning man-in-the-middle attack in progress",
    "tcp_abuse": "TCP/IP stack exploitation — session hijacking or RST injection",
    "fuzzing":   "Protocol fuzzing — probing the target for input validation flaws",
    "covert_c2": "Covert command-and-control channel — data encoded in protocol fields",
    "general":   "General packet observation — no specific attack context",
}

# ── Packet serializer ────────────────────────────────────────────────────────

def packet_to_dict(pkt) -> dict:
    """
    Convert a Scapy packet into a clean dict for Claude.
    Extracts layer names, key fields, and raw hex — without the noise.
    """
    from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Ether, Raw

    result = {
        "timestamp": time.strftime("%H:%M:%S"),
        "summary":   pkt.summary(),
        "layers":    [],
        "hex_head":  pkt.build()[:40].hex(),   # first 40 bytes as hex
        "size":      len(pkt),
    }

    # Walk each layer and extract the fields that matter
    layer = pkt
    while layer:
        layer_info = {"name": layer.__class__.__name__, "fields": {}}

        if layer.haslayer(Ether) and layer == layer.getlayer(Ether):
            layer_info["fields"] = {
                "src": layer.src, "dst": layer.dst, "type": hex(layer.type),
            }
        elif layer.haslayer(IP) and layer == layer.getlayer(IP):
            layer_info["fields"] = {
                "src": layer.src, "dst": layer.dst,
                "ttl": layer.ttl, "proto": layer.proto,
                "flags": str(layer.flags), "id": layer.id,
                "len": layer.len,
            }
        elif layer.haslayer(TCP) and layer == layer.getlayer(TCP):
            layer_info["fields"] = {
                "sport": layer.sport, "dport": layer.dport,
                "flags": str(layer.flags), "seq": layer.seq,
                "ack": layer.ack, "window": layer.window,
                "options": str(layer.options),
            }
        elif layer.haslayer(UDP) and layer == layer.getlayer(UDP):
            layer_info["fields"] = {
                "sport": layer.sport, "dport": layer.dport, "len": layer.len,
            }
        elif layer.haslayer(ICMP) and layer == layer.getlayer(ICMP):
            layer_info["fields"] = {
                "type": layer.type, "code": layer.code,
                "id": layer.id, "seq": layer.seq,
            }
        elif layer.haslayer(ARP) and layer == layer.getlayer(ARP):
            layer_info["fields"] = {
                "op": layer.op,
                "hwsrc": layer.hwsrc, "psrc": layer.psrc,
                "hwdst": layer.hwdst, "pdst": layer.pdst,
            }
        elif layer.haslayer(DNS) and layer == layer.getlayer(DNS):
            qname = ""
            if layer.qd:
                try:
                    qname = layer.qd.qname.decode(errors="replace")
                except Exception:
                    qname = str(layer.qd.qname)
            layer_info["fields"] = {
                "id": layer.id, "qr": layer.qr, "opcode": layer.opcode,
                "rcode": layer.rcode, "qdcount": layer.qdcount,
                "qname": qname,
            }
        elif layer.haslayer(Raw) and layer == layer.getlayer(Raw):
            raw = layer.load
            layer_info["fields"] = {
                "length": len(raw),
                "preview": raw[:64].decode(errors="replace"),
                "hex": raw[:32].hex(),
            }
        else:
            try:
                layer_info["fields"] = {
                    k: str(v) for k, v in layer.fields.items()
                }
            except Exception:
                layer_info["fields"] = {}

        if layer_info["fields"]:
            result["layers"].append(layer_info)

        # Move to next layer
        try:
            next_layer = layer.payload
            if next_layer is None or next_layer.__class__.__name__ == "NoPayload":
                break
            layer = next_layer
        except Exception:
            break

    return result


# ── PacketNarrator ────────────────────────────────────────────────────────────

class PacketNarrator:
    """
    Streams Claude-powered narrative explanations for Scapy packet events.

    Each instance maintains a conversation history so Claude has context
    about the full attack sequence — not just the current packet.

    Args:
        attack_context:  One of ATTACK_CONTEXTS keys (default: "general")
        model:           Claude model to use (default: claude-opus-4-8)
        max_history:     Max conversation turns to retain (default: 20)
        temperature:     Sampling temperature (default: 1.0 for streaming)
    """

    def __init__(
        self,
        attack_context: str = "general",
        model: str = "claude-opus-4-8",
        max_history: int = 20,
    ):
        self.client         = anthropic.Anthropic()
        self.attack_context = attack_context
        self.model          = model
        self.max_history    = max_history
        self._history: list[dict] = []
        self._packet_count  = 0

    # ── Context management ─────────────────────────────────────────────────

    def set_context(self, context: str):
        """Switch attack context and clear history (new attack phase)."""
        if context not in ATTACK_CONTEXTS:
            raise ValueError(f"Unknown context: {context}. Choose from: {list(ATTACK_CONTEXTS)}")
        self.attack_context = context
        self._history.clear()
        self._packet_count = 0

    def reset(self):
        """Clear conversation history."""
        self._history.clear()
        self._packet_count = 0

    # ── System prompt (with prompt caching) ───────────────────────────────

    def _system_content(self) -> list[dict]:
        """
        System prompt as a content list with cache_control.
        The stable base prompt is cached; the dynamic context appended after.
        """
        context_note = (
            f"\n\nCurrent attack context: {self.attack_context.upper()} — "
            f"{ATTACK_CONTEXTS[self.attack_context]}"
        )
        return [
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},  # cache the large stable prompt
            },
            {
                "type": "text",
                "text": context_note,
                # no cache_control — context changes when user switches mode
            },
        ]

    # ── History management ────────────────────────────────────────────────

    def _trim_history(self):
        """Keep only the last max_history turns to avoid context bloat."""
        if len(self._history) > self.max_history * 2:
            self._history = self._history[-(self.max_history * 2):]

    def _add_to_history(self, role: str, content: str):
        self._history.append({"role": role, "content": content})
        self._trim_history()

    # ── Core narration methods ─────────────────────────────────────────────

    def narrate_packet(self, pkt) -> Generator[str, None, None]:
        """
        Stream a narrative explanation for a single Scapy packet.

        Usage:
            for chunk in narrator.narrate_packet(pkt):
                print(chunk, end="", flush=True)
        """
        self._packet_count += 1
        pkt_dict = packet_to_dict(pkt)

        user_msg = (
            f"[Packet #{self._packet_count}]\n"
            f"{json.dumps(pkt_dict, indent=2)}\n\n"
            f"Narrate this packet."
        )

        yield from self._stream_response(user_msg)

    def narrate_attack_step(
        self,
        step_name: str,
        description: str,
        packets: list | None = None,
    ) -> Generator[str, None, None]:
        """
        Stream a narrative for a named attack step (e.g., "ARP Poison Sent").
        Optionally include a list of Scapy packets for packet-level context.

        Usage:
            for chunk in narrator.narrate_attack_step(
                "ARP Cache Poisoned",
                "Sent 2 gratuitous ARP replies targeting victim and gateway",
                packets=[pkt1, pkt2],
            ):
                print(chunk, end="", flush=True)
        """
        pkt_summaries = ""
        if packets:
            summaries = [f"  - {p.summary()}" for p in packets[:5]]
            pkt_summaries = "\n\nPackets involved:\n" + "\n".join(summaries)

        user_msg = (
            f"Attack step completed: **{step_name}**\n"
            f"{description}"
            f"{pkt_summaries}\n\n"
            f"Tell the story of what just happened and what it means."
        )

        yield from self._stream_response(user_msg)

    def narrate_sequence(
        self,
        packets: list,
        label: str = "Packet sequence",
    ) -> Generator[str, None, None]:
        """
        Stream a unified narrative for a sequence of packets (e.g., a full scan result).
        Groups them into a single story rather than packet-by-packet.

        Usage:
            for chunk in narrator.narrate_sequence(answered_packets, "SYN scan result"):
                print(chunk, end="", flush=True)
        """
        summaries = [f"  {i+1}. {p.summary()}" for i, p in enumerate(packets[:10])]
        pkt_block = "\n".join(summaries)

        user_msg = (
            f"{label} ({len(packets)} packets):\n{pkt_block}\n\n"
            f"Narrate what this sequence reveals about the target and the attacker's strategy."
        )

        yield from self._stream_response(user_msg)

    def ask(self, question: str) -> Generator[str, None, None]:
        """
        Stream an answer to a free-form question about what's happening.

        Usage:
            for chunk in narrator.ask("Why didn't we get a reply to that SYN?"):
                print(chunk, end="", flush=True)
        """
        yield from self._stream_response(question)

    # ── Internal streaming helper ─────────────────────────────────────────

    def _stream_response(self, user_content: str) -> Generator[str, None, None]:
        """
        Send user_content to Claude with the full conversation history.
        Streams text chunks back; appends both turns to history when done.
        """
        self._add_to_history("user", user_content)

        full_response = ""
        try:
            with self.client.messages.stream(
                model=self.model,
                max_tokens=1024,
                system=self._system_content(),
                thinking={"type": "adaptive"},
                messages=self._history,
            ) as stream:
                for text in stream.text_stream:
                    full_response += text
                    yield text

        except anthropic.AuthenticationError:
            msg = "\n[PacketSage] ❌ Invalid API key. Set ANTHROPIC_API_KEY.\n"
            yield msg
            self._history.pop()   # remove the user turn that failed
            return
        except anthropic.RateLimitError:
            msg = "\n[PacketSage] ⏳ Rate limited. Pause a moment and retry.\n"
            yield msg
            self._history.pop()
            return
        except Exception as e:
            msg = f"\n[PacketSage] ⚠️  API error: {e}\n"
            yield msg
            self._history.pop()
            return

        self._add_to_history("assistant", full_response)


# ── CLI demo ──────────────────────────────────────────────────────────────────

def cli_demo(iface: str, mode: str, count: int = 10):
    """
    Live CLI demo: capture packets and narrate each one in real time.
    Requires root and ANTHROPIC_API_KEY.
    """
    from scapy.all import sniff, conf
    conf.verb = 0
    conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)

    narrator = PacketNarrator(attack_context=mode)

    print(f"\n{'='*60}")
    print(f"  PacketSage — Live Packet Narration ({mode.upper()} mode)")
    print(f"  Interface: {iface}  |  Packets: {count}")
    print(f"  Model: {narrator.model}")
    print(f"{'='*60}\n")

    # Context intro
    print("🧠 PacketSage: ", end="", flush=True)
    for chunk in narrator.ask(
        f"I'm now watching live traffic in {mode.upper()} mode. "
        f"Give me a 2-sentence briefing on what to watch for in this attack phase."
    ):
        print(chunk, end="", flush=True)
    print("\n")

    def handle(pkt):
        print(f"\n📦 Packet: {pkt.summary()}")
        print("🧠 PacketSage: ", end="", flush=True)
        for chunk in narrator.narrate_packet(pkt):
            print(chunk, end="", flush=True)
        print("\n" + "─" * 50)

    sniff(iface=iface, count=count, prn=handle, store=False)
    print("\n[Done]")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PacketNarrator CLI demo")
    parser.add_argument("--iface",  default="eth0")
    parser.add_argument("--mode",   choices=list(ATTACK_CONTEXTS), default="general")
    parser.add_argument("--count",  type=int, default=10)
    parser.add_argument("--ask",    default=None, help="Ask PacketSage a question and exit")
    args = parser.parse_args()

    if args.ask:
        narrator = PacketNarrator()
        print("🧠 PacketSage: ", end="", flush=True)
        for chunk in narrator.ask(args.ask):
            print(chunk, end="", flush=True)
        print()
    else:
        cli_demo(args.iface, args.mode, args.count)


if __name__ == "__main__":
    main()
