#!/usr/bin/env python3
"""
Module 7 — AI Lab: Claude + Scapy Interactive Experience

A Streamlit application that fuses live Scapy packet capture with
Claude's real-time narrative intelligence. Three panels:

  LEFT   — Live packet feed (auto-updating table)
  RIGHT  — PacketSage streaming commentary (per packet or per attack step)
  BOTTOM — Chat interface: ask PacketSage anything about what's happening

Run (root required for raw sockets):
    sudo streamlit run module7/ai_lab.py

Environment:
    export ANTHROPIC_API_KEY=sk-ant-...
    Or enter it in the sidebar at runtime.
"""

import os
import sys
import time
import queue
import threading
from collections import deque
from datetime import datetime

import streamlit as st

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="DC34 AI Lab — PacketSage",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded",
)

from module7.packet_narrator import PacketNarrator, ATTACK_CONTEXTS, packet_to_dict

# ── Shared state ───────────────────────────────────────────────────────────────
# Packet queue: background sniffer → Streamlit UI
_pkt_queue:    queue.Queue = queue.Queue(maxsize=500)
_sniffer_stop: threading.Event = threading.Event()
_sniffer_thread: threading.Thread | None = None

# ── Session state init ─────────────────────────────────────────────────────────
def _init():
    defaults = {
        "api_key":        os.environ.get("ANTHROPIC_API_KEY", ""),
        "attack_context": "general",
        "sniffing":       False,
        "packets":        deque(maxlen=200),     # raw summaries for display
        "chat_history":   [],                    # [{role, content}]
        "narrator":       None,
        "narrate_auto":   False,
        "last_narrated":  0,                     # packet index of last auto-narration
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init()


# ── Sniffer thread ─────────────────────────────────────────────────────────────

def _sniffer_worker(iface: str, bpf: str):
    """Background thread: sniff packets and push to _pkt_queue."""
    from scapy.all import sniff, conf
    conf.verb = 0
    conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)

    def push(pkt):
        try:
            _pkt_queue.put_nowait(pkt)
        except queue.Full:
            pass   # drop if queue is full

    sniff(
        iface=iface,
        filter=bpf or None,
        prn=push,
        store=False,
        stop_filter=lambda _: _sniffer_stop.is_set(),
    )


def start_sniffer(iface: str, bpf: str):
    global _sniffer_thread
    _sniffer_stop.clear()
    _sniffer_thread = threading.Thread(
        target=_sniffer_worker, args=(iface, bpf), daemon=True
    )
    _sniffer_thread.start()
    st.session_state["sniffing"] = True


def stop_sniffer():
    _sniffer_stop.set()
    st.session_state["sniffing"] = False


# ── PacketSage helper ──────────────────────────────────────────────────────────

def get_narrator() -> PacketNarrator:
    """Get or create a PacketNarrator, re-creating if API key changed."""
    key     = st.session_state["api_key"]
    context = st.session_state["attack_context"]

    if st.session_state["narrator"] is None:
        if key:
            os.environ["ANTHROPIC_API_KEY"] = key
        n = PacketNarrator(attack_context=context)
        st.session_state["narrator"] = n
    else:
        n = st.session_state["narrator"]
        if n.attack_context != context:
            n.set_context(context)
            # Add a context-switch notice to chat
            st.session_state["chat_history"].append({
                "role": "system",
                "content": f"⚙️ Context switched to **{context.upper()}** — "
                           f"{ATTACK_CONTEXTS[context]}",
            })

    if key:
        os.environ["ANTHROPIC_API_KEY"] = key

    return n


# ── CSS ────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
.packet-row      { font-family: monospace; font-size: 0.78rem; padding: 3px 6px;
                   border-radius: 4px; margin: 1px 0; }
.packet-tcp      { background: #0d2137; color: #4db8ff; }
.packet-udp      { background: #1a2d0d; color: #7ddb57; }
.packet-arp      { background: #2d1a0d; color: #ffb347; }
.packet-icmp     { background: #2d0d2d; color: #e07aff; }
.packet-dns      { background: #0d2d2a; color: #7ddbcf; }
.packet-other    { background: #1a1a1a; color: #aaaaaa; }
.sage-bubble     { background: #0f1b0f; border-left: 3px solid #00cc44;
                   padding: 10px 14px; border-radius: 6px; margin: 6px 0;
                   font-size: 0.92rem; color: #ddeedd; }
.user-bubble     { background: #0d1526; border-left: 3px solid #4488ff;
                   padding: 10px 14px; border-radius: 6px; margin: 6px 0;
                   font-size: 0.92rem; color: #ccd9ff; }
.system-bubble   { background: #1a1a0d; border-left: 3px solid #cc8800;
                   padding: 6px 14px; border-radius: 6px; margin: 4px 0;
                   font-size: 0.82rem; color: #cc9944; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🧠 PacketSage Settings")
    st.caption("DC34 — AI-Powered Network Intelligence")
    st.divider()

    # API Key
    api_key_input = st.text_input(
        "Anthropic API Key",
        value=st.session_state["api_key"],
        type="password",
        placeholder="sk-ant-...",
        help="Or set ANTHROPIC_API_KEY env var before launching",
    )
    if api_key_input != st.session_state["api_key"]:
        st.session_state["api_key"] = api_key_input
        st.session_state["narrator"] = None   # force recreation
        os.environ["ANTHROPIC_API_KEY"] = api_key_input

    if not st.session_state["api_key"]:
        st.warning("⚠️ API key required for narration")

    st.divider()

    # Attack context
    ctx_options = list(ATTACK_CONTEXTS.keys())
    ctx_index   = ctx_options.index(st.session_state["attack_context"])
    new_ctx = st.selectbox(
        "Attack Context",
        ctx_options,
        index=ctx_index,
        format_func=lambda k: f"{k.upper()}  —  {ATTACK_CONTEXTS[k][:40]}",
    )
    if new_ctx != st.session_state["attack_context"]:
        st.session_state["attack_context"] = new_ctx
        # Trigger context switch on next narrator call

    st.divider()

    # Sniffer controls
    st.subheader("Packet Capture")
    iface = st.text_input("Interface", value="eth0")
    bpf   = st.text_input(
        "BPF Filter",
        value="",
        placeholder="e.g. tcp port 80, arp, icmp",
        help="Leave blank to capture everything",
    )

    col1, col2 = st.columns(2)
    if col1.button("▶ Start", type="primary",  use_container_width=True,
                   disabled=st.session_state["sniffing"]):
        start_sniffer(iface, bpf)
        st.rerun()
    if col2.button("■ Stop",  type="secondary", use_container_width=True,
                   disabled=not st.session_state["sniffing"]):
        stop_sniffer()
        st.rerun()

    st.divider()

    # Auto-narrate toggle
    auto = st.toggle(
        "🤖 Auto-narrate packets",
        value=st.session_state["narrate_auto"],
        help="PacketSage automatically comments on every new packet",
    )
    st.session_state["narrate_auto"] = auto
    if auto:
        st.caption("PacketSage will narrate each captured packet automatically.")

    if st.button("🗑 Clear history", use_container_width=True):
        st.session_state["packets"].clear()
        st.session_state["chat_history"].clear()
        if st.session_state["narrator"]:
            st.session_state["narrator"].reset()
        st.rerun()

    st.divider()
    status = "🟢 Capturing" if st.session_state["sniffing"] else "⬜ Idle"
    st.metric("Status", status)
    st.metric("Packets captured", len(st.session_state["packets"]))

    st.divider()
    st.caption("⚠️ Requires root (raw sockets)")
    st.caption("sudo streamlit run module7/ai_lab.py")


# ── Drain packet queue into session state ─────────────────────────────────────
new_packets = []
try:
    while True:
        pkt = _pkt_queue.get_nowait()
        new_packets.append(pkt)
        st.session_state["packets"].append(pkt)
except queue.Empty:
    pass


# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown(
    "<h1 style='color:#00CC44;margin-bottom:0'>🧠 PacketSage — AI Network Intelligence Lab</h1>"
    "<p style='color:#666;margin-top:2px'>Live Scapy packet capture · Claude-powered narration · Interactive Q&A</p>",
    unsafe_allow_html=True,
)
st.divider()


# ── Main area: two columns ─────────────────────────────────────────────────────
col_pkts, col_sage = st.columns([1, 1], gap="medium")

LAYER_COLORS = {
    "TCP":  "packet-tcp",
    "UDP":  "packet-udp",
    "ARP":  "packet-arp",
    "ICMP": "packet-icmp",
    "DNS":  "packet-dns",
}

def pkt_css_class(pkt) -> str:
    from scapy.all import TCP, UDP, ARP, ICMP, DNS
    if pkt.haslayer(DNS):   return "packet-dns"
    if pkt.haslayer(TCP):   return "packet-tcp"
    if pkt.haslayer(UDP):   return "packet-udp"
    if pkt.haslayer(ARP):   return "packet-arp"
    if pkt.haslayer(ICMP):  return "packet-icmp"
    return "packet-other"


# ── Left: Packet feed ──────────────────────────────────────────────────────────
with col_pkts:
    st.subheader(f"📡 Live Packet Feed  ({len(st.session_state['packets'])} captured)")

    packets_list = list(st.session_state["packets"])
    if not packets_list:
        st.markdown(
            "<div style='height:300px;display:flex;align-items:center;"
            "justify-content:center;border:1px dashed #333;border-radius:8px;"
            "color:#444'>Start capture to see packets here</div>",
            unsafe_allow_html=True,
        )
    else:
        # Show last 30 packets
        display = packets_list[-30:]
        rows_html = ""
        for i, pkt in enumerate(reversed(display)):
            css    = pkt_css_class(pkt)
            ts     = datetime.now().strftime("%H:%M:%S")
            size   = len(pkt)
            summary = pkt.summary()[:80]
            rows_html += (
                f"<div class='packet-row {css}'>"
                f"<b>{ts}</b>  {size:4d}B  {summary}"
                f"</div>"
            )
        st.markdown(rows_html, unsafe_allow_html=True)

    # Manual narration controls
    st.divider()
    st.caption("📋 Manual Narration Controls")

    c1, c2, c3 = st.columns(3)

    narrate_last = c1.button(
        "🧠 Narrate last packet",
        use_container_width=True,
        disabled=not packets_list or not st.session_state["api_key"],
    )
    narrate_last5 = c2.button(
        "📖 Narrate last 5",
        use_container_width=True,
        disabled=len(packets_list) < 2 or not st.session_state["api_key"],
    )
    explain_context = c3.button(
        "💡 Explain current context",
        use_container_width=True,
        disabled=not st.session_state["api_key"],
    )


# ── Right: PacketSage commentary ───────────────────────────────────────────────
with col_sage:
    st.subheader("🧠 PacketSage Commentary")

    chat_container = st.container(height=420)

    def render_chat(container):
        with container:
            for msg in st.session_state["chat_history"]:
                role = msg["role"]
                content = msg["content"]
                if role == "assistant":
                    st.markdown(
                        f"<div class='sage-bubble'><b>🧠 PacketSage</b><br>{content}</div>",
                        unsafe_allow_html=True,
                    )
                elif role == "user":
                    st.markdown(
                        f"<div class='user-bubble'><b>👤 You</b><br>{content}</div>",
                        unsafe_allow_html=True,
                    )
                elif role == "system":
                    st.markdown(
                        f"<div class='system-bubble'>{content}</div>",
                        unsafe_allow_html=True,
                    )

    render_chat(chat_container)


# ── Handle manual narration actions ───────────────────────────────────────────

def stream_to_chat(label: str, gen):
    """Stream generator output into chat history, updating display in real time."""
    st.session_state["chat_history"].append({"role": "system", "content": label})
    full = ""
    placeholder = st.empty()
    with placeholder.container():
        with st.chat_message("assistant", avatar="🧠"):
            streamed = st.write_stream(gen)
            if isinstance(streamed, str):
                full = streamed
            elif isinstance(streamed, list):
                full = "".join(streamed)
    placeholder.empty()
    st.session_state["chat_history"].append({"role": "assistant", "content": full})


if narrate_last and packets_list:
    narrator = get_narrator()
    pkt = packets_list[-1]
    label = f"🔍 Narrating: `{pkt.summary()[:60]}`"
    stream_to_chat(label, narrator.narrate_packet(pkt))
    st.rerun()

if narrate_last5 and len(packets_list) >= 2:
    narrator = get_narrator()
    recent = packets_list[-5:]
    label = f"📖 Narrating last {len(recent)} packets as a sequence"
    stream_to_chat(label, narrator.narrate_sequence(recent, f"Last {len(recent)} packets"))
    st.rerun()

if explain_context:
    narrator = get_narrator()
    context  = st.session_state["attack_context"]
    label    = f"💡 Context briefing: **{context.upper()}**"
    q = (
        f"I've just switched into {context.upper()} mode. Give me a 3-sentence "
        f"briefing on what packets I should expect to see and what to watch for "
        f"from both the attacker's and defender's perspectives."
    )
    stream_to_chat(label, narrator.ask(q))
    st.rerun()


# ── Auto-narrate new packets ───────────────────────────────────────────────────
if st.session_state["narrate_auto"] and new_packets and st.session_state["api_key"]:
    # Narrate at most the last 1 new packet per refresh cycle (avoid API flooding)
    narrator = get_narrator()
    pkt = new_packets[-1]
    label = f"🤖 Auto: `{pkt.summary()[:55]}`"
    full_response = ""
    for chunk in narrator.narrate_packet(pkt):
        full_response += chunk
    st.session_state["chat_history"].append({"role": "system",  "content": label})
    st.session_state["chat_history"].append({"role": "assistant", "content": full_response})


# ── Bottom: Chat interface ─────────────────────────────────────────────────────
st.divider()
st.subheader("💬 Ask PacketSage")

# Quick-ask prompts
st.caption("Quick prompts:")
qcols = st.columns(4)
quick_prompts = [
    "Why isn't the target responding?",
    "What would Snort alert on here?",
    "How does an analyst detect this?",
    "What's the next attack step?",
]
for i, prompt in enumerate(quick_prompts):
    if qcols[i].button(prompt, use_container_width=True, key=f"quick_{i}",
                        disabled=not st.session_state["api_key"]):
        st.session_state["chat_history"].append({"role": "user", "content": prompt})
        narrator = get_narrator()
        full = ""
        for chunk in narrator.ask(prompt):
            full += chunk
        st.session_state["chat_history"].append({"role": "assistant", "content": full})
        st.rerun()

# Free-form chat input
user_input = st.chat_input(
    "Ask anything about the packets, the attack, or network security...",
    disabled=not st.session_state["api_key"],
)

if user_input:
    st.session_state["chat_history"].append({"role": "user", "content": user_input})
    narrator = get_narrator()
    full = ""
    for chunk in narrator.ask(user_input):
        full += chunk
    st.session_state["chat_history"].append({"role": "assistant", "content": full})
    st.rerun()

if not st.session_state["api_key"]:
    st.info("Enter your Anthropic API key in the sidebar to enable PacketSage.")


# ── Attack scenario shortcuts ──────────────────────────────────────────────────
st.divider()
with st.expander("⚡ Attack Scenario Narrations (no live capture needed)", expanded=False):
    st.caption(
        "These generate narrative walkthroughs of complete attack flows using "
        "PacketSage's knowledge — no packets need to be captured first."
    )

    scenarios = {
        "🔍 SYN Scan Walkthrough": (
            "recon",
            "narrate_attack_step",
            "SYN Port Scan Completed",
            "Sent SYN probes to ports 1-1024 on 192.168.56.2. "
            "Received SYN-ACK on ports 22, 80, 443, 9000. "
            "All other ports returned RST or no response. "
            "Immediately sent RST to each open port to avoid completing the handshake.",
        ),
        "☠️ ARP MitM Walkthrough": (
            "arp_mitm",
            "narrate_attack_step",
            "ARP Cache Poisoning Active",
            "Sent gratuitous ARP replies to 192.168.56.2 claiming 192.168.56.254 is at attacker MAC. "
            "Sent gratuitous ARP replies to 192.168.56.254 claiming 192.168.56.2 is at attacker MAC. "
            "IP forwarding enabled. Both caches now poisoned. Traffic flows through attacker.",
        ),
        "💥 Buffer Overflow Found": (
            "fuzzing",
            "narrate_attack_step",
            "Crash Detected on Port 9000",
            "Sent DC34 protocol frame with opcode=0xFF and 100-byte payload. "
            "Server at 192.168.56.2:9000 stopped responding to canary PING probes. "
            "Crash-triggering packet saved to crashes/crash_20260326_143022.pcap. "
            "Server recovered after ~8 seconds.",
        ),
        "📡 ICMP C2 Session": (
            "covert_c2",
            "narrate_attack_step",
            "ICMP C2 Command Executed",
            "Sent ICMP echo request to 192.168.56.2 with 'whoami' encoded in payload. "
            "Received ICMP echo reply with 'root' encoded in reply payload. "
            "Channel is bidirectional, uses session ID 0xA3F1 for tracking. "
            "Traffic appears as normal ping activity to casual inspection.",
        ),
    }

    scols = st.columns(2)
    for idx, (label, scenario_args) in enumerate(scenarios.items()):
        col = scols[idx % 2]
        if col.button(label, use_container_width=True,
                      disabled=not st.session_state["api_key"],
                      key=f"scenario_{idx}"):
            ctx, method, step, desc = scenario_args
            narrator = get_narrator()
            narrator.set_context(ctx)
            st.session_state["attack_context"] = ctx
            st.session_state["chat_history"].append({
                "role": "system",
                "content": f"⚡ Running scenario: **{label}** (context: {ctx.upper()})"
            })
            full = ""
            for chunk in narrator.narrate_attack_step(step, desc):
                full += chunk
            st.session_state["chat_history"].append({"role": "assistant", "content": full})
            st.rerun()


# ── Auto-refresh while capturing ──────────────────────────────────────────────
if st.session_state["sniffing"]:
    time.sleep(2)
    st.rerun()
