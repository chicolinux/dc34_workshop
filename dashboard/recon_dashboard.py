#!/usr/bin/env python3
"""
DC34 Workshop — Recon Dashboard

Live visual interface for Module 2: host discovery, SYN port scan,
and OS fingerprinting. Results update in real time as Scapy probes
the network.

Run as root (raw sockets required):
    sudo streamlit run dashboard/recon_dashboard.py

Opens at: http://localhost:8501
"""

import os
import sys
import threading
import time
from collections import defaultdict

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx
import streamlit as st

# ── Path setup ─────────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# ── Page config (must be first Streamlit call) ─────────────────────────────────
st.set_page_config(
    page_title="DC34 Recon Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Shared scan state (module-level — survives Streamlit reruns) ───────────────
_scan_lock   = threading.Lock()
_scan_state  = {
    "running":   False,
    "phase":     "idle",        # idle | discovery | scanning | fingerprinting | done
    "hosts":     {},            # {ip: {mac, method, ttl}}
    "ports":     defaultdict(dict),  # {ip: {port: state}}
    "os_info":   {},            # {ip: {ttl, window, options, guess}}
    "log":       [],            # list of status strings
    "progress":  0.0,           # 0.0–1.0
    "started_at": None,
    "finished_at": None,
}


def _log(msg: str):
    ts = time.strftime("%H:%M:%S")
    with _scan_lock:
        _scan_state["log"].append(f"[{ts}] {msg}")
        if len(_scan_state["log"]) > 200:
            _scan_state["log"] = _scan_state["log"][-200:]


# ── Background scan worker ─────────────────────────────────────────────────────

def run_scan(network: str, method: str, ports_spec: str, fingerprint: bool, iface: str):
    """
    Background thread: runs host discovery → port scan → OS fingerprint.
    Writes results into _scan_state dict as they arrive.
    """
    from scapy.all import conf
    conf.verb = 0

    with _scan_lock:
        _scan_state.update({
            "running": True, "phase": "discovery",
            "hosts": {}, "ports": defaultdict(dict),
            "os_info": {}, "log": [],
            "progress": 0.0, "started_at": time.time(), "finished_at": None,
        })

    _log(f"Starting host discovery on {network} via {method}")

    # ── Phase 1: Host discovery ────────────────────────────────────────────────
    try:
        import ipaddress
        from scapy.all import Ether, ARP, IP, TCP, ICMP, sr1, srp1, RandShort

        net     = ipaddress.ip_network(network, strict=False)
        all_ips = [str(ip) for ip in net.hosts()]
        total   = len(all_ips)

        for i, ip in enumerate(all_ips):
            if not _scan_state["running"]:
                break

            result = None
            if method in ("arp", "all"):
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                try:
                    reply = srp1(pkt, iface=iface, timeout=0.5, verbose=False)
                    if reply and reply.haslayer(ARP) and reply[ARP].op == 2:
                        result = {"mac": reply[ARP].hwsrc, "method": "ARP", "ttl": None}
                except Exception:
                    pass

            if not result and method in ("icmp", "all"):
                try:
                    reply = sr1(IP(dst=ip) / ICMP(), timeout=0.5, verbose=False)
                    if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
                        result = {"mac": "—", "method": "ICMP", "ttl": reply[IP].ttl}
                except Exception:
                    pass

            if not result and method in ("tcp", "all"):
                try:
                    reply = sr1(
                        IP(dst=ip) / TCP(dport=80, sport=RandShort(), flags="S"),
                        timeout=0.5, verbose=False,
                    )
                    if reply and reply.haslayer("TCP"):
                        flags = reply["TCP"].flags
                        if flags & 0x12 == 0x12 or flags & 0x04:
                            result = {"mac": "—", "method": "TCP-SYN", "ttl": reply[IP].ttl}
                except Exception:
                    pass

            if result:
                with _scan_lock:
                    _scan_state["hosts"][ip] = result
                _log(f"LIVE  {ip}  via {result['method']}  mac={result.get('mac','')}")

            with _scan_lock:
                _scan_state["progress"] = (i + 1) / total * 0.4   # discovery = 0–40%

    except Exception as e:
        _log(f"Discovery error: {e}")

    # ── Phase 2: Port scan ─────────────────────────────────────────────────────
    with _scan_lock:
        live_hosts = list(_scan_state["hosts"].keys())
        _scan_state["phase"] = "scanning"

    if not live_hosts:
        _log("No live hosts found — skipping port scan")
    else:
        _log(f"Port scanning {len(live_hosts)} host(s): {ports_spec}")

        try:
            from module2.syn_scanner import syn_scan, parse_ports
            port_list = parse_ports(ports_spec)

            for hi, ip in enumerate(live_hosts):
                if not _scan_state["running"]:
                    break
                _log(f"Scanning {ip} ({len(port_list)} ports)...")
                results = syn_scan(ip, port_list, timeout=1.5, chunk_size=256)
                with _scan_lock:
                    _scan_state["ports"][ip] = results
                    open_count = sum(1 for s in results.values() if s == "open")
                _log(f"  {ip}: {open_count} open port(s)")
                with _scan_lock:
                    _scan_state["progress"] = 0.4 + (hi + 1) / len(live_hosts) * 0.4

        except Exception as e:
            _log(f"Port scan error: {e}")

    # ── Phase 3: OS fingerprinting ─────────────────────────────────────────────
    if fingerprint:
        with _scan_lock:
            _scan_state["phase"] = "fingerprinting"

        _log("Running OS fingerprinting...")

        try:
            from module2.os_fingerprint import icmp_probe, tcp_syn_probe, match_os, ttl_bucket, parse_tcp_options

            for fi, ip in enumerate(live_hosts):
                if not _scan_state["running"]:
                    break

                # Find an open port to probe
                with _scan_lock:
                    port_results = dict(_scan_state["ports"].get(ip, {}))
                open_ports = [p for p, s in port_results.items() if s == "open"]
                probe_port  = open_ports[0] if open_ports else 80

                icmp_r = icmp_probe(ip, timeout=1.0)
                tcp_r  = tcp_syn_probe(ip, probe_port, timeout=1.0)

                os_info = {"ttl": None, "window": None, "options": [], "guess": "Unknown"}
                if tcp_r:
                    os_info = {
                        "ttl":     tcp_r["ttl"],
                        "window":  tcp_r["window"],
                        "options": tcp_r["options"],
                        "guess":   match_os(tcp_r["ttl"], tcp_r["window"], tcp_r["options"]),
                    }
                elif icmp_r:
                    os_info["ttl"]   = icmp_r["ttl"]
                    os_info["guess"] = f"TTL-bucket {ttl_bucket(icmp_r['ttl'])}"

                with _scan_lock:
                    _scan_state["os_info"][ip] = os_info
                _log(f"  {ip}: {os_info['guess']}")

                with _scan_lock:
                    _scan_state["progress"] = 0.8 + (fi + 1) / len(live_hosts) * 0.2

        except Exception as e:
            _log(f"Fingerprint error: {e}")

    with _scan_lock:
        _scan_state.update({
            "running": False,
            "phase": "done",
            "progress": 1.0,
            "finished_at": time.time(),
        })
    _log("Scan complete.")


# ── Helper: start scan in background thread ────────────────────────────────────

def start_scan(network, method, ports_spec, fingerprint, iface):
    if _scan_state["running"]:
        return
    t = threading.Thread(
        target=run_scan,
        args=(network, method, ports_spec, fingerprint, iface),
        daemon=True,
    )
    t.start()


def stop_scan():
    with _scan_lock:
        _scan_state["running"] = False


# ── Plotly charts ──────────────────────────────────────────────────────────────

def network_graph(hosts: dict, ports: dict) -> go.Figure:
    """
    Draws a star topology: attacker in center, live hosts around it.
    Node color = OS guess family. Node size = number of open ports.
    """
    G = nx.Graph()
    attacker_ip = "attacker\n(10.0.0.1)"
    G.add_node(attacker_ip, kind="attacker")

    for ip, info in hosts.items():
        G.add_node(ip, kind="host")
        G.add_edge(attacker_ip, ip)

    pos = nx.spring_layout(G, seed=42, k=2.5)

    edge_x, edge_y = [], []
    for u, v in G.edges():
        x0, y0 = pos[u]; x1, y1 = pos[v]
        edge_x += [x0, x1, None]; edge_y += [y0, y1, None]

    node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
    os_colors = {
        "Linux":   "#00CC44",
        "Windows": "#4488FF",
        "macOS":   "#FFAA00",
        "Cisco":   "#FF6600",
        "Network": "#AA44FF",
        "Unknown": "#888888",
        "attacker": "#FF3333",
    }

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x); node_y.append(y)

        if node == attacker_ip:
            node_text.append(node)
            node_color.append(os_colors["attacker"])
            node_size.append(30)
        else:
            open_count = sum(1 for s in ports.get(node, {}).values() if s == "open")
            os_guess   = _scan_state["os_info"].get(node, {}).get("guess", "Unknown")
            mac        = hosts[node].get("mac", "")
            color_key  = next((k for k in os_colors if k in os_guess), "Unknown")

            node_text.append(f"{node}<br>Open: {open_count}<br>OS: {os_guess}<br>MAC: {mac}")
            node_color.append(os_colors[color_key])
            node_size.append(max(20, 15 + open_count * 3))

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line=dict(width=1, color="#444"),
        hoverinfo="none",
    ))
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y, mode="markers+text",
        marker=dict(size=node_size, color=node_color,
                    line=dict(width=2, color="#111")),
        text=[n.split("<br>")[0] for n in node_text],
        textposition="top center",
        hovertext=node_text,
        hoverinfo="text",
        textfont=dict(size=11, color="white"),
    ))
    fig.update_layout(
        showlegend=False,
        plot_bgcolor="#0E1117",
        paper_bgcolor="#0E1117",
        font_color="white",
        margin=dict(l=20, r=20, t=20, b=20),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=400,
    )
    return fig


def port_heatmap(ports: dict) -> go.Figure | None:
    """Color-coded port state grid: open=green, filtered=yellow, closed=gray."""
    if not ports:
        return None

    all_open = set()
    for port_dict in ports.values():
        all_open |= {p for p, s in port_dict.items() if s == "open"}

    if not all_open:
        return None

    sorted_ports = sorted(all_open)
    sorted_hosts = sorted(ports.keys())

    state_map = {"open": 2, "filtered": 1, "closed": 0}
    z, text = [], []
    for ip in sorted_hosts:
        row, trow = [], []
        for port in sorted_ports:
            state = ports[ip].get(port, "—")
            row.append(state_map.get(state, -1))
            trow.append(f"{ip}:{port}<br>{state}")
        z.append(row)
        text.append(trow)

    fig = go.Figure(go.Heatmap(
        z=z,
        x=[str(p) for p in sorted_ports],
        y=sorted_hosts,
        text=text,
        hoverinfo="text",
        colorscale=[
            [0.0,  "#1a1a1a"],   # closed  — dark
            [0.5,  "#CC8800"],   # filtered — amber
            [1.0,  "#00CC44"],   # open     — green
        ],
        zmin=0, zmax=2,
        showscale=False,
    ))
    fig.update_layout(
        plot_bgcolor="#0E1117",
        paper_bgcolor="#0E1117",
        font_color="white",
        margin=dict(l=10, r=10, t=10, b=10),
        height=max(180, len(sorted_hosts) * 50),
        xaxis=dict(title="Port", tickfont=dict(size=10)),
        yaxis=dict(title="Host"),
    )
    return fig


def open_port_bar(ports: dict) -> go.Figure | None:
    """Bar chart: open port count per host."""
    counts = {ip: sum(1 for s in pd.items() if s == "open") for ip, pd in ports.items()}
    counts = {ip: c for ip, c in counts.items() if c > 0}
    if not counts:
        return None

    fig = go.Figure(go.Bar(
        x=list(counts.keys()),
        y=list(counts.values()),
        marker_color="#00CC44",
        text=list(counts.values()),
        textposition="outside",
    ))
    fig.update_layout(
        plot_bgcolor="#0E1117",
        paper_bgcolor="#0E1117",
        font_color="white",
        xaxis_title="Host",
        yaxis_title="Open Ports",
        margin=dict(l=10, r=10, t=10, b=10),
        height=260,
    )
    return fig


# ── Main Streamlit UI ──────────────────────────────────────────────────────────

def main():
    # ── Sidebar ────────────────────────────────────────────────────────────────
    with st.sidebar:
        st.image("https://raw.githubusercontent.com/secdev/scapy/master/doc/scapy/graphics/scapy_logo.png",
                 width=120)
        st.title("Recon Dashboard")
        st.caption("DC34 — Offensive Packet Wizardry")
        st.divider()

        network   = st.text_input("Target Network (CIDR)", value="10.0.0.0/24")
        method    = st.selectbox("Discovery Method", ["arp", "icmp", "tcp", "all"], index=0)
        ports_spec = st.text_input("Port Range", value="21-23,25,53,80,443,8080,9000")
        do_fp     = st.checkbox("OS Fingerprinting", value=True)
        iface     = st.text_input("Interface", value="eth0")

        st.divider()
        col1, col2 = st.columns(2)
        start_btn = col1.button("▶  Start Scan", type="primary",  use_container_width=True)
        stop_btn  = col2.button("■  Stop",        type="secondary", use_container_width=True)

        if start_btn:
            start_scan(network, method, ports_spec, do_fp, iface)
            st.session_state["auto_refresh"] = True

        if stop_btn:
            stop_scan()
            st.session_state["auto_refresh"] = False

        st.divider()
        st.caption("⚠️  Requires root (raw sockets)")
        st.caption("sudo streamlit run dashboard/recon_dashboard.py")

    # ── Read shared state snapshot ─────────────────────────────────────────────
    with _scan_lock:
        running     = _scan_state["running"]
        phase       = _scan_state["phase"]
        hosts       = dict(_scan_state["hosts"])
        ports       = {ip: dict(pd) for ip, pd in _scan_state["ports"].items()}
        os_info     = dict(_scan_state["os_info"])
        log_lines   = list(_scan_state["log"])
        progress    = _scan_state["progress"]
        started_at  = _scan_state["started_at"]
        finished_at = _scan_state["finished_at"]

    # ── Header ─────────────────────────────────────────────────────────────────
    st.markdown(
        "<h1 style='color:#00CC44;margin-bottom:0'>🔍 Network Recon Dashboard</h1>"
        "<p style='color:#888;margin-top:0'>Live host discovery · Port scanning · OS fingerprinting</p>",
        unsafe_allow_html=True,
    )

    # ── Status bar ─────────────────────────────────────────────────────────────
    phase_labels = {
        "idle":            "⬜ Idle — configure scan in sidebar",
        "discovery":       "🔵 Phase 1/3 — Host Discovery",
        "scanning":        "🟡 Phase 2/3 — Port Scanning",
        "fingerprinting":  "🟠 Phase 3/3 — OS Fingerprinting",
        "done":            "🟢 Scan Complete",
    }
    st.info(phase_labels.get(phase, phase))

    if running or phase == "done":
        st.progress(progress, text=f"{progress*100:.0f}%")

    # ── Metrics row ────────────────────────────────────────────────────────────
    m1, m2, m3, m4 = st.columns(4)
    total_open = sum(
        sum(1 for s in pd.values() if s == "open")
        for pd in ports.values()
    )
    elapsed = ""
    if started_at:
        end = finished_at or time.time()
        elapsed = f"{end - started_at:.1f}s"

    m1.metric("Live Hosts",  len(hosts))
    m2.metric("Open Ports",  total_open)
    m3.metric("Hosts Scanned", len(ports))
    m4.metric("Elapsed",     elapsed or "—")

    st.divider()

    # ── Network graph + hosts table ────────────────────────────────────────────
    col_graph, col_table = st.columns([3, 2])

    with col_graph:
        st.subheader("Network Map")
        if hosts:
            fig = network_graph(hosts, ports)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.markdown(
                "<div style='height:400px;display:flex;align-items:center;"
                "justify-content:center;border:1px dashed #333;border-radius:8px;"
                "color:#555'>No hosts discovered yet</div>",
                unsafe_allow_html=True,
            )

    with col_table:
        st.subheader("Discovered Hosts")
        if hosts:
            rows = []
            for ip, info in sorted(hosts.items()):
                open_count = sum(1 for s in ports.get(ip, {}).values() if s == "open")
                guess = os_info.get(ip, {}).get("guess", "—")
                rows.append({
                    "IP":        ip,
                    "MAC":       info.get("mac", "—"),
                    "Discovery": info.get("method", "—"),
                    "TTL":       info.get("ttl") or os_info.get(ip, {}).get("ttl") or "—",
                    "Open Ports": open_count,
                    "OS Guess":  guess,
                })
            df = pd.DataFrame(rows)
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Open Ports": st.column_config.NumberColumn(format="%d"),
                },
            )
        else:
            st.caption("Hosts will appear here as they are discovered.")

    st.divider()

    # ── Port scan results ──────────────────────────────────────────────────────
    st.subheader("Port Scan Results")
    col_heat, col_bar = st.columns([3, 2])

    with col_heat:
        fig_heat = port_heatmap(ports)
        if fig_heat:
            st.plotly_chart(fig_heat, use_container_width=True)
        else:
            st.caption("Port heatmap will appear after scanning (showing open ports only).")

    with col_bar:
        fig_bar = open_port_bar(ports)
        if fig_bar:
            st.plotly_chart(fig_bar, use_container_width=True)

    # Open ports detail table
    if ports:
        all_open_rows = []
        for ip, port_dict in sorted(ports.items()):
            for port, state in sorted(port_dict.items()):
                if state == "open":
                    all_open_rows.append({"Host": ip, "Port": port, "State": state})
        if all_open_rows:
            st.dataframe(
                pd.DataFrame(all_open_rows),
                use_container_width=True,
                hide_index=True,
            )

    st.divider()

    # ── OS Fingerprint table ───────────────────────────────────────────────────
    if os_info:
        st.subheader("OS Fingerprinting")
        fp_rows = []
        for ip, info in sorted(os_info.items()):
            fp_rows.append({
                "Host":       ip,
                "TTL":        info.get("ttl", "—"),
                "TCP Window": info.get("window", "—"),
                "TCP Options": str(info.get("options", [])),
                "OS Guess":   info.get("guess", "Unknown"),
            })
        st.dataframe(pd.DataFrame(fp_rows), use_container_width=True, hide_index=True)
        st.divider()

    # ── Activity log ──────────────────────────────────────────────────────────
    with st.expander("Activity Log", expanded=running):
        log_text = "\n".join(reversed(log_lines[-60:]))
        st.code(log_text or "(no activity yet)", language=None)

    # ── Auto-refresh while scan is running ────────────────────────────────────
    if running:
        time.sleep(1.5)
        st.rerun()


if __name__ == "__main__":
    main()
