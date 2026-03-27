# Dashboard — Streamlit Visual Layer

Two Streamlit apps that complement the CLI tools with live visual output.

---

## recon_dashboard.py — Live Recon UI

Visual front-end for Module 2: host discovery, SYN port scan, and OS fingerprinting.
All scanning still runs via Scapy in a background thread — Streamlit just renders results.

**Requires root** (raw socket access for Scapy):

```bash
sudo streamlit run dashboard/recon_dashboard.py
```

Opens at `http://localhost:8501`

### What you see

| Panel | Content |
|-------|---------|
| Network Map | Star topology graph — hosts appear as nodes as they are discovered. Node color = OS family. Node size = open port count. |
| Discovered Hosts | Live-updating table: IP, MAC, discovery method, TTL, open ports, OS guess |
| Port Heatmap | Color grid — green = open, amber = filtered, dark = closed |
| Open Ports Bar | Count of open ports per host |
| OS Fingerprinting | TTL, TCP window size, TCP option order, OS guess |
| Activity Log | Real-time scroll of every Scapy probe result |

### Controls (sidebar)

- **Target Network** — CIDR range, e.g. `10.0.0.0/24`
- **Discovery Method** — `arp` (default) / `icmp` / `tcp` / `all`
- **Port Range** — comma list or range: `21-23,80,443,9000`
- **OS Fingerprinting** — toggle on/off (adds ~5s per host)
- **Interface** — your lab interface, e.g. `eth0`
- **Start / Stop** buttons

### Workshop tip

Use this during Module 2 instead of (or alongside) the terminal tools.
The network graph is especially effective for a live demo — attendees watch hosts
pop onto the map as Scapy discovers them.

---

## capstone_scoreboard.py — Capstone Leaderboard

Projected on screen during the "Silent Pivot" capstone exercise.
The instructor marks objectives complete per team via the sidebar.
All attendees see the live leaderboard update.

**Does NOT require root** (no raw sockets):

```bash
streamlit run dashboard/capstone_scoreboard.py
```

To make it accessible to all VMs on the lab bridge:

```bash
streamlit run dashboard/capstone_scoreboard.py --server.address 0.0.0.0
# Attendees access: http://10.0.0.1:8501
```

### What you see

| Panel | Content |
|-------|---------|
| Leaderboard bar | Horizontal bars — gold/silver/bronze for top 3 |
| Rankings sidebar | Medal list with score, objective count, completion % |
| Points breakdown | Stacked bar — each objective segment color-coded |
| Team cards | Radar chart + objective checklist per team |
| Objectives reference | Full description and point values |

### Controls (sidebar — instructor only)

- **Add / Remove teams** — configure before the exercise starts
- **Mark objectives** — check off each completed objective per team
- **Reset timer** — elapsed time display for pacing

### Scoring

| # | Objective | Points |
|---|-----------|--------|
| 1 | Host discovery (< 5 Snort alerts) | 20 |
| 2 | Service identification on port 9000 | 15 |
| 3 | Crash the service with fuzzer | 25 |
| 4 | Execute command via ICMP C2 | 20 |
| 5 | Exfiltrate /etc/shadow via DNS | 20 |
| B | Clean exit (restore ARP, kill agents) | +10 |

---

## Dependencies

```
streamlit>=1.35.0
plotly>=5.20.0
networkx>=3.2.0
pandas>=2.0.0
```

All included in `requirements.txt`. Install with:

```bash
pip3 install -r requirements.txt
```
