#!/usr/bin/env python3
"""
DC34 Workshop — Capstone Scoreboard

Shared leaderboard for the "Silent Pivot" capstone exercise.
Project this on screen while attendees complete the objectives.

Features:
  - Add / remove teams
  - Instructor marks objectives complete per team
  - Live points tally and ranked leaderboard
  - Progress bars per team
  - Auto-refresh every 5 seconds
  - Confetti animation on first-place completion

Run (no root needed — no raw sockets):
    streamlit run dashboard/capstone_scoreboard.py

Best displayed in full-screen browser (F11).
Accessible to all attendees at: http://192.168.56.1:8501
"""

import time
import random

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="DC34 Capstone Scoreboard",
    page_icon="🏆",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Objectives definition ──────────────────────────────────────────────────────
OBJECTIVES = [
    {"id": "obj1", "label": "Host Discovery",       "desc": "Find all live hosts without > 5 Snort alerts", "points": 20, "emoji": "🔍"},
    {"id": "obj2", "label": "Service ID",            "desc": "Identify the service on port 9000",            "points": 15, "emoji": "🔌"},
    {"id": "obj3", "label": "Exploit / Crash",       "desc": "Crash the service using your fuzzer",          "points": 25, "emoji": "💥"},
    {"id": "obj4", "label": "ICMP C2",               "desc": "Execute a command via ICMP tunnel",            "points": 20, "emoji": "📡"},
    {"id": "obj5", "label": "DNS Exfiltration",      "desc": "Exfiltrate /etc/shadow over DNS",              "points": 20, "emoji": "📤"},
    {"id": "bonus","label": "Clean Exit (Bonus)",    "desc": "Restore ARP, kill agents, no traces",          "points": 10, "emoji": "🧹"},
]
MAX_POINTS = sum(o["points"] for o in OBJECTIVES)

# ── Session state init ─────────────────────────────────────────────────────────
def _init_state():
    if "teams" not in st.session_state:
        st.session_state["teams"] = {}
        # Seed with default teams so the board isn't empty
        for name in ["Team Alpha", "Team Bravo", "Team Charlie"]:
            _add_team(name)

    if "start_time" not in st.session_state:
        st.session_state["start_time"] = time.time()

    if "completed_fireworks" not in st.session_state:
        st.session_state["completed_fireworks"] = set()


def _add_team(name: str):
    name = name.strip()
    if not name or name in st.session_state["teams"]:
        return
    st.session_state["teams"][name] = {
        obj["id"]: False for obj in OBJECTIVES
    }


def _remove_team(name: str):
    st.session_state["teams"].pop(name, None)


def _team_score(name: str) -> int:
    completed = st.session_state["teams"].get(name, {})
    obj_map   = {o["id"]: o["points"] for o in OBJECTIVES}
    return sum(obj_map[oid] for oid, done in completed.items() if done)


def _team_completed_count(name: str) -> int:
    return sum(1 for done in st.session_state["teams"].get(name, {}).values() if done)


def _leaderboard() -> pd.DataFrame:
    rows = []
    for name in st.session_state["teams"]:
        score    = _team_score(name)
        done     = _team_completed_count(name)
        pct      = score / MAX_POINTS * 100
        rows.append({"Team": name, "Score": score, "Objectives": done, "Completion %": pct})
    df = pd.DataFrame(rows).sort_values("Score", ascending=False).reset_index(drop=True)
    df.index += 1
    return df


# ── Charts ─────────────────────────────────────────────────────────────────────

def leaderboard_bar(df: pd.DataFrame) -> go.Figure:
    colors = ["#FFD700", "#C0C0C0", "#CD7F32"] + ["#4488FF"] * max(0, len(df) - 3)

    fig = go.Figure(go.Bar(
        x=df["Score"],
        y=df["Team"],
        orientation="h",
        marker_color=colors[:len(df)],
        text=[f"{s} pts" for s in df["Score"]],
        textposition="outside",
        textfont=dict(color="white", size=14),
    ))
    fig.update_layout(
        plot_bgcolor="#0E1117",
        paper_bgcolor="#0E1117",
        font_color="white",
        xaxis=dict(range=[0, MAX_POINTS + 10], showgrid=True,
                   gridcolor="#222", title="Points"),
        yaxis=dict(autorange="reversed"),
        margin=dict(l=20, r=60, t=10, b=10),
        height=max(200, len(df) * 70),
    )
    return fig


def objective_breakdown(teams: dict) -> go.Figure:
    """Stacked bar: each objective segment per team."""
    obj_labels  = [o["label"] for o in OBJECTIVES]
    obj_ids     = [o["id"]    for o in OBJECTIVES]
    obj_points  = [o["points"] for o in OBJECTIVES]
    team_names  = list(teams.keys())

    obj_colors = [
        "#00CC44", "#4488FF", "#FF3333",
        "#FFAA00", "#AA44FF", "#00CCCC",
    ]

    fig = go.Figure()
    for i, (oid, label, pts) in enumerate(zip(obj_ids, obj_labels, obj_points)):
        values = [pts if teams[t].get(oid) else 0 for t in team_names]
        fig.add_trace(go.Bar(
            name=f"{label} ({pts}pts)",
            x=team_names,
            y=values,
            marker_color=obj_colors[i % len(obj_colors)],
            text=[f"+{pts}" if v > 0 else "" for v in values],
            textfont=dict(size=12, color="white"),
        ))

    fig.update_layout(
        barmode="stack",
        plot_bgcolor="#0E1117",
        paper_bgcolor="#0E1117",
        font_color="white",
        yaxis=dict(range=[0, MAX_POINTS + 5], title="Points", gridcolor="#222"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, bgcolor="rgba(0,0,0,0)"),
        margin=dict(l=10, r=10, t=40, b=10),
        height=380,
    )
    return fig


def radar_chart(name: str, completed: dict) -> go.Figure:
    """Radar / spider chart showing which objectives a team has completed."""
    labels  = [o["label"] for o in OBJECTIVES]
    values  = [o["points"] if completed.get(o["id"]) else 0 for o in OBJECTIVES]
    max_vals = [o["points"] for o in OBJECTIVES]

    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=max_vals + [max_vals[0]],
        theta=labels + [labels[0]],
        fill="none",
        line=dict(color="#333", width=1),
        name="Max",
    ))
    fig.add_trace(go.Scatterpolar(
        r=values + [values[0]],
        theta=labels + [labels[0]],
        fill="toself",
        fillcolor="rgba(0, 204, 68, 0.25)",
        line=dict(color="#00CC44", width=2),
        name=name,
    ))
    fig.update_layout(
        polar=dict(
            bgcolor="#0E1117",
            radialaxis=dict(visible=False, range=[0, max(max_vals)]),
            angularaxis=dict(tickfont=dict(size=10, color="white")),
        ),
        paper_bgcolor="#0E1117",
        showlegend=False,
        margin=dict(l=30, r=30, t=30, b=30),
        height=220,
    )
    return fig


# ── Main UI ────────────────────────────────────────────────────────────────────

def main():
    _init_state()

    teams    = st.session_state["teams"]
    lb       = _leaderboard()

    # ── Sidebar — instructor controls ──────────────────────────────────────────
    with st.sidebar:
        st.title("🎛️ Instructor Panel")
        st.caption("DC34 — Capstone Scoreboard")
        st.divider()

        # Add team
        st.subheader("Teams")
        new_name = st.text_input("Add team", placeholder="e.g. Team Delta")
        if st.button("➕ Add", use_container_width=True):
            _add_team(new_name)
            st.rerun()

        # Remove team
        if teams:
            del_name = st.selectbox("Remove team", ["—"] + list(teams.keys()))
            if st.button("🗑 Remove", use_container_width=True) and del_name != "—":
                _remove_team(del_name)
                st.rerun()

        st.divider()

        # Mark objectives
        st.subheader("Mark Objectives")
        sel_team = st.selectbox("Team", ["—"] + list(teams.keys()), key="sel_team")
        if sel_team != "—":
            changed = False
            for obj in OBJECTIVES:
                current = teams[sel_team].get(obj["id"], False)
                new_val = st.checkbox(
                    f"{obj['emoji']} {obj['label']} (+{obj['points']})",
                    value=current,
                    key=f"cb_{sel_team}_{obj['id']}",
                )
                if new_val != current:
                    teams[sel_team][obj["id"]] = new_val
                    changed = True
            if changed:
                st.rerun()

        st.divider()

        # Timer
        elapsed = time.time() - st.session_state["start_time"]
        mins, secs = divmod(int(elapsed), 60)
        st.metric("⏱ Elapsed", f"{mins:02d}:{secs:02d}")
        if st.button("🔄 Reset Timer"):
            st.session_state["start_time"] = time.time()

        st.divider()
        st.caption("Auto-refreshes every 5s")

    # ── Header ─────────────────────────────────────────────────────────────────
    st.markdown(
        "<h1 style='text-align:center;color:#FFD700;font-size:2.6rem;margin-bottom:0'>"
        "🏆 Silent Pivot — Capstone Scoreboard</h1>"
        "<p style='text-align:center;color:#888;margin-top:0;font-size:1.1rem'>"
        "DC34 Offensive Packet Wizardry with Scapy</p>",
        unsafe_allow_html=True,
    )
    st.divider()

    if not teams:
        st.info("No teams yet. Add teams in the sidebar.")
        return

    # ── Leaderboard bar chart ──────────────────────────────────────────────────
    col_lb, col_medals = st.columns([3, 1])

    with col_lb:
        st.subheader("Leaderboard")
        st.plotly_chart(leaderboard_bar(lb), use_container_width=True)

    with col_medals:
        st.subheader("Rankings")
        medals = ["🥇", "🥈", "🥉"]
        for i, row in lb.iterrows():
            medal   = medals[i - 1] if i <= 3 else f"#{i}"
            pct     = row["Completion %"]
            color   = "#FFD700" if i == 1 else ("#C0C0C0" if i == 2 else ("#CD7F32" if i == 3 else "#4488FF"))
            st.markdown(
                f"<div style='padding:8px;margin:4px 0;border-radius:6px;"
                f"border-left:4px solid {color};background:#111'>"
                f"<b style='color:{color}'>{medal} {row['Team']}</b><br>"
                f"<span style='color:#aaa'>{row['Score']} pts &nbsp;|&nbsp; "
                f"{row['Objectives']}/{len(OBJECTIVES)} objectives &nbsp;|&nbsp; "
                f"{pct:.0f}%</span></div>",
                unsafe_allow_html=True,
            )

    st.divider()

    # ── Objective breakdown ────────────────────────────────────────────────────
    st.subheader("Points Breakdown by Objective")
    st.plotly_chart(objective_breakdown(teams), use_container_width=True)
    st.divider()

    # ── Per-team progress cards ────────────────────────────────────────────────
    st.subheader("Team Detail")
    cols = st.columns(min(len(teams), 3))

    for i, (name, completed) in enumerate(teams.items()):
        score = _team_score(name)
        pct   = score / MAX_POINTS * 100
        col   = cols[i % len(cols)]

        with col:
            # Header card
            rank = lb[lb["Team"] == name].index[0]
            medal = ["🥇", "🥈", "🥉"][rank - 1] if rank <= 3 else f"#{rank}"
            st.markdown(
                f"<div style='padding:10px;border-radius:8px;background:#111;"
                f"border:1px solid #333;margin-bottom:8px'>"
                f"<h3 style='margin:0;color:#FFD700'>{medal} {name}</h3>"
                f"<b style='font-size:1.4rem;color:#00CC44'>{score}</b>"
                f"<span style='color:#888'> / {MAX_POINTS} pts</span>"
                f"</div>",
                unsafe_allow_html=True,
            )
            st.progress(pct / 100)

            # Radar chart
            st.plotly_chart(radar_chart(name, completed), use_container_width=True)

            # Objective checklist
            for obj in OBJECTIVES:
                done = completed.get(obj["id"], False)
                icon = "✅" if done else "⬜"
                pts  = f"+{obj['points']}" if done else f"  {obj['points']}pts"
                st.markdown(
                    f"<div style='font-size:0.85rem;color:{'#00CC44' if done else '#555'}'>"
                    f"{icon} {obj['emoji']} {obj['label']} <b>{pts}</b>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

    # ── Objectives reference ───────────────────────────────────────────────────
    st.divider()
    with st.expander("📋 Objectives Reference", expanded=False):
        for obj in OBJECTIVES:
            bonus_tag = " *(bonus)*" if obj["id"] == "bonus" else ""
            st.markdown(
                f"**{obj['emoji']} {obj['label']}** — {obj['points']} pts{bonus_tag}  \n"
                f"*{obj['desc']}*"
            )

    # ── Confetti when a team completes everything ──────────────────────────────
    completed_teams = [n for n in teams if _team_score(n) >= MAX_POINTS]
    new_completions = [n for n in completed_teams if n not in st.session_state["completed_fireworks"]]
    if new_completions:
        for n in new_completions:
            st.session_state["completed_fireworks"].add(n)
        st.balloons()
        st.success(f"🎉 {' and '.join(new_completions)} completed ALL objectives! 🎉")

    # ── Auto-refresh ───────────────────────────────────────────────────────────
    time.sleep(5)
    st.rerun()


if __name__ == "__main__":
    main()
