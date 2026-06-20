# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Teaching material for a 4-hour DEF CON 34 workshop, "Offensive Packet Wizardry with Scapy." It is **not** production software — it's a set of standalone, didactic offensive-security scripts (recon, ARP MitM, TCP abuse, fuzzing, covert channels) that students run against an isolated two-VM lab. Code clarity for learners outweighs abstraction; expect deliberate repetition across modules so each script reads standalone.

All exercises target the isolated lab only: attacker `192.168.56.1` (Kali), target `192.168.56.2` (Ubuntu 24.04), gateway `192.168.56.254` (simulated), on an isolated VirtualBox internal network `192.168.56.0/24`. These IPs are hardcoded as defaults throughout (e.g. `setup/verify_env.py`). The lab is built and provisioned by the root `Vagrantfile` (`vagrant up` → Kali attacker + Ubuntu target); the repo mounts at `/vagrant` inside the attacker VM, where Scapy and deps are pre-installed.

## Running things

Everything that touches the network needs raw sockets, so **run with `sudo`** and Python 3.10+.

```bash
pip3 install -r requirements.txt
sudo python3 setup/verify_env.py          # pre-flight check, run first

# Individual module scripts are self-contained CLIs (argparse, --help works):
sudo python3 module2/syn_scanner.py --target 192.168.56.2 --ports 1-1024

# Unified CLI over the assembled package:
sudo python3 redteam_toolkit/cli.py recon --target 192.168.56.0/24
sudo python3 redteam_toolkit/cli.py {recon|scan|mitm|fuzz|c2|exfil|flood|rst} ...

# Streamlit dashboards (also need root for the Scapy threads):
sudo streamlit run dashboard/recon_dashboard.py        # → http://localhost:8501
sudo streamlit run dashboard/capstone_scoreboard.py
sudo streamlit run module7/ai_lab.py                   # needs ANTHROPIC_API_KEY
```

There is **no test suite, linter, or build step**. "Does it work" = run the script against the lab VM and read the output. `setup/verify_env.py` is the closest thing to a smoke test (checks Python/Scapy versions, raw-socket capability, lab reachability).

## Architecture

Two layers, and understanding the relationship is the key to navigating the repo:

1. **`moduleN/` directories** — the lesson scripts. Each is a self-contained teaching unit (`moduleN/README.md` + several `.py` scripts), ordered to match the workshop timeline (module1 → capstone). These hold the *real* implementations.

2. **`redteam_toolkit/`** — the "payoff" package students assemble at the end. It does **not** reimplement anything; each toolkit module is a thin re-export wrapper that imports from the `moduleN/` scripts and presents a clean API:
   - `recon.py`  → wraps `module2/` (host_discovery, syn_scanner, os_fingerprint)
   - `mitm.py`   → wraps `module3/arp_mitm`
   - `exploit.py`→ wraps `module4/` (rst_injector, etc.)
   - `fuzzer.py` → wraps `module5/` (custom_fuzzer, dns_fuzzer)
   - `covert.py` → wraps `module6/` (icmp_tunnel, dns_exfil)
   - `cli.py`    → unified argparse dispatcher over all of the above
   - `__init__.py` re-exports the public primitives (`sweep`, `syn_scan`, `ArpMitm`, `fuzz_service`, `IcmpC2`, `DnsExfil`)

   **Consequence:** changing behavior usually means editing the `moduleN/` source, not the toolkit wrapper. The wrappers fix up imports via `sys.path.insert(0, <repo root>)` so the `module*` packages resolve when run as scripts.

3. **`module7/` (optional AI lab)** — `packet_narrator.py` defines `PacketNarrator`, which streams Scapy packet objects to the Claude API for live "instructor commentary" framed in MITRE ATT&CK terms; `ai_lab.py` is the Streamlit UI around it (background sniffer thread → `queue.Queue` → UI). Requires `ANTHROPIC_API_KEY`. **When touching anything that calls the Claude API, consult the `claude-api` skill — do not rely on memory for model IDs or pricing.** The code pins `claude-opus-4-8`.

4. **Some attacks ship both sides** (so the lab is self-contained): e.g. `module5/target_server.py` is the intentionally-vulnerable fuzz target with planted bugs; `module6/` has both the exfil/C2 client and the collector/agent. Don't mistake the server/collector halves for attacker tooling.

## Conventions to match

- Scripts set `conf.verb = 0` and print their own `[*]` / `[+]` / `[-]` status lines rather than relying on Scapy's output.
- Network-touching scripts check for root (`os.geteuid()`) and exit with a clear message.
- Keep the hardcoded `192.168.56.0/24` lab defaults; they're intentional teaching anchors, not configuration to generalize away.

## Companion docs

`README.md` (overview/agenda), `HOWTO.md` (file map + 4-hour timeline), `reference_guide.md` (~2200-line student reference), and `submission.md` / `submission_files/` (DEF CON CFP submission artifacts). `samples/` holds PCAPs and test data.
