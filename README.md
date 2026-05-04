# 🔥 PyreWall — Personal Firewall Application

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Capture-orange?style=for-the-badge)
![Flask](https://img.shields.io/badge/Flask-Dashboard-lightgrey?style=for-the-badge&logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A custom personal firewall built in Python that monitors and filters network traffic using rule-based packet filtering, rate limiting, and real-time dashboarding.**

</div>

---

## 📋 Project Overview

| Field | Details |
|-------|---------|
| **Project Type** | Personal Firewall (Network Security) |
| **Language** | Python 3.10+ |
| **Packet Engine** | Scapy (raw packet capture & analysis) |
| **Interfaces** | CLI (interactive terminal) + Web Dashboard (Flask) |
| **Rule Engine** | First-match-wins, top-down rule evaluation |
| **Extras** | Rate limiting, preset rulesets, demo/simulation mode |

---

## 🛡️ Features

| Feature | Description |
|---------|-------------|
| **Packet Capture** | Real-time capture via Scapy (TCP, UDP, ICMP) |
| **Rule-Based Filtering** | Allow/Block rules by IP, port, protocol, direction |
| **First-Match-Wins** | Rules evaluated top-down — first match decides action |
| **Rate Limiting** | Auto-blocks IPs exceeding 50 connections in 10 seconds |
| **Preset Rulesets** | Basic (allow common, block dangerous) and Strict (whitelist) |
| **Demo Mode** | Simulates traffic with no root/admin needed — perfect for presentations |
| **Web Dashboard** | Real-time stats, rule management, packet log via browser |
| **CLI Interface** | Full interactive terminal with colored output |
| **Logging** | Rotating log files + console output |
| **Save/Load Rules** | Export and import rules as JSON |
| **Statistics** | Packet counts, protocol breakdown, top blocked IPs |

---

## 🗂️ Repository Structure

```
PyreWall/
├── app/
│   ├── __init__.py          # Package init
│   ├── firewall.py          # Core engine: rules, packet processing, rate limiter
│   ├── logger.py            # Rotating file + console logging
│   ├── cli.py               # Interactive CLI interface
│   ├── dashboard.py         # Flask web dashboard
│   └── simulator.py         # Traffic simulation (demo mode)
├── tests/
│   └── test_firewall.py     # 16 tests: rules, rate limiting, presets
├── run.py                   # Entry point (CLI / Web / Demo)
├── requirements.txt         # Dependencies
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip

### Setup

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/PyreWall.git
cd PyreWall

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run in demo mode (NO ROOT NEEDED — perfect for testing)
python run.py --demo

# 4. Or launch CLI (root needed for live packet capture)
sudo python run.py --cli

# 5. Or launch Web Dashboard
python run.py --web
# Open http://127.0.0.1:5000
```

---

## 🎮 Usage Modes

### Demo Mode (Recommended for Viva)
```bash
python run.py --demo
```
Simulates 3 scenarios: normal browsing, attack attempts, and a port scan — no root needed.

### CLI Mode
```bash
sudo python run.py --cli
```
Interactive terminal. Type `help` for commands:
- `preset basic` — Load common security rules
- `start` — Begin packet capture
- `packets` — View captured traffic
- `add` — Add custom rule
- `status` — View statistics
- `demo` — Run simulation

### Web Dashboard
```bash
python run.py --web
```
Opens at `http://127.0.0.1:5000` with real-time stats, rule management, and packet log.

---

## 📐 How It Works

### Rule Evaluation (First-Match-Wins)
```
Incoming Packet
    │
    ▼
Rule #1: Block Telnet (port 23) ── match? ──▶ BLOCK
    │ no
    ▼
Rule #2: Allow HTTP (port 80)  ── match? ──▶ ALLOW
    │ no
    ▼
Rule #3: Allow DNS (port 53)   ── match? ──▶ ALLOW
    │ no
    ▼
Default Policy (allow/block)   ──────────▶ DEFAULT ACTION
```

### Rate Limiter
Tracks connections per source IP in a sliding window (default: 50 connections per 10 seconds). Exceeding the limit auto-blocks the IP — detects port scans and DDoS attempts.

---

## 🧪 Testing

```bash
python -m pytest tests/ -v
```

Tests cover: rule matching (IP, port, protocol, direction), first-match-wins ordering, default policy, rate limiting, rule management (add/remove/list), hit counters, and preset loading.

---

## 🎓 Skills Demonstrated

- **Network Security:** Packet filtering, stateless firewall design
- **Packet Analysis:** Scapy-based packet capture and dissection
- **Protocol Knowledge:** TCP, UDP, ICMP, well-known port identification
- **Rate Limiting:** Sliding window algorithm for DDoS detection
- **Python:** OOP, threading, data structures (defaultdict, deque)
- **Web Development:** Flask REST API + real-time dashboard
- **Testing:** pytest test suite with fixture-based setup
- **Security Logging:** Rotating log files, structured audit events

---

## 📚 References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Linux iptables Tutorial](https://www.netfilter.org/documentation/)
- [NIST SP 800-41 — Guidelines on Firewalls and Firewall Policy](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final)
- [TCP/IP Protocol Suite — Behrouz Forouzan](https://www.mheducation.com/highered/product/tcp-ip-protocol-suite-forouzan/M9780073376042.html)

---

## 👤 Author

**[Your Name]**
- 🔗 LinkedIn: [Your LinkedIn]
- 💻 GitHub: [Your GitHub]

---

*Built as part of a Cybersecurity Internship at Codec Technologies — 2026*
