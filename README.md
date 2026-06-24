# 🛡️ SentinelShield
## Advanced Intrusion Detection & Web Application Firewall System

> A practical cybersecurity project simulating a lightweight WAF/IDS for educational use.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Folder Structure](#folder-structure)
- [Setup & Installation](#setup--installation)
- [How to Run](#how-to-run)
- [How to Use](#how-to-use)
- [Attack Detection](#attack-detection)
- [System Workflow](#system-workflow)
- [Screenshots](#screenshots)
- [Viva / Demo Explanation](#viva--demo-explanation)

---

## Overview

SentinelShield is a simplified but realistic **Web Application Firewall (WAF)** and **Intrusion Detection System (IDS)** built with Python Flask. It inspects incoming HTTP requests for malicious content, blocks attack payloads, enforces rate limiting, logs all traffic, and presents a real-time security dashboard.

This project is designed for **cybersecurity practical work** — helping students understand how real WAFs operate, how attack signatures are defined and matched, and how security analysts use logs and dashboards to monitor threats.

> **Important:** This is a simulation tool. No real system access occurs. All "attacks" are analyzed as text strings only.

---

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **Request Inspection** | Inspects URL, query params, headers, and request body |
| 🚨 **Attack Detection** | Detects 6 attack categories using regex-based rule engine |
| ⏱️ **Rate Limiting** | IP-based request throttling with auto-ban |
| 📊 **Live Dashboard** | Real-time statistics, charts, and attack breakdown |
| 📁 **Dual Logging** | SQLite database + flat file log |
| 🧪 **Test Interface** | Interactive payload testing with sample attacks |
| 📄 **Report Generator** | Auto-generated practical session report |
| 🎯 **Alert Engine** | Per-attack alerts with severity classification |

---

## Folder Structure

```
SentinelShield/
│── app.py                          # Main Flask application
│── requirements.txt                # Python dependencies
│── README.md                       # This file
│── PRACTICAL_DOCUMENTATION.md      # Detailed academic documentation
│── .gitignore
│
│── database/
│   └── sentinelshield.db           # Auto-created SQLite database
│
│── logs/
│   └── alerts.log                  # Auto-created flat file log
│
│── templates/
│   ├── base.html                   # Base layout with navbar
│   ├── dashboard.html              # Main dashboard with charts
│   ├── test_request.html           # Payload testing interface
│   ├── logs.html                   # Log viewer with filters
│   └── report.html                 # Auto-generated report
│
│── static/
│   ├── css/style.css               # Dark cybersecurity theme
│   └── js/dashboard.js             # Auto-refresh and interactions
│
│── waf/
│   ├── __init__.py                 # Package init
│   ├── rules.py                    # Attack signature definitions
│   ├── detector.py                 # Core inspection & detection engine
│   ├── rate_limiter.py             # IP-based rate limiting
│   └── logger.py                   # Database & file logging
│
│── sample_tests/
│   └── test_payloads.md            # Sample attack payloads for demo
```

---

## Setup & Installation

### Requirements
- Python 3.8 or higher
- pip

### Steps

**1. Clone or download the project**
```bash
git clone <repo-url>
cd SentinelShield
```

**2. (Optional) Create a virtual environment**
```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# Linux / macOS:
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

That's it! Flask is the only dependency.

---

## How to Run

```bash
python app.py
```

Then open your browser and navigate to:

```
http://127.0.0.1:5000
```

The database and log file are created automatically on first run.

---

## How to Use

### Dashboard (`/`)
- View total/blocked/allowed request counts
- See attack type breakdown (doughnut chart)
- See severity distribution (bar chart)
- View flagged IPs and recent alerts
- Click **"Reset Logs"** for a fresh demo session

### Test Requests (`/test`)
- Choose HTTP method and path
- Enter a payload (or click a sample from the accordion)
- Click **"Analyze Request"** to see detection results
- Results show: status, severity, matched patterns, rate limit status

### Logs (`/logs`)
- View all requests with timestamps, IPs, and detection details
- Filter by status: All / Blocked / Allowed / Rate Limited

### Report (`/report`)
- Auto-generated report of the session
- Includes attack breakdown, flagged IPs, and security recommendations
- Click **"Print Report"** to export

---

## Attack Detection

SentinelShield detects these attack categories:

| Category | Severity | Example |
|----------|----------|---------|
| SQL Injection | CRITICAL | `' OR '1'='1` |
| Cross-Site Scripting (XSS) | HIGH | `<script>alert(1)</script>` |
| Local File Inclusion (LFI) | CRITICAL | `../../../../etc/passwd` |
| Directory Traversal | HIGH | `../../../windows/system32` |
| Command Injection | CRITICAL | `; cat /etc/passwd` |
| Path Manipulation | MEDIUM | Null bytes, wildcard paths |

Each attack category has multiple regex patterns that catch both standard and obfuscated variants (URL encoding, double encoding, case variations).

---

## System Workflow

```
Incoming Request
       │
       ▼
 Rate Limit Check ──── BANNED ──────► Block + Log
       │
     OK/SUSPICIOUS
       │
       ▼
 Request Parsing
 (URL + Params + Headers + Body)
       │
       ▼
 Rule Engine (Regex Matching)
       │
    ┌──┴──┐
  MATCH  NO MATCH
    │         │
    ▼         ▼
 BLOCKED   ALLOWED
    │         │
    └────┬────┘
         │
         ▼
   Log to SQLite
   Write to alerts.log
   Update Dashboard
```

---

## Screenshots

> Replace these placeholders with actual screenshots after running the project.

| Page | Screenshot |
|------|-----------|
| Dashboard | _(add screenshot here)_ |
| Blocked Request | _(add screenshot here)_ |
| Allowed Request | _(add screenshot here)_ |
| Logs View | _(add screenshot here)_ |
| Security Report | _(add screenshot here)_ |

---

## Viva / Demo Explanation

### Q: What is a WAF?
**A:** A Web Application Firewall (WAF) inspects HTTP requests coming into a web server and blocks those that appear malicious, based on predefined rules or signatures.

### Q: How does SentinelShield detect SQL Injection?
**A:** It uses regular expressions (regex) to match known SQL syntax patterns in any part of the request — URL, parameters, headers, and body. For example, the pattern `OR '1'='1` is a classic SQL bypass that the rules engine catches.

### Q: What is rate limiting and why is it important?
**A:** Rate limiting counts how many requests an IP address sends in a time window. If they exceed the threshold, they're flagged or banned. This prevents brute-force attacks, credential stuffing, and DDoS flooding.

### Q: Why use both SQLite and a flat log file?
**A:** SQLite allows structured queries for the dashboard (counts by category, filter by IP). The flat file is simpler to read, grep, and ship to external monitoring tools (SIEM systems).

### Q: What's the difference between detection and prevention?
**A:** Detection (IDS) identifies and alerts on attacks. Prevention (IPS/WAF) also blocks them. SentinelShield does both — it detects malicious patterns AND blocks the request from proceeding.

### Q: How would you improve this in production?
**A:** Use Redis for distributed rate limiting, add machine learning for anomaly detection, integrate with SIEM tools, add CAPTCHA for suspicious IPs, and use a proper reverse proxy (Nginx/Apache) in front.

---

*SentinelShield — Practical Cybersecurity Project*