# =============================================================================
# waf/rules.py - Attack Signature Rules Engine
# =============================================================================
# This module defines all the attack signatures (patterns) that SentinelShield
# uses to detect malicious requests. Each rule has:
#   - name: human-readable attack type
#   - pattern: regex pattern to match malicious content
#   - severity: LOW / MEDIUM / HIGH / CRITICAL
#   - description: explains what the attack does
# =============================================================================

import re

# Each rule is a dictionary defining an attack signature
ATTACK_RULES = [

    # -------------------------------------------------------------------------
    # SQL INJECTION RULES
    # SQL Injection occurs when attackers insert SQL commands into input fields
    # to manipulate or dump the database.
    # Example: ' OR '1'='1  |  UNION SELECT * FROM users
    # -------------------------------------------------------------------------
    {
        "name": "SQL Injection",
        "category": "sqli",
        "severity": "CRITICAL",
        "description": "Attempts to manipulate SQL queries to access or corrupt database data.",
        "patterns": [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b)",
            r"(--|;|\/\*|\*\/)",               # SQL comment markers
            r"('\s*(OR|AND)\s*'?\d)",          # OR/AND bypass: ' OR '1'='1
            r"(SLEEP\s*\(|BENCHMARK\s*\()",    # Time-based blind SQLi
            r"(INFORMATION_SCHEMA|sys\.tables|sysobjects)",  # Schema enumeration
            r"(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)",   # File read/write
            r"(\bOR\b\s+\d+\s*=\s*\d+)",       # OR 1=1 style
            r"(\bWAITFOR\b\s+DELAY)",           # MSSQL delay
            r"(xp_cmdshell|sp_executesql)",     # MSSQL stored procs
        ]
    },

    # -------------------------------------------------------------------------
    # CROSS-SITE SCRIPTING (XSS) RULES
    # XSS attacks inject malicious scripts into web pages viewed by other users.
    # Example: <script>alert('XSS')</script>  |  <img src=x onerror=alert(1)>
    # -------------------------------------------------------------------------
    {
        "name": "Cross-Site Scripting (XSS)",
        "category": "xss",
        "severity": "HIGH",
        "description": "Injects malicious scripts into web pages to steal sessions or redirect users.",
        "patterns": [
            r"(<\s*script[^>]*>)",                      # <script> tag
            r"(<\s*\/\s*script\s*>)",                   # </script> tag
            r"(javascript\s*:)",                         # javascript: protocol
            r"(on\w+\s*=\s*[\"']?\s*(alert|confirm|prompt|eval|document))", # Event handlers
            r"(<\s*(iframe|object|embed|applet|meta)[^>]*>)",  # Dangerous HTML tags
            r"(document\.(cookie|write|location))",      # DOM manipulation
            r"(eval\s*\(|setTimeout\s*\(|setInterval\s*\()",  # JS execution
            r"(alert\s*\(|confirm\s*\(|prompt\s*\()",   # Dialog boxes
            r"(\\u003c|\\u003e|%3Cscript|%3E)",         # Encoded < > characters
            r"(expression\s*\()",                        # CSS expression
        ]
    },

    # -------------------------------------------------------------------------
    # LOCAL FILE INCLUSION (LFI) RULES
    # LFI exploits allow attackers to read files from the server's filesystem.
    # Example: ?file=../../../../etc/passwd
    # -------------------------------------------------------------------------
    {
        "name": "Local File Inclusion (LFI)",
        "category": "lfi",
        "severity": "CRITICAL",
        "description": "Attempts to read sensitive local files on the server filesystem.",
        "patterns": [
            r"(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts)",   # Linux sensitive files
            r"(\/proc\/self\/environ|\/proc\/version)",       # Process info
            r"(C:\\\\Windows\\\\System32|C:\\\\boot\.ini)",  # Windows system files
            r"(\.\.\\/|\.\.\\/\.\.\\/)",                     # Path traversal patterns
            r"(php:\/\/filter|php:\/\/input)",                # PHP wrappers
            r"(data:\/\/text|expect:\/\/)",                   # Data URI / expect wrapper
            r"(\/var\/log\/|\/var\/www\/|\/home\/\w+\/\.)",  # Log/home file access
        ]
    },

    # -------------------------------------------------------------------------
    # DIRECTORY TRAVERSAL RULES
    # Attackers navigate outside the intended directory to access system files.
    # Example: ../../../../etc/passwd  |  ..%2F..%2F..%2Fetc%2Fpasswd
    # -------------------------------------------------------------------------
    {
        "name": "Directory Traversal",
        "category": "traversal",
        "severity": "HIGH",
        "description": "Navigates outside web root to access unauthorized files and directories.",
        "patterns": [
            r"(\.\./){2,}",                          # Multiple ../ patterns
            r"(\.\.\\/){2,}",                        # Multiple ..\\ patterns (Windows)
            r"(%2e%2e%2f|%2e%2e\/|\.\.%2f)",        # URL encoded traversal
            r"(%252e%252e|%c0%af|%c1%9c)",           # Double-encoded traversal
            r"(\.\.;\/|\.\.%3b\/)",                  # Semicolon bypass
            r"(\/\.\.\.|\\\.\.\.)",                  # Three-dot traversal
        ]
    },

    # -------------------------------------------------------------------------
    # COMMAND INJECTION RULES
    # Attackers inject OS commands to execute on the server.
    # Example: ; ls -la  |  && cat /etc/passwd  |  | whoami
    # -------------------------------------------------------------------------
    {
        "name": "Command Injection",
        "category": "cmdi",
        "severity": "CRITICAL",
        "description": "Injects OS-level commands to execute arbitrary code on the server.",
        "patterns": [
            r"(;\s*(ls|cat|pwd|whoami|id|uname|ifconfig|netstat))",   # Semicolon + command
            r"(\|\s*(ls|cat|pwd|whoami|id|uname|nc|curl|wget))",       # Pipe + command
            r"(&&\s*(ls|cat|rm|cp|mv|chmod|chown|python|perl|ruby))",  # AND + command
            r"(\$\(.*\)|`[^`]*`)",                                      # Command substitution
            r"(\/bin\/sh|\/bin\/bash|\/usr\/bin\/perl|\/usr\/bin\/python)", # Shell paths
            r"(curl\s+|wget\s+|nc\s+-|ncat\s+)",                       # Network tools
            r"(base64\s+(-d|--decode)|echo\s+.*\|\s*base64)",          # Base64 decode trick
            r"(ping\s+-c|nslookup\s+|dig\s+)",                         # Network enumeration
        ]
    },

    # -------------------------------------------------------------------------
    # PATH MANIPULATION RULES
    # Trying to access files using unusual encoding or path characters
    # -------------------------------------------------------------------------
    {
        "name": "Path Manipulation",
        "category": "path",
        "severity": "MEDIUM",
        "description": "Uses unusual encoding or characters to bypass path filters.",
        "patterns": [
            r"(%00|%0d%0a|%0a%0d)",          # Null byte or CRLF injection
            r"(\/\*|\/\?|\*\.php|\*\.asp)",  # Wildcard path access
            r"(\.(php|asp|aspx|jsp|cgi|sh|py|rb|pl)\s*$)", # Script file access
        ]
    },
]


def get_all_rules():
    """Return the complete list of attack rules."""
    return ATTACK_RULES


def get_rule_categories():
    """Return a unique list of all attack categories."""
    categories = set()
    for rule in ATTACK_RULES:
        categories.add(rule["category"])
    return list(categories)


def get_rules_by_category(category):
    """Return all rules matching a given category."""
    return [rule for rule in ATTACK_RULES if rule["category"] == category]