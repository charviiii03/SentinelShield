# =============================================================================
# waf/logger.py - Request Logging, Alert Generation & Database Management
# =============================================================================
# This module handles:
#   1. Writing every request (allowed + blocked) to the SQLite database
#   2. Writing alerts for malicious requests to a log file
#   3. Querying logs for dashboard display
#   4. Generating summary statistics
#
# Why dual logging (DB + file)?
#   - SQLite: structured queries, dashboard data, filtering by category/IP
#   - File log: flat text, easy to grep, monitor, or ship to SIEM systems
# =============================================================================

import sqlite3
import json
import os
import logging
from datetime import datetime

# -----------------------------------------------------------------------------
# Path Configuration
# -----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "sentinelshield.db")
LOG_PATH = os.path.join(BASE_DIR, "logs", "alerts.log")

# Set up Python's file logger for the alerts.log file
file_logger = logging.getLogger("sentinelshield")
file_logger.setLevel(logging.INFO)

# Ensure logs directory exists before adding handler
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
_handler = logging.FileHandler(LOG_PATH)
_handler.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
))
file_logger.addHandler(_handler)


def init_database():
    """
    Initialize the SQLite database and create tables if they don't exist.
    Call this once when the application starts.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Main request log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            ip_address  TEXT NOT NULL,
            method      TEXT NOT NULL,
            path        TEXT,
            query       TEXT,
            status      TEXT NOT NULL,           -- ALLOWED / BLOCKED / RATE_LIMITED / BANNED
            is_malicious INTEGER DEFAULT 0,      -- 0 = safe, 1 = malicious
            attack_categories TEXT,              -- JSON list of detected categories
            severity    TEXT DEFAULT 'NONE',     -- NONE / LOW / MEDIUM / HIGH / CRITICAL
            summary     TEXT,                    -- Human-readable detection summary
            detections  TEXT,                    -- Full JSON of detection details
            rate_status TEXT DEFAULT 'OK'        -- OK / SUSPICIOUS / RATE_LIMITED / BANNED
        )
    """)
    
    # Alert table for quick dashboard queries
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            ip_address  TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity    TEXT NOT NULL,
            description TEXT,
            path        TEXT,
            log_id      INTEGER,
            FOREIGN KEY (log_id) REFERENCES request_logs(id)
        )
    """)
    
    conn.commit()
    conn.close()


def log_request(ip: str, method: str, path: str, query: str,
                detection_result: dict, rate_result: dict) -> int:
    """
    Log a processed request to the database and file system.
    
    Args:
        ip: Client IP address
        method: HTTP method (GET, POST, etc.)
        path: Request path (/search, /login, etc.)
        query: Query string (?id=1&name=test)
        detection_result: Result from detector.analyze_request()
        rate_result: Result from rate_limiter.check_rate_limit()
    
    Returns:
        The database row ID of the inserted log entry.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Determine overall request status
    if not rate_result["allowed"]:
        status = rate_result["status"]  # RATE_LIMITED or BANNED
    elif detection_result["is_malicious"]:
        status = "BLOCKED"
    else:
        status = "ALLOWED"
    
    # Serialize detection data to JSON for storage
    categories_json = json.dumps(detection_result.get("categories", []))
    detections_json = json.dumps(detection_result.get("detections", []))
    
    # Write to SQLite database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO request_logs
            (timestamp, ip_address, method, path, query, status,
             is_malicious, attack_categories, severity, summary, detections, rate_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp, ip, method, path, query, status,
        1 if detection_result["is_malicious"] else 0,
        categories_json,
        detection_result.get("highest_severity", "NONE"),
        detection_result.get("summary", ""),
        detections_json,
        rate_result.get("status", "OK")
    ))
    
    log_id = cursor.lastrowid
    
    # If malicious, also insert individual alerts for each attack category
    if detection_result["is_malicious"]:
        for detection in detection_result.get("detections", []):
            cursor.execute("""
                INSERT INTO alerts (timestamp, ip_address, attack_type, severity, description, path, log_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, ip,
                detection["rule_name"],
                detection["severity"],
                detection.get("description", ""),
                path, log_id
            ))
    
    conn.commit()
    conn.close()
    
    # Write to flat file log
    if detection_result["is_malicious"] or not rate_result["allowed"]:
        log_level = logging.WARNING if detection_result.get("highest_severity") in ("HIGH", "CRITICAL") else logging.INFO
        file_logger.log(
            log_level,
            f"[{status}] IP={ip} Method={method} Path={path} | "
            f"Severity={detection_result.get('highest_severity', 'NONE')} | "
            f"Categories={detection_result.get('categories', [])} | "
            f"{detection_result.get('summary', '')}"
        )
    
    return log_id


def get_recent_logs(limit: int = 50, filter_status: str = None) -> list:
    """
    Retrieve recent request logs for dashboard display.
    
    Args:
        limit: Maximum number of rows to return
        filter_status: Optional filter (ALLOWED, BLOCKED, RATE_LIMITED, BANNED)
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Return dict-like rows
    cursor = conn.cursor()
    
    if filter_status:
        cursor.execute("""
            SELECT * FROM request_logs
            WHERE status = ?
            ORDER BY id DESC LIMIT ?
        """, (filter_status, limit))
    else:
        cursor.execute("""
            SELECT * FROM request_logs
            ORDER BY id DESC LIMIT ?
        """, (limit,))
    
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    # Parse JSON fields back to Python objects
    for row in rows:
        try:
            row["attack_categories"] = json.loads(row["attack_categories"] or "[]")
            row["detections"] = json.loads(row["detections"] or "[]")
        except (json.JSONDecodeError, TypeError):
            row["attack_categories"] = []
            row["detections"] = []
    
    return rows


def get_dashboard_stats() -> dict:
    """
    Generate summary statistics for the dashboard.
    Returns counts, category breakdowns, and flagged IPs.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Total request count
    cursor.execute("SELECT COUNT(*) FROM request_logs")
    total_requests = cursor.fetchone()[0]
    
    # Blocked request count
    cursor.execute("SELECT COUNT(*) FROM request_logs WHERE is_malicious = 1")
    blocked_requests = cursor.fetchone()[0]
    
    # Allowed request count
    cursor.execute("SELECT COUNT(*) FROM request_logs WHERE status = 'ALLOWED'")
    allowed_requests = cursor.fetchone()[0]
    
    # Rate limited count
    cursor.execute("SELECT COUNT(*) FROM request_logs WHERE status IN ('RATE_LIMITED', 'BANNED')")
    rate_limited_requests = cursor.fetchone()[0]
    
    # Attack type breakdown from alerts table
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM alerts
        GROUP BY attack_type
        ORDER BY count DESC
    """)
    attack_breakdown = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Top flagged IPs
    cursor.execute("""
        SELECT ip_address, COUNT(*) as attack_count,
               GROUP_CONCAT(DISTINCT attack_type) as attack_types
        FROM alerts
        GROUP BY ip_address
        ORDER BY attack_count DESC
        LIMIT 10
    """)
    flagged_ips = []
    for row in cursor.fetchall():
        flagged_ips.append({
            "ip": row[0],
            "attack_count": row[1],
            "attack_types": row[2].split(",") if row[2] else [],
        })
    
    # Severity breakdown
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM request_logs
        WHERE is_malicious = 1
        GROUP BY severity
    """)
    severity_breakdown = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Recent alerts (last 10)
    cursor.execute("""
        SELECT * FROM alerts ORDER BY id DESC LIMIT 10
    """)
    cols = [description[0] for description in cursor.description]
    recent_alerts = [dict(zip(cols, row)) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "allowed_requests": allowed_requests,
        "rate_limited_requests": rate_limited_requests,
        "attack_breakdown": attack_breakdown,
        "flagged_ips": flagged_ips,
        "severity_breakdown": severity_breakdown,
        "recent_alerts": recent_alerts,
        "block_rate": round((blocked_requests / total_requests * 100), 1) if total_requests > 0 else 0,
    }


def clear_all_logs():
    """Clear all logs from the database. Used for testing/reset."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM request_logs")
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()