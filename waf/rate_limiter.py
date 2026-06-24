# =============================================================================
# waf/rate_limiter.py - IP-Based Rate Limiting & Brute-Force Detection
# =============================================================================
# Rate limiting prevents attackers from flooding the server with repeated
# requests (brute-force, credential stuffing, DoS attacks).
#
# How it works:
#   - Track how many requests each IP has sent within a TIME_WINDOW (seconds)
#   - If requests exceed MAX_REQUESTS → flag as RATE_LIMITED
#   - After a ban expires, the IP gets a fresh window
#   - Persistent offenders can be permanently flagged
#
# This is an in-memory implementation using Python dicts.
# In production, you'd use Redis for distributed rate limiting.
# =============================================================================

import time
from collections import defaultdict

# -----------------------------------------------------------------------------
# Configuration Constants
# -----------------------------------------------------------------------------
TIME_WINDOW = 60          # Time window in seconds (1 minute)
MAX_REQUESTS = 30         # Max requests allowed per IP per TIME_WINDOW
BAN_DURATION = 300        # How long (seconds) an IP stays banned (5 minutes)
SUSPICIOUS_THRESHOLD = 20 # Requests above this but below MAX = suspicious

# -----------------------------------------------------------------------------
# In-Memory Storage
# (In production, replace with Redis or a database-backed solution)
# -----------------------------------------------------------------------------

# Tracks request timestamps per IP: { "ip_address": [timestamp1, timestamp2, ...] }
_request_log = defaultdict(list)

# Tracks banned IPs: { "ip_address": ban_expiry_timestamp }
_banned_ips = {}

# Tracks flagged IPs (suspicious but not yet banned)
_flagged_ips = set()

# Total request count per IP (cumulative, not windowed)
_total_requests = defaultdict(int)


def _clean_old_requests(ip: str, current_time: float):
    """
    Remove timestamps outside the current time window for an IP.
    This keeps memory usage from growing indefinitely.
    """
    window_start = current_time - TIME_WINDOW
    _request_log[ip] = [
        t for t in _request_log[ip]
        if t > window_start
    ]


def is_banned(ip: str) -> bool:
    """
    Check if an IP is currently banned.
    If the ban has expired, automatically unban the IP.
    """
    if ip not in _banned_ips:
        return False
    
    # Check if ban has expired
    if time.time() > _banned_ips[ip]:
        # Ban expired — clean up
        del _banned_ips[ip]
        _flagged_ips.discard(ip)
        return False
    
    return True


def check_rate_limit(ip: str) -> dict:
    """
    Check if an IP has exceeded the rate limit.
    
    Call this for every incoming request BEFORE processing it.
    
    Returns a dict with:
      - allowed: True if request should proceed
      - status: "OK" / "SUSPICIOUS" / "RATE_LIMITED" / "BANNED"
      - request_count: how many requests this IP has made in the window
      - message: human-readable explanation
    """
    current_time = time.time()
    
    # --- Check if already banned ---
    if is_banned(ip):
        ban_remaining = int(_banned_ips[ip] - current_time)
        return {
            "allowed": False,
            "status": "BANNED",
            "request_count": _total_requests[ip],
            "message": f"IP is banned. Ban expires in {ban_remaining} seconds.",
            "ban_remaining": ban_remaining,
        }
    
    # --- Record this request ---
    _request_log[ip].append(current_time)
    _total_requests[ip] += 1
    
    # --- Clean old requests outside the time window ---
    _clean_old_requests(ip, current_time)
    
    # --- Count requests in current window ---
    window_count = len(_request_log[ip])
    
    # --- Check against thresholds ---
    if window_count > MAX_REQUESTS:
        # BAN this IP
        _banned_ips[ip] = current_time + BAN_DURATION
        _flagged_ips.add(ip)
        return {
            "allowed": False,
            "status": "RATE_LIMITED",
            "request_count": window_count,
            "message": f"Rate limit exceeded: {window_count} requests in {TIME_WINDOW}s. IP banned for {BAN_DURATION}s.",
            "ban_remaining": BAN_DURATION,
        }
    
    elif window_count > SUSPICIOUS_THRESHOLD:
        # Flag as suspicious but still allow
        _flagged_ips.add(ip)
        return {
            "allowed": True,
            "status": "SUSPICIOUS",
            "request_count": window_count,
            "message": f"Suspicious activity: {window_count} requests in {TIME_WINDOW}s (limit: {MAX_REQUESTS}).",
            "ban_remaining": 0,
        }
    
    else:
        # Normal traffic
        return {
            "allowed": True,
            "status": "OK",
            "request_count": window_count,
            "message": f"Request allowed. {window_count}/{MAX_REQUESTS} requests in current window.",
            "ban_remaining": 0,
        }


def get_ip_stats(ip: str) -> dict:
    """
    Get rate-limiting statistics for a specific IP.
    Useful for dashboard and logging.
    """
    current_time = time.time()
    _clean_old_requests(ip, current_time)
    
    return {
        "ip": ip,
        "requests_in_window": len(_request_log.get(ip, [])),
        "total_requests": _total_requests.get(ip, 0),
        "is_banned": is_banned(ip),
        "is_flagged": ip in _flagged_ips,
        "ban_expiry": _banned_ips.get(ip, None),
    }


def get_all_flagged_ips() -> list:
    """
    Return a list of all currently flagged or banned IPs.
    Used by the dashboard to show threat actors.
    """
    flagged = []
    current_time = time.time()
    
    for ip in list(_flagged_ips):
        stats = get_ip_stats(ip)
        flagged.append(stats)
    
    return flagged


def reset_ip(ip: str):
    """
    Manually reset/unban an IP address. (Admin function)
    """
    _request_log[ip] = []
    _banned_ips.pop(ip, None)
    _flagged_ips.discard(ip)
    _total_requests[ip] = 0


def get_rate_limit_config() -> dict:
    """Return current rate limiting configuration."""
    return {
        "time_window": TIME_WINDOW,
        "max_requests": MAX_REQUESTS,
        "ban_duration": BAN_DURATION,
        "suspicious_threshold": SUSPICIOUS_THRESHOLD,
    }