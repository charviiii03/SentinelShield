# =============================================================================
# waf/__init__.py - WAF Package Initializer
# =============================================================================
# Makes the waf/ directory a Python package, allowing imports like:
#   from waf.detector import analyze_request
#   from waf.rate_limiter import check_rate_limit
# =============================================================================

from .detector import analyze_request
from .rate_limiter import check_rate_limit, get_all_flagged_ips
from .logger import init_database, log_request, get_recent_logs, get_dashboard_stats

__all__ = [
    "analyze_request",
    "check_rate_limit",
    "get_all_flagged_ips",
    "init_database",
    "log_request",
    "get_recent_logs",
    "get_dashboard_stats",
]