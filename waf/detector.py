# =============================================================================
# waf/detector.py - Core Request Inspection & Detection Engine
# =============================================================================
# This module is the brain of SentinelShield. It takes an incoming HTTP request
# and inspects every part of it (URL, query params, headers, body) against all
# known attack signatures defined in rules.py.
#
# Detection Flow:
#   1. Extract all parts of the request
#   2. Normalize / decode the content (URL decode, lowercase)
#   3. Match each part against every attack rule's patterns
#   4. If any pattern matches → mark as MALICIOUS + record which rule fired
#   5. Return a structured detection result
# =============================================================================

import re
import urllib.parse
from .rules import get_all_rules


def normalize_input(value: str) -> str:
    """
    Normalize input to catch encoded or obfuscated attack payloads.
    
    Attackers often encode their payloads (URL encoding, double encoding, 
    HTML entities) to bypass simple string matching. Normalization helps
    detect these evasion attempts.
    """
    if not value:
        return ""
    
    # Convert to string if not already
    value = str(value)
    
    # Step 1: URL decode (catches %3Cscript%3E → <script>)
    try:
        decoded = urllib.parse.unquote(value)
    except Exception:
        decoded = value
    
    # Step 2: Double URL decode (catches %253Cscript → <script>)
    try:
        double_decoded = urllib.parse.unquote(decoded)
    except Exception:
        double_decoded = decoded
    
    # Step 3: Lowercase everything (catches SELECT, Select, sElEcT)
    normalized = double_decoded.lower()
    
    # Step 4: Remove excessive whitespace (some attacks use spaces to evade)
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    
    return normalized


def extract_request_parts(request_data: dict) -> dict:
    """
    Extract all inspectable parts from a request dictionary.
    
    A real HTTP request has many parts that could carry attack payloads:
    - URL path
    - Query string parameters
    - HTTP headers (User-Agent, Referer, Cookie, etc.)
    - POST body / form data
    
    Returns a dict mapping field names to their values for inspection.
    """
    parts = {}
    
    # URL path (e.g., /admin/../etc/passwd)
    if "path" in request_data:
        parts["URL Path"] = request_data["path"]
    
    # Query parameters (e.g., ?id=1 OR 1=1)
    if "query_string" in request_data:
        parts["Query String"] = request_data["query_string"]
    
    # Individual query parameter values
    if "params" in request_data and isinstance(request_data["params"], dict):
        for key, value in request_data["params"].items():
            parts[f"Param[{key}]"] = str(value)
    
    # HTTP Headers - attackers can inject via User-Agent, Referer, Cookie
    if "headers" in request_data and isinstance(request_data["headers"], dict):
        # Only inspect headers commonly used in attacks
        dangerous_headers = ["user-agent", "referer", "cookie", "x-forwarded-for", "host"]
        for header_name, header_value in request_data["headers"].items():
            if header_name.lower() in dangerous_headers:
                parts[f"Header[{header_name}]"] = str(header_value)
    
    # POST body (e.g., username=admin'--&password=anything)
    if "body" in request_data and request_data["body"]:
        parts["Request Body"] = str(request_data["body"])
    
    # Form data fields
    if "form_data" in request_data and isinstance(request_data["form_data"], dict):
        for key, value in request_data["form_data"].items():
            parts[f"Form[{key}]"] = str(value)
    
    return parts


def inspect_value(value: str, rules: list) -> list:
    """
    Inspect a single value against all attack rules.
    
    For each rule, check all its regex patterns against the normalized value.
    Returns a list of matches found (may be multiple attack types in one value).
    """
    matches = []
    normalized = normalize_input(value)
    
    for rule in rules:
        for pattern in rule["patterns"]:
            try:
                # re.IGNORECASE as extra protection, normalize already lowercased
                match = re.search(pattern, normalized, re.IGNORECASE)
                if match:
                    matches.append({
                        "rule_name": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "matched_pattern": pattern,
                        "matched_text": match.group(0)[:100],  # Limit to 100 chars
                    })
                    # One match per rule is enough (don't report same rule twice)
                    break
            except re.error:
                # Skip malformed regex patterns
                continue
    
    return matches


def analyze_request(request_data: dict) -> dict:
    """
    Main detection function. Analyzes a complete HTTP request for threats.
    
    Args:
        request_data: dict with keys: path, query_string, params, headers, body
        
    Returns:
        A result dict with:
          - is_malicious: True/False
          - detections: list of detection details
          - highest_severity: the worst severity found
          - categories: list of attack categories detected
          - summary: human-readable summary
    """
    rules = get_all_rules()
    all_detections = []
    
    # Extract all parts of the request for inspection
    request_parts = extract_request_parts(request_data)
    
    # Inspect each part of the request
    for field_name, field_value in request_parts.items():
        if not field_value:
            continue
        
        # Run detection on this field
        field_matches = inspect_value(field_value, rules)
        
        # Tag each match with which field it was found in
        for match in field_matches:
            match["field"] = field_name
            match["field_value"] = str(field_value)[:200]  # Limit stored value
            all_detections.append(match)
    
    # Deduplicate: if same category found in multiple fields, keep all
    # but don't report same exact pattern twice for same field
    seen = set()
    unique_detections = []
    for detection in all_detections:
        key = (detection["field"], detection["category"])
        if key not in seen:
            seen.add(key)
            unique_detections.append(detection)
    
    # Determine if request is malicious
    is_malicious = len(unique_detections) > 0
    
    # Get all categories detected
    categories = list(set(d["category"] for d in unique_detections))
    
    # Determine highest severity
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    highest_severity = "NONE"
    if unique_detections:
        highest_severity = max(
            unique_detections,
            key=lambda x: severity_order.get(x["severity"], 0)
        )["severity"]
    
    # Build a human-readable summary
    if is_malicious:
        attack_names = list(set(d["rule_name"] for d in unique_detections))
        summary = f"BLOCKED: Detected {', '.join(attack_names)} [{highest_severity}]"
    else:
        summary = "ALLOWED: No threats detected"
    
    return {
        "is_malicious": is_malicious,
        "detections": unique_detections,
        "highest_severity": highest_severity,
        "categories": categories,
        "summary": summary,
        "total_matches": len(unique_detections),
    }