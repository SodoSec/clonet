# ============================================================
# modules/autoscan.py
# ============================================================
# Orchestrates a full recon scan against a single target.
# Runs all modules in the right order and collects results.
#
# ORDER:
#   1. WHOIS         → who owns it
#   2. DNS           → what records exist
#   3. SSL           → cert and TLS status
#   4. Headers       → HTTP security posture
#   5. Tech Stack    → what software is running
#   6. Subdomains    → what other hosts exist
#   7. Port Scan     → what services are exposed
#
# Each module result is yielded back to the Flask route
# using Server-Sent Events (SSE) so the UI can update
# in real time as each module finishes — you see results
# populate one by one without waiting for everything.
# ============================================================

import json
import datetime
from modules.whois_lookup import run_whois
from modules.dns_enum     import run_dns_enum
from modules.ssl_check    import run_ssl_check
from modules.headers      import run_header_check
from modules.techstack    import run_techstack
from modules.subdomain    import run_subdomain_scan
from modules.port_scanner import run_port_scan


def run_autoscan(target: str, port_range: str = "1-1000") -> dict:
    """
    Run all recon modules against a target and return combined results.

    Args:
        target:     Domain or IP to scan
        port_range: Port range for the port scanner

    Returns:
        Dictionary with results from every module
    """

    results  = {}
    errors   = {}
    ts_start = datetime.datetime.now()

    # Clean target for use across modules
    clean = target.replace("https://","").replace("http://","").split("/")[0]

    # ── 1. WHOIS ─────────────────────────────────────────────
    try:
        results["whois"] = run_whois(clean)
    except Exception as e:
        errors["whois"] = str(e)

    # ── 2. DNS ───────────────────────────────────────────────
    try:
        results["dns"] = run_dns_enum(clean)
    except Exception as e:
        errors["dns"] = str(e)

    # ── 3. SSL ───────────────────────────────────────────────
    try:
        results["ssl"] = run_ssl_check(clean)
    except Exception as e:
        errors["ssl"] = str(e)

    # ── 4. HEADERS ───────────────────────────────────────────
    try:
        results["headers"] = run_header_check(f"https://{clean}")
        # Fallback to HTTP if HTTPS fails
        if not results["headers"].get("success"):
            results["headers"] = run_header_check(f"http://{clean}")
    except Exception as e:
        errors["headers"] = str(e)

    # ── 5. TECH STACK ────────────────────────────────────────
    try:
        results["techstack"] = run_techstack(clean)
    except Exception as e:
        errors["techstack"] = str(e)

    # ── 6. SUBDOMAINS ────────────────────────────────────────
    try:
        results["subdomains"] = run_subdomain_scan(clean, wordlist="default")
    except Exception as e:
        errors["subdomains"] = str(e)

    # ── 7. PORT SCAN ─────────────────────────────────────────
    try:
        results["ports"] = run_port_scan(clean, port_range=port_range, speed="normal")
    except Exception as e:
        errors["ports"] = str(e)

    # ── SUMMARY ──────────────────────────────────────────────
    duration = (datetime.datetime.now() - ts_start).seconds
    summary  = _build_summary(results)

    return {
        "success":   True,
        "target":    target,
        "timestamp": ts_start.strftime("%Y-%m-%d %H:%M:%S"),
        "duration":  duration,
        "results":   results,
        "errors":    errors,
        "summary":   summary,
    }


def _build_summary(results: dict) -> dict:
    """Build a top-level summary of all findings."""

    all_findings = []
    risk_score   = 0

    # Collect findings from each module
    # DNS findings
    dns = results.get("dns", {})
    for f in dns.get("findings", []):
        all_findings.append({"module": "DNS", **f})
        if f.get("type") == "high":   risk_score += 20
        if f.get("type") == "medium": risk_score += 10

    # SSL findings
    ssl = results.get("ssl", {})
    for f in ssl.get("findings", []):
        sev = f.get("severity", "INFO")
        all_findings.append({"module": "SSL", "type": sev.lower(), **f})
        if sev == "CRITICAL": risk_score += 30
        if sev == "HIGH":     risk_score += 20
        if sev == "MEDIUM":   risk_score += 10

    # Header findings (missing headers)
    headers = results.get("headers", {})
    for h in headers.get("missing_headers", []):
        sev = h.get("severity", "INFO")
        all_findings.append({
            "module":  "Headers",
            "type":    sev.lower(),
            "title":   f"Missing: {h['name']}",
            "detail":  h.get("desc", ""),
            "severity": sev,
        })
        if sev == "HIGH":   risk_score += 15
        if sev == "MEDIUM": risk_score += 8

    # Port findings (risky open ports)
    ports = results.get("ports", {})
    risky_ports = {21,23,445,3389,5900,6379,27017,1433,3306,5432}
    for p in ports.get("open_ports", []):
        if p["port"] in risky_ports:
            all_findings.append({
                "module":   "Ports",
                "type":     "medium",
                "title":    f"Risky Port Open: {p['port']} ({p['service']})",
                "detail":   p.get("note", ""),
                "severity": "MEDIUM",
            })
            risk_score += 10

    # Cap risk score at 100
    risk_score = min(risk_score, 100)

    # Risk label
    if risk_score >= 70:   risk_label = "HIGH"
    elif risk_score >= 40: risk_label = "MEDIUM"
    elif risk_score >= 10: risk_label = "LOW"
    else:                  risk_label = "MINIMAL"

    return {
        "risk_score":      risk_score,
        "risk_label":      risk_label,
        "total_findings":  len(all_findings),
        "findings":        all_findings,
        "open_ports":      ports.get("total_open", 0),
        "subdomains_found": results.get("subdomains", {}).get("total_found", 0),
        "tech_detected":   results.get("techstack", {}).get("total_found", 0),
        "ssl_grade":       ssl.get("grade", "N/A"),
        "header_grade":    headers.get("security_score", {}).get("grade", "N/A"),
    }
