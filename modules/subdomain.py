# ============================================================
# modules/subdomain.py
# ============================================================
# Subdomain enumeration tries common subdomains against a
# domain to find ones that actually exist.
#
# Example: if target is "example.com" we try:
#   mail.example.com, dev.example.com, api.example.com ...
# and check which ones resolve to an IP address.
#
# WHY THIS MATTERS IN A PENTEST:
#   The main domain (example.com) might be locked down,
#   but dev.example.com or admin.example.com might not be.
#   Subdomains often expose:
#     - Dev/staging environments (less hardened)
#     - Admin panels
#     - Old forgotten apps
#     - Internal tools accidentally exposed
#
# This uses DNS resolution to check — no direct connection
# to the target, just asking DNS servers if each subdomain exists.
# ============================================================

import socket
import concurrent.futures
import dns.resolver
import dns.exception


# Built-in wordlist — common subdomains seen in the wild
# This covers the most likely hits without needing an external file
DEFAULT_WORDLIST = [
    "www", "mail", "email", "webmail", "smtp", "pop", "imap",
    "ftp", "sftp", "ssh", "vpn", "remote", "rdp",
    "api", "api2", "v1", "v2", "graphql", "rest",
    "dev", "dev2", "development", "develop", "devel",
    "staging", "stage", "stg", "uat", "qa", "test", "testing",
    "sandbox", "demo", "preview", "beta", "alpha",
    "admin", "administrator", "manage", "management", "manager",
    "panel", "cpanel", "whm", "plesk", "portal", "dashboard",
    "app", "apps", "application", "web", "web2",
    "old", "new", "backup", "bak", "archive",
    "static", "assets", "media", "cdn", "img", "images", "files",
    "upload", "uploads", "download", "downloads",
    "db", "database", "mysql", "sql", "mongo", "redis",
    "git", "gitlab", "github", "svn", "repo",
    "ci", "jenkins", "build", "deploy", "docker",
    "jira", "confluence", "wiki", "docs", "help", "support",
    "blog", "shop", "store", "pay", "payment", "checkout",
    "auth", "login", "sso", "oauth", "id", "accounts",
    "internal", "intranet", "corp", "office", "extranet",
    "monitor", "monitoring", "nagios", "grafana", "kibana",
    "elasticsearch", "logstash", "splunk",
    "proxy", "gateway", "router", "fw", "firewall",
    "ns", "ns1", "ns2", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay", "mail2",
    "server", "server1", "server2", "host", "host1",
    "mobile", "m", "wap",
    "secure", "ssl", "tls",
    "status", "health", "ping", "up",
]

# How to interpret what we find
INTERESTING_SUBDOMAINS = [
    "admin", "administrator", "panel", "dashboard", "manage",
    "dev", "development", "staging", "test", "qa", "uat",
    "internal", "intranet", "corp", "vpn", "remote",
    "backup", "old", "archive",
    "jenkins", "gitlab", "jira", "confluence",
    "db", "database", "mysql", "redis", "mongo",
    "api", "graphql",
]


def run_subdomain_scan(target: str, wordlist: str = "default",
                        threads: int = 20) -> dict:
    """
    Brute-force subdomains of a target domain using DNS resolution.

    Args:
        target:   Base domain (e.g. "example.com") — strip www if present
        wordlist: "default" uses built-in list, or "large" for extended list
        threads:  How many subdomains to check simultaneously (default 20)

    Returns:
        Dictionary with found subdomains, their IPs, and notable findings
    """

    # Clean up the target — remove http/https/www if someone pastes a URL
    target = _clean_domain(target)

    # Pick wordlist
    words = DEFAULT_WORDLIST
    if wordlist == "large":
        words = DEFAULT_WORDLIST + _extended_wordlist()

    found      = []   # Subdomains that resolved
    not_found  = 0    # Count of misses (don't store them all)
    errors     = 0

    # Check subdomains in parallel using a thread pool
    # ThreadPoolExecutor lets us check multiple subdomains at once
    # instead of one at a time (much faster)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:

        # Submit all checks at once
        # Each future = one subdomain check running in background
        future_to_sub = {
            executor.submit(_check_subdomain, word, target): word
            for word in words
        }

        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_sub):
            try:
                result = future.result(timeout=5)
                if result:
                    found.append(result)
                else:
                    not_found += 1
            except Exception:
                errors += 1

    # Sort results alphabetically by subdomain
    found.sort(key=lambda x: x["subdomain"])

    # Flag interesting ones
    for item in found:
        sub = item["subdomain"].split(".")[0].lower()
        item["interesting"] = sub in INTERESTING_SUBDOMAINS

    interesting_count = sum(1 for f in found if f["interesting"])

    return {
        "success":          True,
        "target":           target,
        "found":            found,
        "total_found":      len(found),
        "total_checked":    len(words),
        "interesting":      interesting_count,
        "wordlist":         wordlist,
    }


def _check_subdomain(word: str, domain: str) -> dict | None:
    """
    Check if a single subdomain exists by trying to resolve it.
    Returns a dict if it exists, None if it doesn't.
    """
    subdomain = f"{word}.{domain}"

    try:
        # socket.getaddrinfo returns all addresses for the hostname
        # If it raises an exception, the subdomain doesn't exist
        results = socket.getaddrinfo(subdomain, None, socket.AF_INET)
        ips = list(set(r[4][0] for r in results))

        # Also try to get a CNAME if present
        cname = _get_cname(subdomain)

        return {
            "subdomain": subdomain,
            "word":      word,
            "ips":       ips,
            "cname":     cname,
        }

    except socket.gaierror:
        # NXDOMAIN or similar — subdomain doesn't exist
        return None
    except Exception:
        return None


def _get_cname(subdomain: str) -> str | None:
    """Try to get a CNAME record for the subdomain."""
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=3)
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None


def _clean_domain(target: str) -> str:
    """Strip protocols and www from a domain string."""
    target = target.lower().strip()
    for prefix in ["https://", "http://"]:
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0]   # Remove any path
    target = target.split(":")[0]   # Remove any port
    if target.startswith("www."):
        target = target[4:]
    return target


def _extended_wordlist() -> list:
    """Additional subdomains for a more thorough scan."""
    return [
        "api3", "api4", "api-dev", "api-staging", "api-test",
        "app2", "app3", "app-dev", "app-staging",
        "backend", "frontend", "service", "services",
        "data", "analytics", "reporting", "reports",
        "crm", "erp", "hr", "finance", "accounting",
        "chat", "slack", "helpdesk", "ticket", "tickets",
        "forum", "community", "social",
        "map", "maps", "geo",
        "video", "stream", "streaming", "media2",
        "partner", "partners", "vendor", "vendors",
        "client", "clients", "customer", "customers",
        "extranet", "b2b", "b2c",
        "office365", "autodiscover", "lyncdiscover", "sip",
        "meet", "meeting", "conference", "webinar",
        "news", "press", "about", "careers", "jobs",
        "legal", "privacy", "terms",
        "open", "public", "external",
    ]
