# ============================================================
# modules/dns_enum.py
# ============================================================
# Automatically pulls ALL common public DNS record types for
# a given domain. Public DNS records are openly available to
# anyone — this is the same info dig/nslookup returns.
#
# RECORD TYPES WE PULL:
#   A      → IPv4 address (where the domain points)
#   AAAA   → IPv6 address
#   MX     → Mail servers (priority + hostname)
#   NS     → Nameservers (who controls DNS for this domain)
#   TXT    → Text records (SPF, DKIM, DMARC, verification tokens)
#   CNAME  → Alias records (this domain points to another)
#   SOA    → Start of Authority (zone admin info)
#   CAA    → Certificate Authority Authorization (who can issue SSL certs)
#   SRV    → Service records (used by VoIP, XMPP, etc.)
#   PTR    → Reverse DNS (IP → hostname, for IPs only)
#
# WHY THESE MATTER IN A PENTEST:
#   MX  → Reveals email provider (Google? Microsoft? Self-hosted?)
#   TXT → SPF/DKIM tells you email security posture
#         Sometimes contains internal hostnames or service tokens
#   NS  → Who controls DNS — needed for zone transfer attempts
#   CAA → Which CAs can issue certs — useful for cert transparency recon
#   SOA → Admin email and zone serial number
# ============================================================

import dns.resolver
import dns.reversename
import dns.exception
import socket


# All record types we attempt to query automatically
AUTO_RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
    "SOA",
    "CAA",
    "SRV",
]

# TXT record keywords worth flagging during recon
# These often reveal services in use or security config
INTERESTING_TXT_KEYWORDS = [
    "v=spf",        # SPF email policy
    "v=dkim",       # DKIM email signing
    "v=dmarc",      # DMARC email policy
    "google-site",  # Google Search Console verification
    "ms=",          # Microsoft/O365 verification
    "amazonses",    # Amazon SES email
    "mailgun",      # Mailgun email service
    "sendgrid",     # SendGrid email service
    "docusign",     # DocuSign
    "atlassian",    # Atlassian/Jira/Confluence
    "stripe",       # Stripe payments
    "zoom",         # Zoom verification
    "include:",     # SPF include directives (reveals email services)
]


def run_dns_enum(target: str) -> dict:
    """
    Automatically enumerate all public DNS records for a domain.

    Args:
        target: Domain name (e.g. "example.com")
                OR an IP address for reverse DNS lookup

    Returns:
        Dictionary with all found records grouped by type,
        plus a summary of notable findings
    """

    # If target looks like an IP, do reverse DNS instead
    if _is_ip(target):
        return _reverse_dns(target)

    records  = {}   # { "A": [...], "MX": [...], etc. }
    errors   = {}   # { "SRV": "No records", etc. }
    findings = []   # Notable items to highlight

    # Query every record type automatically
    for record_type in AUTO_RECORD_TYPES:
        try:
            # dns.resolver.resolve() is the same as running:
            #   dig example.com MX
            answers = dns.resolver.resolve(target, record_type, lifetime=6)
            formatted = _format_records(record_type, answers)
            if formatted:
                records[record_type] = formatted

        except dns.resolver.NoAnswer:
            # Domain exists but no records of this type — totally normal
            pass
        except dns.resolver.NXDOMAIN:
            # Domain flat out doesn't exist
            return {
                "success": False,
                "error":   f"Domain does not exist: {target}",
                "target":  target,
            }
        except dns.resolver.NoNameservers:
            errors[record_type] = "No nameservers responded"
        except dns.exception.Timeout:
            errors[record_type] = "Query timed out"
        except Exception as e:
            # Don't let one failed record type kill the whole scan
            errors[record_type] = str(e)

    # Also try to get the resolved IP even if A record query failed
    resolved_ip = _resolve_ip(target)

    # Build findings — things worth calling out specifically
    findings = _analyze_findings(records, target)

    # Count total records found
    total = sum(len(v) for v in records.values())

    return {
        "success":     True,
        "target":      target,
        "resolved_ip": resolved_ip,
        "records":     records,
        "errors":      errors,
        "findings":    findings,
        "total_records": total,
        "record_types_found": list(records.keys()),
    }


def _format_records(record_type: str, answers) -> list:
    """
    Format raw DNS answer objects into clean dicts/strings.
    Each record type has a different structure.
    """
    formatted = []

    for rdata in answers:

        if record_type == "A" or record_type == "AAAA":
            # Simple IP address string
            formatted.append(str(rdata))

        elif record_type == "MX":
            # Mail exchange: has a priority number and a hostname
            # Lower priority number = higher preference
            formatted.append({
                "priority": int(rdata.preference),
                "host":     str(rdata.exchange).rstrip("."),
            })

        elif record_type == "NS":
            # Nameserver hostname
            formatted.append(str(rdata.target).rstrip("."))

        elif record_type == "CNAME":
            # Canonical name (alias target)
            formatted.append(str(rdata.target).rstrip("."))

        elif record_type == "TXT":
            # TXT records are stored as byte strings — decode them
            txt = " ".join(
                s.decode("utf-8", errors="replace")
                for s in rdata.strings
            )
            formatted.append(txt)

        elif record_type == "SOA":
            # Start of Authority — zone control info
            formatted.append({
                "primary_ns": str(rdata.mname).rstrip("."),
                "admin_email": str(rdata.rname).rstrip(".").replace(".", "@", 1),
                "serial":     int(rdata.serial),
                "refresh":    int(rdata.refresh),
                "retry":      int(rdata.retry),
                "expire":     int(rdata.expire),
                "minimum":    int(rdata.minimum),
            })

        elif record_type == "CAA":
            # Certificate Authority Authorization
            # tag is usually "issue", "issuewild", or "iodef"
            formatted.append({
                "flag": rdata.flags,
                "tag":  rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag),
                "value": rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value),
            })

        elif record_type == "SRV":
            # Service record — used for things like SIP, XMPP
            formatted.append({
                "priority": int(rdata.priority),
                "weight":   int(rdata.weight),
                "port":     int(rdata.port),
                "target":   str(rdata.target).rstrip("."),
            })

        else:
            formatted.append(str(rdata))

    # Sort MX records by priority so highest priority shows first
    if record_type == "MX":
        formatted.sort(key=lambda x: x["priority"])

    return formatted


def _analyze_findings(records: dict, target: str) -> list:
    """
    Analyze the DNS records and flag notable recon findings.
    These show up highlighted in the UI.
    """
    findings = []

    # Check MX records — reveal email provider
    if "MX" in records:
        mx_hosts = [r["host"].lower() for r in records["MX"]]
        if any("google" in h or "gmail" in h for h in mx_hosts):
            findings.append({
                "type":    "info",
                "title":   "Email: Google Workspace",
                "detail":  "Target uses Google Workspace for email",
            })
        elif any("outlook" in h or "microsoft" in h or "protection.outlook" in h for h in mx_hosts):
            findings.append({
                "type":    "info",
                "title":   "Email: Microsoft 365",
                "detail":  "Target uses Microsoft 365 / Exchange Online for email",
            })
        elif any("amazonses" in h or "amazonaws" in h for h in mx_hosts):
            findings.append({
                "type":    "info",
                "title":   "Email: Amazon SES",
                "detail":  "Target uses Amazon SES for email",
            })

    # Check TXT records for SPF / DMARC
    if "TXT" in records:
        has_spf   = False
        has_dmarc = False

        for txt in records["TXT"]:
            txt_lower = txt.lower()

            if "v=spf1" in txt_lower:
                has_spf = True
                # Check for permissive SPF
                if "+all" in txt_lower:
                    findings.append({
                        "type":   "high",
                        "title":  "SPF: Permissive (+all)",
                        "detail": f"SPF record uses +all — allows ANY server to send as this domain: {txt}",
                    })
                elif "~all" in txt_lower:
                    findings.append({
                        "type":   "medium",
                        "title":  "SPF: Soft Fail (~all)",
                        "detail": "SPF uses ~all (soft fail) — unauthorized senders aren't hard rejected",
                    })
                elif "-all" in txt_lower:
                    findings.append({
                        "type":   "good",
                        "title":  "SPF: Strict (-all)",
                        "detail": "SPF is properly configured with hard fail",
                    })

            if "v=dmarc1" in txt_lower:
                has_dmarc = True
                if "p=none" in txt_lower:
                    findings.append({
                        "type":   "medium",
                        "title":  "DMARC: Policy = None",
                        "detail": "DMARC is present but policy is 'none' — emails aren't rejected, just monitored",
                    })
                elif "p=quarantine" in txt_lower:
                    findings.append({
                        "type":   "info",
                        "title":  "DMARC: Policy = Quarantine",
                        "detail": "DMARC quarantines unauthorized emails",
                    })
                elif "p=reject" in txt_lower:
                    findings.append({
                        "type":   "good",
                        "title":  "DMARC: Policy = Reject",
                        "detail": "DMARC is fully enforced — unauthorized emails are rejected",
                    })

        if not has_spf:
            findings.append({
                "type":   "high",
                "title":  "No SPF Record",
                "detail": "Domain has no SPF record — spoofing emails from this domain may be possible",
            })

        if not has_dmarc:
            findings.append({
                "type":   "high",
                "title":  "No DMARC Record",
                "detail": "No DMARC policy found — email spoofing is not monitored or enforced",
            })

    # Check NS records — many nameservers might indicate large infra
    if "NS" in records:
        ns_list = records["NS"]
        if len(ns_list) < 2:
            findings.append({
                "type":   "medium",
                "title":  "Single Nameserver",
                "detail": "Only one NS record found — no DNS redundancy",
            })

    return findings


def _is_ip(target: str) -> bool:
    """Check if the target string looks like an IP address."""
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


def _resolve_ip(target: str) -> str:
    """Try to resolve the domain to an IP address."""
    try:
        return socket.gethostbyname(target)
    except Exception:
        return "Unresolved"


def _reverse_dns(ip: str) -> dict:
    """
    Perform a reverse DNS lookup on an IP address.
    Reverse DNS maps an IP back to a hostname.
    Useful for finding what domain is hosted on an IP.
    """
    try:
        rev_name = dns.reversename.from_address(ip)
        answers  = dns.resolver.resolve(rev_name, "PTR", lifetime=6)
        hostnames = [str(r).rstrip(".") for r in answers]

        return {
            "success":   True,
            "target":    ip,
            "type":      "reverse",
            "hostnames": hostnames,
            "records":   {"PTR": hostnames},
            "findings":  [],
            "total_records": len(hostnames),
            "record_types_found": ["PTR"],
        }

    except Exception as e:
        return {
            "success": False,
            "error":   f"Reverse DNS failed: {str(e)}",
            "target":  ip,
        }
