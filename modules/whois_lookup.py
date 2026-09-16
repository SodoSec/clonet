import whois
import datetime

def run_whois(target: str) -> dict:
    try:
        w = whois.whois(target)
    except Exception as e:
        return {"success": False, "error": f"WHOIS lookup failed: {str(e)}", "target": target}

    if not w:
        return {"success": False, "error": "No WHOIS data returned.", "target": target}

    def fmt_date(val):
        if val is None: return "N/A"
        if isinstance(val, list): val = val[0]
        if isinstance(val, datetime.datetime): return val.strftime("%Y-%m-%d")
        return str(val)

    def fmt_field(val):
        if val is None: return "N/A"
        if isinstance(val, list): return ", ".join(str(v) for v in val if v)
        return str(val)

    ns = w.name_servers
    if not ns: nameservers = []
    elif isinstance(ns, str): nameservers = [ns.lower()]
    else: nameservers = sorted(set(n.lower() for n in ns if n))

    return {
        "success":     True,
        "target":      target,
        "domain_name": fmt_field(w.domain_name),
        "registrar":   fmt_field(w.registrar),
        "created":     fmt_date(w.creation_date),
        "expires":     fmt_date(w.expiration_date),
        "updated":     fmt_date(w.updated_date),
        "status":      fmt_field(w.status),
        "nameservers": nameservers,
        "emails":      fmt_field(w.emails),
        "org":         fmt_field(getattr(w, "org", None)),
        "country":     fmt_field(getattr(w, "country", None)),
    }
