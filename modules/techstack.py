# ============================================================
# modules/techstack.py
# ============================================================
# Tech stack fingerprinting figures out what software a web
# target is running — server, framework, CMS, CDN, etc.
#
# We detect technologies by looking at:
#   - HTTP response headers (Server, X-Powered-By, etc.)
#   - HTML content (meta tags, script paths, CSS paths)
#   - Cookie names (WordPress sets 'wordpress_logged_in', etc.)
#   - URL patterns in page source
#
# WHY THIS MATTERS IN A PENTEST:
#   Once you know the stack you can look up CVEs.
#   "WordPress 5.8" → searchsploit, exploit-db, wpscan
#   "Apache 2.4.49" → CVE-2021-41773 (path traversal)
#   "PHP 7.2"       → look for known PHP deserialization issues
# ============================================================

import requests
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Signature database — each entry has:
#   "name"     → technology name to display
#   "category" → grouping (Server, CMS, Framework, etc.)
#   "implies"  → other tech this implies (e.g. WordPress implies PHP)
#
# Detection methods checked:
#   headers  → look in HTTP response headers
#   html     → look in page HTML source
#   cookies  → look at cookie names/values
#   url      → look at URLs in page source

SIGNATURES = [

    # ── WEB SERVERS ─────────────────────────────────────────
    {"name": "Apache",       "category": "Web Server",
     "headers": [("Server", r"Apache")]},

    {"name": "Nginx",        "category": "Web Server",
     "headers": [("Server", r"nginx")]},

    {"name": "IIS",          "category": "Web Server",
     "headers": [("Server", r"Microsoft-IIS")]},

    {"name": "LiteSpeed",    "category": "Web Server",
     "headers": [("Server", r"LiteSpeed")]},

    {"name": "Cloudflare",   "category": "CDN / Proxy",
     "headers": [("Server", r"cloudflare"), ("CF-RAY", r".+")]},

    {"name": "AWS CloudFront","category": "CDN / Proxy",
     "headers": [("Via", r"CloudFront"), ("X-Cache", r"CloudFront")]},

    {"name": "Fastly",       "category": "CDN / Proxy",
     "headers": [("X-Served-By", r"cache"), ("Fastly-Debug-Digest", r".+")]},

    # ── BACKEND LANGUAGES ────────────────────────────────────
    {"name": "PHP",          "category": "Language",
     "headers": [("X-Powered-By", r"PHP")]},

    {"name": "ASP.NET",      "category": "Language",
     "headers": [("X-Powered-By", r"ASP\.NET"), ("X-AspNet-Version", r".+")]},

    {"name": "Node.js",      "category": "Language",
     "headers": [("X-Powered-By", r"Express")]},

    {"name": "Python",       "category": "Language",
     "headers": [("X-Powered-By", r"Python")]},

    # ── CMS ──────────────────────────────────────────────────
    {"name": "WordPress",    "category": "CMS",
     "html":    [r"wp-content", r"wp-includes"],
     "cookies": [r"wordpress", r"wp-settings"],
     "headers": [("Link", r"wp-json")]},

    {"name": "Drupal",       "category": "CMS",
     "html":    [r"drupal\.js", r"Drupal\.settings", r"/sites/default/files"],
     "headers": [("X-Generator", r"Drupal"), ("X-Drupal-Cache", r".+")]},

    {"name": "Joomla",       "category": "CMS",
     "html":    [r"/media/jui/", r"joomla"]},

    {"name": "Shopify",      "category": "E-Commerce",
     "html":    [r"cdn\.shopify\.com", r"Shopify\.theme"],
     "headers": [("X-ShopId", r".+")]},

    {"name": "Magento",      "category": "E-Commerce",
     "html":    [r"mage/", r"Mage\.Cookies", r"skin/frontend"]},

    {"name": "WooCommerce",  "category": "E-Commerce",
     "html":    [r"woocommerce"],
     "cookies": [r"woocommerce"]},

    # ── JAVASCRIPT FRAMEWORKS ────────────────────────────────
    {"name": "React",        "category": "JS Framework",
     "html":    [r"react\.development\.js", r"react\.min\.js",
                 r"__REACT", r"data-reactroot", r"data-reactid"]},

    {"name": "Vue.js",       "category": "JS Framework",
     "html":    [r"vue\.min\.js", r"vue\.js", r"__vue__"]},

    {"name": "Angular",      "category": "JS Framework",
     "html":    [r"angular\.min\.js", r"ng-version", r"angular\.js"]},

    {"name": "jQuery",       "category": "JS Library",
     "html":    [r"jquery\.min\.js", r"jquery-\d", r"jQuery v\d"]},

    {"name": "Bootstrap",    "category": "CSS Framework",
     "html":    [r"bootstrap\.min\.css", r"bootstrap\.css",
                 r"bootstrap\.min\.js"]},

    # ── WEB FRAMEWORKS ───────────────────────────────────────
    {"name": "Laravel",      "category": "Framework",
     "cookies": [r"laravel_session"],
     "html":    [r"laravel"]},

    {"name": "Django",       "category": "Framework",
     "cookies": [r"csrftoken", r"django"],
     "html":    [r"csrfmiddlewaretoken"]},

    {"name": "Ruby on Rails","category": "Framework",
     "headers": [("X-Powered-By", r"Phusion Passenger")],
     "cookies": [r"_rails_session"]},

    {"name": "Spring",       "category": "Framework",
     "headers": [("X-Application-Context", r".+")]},

    {"name": "Next.js",      "category": "Framework",
     "headers": [("X-Powered-By", r"Next\.js")],
     "html":    [r"__NEXT_DATA__", r"_next/static"]},

    {"name": "Nuxt.js",      "category": "Framework",
     "html":    [r"__NUXT__", r"_nuxt/"]},

    # ── ANALYTICS / MARKETING ────────────────────────────────
    {"name": "Google Analytics", "category": "Analytics",
     "html":    [r"google-analytics\.com", r"gtag\(", r"UA-\d+-\d+",
                 r"G-[A-Z0-9]+"]},

    {"name": "Google Tag Manager","category": "Analytics",
     "html":    [r"googletagmanager\.com", r"GTM-[A-Z0-9]+"]},

    {"name": "HotJar",       "category": "Analytics",
     "html":    [r"hotjar\.com"]},

    {"name": "Cloudflare Analytics","category": "Analytics",
     "html":    [r"static\.cloudflareinsights\.com"]},

    # ── HOSTING / INFRASTRUCTURE ─────────────────────────────
    {"name": "AWS",          "category": "Cloud",
     "headers": [("Server", r"AmazonS3"), ("x-amz-request-id", r".+")]},

    {"name": "Heroku",       "category": "Cloud",
     "headers": [("Via", r"heroku")]},

    {"name": "Vercel",       "category": "Cloud",
     "headers": [("x-vercel-id", r".+"), ("X-Vercel-Cache", r".+")]},

    {"name": "Netlify",      "category": "Cloud",
     "headers": [("X-Netlify-Cache", r".+"), ("server", r"Netlify")]},
]


def run_techstack(target: str) -> dict:
    """
    Fingerprint the tech stack of a web target.

    Args:
        target: URL or domain (e.g. "example.com" or "https://example.com")

    Returns:
        Dictionary with detected technologies grouped by category
    """

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    try:
        response = requests.get(
            target,
            verify=False,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; CLONET/1.0)"}
        )
    except requests.exceptions.ConnectionError:
        # Try HTTP if HTTPS failed
        try:
            target = target.replace("https://", "http://")
            response = requests.get(target, verify=False, timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; CLONET/1.0)"})
        except Exception as e:
            return {"success": False, "error": str(e), "target": target}
    except Exception as e:
        return {"success": False, "error": str(e), "target": target}

    headers     = {k.lower(): v for k, v in response.headers.items()}
    html        = response.text.lower()
    cookie_str  = " ".join(c.name.lower() for c in response.cookies)

    detected = []

    for sig in SIGNATURES:
        matched = False

        # Check headers
        for header_name, pattern in sig.get("headers", []):
            val = headers.get(header_name.lower(), "")
            if re.search(pattern, val, re.IGNORECASE):
                matched = True
                break

        # Check HTML source
        if not matched:
            for pattern in sig.get("html", []):
                if re.search(pattern, html, re.IGNORECASE):
                    matched = True
                    break

        # Check cookies
        if not matched:
            for pattern in sig.get("cookies", []):
                if re.search(pattern, cookie_str, re.IGNORECASE):
                    matched = True
                    break

        if matched:
            # Try to extract version number from headers
            version = _extract_version(sig["name"], headers, html)
            detected.append({
                "name":     sig["name"],
                "category": sig["category"],
                "version":  version,
                "cve_hint": _cve_hint(sig["name"], version),
            })

    # Group by category for cleaner display
    grouped = {}
    for item in detected:
        cat = item["category"]
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append(item)

    return {
        "success":       True,
        "target":        target,
        "final_url":     response.url,
        "status_code":   response.status_code,
        "detected":      detected,
        "grouped":       grouped,
        "total_found":   len(detected),
        "categories":    list(grouped.keys()),
    }


def _extract_version(tech_name: str, headers: dict, html: str) -> str:
    """Try to pull a version number for the detected technology."""

    patterns = {
        "WordPress":  [r"wordpress[\s/]+([\d.]+)", r"wp-includes.*?ver=([\d.]+)"],
        "PHP":        [r"PHP/([\d.]+)"],
        "Apache":     [r"Apache/([\d.]+)"],
        "Nginx":      [r"nginx/([\d.]+)"],
        "IIS":        [r"Microsoft-IIS/([\d.]+)"],
        "ASP.NET":    [r"ASP\.NET Version:([\d.]+)", r"X-AspNet-Version: ([\d.]+)"],
        "jQuery":     [r"jQuery v([\d.]+)", r"jquery-([\d.]+)\.min\.js"],
        "Bootstrap":  [r"Bootstrap v([\d.]+)", r"bootstrap-([\d.]+)"],
        "Next.js":    [r"Next\.js ([\d.]+)"],
        "Drupal":     [r"Drupal ([\d.]+)"],
    }

    if tech_name not in patterns:
        return None

    # Search in headers (as a combined string) and HTML
    search_targets = [" ".join(f"{k}: {v}" for k, v in headers.items()), html]

    for pattern in patterns[tech_name]:
        for text in search_targets:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

    return None


def _cve_hint(tech_name: str, version: str) -> str:
    """Return a search hint for finding CVEs for this technology."""
    if not version:
        return f"Search: '{tech_name} CVE site:nvd.nist.gov'"
    return f"Search: '{tech_name} {version} CVE' on NVD or Exploit-DB"
