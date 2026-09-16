import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"desc": "HSTS — forces HTTPS", "missing": "HIGH"},
    "Content-Security-Policy":   {"desc": "CSP — prevents XSS",  "missing": "HIGH"},
    "X-Frame-Options":           {"desc": "Prevents clickjacking","missing": "MEDIUM"},
    "X-Content-Type-Options":    {"desc": "Prevents MIME sniffing","missing": "LOW"},
    "Referrer-Policy":           {"desc": "Controls referrer leakage","missing": "LOW"},
    "Permissions-Policy":        {"desc": "Restricts browser features","missing": "INFO"},
}

DISCLOSURE_HEADERS = ["Server","X-Powered-By","X-AspNet-Version","X-AspNetMvc-Version","X-Generator"]

def run_header_check(target: str) -> dict:
    if not target.startswith(("http://","https://")):
        target = "https://" + target
    try:
        response = requests.get(target, verify=False, timeout=10, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; CLONET/1.0)"})
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": f"Could not connect to {target}", "target": target}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Connection timed out", "target": target}
    except Exception as e:
        return {"success": False, "error": str(e), "target": target}

    headers = dict(response.headers)
    missing, present = [], []

    for name, meta in SECURITY_HEADERS.items():
        if name in headers:
            present.append({"name": name, "value": headers[name], "desc": meta["desc"]})
        else:
            missing.append({"name": name, "severity": meta["missing"], "desc": meta["desc"]})

    disclosure = [{"header": h, "value": headers[h]} for h in DISCLOSURE_HEADERS if h in headers]

    cookies = []
    for cookie in response.cookies:
        issues = []
        if not cookie.secure: issues.append("Missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"): issues.append("Missing HttpOnly flag")
        cookies.append({"name": cookie.name, "issues": issues, "secure": cookie.secure})

    total = len(SECURITY_HEADERS)
    passed = total - len(missing)
    pct = int((passed / total) * 100)
    grade = "A" if pct==100 else "B" if pct>=80 else "C" if pct>=60 else "D" if pct>=40 else "F"

    return {
        "success":         True,
        "target":          target,
        "final_url":       response.url,
        "status_code":     response.status_code,
        "all_headers":     headers,
        "missing_headers": missing,
        "present_headers": present,
        "tech_disclosure": disclosure,
        "cookie_analysis": cookies,
        "security_score":  {"grade": grade, "percent": pct, "passed": passed, "total_checked": total},
        "https":           response.url.startswith("https://"),
    }
