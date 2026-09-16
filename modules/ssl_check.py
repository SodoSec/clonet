# ============================================================
# modules/ssl_check.py
# ============================================================
# Checks SSL/TLS configuration for a target domain.
#
# We check:
#   - Certificate validity (is it expired? self-signed?)
#   - Certificate issuer and subject
#   - Expiration date (flag if expiring soon)
#   - TLS versions supported (TLS 1.0/1.1 = finding)
#   - Basic cipher info
#   - Overall grade (A-F)
#
# WHY THIS MATTERS IN A PENTEST:
#   Expired certs = no one is maintaining this server
#   TLS 1.0/1.1   = vulnerable to POODLE, BEAST attacks
#   Self-signed    = no CA validation, MITM risk
#   Weak ciphers   = data interception possible
# ============================================================

import ssl
import socket
import datetime


def run_ssl_check(target: str, port: int = 443) -> dict:
    """
    Analyze SSL/TLS configuration for a target.

    Args:
        target: Domain name (e.g. "example.com")
        port:   Port to check (default 443)

    Returns:
        Dictionary with cert info, TLS versions, and grade
    """

    # Strip any protocol prefix
    target = target.replace("https://", "").replace("http://", "").split("/")[0]

    findings = []
    grade    = "A"

    # ── CERTIFICATE CHECK ────────────────────────────────────
    cert_info = _get_cert_info(target, port)

    if not cert_info["success"]:
        return {
            "success": False,
            "error":   cert_info["error"],
            "target":  target,
        }

    # Check expiry
    days_left = cert_info.get("days_until_expiry", 999)
    if days_left < 0:
        findings.append({
            "severity": "CRITICAL",
            "title":    "Certificate Expired",
            "detail":   f"Certificate expired {abs(days_left)} days ago",
        })
        grade = "F"
    elif days_left < 14:
        findings.append({
            "severity": "HIGH",
            "title":    "Certificate Expiring Soon",
            "detail":   f"Certificate expires in {days_left} days",
        })
        grade = _downgrade(grade, "C")
    elif days_left < 30:
        findings.append({
            "severity": "MEDIUM",
            "title":    "Certificate Expiring Soon",
            "detail":   f"Certificate expires in {days_left} days",
        })

    # Check if self-signed
    if cert_info.get("self_signed"):
        findings.append({
            "severity": "HIGH",
            "title":    "Self-Signed Certificate",
            "detail":   "Certificate not issued by a trusted CA — MITM risk",
        })
        grade = _downgrade(grade, "D")

    # ── TLS VERSION CHECK ────────────────────────────────────
    tls_results = _check_tls_versions(target, port)

    if tls_results.get("tls_1_0"):
        findings.append({
            "severity": "HIGH",
            "title":    "TLS 1.0 Supported",
            "detail":   "TLS 1.0 is deprecated and vulnerable to POODLE and BEAST attacks",
        })
        grade = _downgrade(grade, "C")

    if tls_results.get("tls_1_1"):
        findings.append({
            "severity": "MEDIUM",
            "title":    "TLS 1.1 Supported",
            "detail":   "TLS 1.1 is deprecated — should be disabled",
        })
        grade = _downgrade(grade, "B")

    if not tls_results.get("tls_1_2") and not tls_results.get("tls_1_3"):
        findings.append({
            "severity": "CRITICAL",
            "title":    "No Modern TLS Support",
            "detail":   "TLS 1.2 and 1.3 not detected — serious configuration issue",
        })
        grade = "F"

    if tls_results.get("tls_1_3"):
        findings.append({
            "severity": "GOOD",
            "title":    "TLS 1.3 Supported",
            "detail":   "Latest TLS version is enabled — good configuration",
        })

    # Final grade if no issues
    if not findings or all(f["severity"] == "GOOD" for f in findings):
        grade = "A"

    return {
        "success":      True,
        "target":       target,
        "port":         port,
        "grade":        grade,
        "cert":         cert_info,
        "tls_versions": tls_results,
        "findings":     findings,
    }


def _get_cert_info(target: str, port: int) -> dict:
    """Fetch and parse the SSL certificate."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

        # Parse expiry date
        expiry_str = cert.get("notAfter", "")
        expiry     = None
        days_left  = 999

        if expiry_str:
            expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days

        # Parse issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        subject_dict = dict(x[0] for x in cert.get("subject", []))

        issuer_org = issuer_dict.get("organizationName", "Unknown")
        common_name = subject_dict.get("commonName", target)

        # Self-signed = issuer and subject are the same
        self_signed = issuer_dict == subject_dict

        # SANs (Subject Alternative Names)
        sans = []
        for san_type, san_val in cert.get("subjectAltName", []):
            if san_type == "DNS":
                sans.append(san_val)

        return {
            "success":           True,
            "common_name":       common_name,
            "issuer":            issuer_org,
            "issuer_full":       issuer_dict,
            "valid_from":        cert.get("notBefore", "N/A"),
            "valid_until":       expiry.strftime("%Y-%m-%d") if expiry else "N/A",
            "days_until_expiry": days_left,
            "self_signed":       self_signed,
            "sans":              sans[:10],  # Limit to 10 for display
            "cipher_suite":      cipher[0] if cipher else "Unknown",
            "tls_version":       cipher[1] if cipher else "Unknown",
        }

    except ssl.SSLCertVerificationError as e:
        # Still get what info we can even if cert is invalid
        return {
            "success":     True,
            "common_name": target,
            "issuer":      "Unverified",
            "self_signed": True,
            "error_note":  str(e),
            "days_until_expiry": -1,
            "valid_until": "Invalid",
            "sans":        [],
        }
    except ConnectionRefusedError:
        return {"success": False, "error": f"Port {port} is closed or not running SSL"}
    except socket.timeout:
        return {"success": False, "error": "Connection timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _check_tls_versions(target: str, port: int) -> dict:
    """Check which TLS versions the server supports."""
    results = {
        "tls_1_0": False,
        "tls_1_1": False,
        "tls_1_2": False,
        "tls_1_3": False,
    }

    version_map = {
        "tls_1_0": ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None,
        "tls_1_1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
        "tls_1_2": ssl.TLSVersion.TLSv1_2,
        "tls_1_3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
    }

    for version_key, tls_version in version_map.items():
        if tls_version is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version

            with socket.create_connection((target, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=target):
                    results[version_key] = True
        except Exception:
            pass

    return results


def _downgrade(current: str, new: str) -> str:
    """Return the worse of two grades."""
    order = ["A", "B", "C", "D", "F"]
    ci = order.index(current) if current in order else 0
    ni = order.index(new) if new in order else 0
    return order[max(ci, ni)]
