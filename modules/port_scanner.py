import nmap
import socket

SPEED_PROFILES = {
    "slow":    "-T2",
    "normal":  "-T3",
    "fast":    "-T4",
    "stealth": "-sS",
}

COMMON_PORTS = {
    21:    "FTP — check for anonymous login",
    22:    "SSH — remote shell",
    23:    "Telnet — unencrypted, legacy",
    25:    "SMTP — mail server",
    53:    "DNS",
    80:    "HTTP — web server",
    110:   "POP3 — email",
    135:   "RPC — Windows",
    139:   "NetBIOS — Windows file sharing",
    143:   "IMAP — email",
    443:   "HTTPS — encrypted web",
    445:   "SMB — Windows file sharing",
    1433:  "MSSQL — database",
    1521:  "Oracle DB",
    3306:  "MySQL — database",
    3389:  "RDP — Windows Remote Desktop",
    5432:  "PostgreSQL — database",
    5900:  "VNC — remote desktop",
    6379:  "Redis — often unauthenticated",
    8080:  "HTTP-alt — web app / proxy",
    8443:  "HTTPS-alt",
    27017: "MongoDB — often unauthenticated",
}

def run_port_scan(target: str, port_range: str = "1-1000", speed: str = "normal", scan_udp: bool = False) -> dict:
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"success": False, "error": f"Could not resolve: {target}", "target": target}

    timing = SPEED_PROFILES.get(speed, "-T3")
    nm = nmap.PortScanner()
    tcp_args = f"-sV --open {timing}"
    if speed == "stealth":
        tcp_args = "-sS -sV --open"

    try:
        nm.scan(hosts=target, ports=port_range, arguments=tcp_args)
    except nmap.PortScannerError as e:
        return {"success": False, "error": f"nmap error: {str(e)}", "target": target}
    except Exception as e:
        return {"success": False, "error": str(e), "target": target}

    host_key = target if target in nm.all_hosts() else resolved_ip
    if host_key not in nm.all_hosts():
        return {"success": False, "error": "Host appears down or unreachable", "target": target, "resolved_ip": resolved_ip}

    open_ports = []
    if "tcp" in nm[host_key]:
        for port, info in nm[host_key]["tcp"].items():
            if info["state"] == "open":
                svc = info.get("name", "unknown")
                product = info.get("product", "")
                version = info.get("version", "")
                svc_str = svc
                if product:
                    svc_str += f" ({product} {version})".strip()
                open_ports.append({
                    "port":     port,
                    "protocol": "tcp",
                    "state":    "open",
                    "service":  svc_str,
                    "note":     COMMON_PORTS.get(port, ""),
                })
    open_ports.sort(key=lambda x: x["port"])

    return {
        "success":     True,
        "target":      target,
        "resolved_ip": resolved_ip,
        "port_range":  port_range,
        "speed":       speed,
        "open_ports":  open_ports,
        "open_udp":    [],
        "total_open":  len(open_ports),
        "total_udp":   0,
        "udp_scanned": False,
        "udp_error":   None,
        "host_status": nm[host_key].state(),
    }
