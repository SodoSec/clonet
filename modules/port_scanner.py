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

def run_port_scan(target: str, port_range: str = "1-1000", speed: str = "normal") -> dict:
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"success": False, "error": f"Could not resolve host: {target}", "target": target}

    timing_flag = SPEED_PROFILES.get(speed, "-T3")
    nmap_args = f"-sV --open {timing_flag}"
    if speed == "stealth":
        nmap_args = "-sS -sV --open"

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, ports=port_range, arguments=nmap_args)
    except nmap.PortScannerError as e:
        return {"success": False, "error": f"nmap error: {str(e)}. Is nmap installed?", "target": target}
    except Exception as e:
        return {"success": False, "error": str(e), "target": target}

    host_key = target if target in nm.all_hosts() else resolved_ip
    if host_key not in nm.all_hosts():
        return {"success": False, "error": "Host appears down or unreachable", "target": target, "resolved_ip": resolved_ip}

    open_ports = []
    if "tcp" in nm[host_key]:
        for port, info in nm[host_key]["tcp"].items():
            if info["state"] == "open":
                service_name = info.get("name", "unknown")
                product = info.get("product", "")
                version = info.get("version", "")
                service_string = service_name
                if product:
                    service_string += f" ({product} {version})".strip()
                open_ports.append({
                    "port":    port,
                    "state":   "open",
                    "service": service_string,
                    "note":    COMMON_PORTS.get(port, ""),
                })

    open_ports.sort(key=lambda x: x["port"])
    return {
        "success":     True,
        "target":      target,
        "resolved_ip": resolved_ip,
        "port_range":  port_range,
        "speed":       speed,
        "open_ports":  open_ports,
        "total_open":  len(open_ports),
        "host_status": nm[host_key].state(),
    }
