# ============================================================
# modules/report.py
# ============================================================
# Generates a professional HTML report from autoscan results.
# The report can be opened in any browser, printed to PDF,
# or sent to a client / interviewer.
# ============================================================

import datetime


def generate_html_report(scan_data: dict) -> str:
    """
    Generate a full HTML report from autoscan results.

    Args:
        scan_data: The full autoscan result dictionary

    Returns:
        HTML string ready to be saved as a .html file
    """

    target    = scan_data.get("target", "Unknown")
    timestamp = scan_data.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    duration  = scan_data.get("duration", 0)
    results   = scan_data.get("results", {})
    summary   = scan_data.get("summary", {})

    risk_score = summary.get("risk_score", 0)
    risk_label = summary.get("risk_label", "UNKNOWN")
    risk_color = {"HIGH":"#ff4757","MEDIUM":"#ffa502","LOW":"#39ff6e","MINIMAL":"#00e5ff"}.get(risk_label,"#7a8fa8")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CLONET Report — {target}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0a0c0f; color:#e0eaf5; font-size:14px; line-height:1.6; }}
  .page {{ max-width:1000px; margin:0 auto; padding:40px 20px; }}
  
  /* Header */
  .report-header {{ background:#0f1318; border:1px solid #1e2d3d; border-radius:8px; padding:32px; margin-bottom:24px; }}
  .report-brand {{ font-size:28px; font-weight:700; letter-spacing:4px; color:#00e5ff; margin-bottom:4px; }}
  .report-sub {{ font-size:13px; color:#3d5068; letter-spacing:2px; text-transform:uppercase; margin-bottom:20px; }}
  .report-target {{ font-size:22px; color:#e0eaf5; font-family:monospace; margin-bottom:8px; }}
  .report-meta {{ font-size:12px; color:#7a8fa8; font-family:monospace; }}

  /* Risk score */
  .risk-block {{ display:flex; align-items:center; gap:24px; background:#141920; border-radius:6px; padding:20px 24px; margin-bottom:24px; border-left:4px solid {risk_color}; }}
  .risk-score {{ font-size:52px; font-weight:700; color:{risk_color}; font-family:monospace; min-width:80px; }}
  .risk-label {{ font-size:22px; font-weight:700; color:{risk_color}; }}
  .risk-detail {{ font-size:13px; color:#7a8fa8; margin-top:4px; }}

  /* Stats grid */
  .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:24px; }}
  .stat {{ background:#0f1318; border:1px solid #1e2d3d; border-radius:6px; padding:16px; text-align:center; }}
  .stat-val {{ font-size:28px; font-weight:700; font-family:monospace; color:#00e5ff; }}
  .stat-lbl {{ font-size:10px; text-transform:uppercase; letter-spacing:2px; color:#3d5068; margin-top:4px; }}

  /* Sections */
  .section {{ background:#0f1318; border:1px solid #1e2d3d; border-radius:8px; padding:24px; margin-bottom:16px; }}
  .section-title {{ font-size:11px; font-weight:700; letter-spacing:3px; text-transform:uppercase; color:#3d5068; border-bottom:1px solid #1e2d3d; padding-bottom:10px; margin-bottom:16px; }}

  /* Findings */
  .finding {{ padding:12px 16px; border-radius:4px; margin-bottom:8px; border-left:3px solid; }}
  .finding-critical {{ background:#ff475710; border-color:#ff4757; }}
  .finding-high     {{ background:#ff475710; border-color:#ff475780; }}
  .finding-medium   {{ background:#ffa50210; border-color:#ffa502; }}
  .finding-low      {{ background:#ffa50210; border-color:#ffa50250; }}
  .finding-good     {{ background:#39ff6e10; border-color:#39ff6e; }}
  .finding-info     {{ background:#00e5ff08; border-color:#00e5ff30; }}
  .finding-title    {{ font-weight:600; margin-bottom:2px; }}
  .finding-detail   {{ font-size:12px; color:#7a8fa8; }}
  .badge {{ display:inline-block; padding:1px 7px; border-radius:3px; font-size:10px; font-weight:700; letter-spacing:1px; text-transform:uppercase; margin-right:8px; }}
  .badge-critical {{ background:#ff475720; color:#ff4757; }}
  .badge-high     {{ background:#ff475720; color:#ff4757; }}
  .badge-medium   {{ background:#ffa50220; color:#ffa502; }}
  .badge-low      {{ background:#ffa50220; color:#ffa502; }}
  .badge-good     {{ background:#39ff6e20; color:#39ff6e; }}
  .badge-info     {{ background:#00e5ff10; color:#00e5ff; }}

  /* Tables */
  table {{ width:100%; border-collapse:collapse; font-family:monospace; font-size:13px; margin-top:8px; }}
  th {{ text-align:left; padding:8px 12px; font-size:10px; letter-spacing:2px; text-transform:uppercase; color:#3d5068; border-bottom:1px solid #1e2d3d; font-family:'Segoe UI',Arial,sans-serif; }}
  td {{ padding:10px 12px; border-bottom:1px solid #1e2d3d; vertical-align:top; }}
  tr:hover td {{ background:#141920; }}
  
  /* Field rows */
  .field {{ display:grid; grid-template-columns:160px 1fr; gap:8px; padding:8px 0; border-bottom:1px solid #1e2d3d; }}
  .field-key {{ color:#3d5068; font-size:11px; text-transform:uppercase; letter-spacing:1px; padding-top:2px; }}
  .field-val {{ font-family:monospace; word-break:break-all; }}

  /* Grade badges */
  .grade {{ display:inline-block; font-size:32px; font-weight:700; font-family:monospace; width:52px; height:52px; line-height:52px; text-align:center; border-radius:6px; }}
  .grade-A {{ background:#39ff6e20; color:#39ff6e; }}
  .grade-B {{ background:#39ff6e20; color:#7dff8f; }}
  .grade-C {{ background:#ffa50220; color:#ffa502; }}
  .grade-D {{ background:#ff8c0020; color:#ff8c00; }}
  .grade-F {{ background:#ff475720; color:#ff4757; }}

  /* Footer */
  .report-footer {{ text-align:center; font-size:11px; color:#3d5068; margin-top:32px; padding-top:16px; border-top:1px solid #1e2d3d; font-family:monospace; }}

  /* DNS record pills */
  .pill {{ display:inline-block; background:#141920; border:1px solid #1e2d3d; border-radius:3px; padding:4px 10px; font-family:monospace; font-size:12px; margin:3px; }}
  .pill-accent {{ border-color:#00e5ff30; color:#00e5ff; }}
  .pill-amber  {{ border-color:#ffa50230; color:#ffa502; }}
  .pill-green  {{ border-color:#39ff6e30; color:#39ff6e; }}
</style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div class="report-header">
    <div class="report-brand">⬡ CLONET</div>
    <div class="report-sub">Network Recon Report — Confidential</div>
    <div class="report-target">{target}</div>
    <div class="report-meta">Generated: {timestamp} &nbsp;|&nbsp; Duration: {duration}s &nbsp;|&nbsp; CLONET v1.0 by CLONE</div>
  </div>

  <!-- RISK SCORE -->
  <div class="risk-block">
    <div class="risk-score">{risk_score}</div>
    <div>
      <div class="risk-label">Risk: {risk_label}</div>
      <div class="risk-detail">{summary.get('total_findings', 0)} findings across all modules</div>
      <div class="risk-detail" style="margin-top:4px">
        Open Ports: {summary.get('open_ports',0)} &nbsp;|&nbsp;
        Subdomains: {summary.get('subdomains_found',0)} &nbsp;|&nbsp;
        Technologies: {summary.get('tech_detected',0)} &nbsp;|&nbsp;
        SSL Grade: {summary.get('ssl_grade','N/A')} &nbsp;|&nbsp;
        Header Grade: {summary.get('header_grade','N/A')}
      </div>
    </div>
  </div>

  <!-- STATS -->
  <div class="stats-grid">
    <div class="stat"><div class="stat-val">{summary.get('open_ports',0)}</div><div class="stat-lbl">Open Ports</div></div>
    <div class="stat"><div class="stat-val">{summary.get('subdomains_found',0)}</div><div class="stat-lbl">Subdomains</div></div>
    <div class="stat"><div class="stat-val">{summary.get('tech_detected',0)}</div><div class="stat-lbl">Technologies</div></div>
    <div class="stat"><div class="stat-val">{summary.get('total_findings',0)}</div><div class="stat-lbl">Findings</div></div>
    <div class="stat"><div class="stat-val">{summary.get('ssl_grade','?')}</div><div class="stat-lbl">SSL Grade</div></div>
    <div class="stat"><div class="stat-val">{summary.get('header_grade','?')}</div><div class="stat-lbl">Header Grade</div></div>
  </div>

  <!-- ALL FINDINGS -->
  {_render_findings_section(summary.get('findings', []))}

  <!-- WHOIS -->
  {_render_whois(results.get('whois', {}))}

  <!-- DNS -->
  {_render_dns(results.get('dns', {}))}

  <!-- SSL -->
  {_render_ssl(results.get('ssl', {}))}

  <!-- HEADERS -->
  {_render_headers(results.get('headers', {}))}

  <!-- TECH STACK -->
  {_render_techstack(results.get('techstack', {}))}

  <!-- SUBDOMAINS -->
  {_render_subdomains(results.get('subdomains', {}))}

  <!-- PORTS -->
  {_render_ports(results.get('ports', {}))}

  <div class="report-footer">
    CLONET Network Recon Dashboard — by CLONE &nbsp;|&nbsp;
    For authorized security testing only &nbsp;|&nbsp;
    Generated {timestamp}
  </div>

</div>
</body>
</html>"""

    return html


# ── SECTION RENDERERS ────────────────────────────────────────

def _render_findings_section(findings: list) -> str:
    if not findings:
        return ""
    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4,"good":5}
    sorted_f = sorted(findings, key=lambda x: sev_order.get(x.get("type","info").lower(), 4))
    html = '<div class="section"><div class="section-title">All Findings</div>'
    for f in sorted_f:
        t = f.get("type","info").lower()
        html += f"""<div class="finding finding-{t}">
          <span class="badge badge-{t}">{f.get('severity', t.upper())}</span>
          <span class="badge" style="background:#1e2d3d;color:#7a8fa8">{f.get('module','')}</span>
          <span class="finding-title">{f.get('title','')}</span>
          <div class="finding-detail">{f.get('detail','')}</div>
        </div>"""
    return html + "</div>"


def _render_whois(data: dict) -> str:
    if not data.get("success"): return ""
    fields = [
        ("Registrar", data.get("registrar")),
        ("Created",   data.get("created")),
        ("Expires",   data.get("expires")),
        ("Org",       data.get("org")),
        ("Country",   data.get("country")),
        ("Emails",    data.get("emails")),
    ]
    html = '<div class="section"><div class="section-title">WHOIS Registration</div>'
    for k, v in fields:
        if v and v != "N/A":
            html += f'<div class="field"><div class="field-key">{k}</div><div class="field-val">{v}</div></div>'
    if data.get("nameservers"):
        html += f'<div class="field"><div class="field-key">Nameservers</div><div class="field-val">{", ".join(data["nameservers"])}</div></div>'
    return html + "</div>"


def _render_dns(data: dict) -> str:
    if not data.get("success"): return ""
    records = data.get("records", {})
    html = '<div class="section"><div class="section-title">DNS Records</div>'
    for rtype, recs in records.items():
        if not recs: continue
        html += f'<div style="margin-bottom:12px"><strong style="color:#7a8fa8;font-size:11px;letter-spacing:2px">{rtype}</strong><div style="margin-top:6px">'
        for r in recs:
            if isinstance(r, dict):
                val = r.get("host") or r.get("primary_ns") or str(r)
                prefix = f"[{r.get('priority','')}] " if "priority" in r else ""
                html += f'<span class="pill pill-accent">{prefix}{val}</span>'
            else:
                html += f'<span class="pill">{r}</span>'
        html += "</div></div>"
    return html + "</div>"


def _render_ssl(data: dict) -> str:
    if not data.get("success"): return ""
    cert = data.get("cert", {})
    grade = data.get("grade", "?")
    tls = data.get("tls_versions", {})
    html = f'<div class="section"><div class="section-title">SSL / TLS Analysis</div>'
    html += f'<div style="display:flex;align-items:center;gap:20px;margin-bottom:16px">'
    html += f'<div class="grade grade-{grade}">{grade}</div>'
    html += f'<div><div style="font-size:16px;font-weight:600">{cert.get("common_name","")}</div>'
    html += f'<div style="font-size:12px;color:#7a8fa8">Issuer: {cert.get("issuer","Unknown")} &nbsp;|&nbsp; Expires: {cert.get("valid_until","?")} ({cert.get("days_until_expiry","?")} days)</div>'
    html += f'<div style="font-size:12px;color:#7a8fa8;margin-top:4px">TLS 1.0: {"✓" if tls.get("tls_1_0") else "✗"} &nbsp; TLS 1.1: {"✓" if tls.get("tls_1_1") else "✗"} &nbsp; TLS 1.2: {"✓" if tls.get("tls_1_2") else "✗"} &nbsp; TLS 1.3: {"✓" if tls.get("tls_1_3") else "✗"}</div>'
    html += '</div></div>'
    for f in data.get("findings", []):
        t = f.get("severity","INFO").lower()
        html += f'<div class="finding finding-{t}"><span class="badge badge-{t}">{f.get("severity","")}</span> <span class="finding-title">{f.get("title","")}</span><div class="finding-detail">{f.get("detail","")}</div></div>'
    return html + "</div>"


def _render_headers(data: dict) -> str:
    if not data.get("success"): return ""
    score = data.get("security_score", {})
    grade = score.get("grade", "?")
    missing = data.get("missing_headers", [])
    html = f'<div class="section"><div class="section-title">HTTP Security Headers</div>'
    html += f'<div style="display:flex;align-items:center;gap:20px;margin-bottom:16px">'
    html += f'<div class="grade grade-{grade}">{grade}</div>'
    html += f'<div><div style="font-size:16px;font-weight:600">{score.get("percent",0)}% — {score.get("passed",0)}/{score.get("total_checked",0)} headers present</div>'
    html += f'<div style="font-size:12px;color:#7a8fa8">Final URL: {data.get("final_url","")}</div></div></div>'
    if missing:
        sev_color = {"HIGH":"#ff4757","MEDIUM":"#ffa502","LOW":"#ffa502","INFO":"#7a8fa8"}
        html += '<table><thead><tr><th>Missing Header</th><th>Severity</th><th>Impact</th></tr></thead><tbody>'
        for h in missing:
            c = sev_color.get(h.get("severity","INFO"), "#7a8fa8")
            html += f'<tr><td>{h["name"]}</td><td style="color:{c};font-weight:600">{h.get("severity","")}</td><td style="color:#7a8fa8">{h.get("desc","")}</td></tr>'
        html += '</tbody></table>'
    if data.get("tech_disclosure"):
        html += '<div style="margin-top:16px"><strong style="font-size:11px;letter-spacing:2px;color:#3d5068">VERSION DISCLOSURE</strong>'
        for h in data["tech_disclosure"]:
            html += f'<div class="field"><div class="field-key">{h["header"]}</div><div class="field-val" style="color:#ffa502">{h["value"]}</div></div>'
        html += '</div>'
    return html + "</div>"


def _render_techstack(data: dict) -> str:
    if not data.get("success") or not data.get("total_found"): return ""
    html = '<div class="section"><div class="section-title">Technology Stack</div>'
    html += '<table><thead><tr><th>Technology</th><th>Category</th><th>Version</th><th>CVE Search</th></tr></thead><tbody>'
    for tech in data.get("detected", []):
        html += f'<tr><td style="font-weight:600">{tech["name"]}</td><td style="color:#7a8fa8">{tech["category"]}</td>'
        html += f'<td style="color:#ffa502">{tech.get("version") or "—"}</td>'
        html += f'<td style="font-size:11px;color:#3d5068">{tech.get("cve_hint","")}</td></tr>'
    return html + '</tbody></table></div>'


def _render_subdomains(data: dict) -> str:
    if not data.get("success") or not data.get("found"): return ""
    html = f'<div class="section"><div class="section-title">Subdomains Found ({data.get("total_found",0)})</div>'
    html += '<table><thead><tr><th>Subdomain</th><th>IP Address(es)</th><th>Notable</th></tr></thead><tbody>'
    for s in data.get("found", []):
        flag = "⚑ Review" if s.get("interesting") else ""
        color = "color:#ffa502" if s.get("interesting") else ""
        html += f'<tr><td style="font-family:monospace;{color}">{s["subdomain"]}</td>'
        html += f'<td style="font-family:monospace;color:#7a8fa8">{", ".join(s.get("ips",[]))}</td>'
        html += f'<td style="color:#ffa502;font-size:12px">{flag}</td></tr>'
    return html + '</tbody></table></div>'


def _render_ports(data: dict) -> str:
    if not data.get("success") or not data.get("open_ports"): return ""
    risky = {21,23,445,3389,5900,6379,27017,1433,3306,5432}
    html = f'<div class="section"><div class="section-title">Open Ports ({data.get("total_open",0)})</div>'
    html += '<table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Notes</th></tr></thead><tbody>'
    for p in data.get("open_ports", []):
        is_risky = p["port"] in risky
        risk_label = "HIGH" if is_risky else "LOW"
        risk_color = "#ff4757" if is_risky else "#39ff6e"
        html += f'<tr><td style="font-weight:600;color:{risk_color}">{p["port"]}</td>'
        html += f'<td>{p.get("service","")}</td>'
        html += f'<td style="color:{risk_color};font-weight:600">{risk_label}</td>'
        html += f'<td style="color:#7a8fa8;font-size:12px">{p.get("note","")}</td></tr>'
    return html + '</tbody></table></div>'
