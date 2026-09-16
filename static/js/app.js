// CLONET app.js — Session 4 patch (DNS + CNAME fix)

const targetInput = document.getElementById("target-input");
const runBtn      = document.getElementById("run-btn");
const runLabel    = document.getElementById("run-label");
const outputArea  = document.getElementById("output-area");
const statusText  = document.getElementById("status-text");
const statusDot   = document.querySelector(".status-dot");
const logEntries  = document.getElementById("log-entries");
const placeholder = document.getElementById("results-placeholder");
const moduleBtns  = document.querySelectorAll(".module-btn");

let activeModule  = "autoscan";
let lastScanData  = null;

function updateClock() {
  document.getElementById("clock").textContent =
    new Date().toUTCString().split(" ").slice(1,5).join(" ") + " UTC";
}
setInterval(updateClock, 1000);
updateClock();

moduleBtns.forEach(btn => {
  btn.addEventListener("click", () => {
    moduleBtns.forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activeModule = btn.dataset.module;
    document.querySelectorAll(".module-options").forEach(p => p.style.display = "none");
    const panel = document.getElementById(`${activeModule}-options`);
    if (panel) panel.style.display = "block";
  });
});

function log(msg, type="") {
  const e = document.createElement("span");
  e.className = `log-entry ${type}`;
  e.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  logEntries.innerHTML = "";
  logEntries.appendChild(e);
}

function setScanning(on) {
  runBtn.disabled = on;
  runLabel.innerHTML = on ? '<span class="spinner">◌</span> SCANNING...' : "▶ RUN SCAN";
  statusDot.classList.toggle("scanning", on);
  statusText.textContent = on ? "Scanning" : "Ready";
}

async function apiCall(endpoint, body) {
  const res = await fetch(endpoint, {
    method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`Server error: ${res.status}`);
  return res.json();
}

runBtn.addEventListener("click", async () => {
  const target = targetInput.value.trim();
  if (!target) { log("No target specified","err"); targetInput.focus(); return; }
  outputArea.innerHTML = "";
  if (placeholder) placeholder.style.display = "none";
  setScanning(true);
  log(`Starting ${activeModule} on ${target}...`,"info");
  try {
    let result;
    if (activeModule === "autoscan") {
      await runAutoScan(target); return;
    } else if (activeModule === "portscan") {
      result = await apiCall("/api/portscan", {target, range: document.getElementById("port-range").value||"1-1000", speed: document.getElementById("scan-speed").value||"normal"});
      renderPortScan(result, target);
    } else if (activeModule === "subdomain") {
      result = await apiCall("/api/subdomain", {target, wordlist: document.getElementById("sub-wordlist").value||"default"});
      renderSubdomain(result, target);
    } else if (activeModule === "ssl") {
      result = await apiCall("/api/ssl", {target});
      renderSSL(result, target);
    } else if (activeModule === "whois") {
      result = await apiCall("/api/whois", {target});
      renderWhois(result, target);
    } else if (activeModule === "dns") {
      result = await apiCall("/api/dns", {target});
      renderDns(result, target);
    } else if (activeModule === "headers") {
      result = await apiCall("/api/headers", {target});
      renderHeaders(result, target);
    } else if (activeModule === "techstack") {
      result = await apiCall("/api/techstack", {target});
      renderTechstack(result, target);
    }
  } catch(err) {
    outputArea.innerHTML = `<div class="error-box">⚠ ${err.message}</div>`;
    log(`Error: ${err.message}`,"err");
  } finally {
    setScanning(false);
  }
});

targetInput.addEventListener("keydown", e => { if (e.key==="Enter") runBtn.click(); });

// ── AUTO SCAN ────────────────────────────────────────────────
async function runAutoScan(target) {
  const steps = [
    {key:"whois",      label:"WHOIS Lookup"},
    {key:"dns",        label:"DNS Enumeration"},
    {key:"ssl",        label:"SSL / TLS Analysis"},
    {key:"headers",    label:"Header Analysis"},
    {key:"techstack",  label:"Tech Stack Fingerprint"},
    {key:"subdomains", label:"Subdomain Brute-Force"},
    {key:"ports",      label:"Port Scanner"},
  ];

  let html = `
    <div class="result-header">
      <div class="result-title">Auto Scan</div>
      <div class="result-target">${target}</div>
      <div class="result-meta">Running all modules in sequence...</div>
    </div>
    <div class="progress-steps" id="progress-steps">`;
  for (const s of steps) {
    html += `<div class="progress-step" id="step-${s.key}">
      <span class="step-icon">◌</span>
      <span class="step-label">${s.label}</span>
      <span class="step-status">Waiting...</span>
    </div>`;
  }
  html += `</div><div id="autoscan-results"></div>`;
  outputArea.innerHTML = html;

  function setStep(key, state, statusText) {
    const el = document.getElementById(`step-${key}`);
    if (!el) return;
    el.className = `progress-step ${state}`;
    const icons = {running:"<span class='spinner'>◌</span>", done:"✓", error:"✗", waiting:"◌"};
    el.querySelector(".step-icon").innerHTML = icons[state] || "◌";
    el.querySelector(".step-status").textContent = statusText || "";
  }

  try {
    setStep("whois","running","Scanning...");
    log("Auto scan running — this takes 1-2 minutes","info");
    const portRange = document.getElementById("auto-port-range")?.value || "1-1000";
    const data = await apiCall("/api/autoscan", {target, range: portRange});
    const results = data.results || {};
    const errors  = data.errors  || {};

    for (const s of steps) {
      const key = s.key;
      if (errors[key]) {
        setStep(key, "error", "Error");
      } else if (results[key]) {
        const r = results[key];
        let summary = "Done";
        if (key==="ports")      summary = `${r.total_open||0} open ports`;
        if (key==="subdomains") summary = `${r.total_found||0} found`;
        if (key==="ssl")        summary = `Grade: ${r.grade||"?"}`;
        if (key==="headers")    summary = `Grade: ${r.security_score?.grade||"?"}`;
        if (key==="techstack")  summary = `${r.total_found||0} detected`;
        if (key==="dns")        summary = `${r.total_records||0} records`;
        setStep(key, "done", summary);
      }
    }

    lastScanData = data;
    renderAutoResults(data, target);
    log(`Auto scan complete — Risk score: ${data.summary?.risk_score}/100`, "ok");
  } catch(err) {
    outputArea.innerHTML += `<div class="error-box">⚠ ${err.message}</div>`;
    log(`Auto scan failed: ${err.message}`,"err");
  } finally {
    setScanning(false);
  }
}

function renderAutoResults(data, target) {
  const summary   = data.summary || {};
  const results   = data.results || {};
  const riskScore = summary.risk_score || 0;
  const riskLabel = summary.risk_label || "UNKNOWN";
  const riskColors = {HIGH:"#ff4757",MEDIUM:"#ffa502",LOW:"#39ff6e",MINIMAL:"#00e5ff"};
  const rc = riskColors[riskLabel] || "#7a8fa8";

  let html = document.getElementById("progress-steps")?.outerHTML || "";
  html += `
    <div class="export-bar">
      <button class="export-btn primary" onclick="exportReport()">⬇ HTML REPORT</button>
      <button class="export-btn" onclick="exportJSON()">⬇ JSON</button>
    </div>
    <div class="risk-block" style="border-color:${rc}20;background:${rc}08">
      <div class="risk-num" style="color:${rc}">${riskScore}</div>
      <div>
        <div class="risk-label-text" style="color:${rc}">Risk: ${riskLabel}</div>
        <div class="risk-detail-text">${summary.total_findings||0} findings &nbsp;|&nbsp; ${data.duration||0}s scan duration &nbsp;|&nbsp; ${new Date().toLocaleString()}</div>
        <div class="risk-detail-text" style="margin-top:6px">
          Ports: ${summary.open_ports||0} &nbsp;|&nbsp;
          Subdomains: ${summary.subdomains_found||0} &nbsp;|&nbsp;
          Technologies: ${summary.tech_detected||0} &nbsp;|&nbsp;
          SSL: ${summary.ssl_grade||"?"} &nbsp;|&nbsp;
          Headers: ${summary.header_grade||"?"}
        </div>
      </div>
    </div>
    ${renderFindingsList(summary.findings || [])}`;

  const r = results;
  if (r.whois?.success)      html += quickWhois(r.whois);
  if (r.dns?.success)        html += quickDNS(r.dns);        // ← NEW: full DNS block
  if (r.ssl?.success)        html += quickSSL(r.ssl);
  if (r.headers?.success)    html += quickHeaders(r.headers);
  if (r.techstack?.success)  html += quickTechstack(r.techstack);
  if (r.subdomains?.success) html += quickSubdomains(r.subdomains);
  if (r.ports?.success)      html += quickPorts(r.ports);

  document.getElementById("autoscan-results").innerHTML = html;
}

function renderFindingsList(findings) {
  if (!findings.length) return "";
  const icons = {critical:"⚠",high:"⚠",medium:"◉",low:"◉",good:"✓",info:"◈"};
  let html = `<div class="section-title">Findings (${findings.length})</div>`;
  const sorted = [...findings].sort((a,b) => {
    const o={critical:0,high:1,medium:2,low:3,info:4,good:5};
    return (o[a.type]||4)-(o[b.type]||4);
  });
  for (const f of sorted) {
    const t=(f.type||"info").toLowerCase();
    const col=t==="high"||t==="critical"?"red":t==="medium"||t==="low"?"amber":t==="good"?"green":"muted";
    html+=`<div class="finding finding-${t}">
      <div class="finding-icon">${icons[t]||"◈"}</div>
      <div>
        <div class="finding-title">
          <span class="badge badge-${col}">${f.severity||f.type?.toUpperCase()||"INFO"}</span>
          [${f.module||""}] ${f.title||""}
        </div>
        <div class="finding-detail">${f.detail||""}</div>
      </div>
    </div>`;
  }
  return html;
}

// ── QUICK BLOCKS FOR AUTO SCAN ───────────────────────────────

function quickWhois(d) {
  return `<div class="section-title">WHOIS</div>
  <div class="field-row"><div class="field-label">Registrar</div><div class="field-value">${d.registrar||"N/A"}</div></div>
  <div class="field-row"><div class="field-label">Created</div><div class="field-value">${d.created||"N/A"}</div></div>
  <div class="field-row"><div class="field-label">Expires</div><div class="field-value">${d.expires||"N/A"}</div></div>
  <div class="field-row" style="margin-bottom:20px"><div class="field-label">Org</div><div class="field-value">${d.org||"N/A"}</div></div>`;
}

// ── NEW: Full DNS block with all record types ─────────────────
// This is what was missing — shows A, AAAA, MX, NS, TXT, CAA,
// SOA, CNAME all properly formatted for the report
function quickDNS(d) {
  const records = d.records || {};
  const typeColor = {
    A:"accent", AAAA:"accent", MX:"amber", NS:"blue",
    TXT:"green", CNAME:"muted", SOA:"muted", CAA:"muted", SRV:"blue", PTR:"accent"
  };

  // Display order — most important first
  const ordered = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA","SRV","PTR"];
  const types = [
    ...ordered.filter(t => records[t]),
    ...Object.keys(records).filter(t => !ordered.includes(t))
  ];

  if (!types.length) return "";

  let html = `<div class="section-title">DNS Records (${d.total_records||0} total — Types: ${types.join(", ")})</div>`;

  // Findings from DNS (SPF, DMARC issues etc)
  if (d.findings?.length) {
    const fIcon = {high:"⚠",medium:"◉",info:"◈",good:"✓"};
    for (const f of d.findings) {
      const col = f.type==="high"?"red":f.type==="medium"?"amber":f.type==="good"?"green":"muted";
      html += `<div class="finding finding-${f.type}" style="margin-bottom:6px">
        <div class="finding-icon">${fIcon[f.type]||"◈"}</div>
        <div><div class="finding-title"><span class="badge badge-${col}">${f.type?.toUpperCase()}</span> ${f.title}</div>
        <div class="finding-detail">${f.detail}</div></div>
      </div>`;
    }
  }

  // Records table grouped by type
  html += `<div class="dns-records">`;

  for (const type of types) {
    const recs = records[type];
    if (!recs?.length) continue;
    const color = typeColor[type] || "muted";

    for (const r of recs) {
      if (type === "A" || type === "AAAA" || type === "NS" || type === "CNAME" || type === "PTR") {
        html += `<div class="dns-record">
          <span class="dns-type badge badge-${color}">${type}</span>
          <span style="font-family:var(--font-mono)">${r}</span>
        </div>`;

      } else if (type === "MX") {
        html += `<div class="dns-record">
          <span class="dns-type badge badge-${color}">${type}</span>
          <span style="color:var(--text-muted);min-width:40px">[${r.priority}]</span>
          <span>${r.host}</span>
        </div>`;

      } else if (type === "TXT") {
        const interesting = /spf|dkim|dmarc|v=/i.test(r);
        html += `<div class="dns-record">
          <span class="dns-type badge badge-${color}">${type}</span>
          <span style="${interesting?"color:var(--amber)":""};word-break:break-all;font-size:12px">${r}</span>
        </div>`;

      } else if (type === "SOA") {
        html += `<div class="dns-record" style="flex-direction:column;gap:4px">
          <span class="badge badge-${color}" style="align-self:flex-start">${type}</span>
          <div style="font-size:12px;color:var(--text-secondary);line-height:1.8;font-family:var(--font-mono)">
            Primary NS: ${r.primary_ns}<br>
            Admin: ${r.admin_email}<br>
            Serial: ${r.serial}
          </div>
        </div>`;

      } else if (type === "CAA") {
        html += `<div class="dns-record">
          <span class="dns-type badge badge-${color}">${type}</span>
          <span style="color:var(--text-muted)">[${r.tag}]</span>
          <span>${r.value}</span>
        </div>`;

      } else if (type === "SRV") {
        html += `<div class="dns-record">
          <span class="dns-type badge badge-${color}">${type}</span>
          <span style="color:var(--text-muted)">[${r.priority}/${r.weight}]</span>
          <span>${r.target}:<strong>${r.port}</strong></span>
        </div>`;

      } else {
        html += `<div class="dns-record">
          <span class="dns-type badge badge-${color}">${type}</span>
          <span>${JSON.stringify(r)}</span>
        </div>`;
      }
    }
  }

  html += `</div>`;

  // Nameservers summary line
  if (records.NS?.length) {
    html += `<div style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);margin-bottom:20px">
      Nameservers: ${records.NS.join(" &nbsp;|&nbsp; ")}
    </div>`;
  }

  return html;
}

function quickSSL(d) {
  const cert=d.cert||{}; const g=d.grade||"?";
  return `<div class="section-title">SSL / TLS</div>
  <div class="score-block" style="margin-bottom:16px">
    <div class="score-grade grade-${g}">${g}</div>
    <div class="score-detail">
      <strong>${cert.common_name||""}</strong><br>
      Issuer: ${cert.issuer||"?"} &nbsp;|&nbsp; Expires: ${cert.valid_until||"?"} (${cert.days_until_expiry||"?"} days)<br>
      TLS 1.2: ${d.tls_versions?.tls_1_2?"✓":"✗"} &nbsp;
      TLS 1.3: ${d.tls_versions?.tls_1_3?"✓":"✗"} &nbsp;
      TLS 1.0: ${d.tls_versions?.tls_1_0?"⚠ Yes":"✓ No"} &nbsp;
      TLS 1.1: ${d.tls_versions?.tls_1_1?"⚠ Yes":"✓ No"}
      ${cert.sans?.length ? `<br>SANs: ${cert.sans.slice(0,5).join(", ")}${cert.sans.length>5?" ...":""}` : ""}
    </div>
  </div>`;
}

function quickHeaders(d) {
  const s=d.security_score||{}; const g=s.grade||"?";
  const missing=(d.missing_headers||[]).filter(h=>h.severity==="HIGH"||h.severity==="MEDIUM");
  let html=`<div class="section-title">Security Headers — Grade ${g}</div>
  <div class="score-block" style="margin-bottom:16px">
    <div class="score-grade grade-${g}">${g}</div>
    <div class="score-detail"><strong>${s.percent||0}% — ${s.passed||0}/${s.total_checked||0} headers present</strong></div>
  </div>`;
  if (missing.length) {
    html+=`<table class="data-table" style="margin-bottom:20px"><thead><tr><th>Missing Header</th><th>Severity</th></tr></thead><tbody>`;
    for (const h of missing)
      html+=`<tr><td>${h.name}</td><td><span class="badge badge-${h.severity==="HIGH"?"red":"amber"}">${h.severity}</span></td></tr>`;
    html+=`</tbody></table>`;
  }
  if (d.tech_disclosure?.length) {
    html+=`<div style="margin-bottom:20px">`;
    for (const h of d.tech_disclosure)
      html+=`<div class="field-row"><div class="field-label">${h.header}</div><div class="field-value" style="color:var(--amber)">${h.value}</div></div>`;
    html+=`</div>`;
  }
  return html;
}

function quickTechstack(d) {
  if (!d.total_found) return "";
  let html=`<div class="section-title">Tech Stack (${d.total_found} detected)</div>
  <table class="data-table" style="margin-bottom:20px"><thead><tr><th>Technology</th><th>Category</th><th>Version</th><th>CVE Search</th></tr></thead><tbody>`;
  for (const t of (d.detected||[]))
    html+=`<tr><td style="font-weight:600">${t.name}</td><td style="color:var(--text-muted)">${t.category}</td><td style="color:var(--amber)">${t.version||"—"}</td><td style="font-size:11px;color:var(--text-muted)">${t.cve_hint||""}</td></tr>`;
  return html+`</tbody></table>`;
}

// ── UPDATED: Subdomains now shows CNAME column ────────────────
function quickSubdomains(d) {
  if (!d.total_found) return `<div class="section-title">Subdomains</div>
  <div style="color:var(--text-muted);font-family:var(--font-mono);font-size:13px;margin-bottom:20px">No subdomains found</div>`;

  let html=`<div class="section-title">Subdomains (${d.total_found} found)</div>
  <table class="data-table" style="margin-bottom:20px">
    <thead><tr><th>Subdomain</th><th>IP Address(es)</th><th>CNAME</th><th>Flag</th></tr></thead>
    <tbody>`;

  // Show interesting ones first
  const sorted = [...(d.found||[])].sort((a,b) => (b.interesting?1:0)-(a.interesting?1:0));

  for (const s of sorted) {
    const color = s.interesting ? "color:var(--amber);font-weight:600" : "color:var(--green)";
    html+=`<tr>
      <td style="${color}">${s.subdomain}</td>
      <td style="color:var(--text-muted);font-family:var(--font-mono)">${(s.ips||[]).join(", ")}</td>
      <td style="color:var(--text-secondary);font-size:12px;font-family:var(--font-mono)">${s.cname||"—"}</td>
      <td style="color:var(--amber);font-size:12px">${s.interesting?"⚑ Review":""}</td>
    </tr>`;
  }
  return html+`</tbody></table>`;
}

function quickPorts(d) {
  if (!d.total_open) return `<div class="section-title">Port Scanner</div>
  <div style="color:var(--text-muted);font-family:var(--font-mono);font-size:13px;margin-bottom:20px">No open ports found in range ${d.port_range||""}</div>`;
  const risky=[21,23,445,3389,5900,6379,27017,1433,3306,5432];
  let html=`<div class="section-title">Open Ports (${d.total_open})</div>
  <table class="data-table" style="margin-bottom:20px"><thead><tr><th>Port</th><th>Service</th><th>Notes</th></tr></thead><tbody>`;
  for (const p of (d.open_ports||[])) {
    const c=risky.includes(p.port)?"color:var(--red)":"color:var(--green)";
    html+=`<tr><td style="${c};font-weight:600">${p.port}</td><td>${p.service||"—"}</td><td class="port-note">${p.note||"—"}</td></tr>`;
  }
  return html+`</tbody></table>`;
}

// ── EXPORT ───────────────────────────────────────────────────
async function exportReport() {
  if (!lastScanData) { log("No scan data — run a scan first","err"); return; }
  try {
    const res = await fetch("/api/report", {
      method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(lastScanData)
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href=url; a.download=`clonet_report_${lastScanData.target||"target"}.html`;
    a.click(); URL.revokeObjectURL(url);
    log("HTML report downloaded","ok");
  } catch(err) { log(`Export failed: ${err.message}`,"err"); }
}

function exportJSON() {
  if (!lastScanData) { log("No scan data — run a scan first","err"); return; }
  const blob = new Blob([JSON.stringify(lastScanData,null,2)], {type:"application/json"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href=url; a.download=`clonet_${lastScanData.target||"target"}.json`;
  a.click(); URL.revokeObjectURL(url);
  log("JSON exported","ok");
}

// ── INDIVIDUAL MODULE RENDERS ────────────────────────────────
function renderPortScan(data, target) {
  if (!data.success) { outputArea.innerHTML=`<div class="error-box">⚠ ${data.error}</div>`; return; }
  log(`Port scan — ${data.total_open} open ports`,"ok");
  const risky=[21,23,445,3389,5900,6379,27017];
  let html=`<div class="result-header"><div class="result-title">Port Scan</div><div class="result-target">${data.target}</div><div class="result-meta">Resolved: ${data.resolved_ip} | Range: ${data.port_range} | ${data.timestamp}</div></div>
  <div class="stats-row">
    <div class="stat-card"><div class="stat-label">Open Ports</div><div class="stat-value ${data.total_open>0?"accent":"green"}">${data.total_open}</div></div>
    <div class="stat-card"><div class="stat-label">Status</div><div class="stat-value green">${data.host_status||"up"}</div></div>
  </div>`;
  if (!data.open_ports.length) { html+=`<div class="error-box" style="color:var(--amber)">No open ports in range ${data.port_range}</div>`; }
  else {
    html+=`<div class="section-title">Open Ports</div><table class="data-table"><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Notes</th></tr></thead><tbody>`;
    for (const p of data.open_ports) {
      const c=risky.includes(p.port)?"color:var(--red)":"color:var(--green)";
      html+=`<tr><td style="${c};font-weight:600">${p.port}</td><td><span class="badge badge-green">OPEN</span></td><td>${p.service||"—"}</td><td class="port-note">${p.note||"—"}</td></tr>`;
    }
    html+=`</tbody></table>`;
  }
  outputArea.innerHTML=html;
}

function renderSSL(data, target) {
  if (!data.success) { outputArea.innerHTML=`<div class="error-box">⚠ ${data.error}</div>`; return; }
  log(`SSL check — Grade ${data.grade}`,"ok");
  const cert=data.cert||{}; const g=data.grade||"?";
  const fIcon={CRITICAL:"⚠",HIGH:"⚠",MEDIUM:"◉",LOW:"◉",GOOD:"✓",INFO:"◈"};
  let html=`<div class="result-header"><div class="result-title">SSL / TLS Analysis</div><div class="result-target">${target}</div><div class="result-meta">${data.timestamp}</div></div>
  <div class="score-block">
    <div class="score-grade grade-${g}">${g}</div>
    <div class="score-detail">
      <strong>${cert.common_name||target}</strong><br>
      Issuer: ${cert.issuer||"Unknown"}<br>
      Valid Until: ${cert.valid_until||"?"} — ${cert.days_until_expiry>0?cert.days_until_expiry+" days remaining":"EXPIRED"}<br>
      Cipher: ${cert.cipher_suite||"?"}
      ${cert.sans?.length?`<br>SANs: ${cert.sans.join(", ")}`:""}
    </div>
  </div>
  <div class="section-title">TLS Versions</div>
  <table class="data-table"><thead><tr><th>Version</th><th>Supported</th><th>Status</th></tr></thead><tbody>`;
  const tls=data.tls_versions||{};
  for (const [v,sup,status] of [["TLS 1.0",tls.tls_1_0,"deprecated"],["TLS 1.1",tls.tls_1_1,"deprecated"],["TLS 1.2",tls.tls_1_2,"current"],["TLS 1.3",tls.tls_1_3,"recommended"]]) {
    const bad=(status==="deprecated")&&sup;
    const good=(status==="current"||status==="recommended")&&sup;
    const c=bad?"color:var(--red)":good?"color:var(--green)":"color:var(--text-muted)";
    html+=`<tr><td>${v}</td><td style="${c};font-weight:600">${sup?"✓ Yes":"✗ No"}</td><td style="color:var(--text-muted);font-size:12px">${status}</td></tr>`;
  }
  html+=`</tbody></table><div class="section-title">Findings</div>`;
  for (const f of (data.findings||[])) {
    const t=(f.severity||"info").toLowerCase();
    const col=t==="critical"||t==="high"?"red":t==="medium"||t==="low"?"amber":t==="good"?"green":"muted";
    html+=`<div class="finding finding-${t}"><div class="finding-icon">${fIcon[f.severity]||"◈"}</div>
    <div><div class="finding-title"><span class="badge badge-${col}">${f.severity}</span> ${f.title}</div>
    <div class="finding-detail">${f.detail}</div></div></div>`;
  }
  outputArea.innerHTML=html;
}

function renderSubdomain(data, target) {
  if (!data.success) { outputArea.innerHTML=`<div class="error-box">⚠ ${data.error}</div>`; return; }
  log(`Subdomains — ${data.total_found} found of ${data.total_checked} checked`,"ok");
  let html=`<div class="result-header"><div class="result-title">Subdomain Enumeration</div><div class="result-target">${data.target}</div>
  <div class="result-meta">Checked: ${data.total_checked} | Found: ${data.total_found} | Interesting: ${data.interesting} | ${data.timestamp}</div></div>
  <div class="stats-row">
    <div class="stat-card"><div class="stat-label">Found</div><div class="stat-value accent">${data.total_found}</div></div>
    <div class="stat-card"><div class="stat-label">Interesting</div><div class="stat-value ${data.interesting>0?"amber":"green"}">${data.interesting}</div></div>
    <div class="stat-card"><div class="stat-label">Checked</div><div class="stat-value">${data.total_checked}</div></div>
  </div>`;
  if (!data.found.length) { html+=`<div class="error-box" style="color:var(--amber)">No subdomains found.</div>`; }
  else {
    html+=`<div class="section-title">All Subdomains</div>
    <table class="data-table"><thead><tr><th>Subdomain</th><th>IP(s)</th><th>CNAME</th><th>Flag</th></tr></thead><tbody>`;
    for (const s of data.found)
      html+=`<tr>
        <td style="color:${s.interesting?"var(--amber)":"var(--green)"};font-weight:${s.interesting?600:400}">${s.subdomain}</td>
        <td style="color:var(--text-muted);font-family:var(--font-mono)">${s.ips.join(", ")}</td>
        <td style="color:var(--text-secondary);font-size:12px;font-family:var(--font-mono)">${s.cname||"—"}</td>
        <td style="color:var(--amber)">${s.interesting?"⚑":""}</td>
      </tr>`;
    html+=`</tbody></table>`;
  }
  outputArea.innerHTML=html;
}

function renderWhois(data, target) {
  if (!data.success) { outputArea.innerHTML=`<div class="error-box">⚠ ${data.error}</div>`; return; }
  log(`WHOIS complete`,"ok");
  const fields=[["Domain",data.domain_name],["Registrar",data.registrar],["Created",data.created],["Expires",data.expires],["Updated",data.updated],["Org",data.org],["Country",data.country],["Emails",data.emails]];
  let html=`<div class="result-header"><div class="result-title">WHOIS Lookup</div><div class="result-target">${target}</div><div class="result-meta">${data.timestamp}</div></div>
  <div class="section-title">Registration Info</div>`;
  for (const [l,v] of fields) { if (!v||v==="N/A") continue; html+=`<div class="field-row"><div class="field-label">${l}</div><div class="field-value">${v}</div></div>`; }
  if (data.nameservers?.length) {
    html+=`<div class="section-title">Nameservers</div><div class="dns-records">`;
    for (const ns of data.nameservers) html+=`<div class="dns-record"><span class="dns-type">NS</span><span>${ns}</span></div>`;
    html+=`</div>`;
  }
  outputArea.innerHTML=html;
}

function renderDns(data, target) {
  if (!data.success) { outputArea.innerHTML=`<div class="error-box">⚠ ${data.error}</div>`; return; }
  log(`DNS — ${data.total_records} records`,"ok");
  // Reuse the quickDNS function for consistent rendering
  outputArea.innerHTML=`<div class="result-header"><div class="result-title">DNS Enumeration</div><div class="result-target">${target}</div>
  <div class="result-meta">Resolved: ${data.resolved_ip||"N/A"} | ${data.total_records} records | ${data.timestamp}</div></div>`
  + quickDNS(data);
}

function renderHeaders(data, target) {
  if (!data.success) { outputArea.innerHTML=`<div class="error-box">⚠ ${data.error}</div>`; return; }
  const score=data.security_score; const g=score.grade;
  log(`Headers — Grade ${g}`,"ok");
  const sevColor={HIGH:"red",MEDIUM:"amber",LOW:"amber",INFO:"muted"};
  let html=`<div class="result-header"><div class="result-title">HTTP Header Analysis</div><div class="result-target">${data.final_url||target}</div>
  <div class="result-meta">Status: ${data.status_code} | HTTPS: ${data.https?"✓":"✗"} | ${data.timestamp}</div></div>
  <div class="score-block"><div class="score-grade grade-${g}">${g}</div>
  <div class="score-detail"><strong>${score.percent}% — ${score.passed}/${score.total_checked} headers present</strong></div></div>`;
  if (data.missing_headers.length) {
    html+=`<div class="section-title">Missing Headers</div><table class="data-table"><thead><tr><th>Header</th><th>Severity</th><th>Impact</th></tr></thead><tbody>`;
    for (const h of data.missing_headers) html+=`<tr><td>${h.name}</td><td><span class="badge badge-${sevColor[h.severity]||"muted"}">${h.severity}</span></td><td style="color:var(--text-secondary);font-size:12px">${h.desc}</td></tr>`;
    html+=`</tbody></table>`;
  }
  outputArea.innerHTML=html;
}

function renderTechstack(data, target) {
  if (!data.success) { outputArea.innerHTML=`<div class="error-box">⚠ ${data.error}</div>`; return; }
  log(`Tech stack — ${data.total_found} technologies`,"ok");
  const catColor={"Web Server":"accent","CDN / Proxy":"blue","Language":"amber","CMS":"red","E-Commerce":"amber","JS Framework":"green","JS Library":"muted","CSS Framework":"muted","Framework":"green","Analytics":"muted","Cloud":"blue"};
  let html=`<div class="result-header"><div class="result-title">Tech Stack</div><div class="result-target">${data.final_url||target}</div><div class="result-meta">${data.total_found} technologies | ${data.timestamp}</div></div>`;
  if (!data.total_found) { html+=`<div class="error-box" style="color:var(--amber)">No technologies detected.</div>`; }
  else {
    for (const [cat,techs] of Object.entries(data.grouped)) {
      const color=catColor[cat]||"muted";
      html+=`<div class="section-title">${cat}</div><div class="dns-records">`;
      for (const t of techs) html+=`<div class="dns-record" style="justify-content:space-between;flex-wrap:wrap;gap:8px">
        <div style="display:flex;align-items:center;gap:12px">
          <span class="badge badge-${color}">${cat.split(" ")[0].toUpperCase()}</span>
          <span style="font-weight:600">${t.name}</span>
          ${t.version?`<span class="badge badge-amber">v${t.version}</span>`:""}
        </div>
        <div style="font-size:11px;color:var(--text-muted)">${t.cve_hint||""}</div>
      </div>`;
      html+=`</div>`;
    }
  }
  outputArea.innerHTML=html;
}
