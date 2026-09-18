from flask import Flask, render_template, request, jsonify, Response
from modules.port_scanner import run_port_scan
from modules.whois_lookup import run_whois
from modules.dns_enum     import run_dns_enum
from modules.headers      import run_header_check
from modules.subdomain    import run_subdomain_scan
from modules.techstack    import run_techstack
from modules.ssl_check    import run_ssl_check
from modules.autoscan     import run_autoscan
from modules.report       import generate_html_report
import datetime, json

app = Flask(__name__)

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/portscan", methods=["POST"])
def api_portscan():
    data = request.json
    target = data.get("target","").strip()
    if not target: return jsonify({"error":"No target"}), 400
    result = run_port_scan(target, data.get("range","1-1000"), data.get("speed","normal"), data.get("scan_udp", False))
    result["timestamp"] = ts()
    return jsonify(result)

@app.route("/api/whois", methods=["POST"])
def api_whois():
    data = request.json
    target = data.get("target","").strip()
    if not target: return jsonify({"error":"No target"}), 400
    result = run_whois(target)
    result["timestamp"] = ts()
    return jsonify(result)

@app.route("/api/dns", methods=["POST"])
def api_dns():
    data = request.json
    target = data.get("target","").strip()
    if not target: return jsonify({"error":"No target"}), 400
    result = run_dns_enum(target)
    result["timestamp"] = ts()
    return jsonify(result)

@app.route("/api/headers", methods=["POST"])
def api_headers():
    data = request.json
    target = data.get("target","").strip()
    if not target: return jsonify({"error":"No target"}), 400
    result = run_header_check(target)
    result["timestamp"] = ts()
    return jsonify(result)

@app.route("/api/subdomain", methods=["POST"])
def api_subdomain():
    data = request.json
    target = data.get("target","").strip()
    if not target: return jsonify({"error":"No target"}), 400
    result = run_subdomain_scan(target, wordlist=data.get("wordlist","default"))
    result["timestamp"] = ts()
    return jsonify(result)

@app.route("/api/techstack", methods=["POST"])
def api_techstack():
    data = request.json
    target = data.get("target","").strip()
    if not target: return jsonify({"error":"No target"}), 400
    result = run_techstack(target)
    result["timestamp"] = ts()
    return jsonify(result)

@app.route("/api/ssl", methods=["POST"])
def api_ssl():
    data = request.json
    target = data.get("target","").strip()
    if not target: return jsonify({"error":"No target"}), 400
    result = run_ssl_check(target)
    result["timestamp"] = ts()
    return jsonify(result)

@app.route("/api/autoscan", methods=["POST"])
def api_autoscan():
    data = request.json
    target = data.get("target","").strip()
    if not target: return jsonify({"error":"No target"}), 400
    result = run_autoscan(target, port_range=data.get("range","1-1000"))
    result["timestamp"] = ts()
    return jsonify(result)

@app.route("/api/report", methods=["POST"])
def api_report():
    """Generate and return an HTML report from scan data."""
    scan_data = request.json
    if not scan_data: return jsonify({"error":"No scan data"}), 400
    html = generate_html_report(scan_data)
    return Response(html, mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename=clonet_report_{scan_data.get('target','target')}.html"})

if __name__ == "__main__":
    print("""
  ██████╗██╗      ██████╗ ███╗   ██╗███████╗████████╗
 ██╔════╝██║     ██╔═══██╗████╗  ██║██╔════╝╚══██╔══╝
 ██║     ██║     ██║   ██║██╔██╗ ██║█████╗     ██║
 ██║     ██║     ██║   ██║██║╚██╗██║██╔══╝     ██║
 ╚██████╗███████╗╚██████╔╝██║ ╚████║███████╗   ██║
  ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
  Running at http://localhost:5000
    """)
    app.run(debug=True, host="0.0.0.0", port=5000)
