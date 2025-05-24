from flask import Flask, jsonify, request, send_file, Response
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from datetime import timedelta
import wmi
import socket
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import pythoncom
import subprocess
import json
import requests
import time  # ✅ Required for log delays
from flask import Response 

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# 🔐 In-memory user store
users = {
    "admin": bcrypt.generate_password_hash("admin123").decode('utf-8')
}

@app.route('/')
def home():
    return jsonify({"message": "Intrudex API is running!"})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in users and bcrypt.check_password_hash(users[username], password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/system_info')
@jwt_required()
def get_system_info():
    pythoncom.CoInitialize()
    c = wmi.WMI()
    try:
        os_info = c.Win32_OperatingSystem()[0]
        system_info = c.Win32_ComputerSystem()[0]
        return jsonify({
            "OS": os_info.Caption,
            "Architecture": os_info.OSArchitecture,
            "Processor": c.Win32_Processor()[0].Name,
            "RAM": f"{round(int(system_info.TotalPhysicalMemory) / (1024 ** 3))} GB",
            "User": system_info.UserName
        })
    finally:
        pythoncom.CoUninitialize()

@app.route('/installed_software')
@jwt_required()
def installed_software():
    try:
        command = 'powershell -Command "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | ConvertTo-Json"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            software_list = json.loads(result.stdout)
            if not isinstance(software_list, list):
                software_list = [software_list]
            return jsonify({"installed_software": software_list})
        else:
            return jsonify({"error": "Failed to fetch installed software"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/open_ports')
@jwt_required()
def open_ports():
    try:
        command = 'powershell -Command "Get-NetTCPConnection | Where-Object { $_.State -eq \'Listen\' } | Select-Object LocalAddress, LocalPort, OwningProcess | ConvertTo-Json -Depth 1"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            ports_data = json.loads(result.stdout)
            return jsonify({"open_ports": ports_data if isinstance(ports_data, list) else [ports_data]})
        else:
            return jsonify({"error": "Failed to fetch open ports"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/firewall_rules')
@jwt_required()
def firewall_rules():
    try:
        command = 'powershell -Command "Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action | ConvertTo-Json -Depth 1"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            firewall_rules = json.loads(result.stdout)
            if not isinstance(firewall_rules, list):
                firewall_rules = [firewall_rules]
            return jsonify({
                "firewall_rules": firewall_rules,
                "security_recommendations": generate_security_recommendations(firewall_rules)
            })
        else:
            return jsonify({"error": "Failed to fetch firewall rules"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def generate_security_recommendations(firewall_rules):
    recommendations = []
    for rule in firewall_rules:
        if rule["Action"] == "Allow" and rule["Direction"] == "Inbound":
            recommendations.append(f"❌ {rule['DisplayName']} allows inbound traffic. Review it.")
    if not any(rule["Action"] == "Block" for rule in firewall_rules):
        recommendations.append("⚠️ No blocking rules found. Consider restricting unused ports.")
    return recommendations

port_vulnerability_map = {
    21: "FTP Server", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL"
}

@app.route('/port_vulnerabilities')
@jwt_required()
def port_vulnerabilities():
    try:
        command = 'powershell -Command "Get-NetTCPConnection | Where-Object { $_.State -eq \'Listen\' } | Select-Object LocalPort | ConvertTo-Json"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            open_ports = json.loads(result.stdout)
            if not isinstance(open_ports, list):
                open_ports = [open_ports]
            vulnerabilities = []
            headers = {"User-Agent": "Mozilla/5.0"}

            for port in open_ports:
                port_number = port["LocalPort"]
                if port_number in port_vulnerability_map:
                    service_name = port_vulnerability_map[port_number]
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service_name}&resultsPerPage=3"
                    try:
                        response = requests.get(url, headers=headers, timeout=5)
                        if response.status_code == 200:
                            cve_data = response.json().get("vulnerabilities", [])
                            formatted_cves = [ {
                                "cve_id": cve["cve"]["id"],
                                "description": cve["cve"]["descriptions"][0]["value"],
                                "cvss_score": cve.get("cve", {}).get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
                                "severity": cve.get("cve", {}).get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseSeverity", "Unknown"),
                                "last_modified": cve["cve"]["lastModified"]
                            } for cve in cve_data]
                            vulnerabilities.append({
                                "port": port_number,
                                "service": service_name,
                                "cve_details": formatted_cves
                            })
                    except requests.exceptions.Timeout:
                        continue
            return jsonify({"open_ports_vulnerabilities": vulnerabilities})
        else:
            return jsonify({"error": "Failed to fetch open ports"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def scan_network():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return {"Hostname": hostname, "IP": ip_address}

def generate_pdf_report(system_info, network_info):
    file_path = "Intrudex_Report.pdf"
    c = canvas.Canvas(file_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 770, "INTRUDEX Security Scan Report")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, 720, "System Information:")
    c.setFont("Helvetica", 10)
    c.drawString(120, 700, f"OS: {system_info['OS']}")
    c.drawString(120, 680, f"Architecture: {system_info['Architecture']}")
    c.drawString(120, 660, f"Processor: {system_info['Processor']}")
    c.drawString(120, 640, f"RAM: {system_info['RAM']}")
    c.drawString(120, 620, f"User: {system_info['User']}")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, 580, "Network Information:")
    c.setFont("Helvetica", 10)
    c.drawString(120, 560, f"Hostname: {network_info['Hostname']}")
    c.drawString(120, 540, f"IP Address: {network_info['IP']}")
    c.save()
    return file_path

@app.route("/scan/generate_report", methods=["GET"])
@jwt_required()
def generate_report():
    pythoncom.CoInitialize()
    system_info = get_system_info().json
    network_info = scan_network()
    file_path = generate_pdf_report(system_info, network_info)
    return send_file(file_path, as_attachment=True)

@app.route('/protected_scan')
@jwt_required()
def protected_scan():
    current_user = get_jwt_identity()
    return jsonify({"msg": f"Hello {current_user}, you are authorized to scan!"})

# ✅ 🌀 Live Scan Route - Streaming Logs using SSE
@app.route("/live_scan")
def live_scan():
    def generate():
        yield "data: Starting live scan...\n\n"
        time.sleep(1)
        yield "data: 🔍 Checking system information...\n\n"
        time.sleep(1)
        yield "data: 🧠 Gathering installed software...\n\n"
        time.sleep(1)
        yield "data: 🌐 Scanning open ports...\n\n"
        time.sleep(1)
        yield "data: 🔐 Checking firewall rules...\n\n"
        time.sleep(1)
        yield "data: ⚠️ Searching for known vulnerabilities...\n\n"
        time.sleep(1)
        yield "data: ✅ Scan Complete\n\n"

    return Response(generate(), mimetype="text/event-stream")



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)




