import React, { useState } from "react";
import axios from "axios";
import { Button, Card, Row, Col } from "react-bootstrap";
import { jwtDecode } from "jwt-decode";
import LiveScan from "./LiveScan"; // Make sure this file exists

const Scan = ({ token }) => {
  const [systemInfo, setSystemInfo] = useState(null);
  const [softwareList, setSoftwareList] = useState(null);
  const [openPorts, setOpenPorts] = useState(null);
  const [firewallRules, setFirewallRules] = useState(null);
  const [portVulnerabilities, setPortVulnerabilities] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);

  const decoded = jwtDecode(token);
  const username = decoded.identity || decoded.sub || "Admin";

  const config = {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  };

  const handleApiError = (error) => {
    if (error.response?.status === 401) {
      alert("Session expired. Please log in again.");
      localStorage.removeItem("token");
      window.location.reload();
    } else {
      alert("An error occurred. Check console.");
      console.error(error);
    }
  };

  const scanSystem = async () => {
    try {
      const res = await axios.get("http://127.0.0.1:5000/system_info", config);
      setSystemInfo(res.data);
    } catch (err) {
      handleApiError(err);
    }
  };

  const fetchSoftware = async () => {
    try {
      const res = await axios.get("http://127.0.0.1:5000/installed_software", config);
      setSoftwareList(res.data.installed_software);
    } catch (err) {
      handleApiError(err);
    }
  };

  const fetchOpenPorts = async () => {
    try {
      const res = await axios.get("http://127.0.0.1:5000/open_ports", config);
      setOpenPorts(res.data.open_ports);
    } catch (err) {
      handleApiError(err);
    }
  };

  const fetchFirewallRules = async () => {
    try {
      const res = await axios.get("http://127.0.0.1:5000/firewall_rules", config);
      setFirewallRules(res.data);
    } catch (err) {
      handleApiError(err);
    }
  };

  const fetchPortVulnerabilities = async () => {
    try {
      const res = await axios.get("http://127.0.0.1:5000/port_vulnerabilities", config);
      setPortVulnerabilities(res.data.open_ports_vulnerabilities);
    } catch (err) {
      handleApiError(err);
    }
  };

  const downloadReport = async () => {
    try {
      const res = await axios.get("http://127.0.0.1:5000/scan/generate_report", {
        headers: { Authorization: `Bearer ${token}` },
        responseType: "blob",
      });
      const blob = new Blob([res.data], { type: "application/pdf" });
      const link = document.createElement("a");
      link.href = window.URL.createObjectURL(blob);
      link.download = "Intrudex_Report.pdf";
      link.click();
    } catch (err) {
      handleApiError(err);
    }
  };

  const fetchScanHistory = async () => {
    try {
      const res = await axios.get("http://127.0.0.1:5000/scan/history", config);
      setScanHistory(res.data);
    } catch (err) {
      handleApiError(err);
    }
  };

  return (
    <div className="container mt-5">
      <h2 className="mb-2 text-center">🛡️ Truth in Traces</h2>
      <p className="text-center text-muted mb-4">
        Welcome, <strong>{username}</strong> 👋
      </p>

      <Row className="g-2 justify-content-center mb-4">
        <Col xs="auto"><Button onClick={scanSystem}>🖥️ System Info</Button></Col>
        <Col xs="auto"><Button onClick={fetchSoftware}>📦 Installed Software</Button></Col>
        <Col xs="auto"><Button onClick={fetchOpenPorts}>🌐 Open Ports</Button></Col>
        <Col xs="auto"><Button onClick={fetchFirewallRules}>🔥 Firewall Rules</Button></Col>
        <Col xs="auto"><Button onClick={fetchPortVulnerabilities}>⚠️ Port Vulnerabilities</Button></Col>
        <Col xs="auto"><Button variant="success" onClick={downloadReport}>📥 PDF Report</Button></Col>
        <Col xs="auto"><Button variant="info" onClick={fetchScanHistory}>📜 View History</Button></Col>
      </Row>

      <LiveScan token={token} />

      {systemInfo && (
        <InfoCard title="🖥️ System Information" data={systemInfo} />
      )}

      {softwareList && (
        <ListCard
          title="📦 Installed Software"
          list={softwareList.map((s) => `${s.DisplayName} - ${s.DisplayVersion}`)}
        />
      )}

      {openPorts && (
        <ListCard
          title="🌐 Open Ports"
          list={openPorts.map((p) => `Port: ${p.LocalPort}, Process: ${p.OwningProcess}`)}
        />
      )}

      {firewallRules && (
        <Card className="mb-4">
          <Card.Body>
            <h5 className="mb-3">🔥 Firewall Rules</h5>
            <ul>
              {firewallRules.firewall_rules.map((rule, i) => (
                <li key={i}>
                  {rule.DisplayName} - {rule.Action} ({rule.Direction})
                </li>
              ))}
            </ul>
            <h6 className="mt-4">🔒 Security Recommendations</h6>
            <ul>
              {firewallRules.security_recommendations.map((rec, i) => (
                <li key={i}>{rec}</li>
              ))}
            </ul>
          </Card.Body>
        </Card>
      )}

      {portVulnerabilities && (
        <Card className="mb-4">
          <Card.Body>
            <h5>⚠️ Port Vulnerabilities</h5>
            <ul>
              {portVulnerabilities.map((vuln, i) => (
                <li key={i}>
                  <strong>Port {vuln.port} ({vuln.service}):</strong>
                  <ul>
                    {vuln.cve_details.map((cve, j) => (
                      <li key={j}>
                        <strong>{cve.cve_id}:</strong> {cve.description} <br />
                        <em>Severity:</em> {cve.severity}, <em>CVSS Score:</em> {cve.cvss_score}
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          </Card.Body>
        </Card>
      )}

      {scanHistory.length > 0 && (
        <Card className="mb-4">
          <Card.Body>
            <h5>📜 Previous Scan History</h5>
            {scanHistory.map((entry, i) => (
              <div key={i} className="mb-3 border-bottom pb-2">
                <p><strong>Date:</strong> {new Date(entry.timestamp).toLocaleString()}</p>
                <p><strong>OS:</strong> {entry.system_info.OS}</p>
                <p><strong>Processor:</strong> {entry.system_info.Processor}</p>
                <p><strong>IP Address:</strong> {entry.network_info.IP}</p>
              </div>
            ))}
          </Card.Body>
        </Card>
      )}
    </div>
  );
};

// Reusable Card for Info
const InfoCard = ({ title, data }) => (
  <Card className="mb-4">
    <Card.Body>
      <h5>{title}</h5>
      {Object.entries(data).map(([key, value]) => (
        <p key={key}><strong>{key}:</strong> {value}</p>
      ))}
    </Card.Body>
  </Card>
);

// Reusable Card for List
const ListCard = ({ title, list }) => (
  <Card className="mb-4">
    <Card.Body>
      <h5>{title}</h5>
      <ul>
        {list.map((item, i) => (
          <li key={i}>{item}</li>
        ))}
      </ul>
    </Card.Body>
  </Card>
);

export default Scan;





  



