// src/LiveScan.js
import React, { useState } from "react";
import { Button, ProgressBar, Card } from "react-bootstrap";

const LiveScan = ({ token }) => {
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [isScanning, setIsScanning] = useState(false);

  const scanSteps = 7;

  const startLiveScan = () => {
    setProgress(0);
    setLogs([]);
    setIsScanning(true);

    const eventSource = new EventSource("http://127.0.0.1:5000/live_scan");

    let step = 0;

    eventSource.onmessage = (event) => {
      const message = event.data;
      step += 1;

      setLogs((prevLogs) => [...prevLogs, message]);
      setProgress(Math.round((step / scanSteps) * 100));

      if (message.includes("✅ Scan Complete")) {
        eventSource.close();
        setIsScanning(false);
      }
    };

    eventSource.onerror = (error) => {
      console.error("Live scan error:", error);
      eventSource.close();
      setLogs((prevLogs) => [...prevLogs, "❌ Scan failed or interrupted."]);
      setIsScanning(false);
    };
  };

  return (
    <Card className="mt-4">
      <Card.Body>
        <h4>🌀 Live Scan Progress</h4>
        <Button onClick={startLiveScan} disabled={isScanning}>
          {isScanning ? "Scanning..." : "Start Live Scan"}
        </Button>

        <ProgressBar now={progress} label={`${progress}%`} striped animated className="mt-3" />

        <div className="mt-3" style={{ maxHeight: "250px", overflowY: "auto", background: "#f8f9fa", padding: "10px", borderRadius: "5px" }}>
          <h6>🔍 Scan Logs:</h6>
          <ul>
            {logs.map((log, index) => (
              <li key={index}>{log}</li>
            ))}
          </ul>
        </div>
      </Card.Body>
    </Card>
  );
};

export default LiveScan;

