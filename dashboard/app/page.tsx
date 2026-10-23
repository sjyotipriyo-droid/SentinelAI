"use client";
import { useState } from "react";
import { ShieldAlert, Upload, Terminal, FileText, Cpu, Globe, AlertTriangle, Download } from "lucide-react";

interface Incident {
  line: number | string;
  timestamp: string;
  ip: string;
  osint?: {
    country: string;
    isp: string;
    asn: string;
  };
  threat_type: string;
  mitre_attack: string;
  payload: string;
  status_code: string;
  severity: string;
}

const SAMPLE_LOG = `192.168.1.10 - - [23/Oct/2026:10:15:23 +0530] "GET /index.html HTTP/1.1" 200 1024
45.33.32.156 - - [23/Oct/2026:10:17:12 +0530] "GET /products?id=1' OR '1'='1 HTTP/1.1" 500 512
45.33.32.156 - - [23/Oct/2026:10:17:15 +0530] "GET /products?id=1 UNION SELECT username, password FROM users-- HTTP/1.1" 200 4096
103.21.244.0 - - [23/Oct/2026:10:18:05 +0530] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 256
185.220.101.5 - - [23/Oct/2026:10:20:01 +0530] "POST /admin/login HTTP/1.1" 401 128
185.220.101.5 - - [23/Oct/2026:10:20:02 +0530] "POST /admin/login HTTP/1.1" 401 128
185.220.101.5 - - [23/Oct/2026:10:20:03 +0530] "POST /admin/login HTTP/1.1" 401 128
185.220.101.5 - - [23/Oct/2026:10:20:04 +0530] "POST /admin/login HTTP/1.1" 401 128
185.220.101.5 - - [23/Oct/2026:10:20:05 +0530] "POST /admin/login HTTP/1.1" 401 128
103.21.244.0 - - [23/Oct/2026:10:21:10 +0530] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1024`;

export default function SentinelDashboard() {
  const [logText, setLogText] = useState(SAMPLE_LOG);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [aiReport, setAiReport] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      setLogText(event.target?.result as string);
      setIncidents([]);
      setAiReport(null);
    };
    reader.readAsText(file);
  };

  const runScan = async (withAi = false) => {
    setErrorMsg(null);
    if (withAi) {
      setAiLoading(true);
    } else {
      setLoading(true);
    }
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          logContent: logText,
          generateAiReport: withAi,
          existingIncidents: withAi && incidents.length > 0 ? incidents : null,
        }),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setErrorMsg(data.error || "Server error occurred");
      } else {
        if (data.incidents) setIncidents(data.incidents);
        if (data.aiReport) setAiReport(data.aiReport);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Network connection failed";
      setErrorMsg(`Connection Error: ${msg}. Make sure 'npm.cmd run dev' is running in terminal!`);
    } finally {
      setLoading(false);
      setAiLoading(false);
    }
  };

  const downloadReport = () => {
    if (!aiReport) return;
    const blob = new Blob([aiReport], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "SentinelAI_Incident_Report.md";
    a.click();
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-sans">
      <div className="max-w-7xl mx-auto space-y-6">
        <header className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800 pb-5 gap-4">
          <div className="flex items-center gap-3">
            <ShieldAlert className="w-10 h-10 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold tracking-wider bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                SENTINEL-AI // SOC SIEM DASHBOARD
              </h1>
              <p className="text-xs text-slate-400">Autonomous Log Threat Hunter + Live OSINT + MITRE ATT&CK Engine</p>
            </div>
          </div>
          <label className="cursor-pointer bg-slate-900 hover:bg-slate-800 border border-slate-700 px-4 py-2 rounded-lg flex items-center gap-2 text-sm">
            <Upload className="w-4 h-4 text-cyan-400" />
            <span>Upload .log File</span>
            <input type="file" accept=".log,.txt" onChange={handleFileUpload} className="hidden" />
          </label>
        </header>

        {errorMsg && (
          <div className="bg-red-950/60 border border-red-500/60 text-red-200 p-4 rounded-xl text-sm font-mono">
            [!] Error: {errorMsg}
          </div>
        )}

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="flex justify-between items-center flex-wrap gap-2">
            <span className="text-xs font-mono uppercase text-slate-400 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" /> Raw Server Telemetry (Apache / Nginx Access Logs)
            </span>
            <div className="flex gap-3">
              <button
                onClick={() => runScan(false)}
                disabled={loading || aiLoading}
                className="bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2 disabled:opacity-50"
              >
                <Globe className="w-4 h-4" />
                {loading ? "Scanning & Querying OSINT..." : "1. Scan Threats & Live OSINT"}
              </button>
              <button
                onClick={() => runScan(true)}
                disabled={aiLoading || loading}
                className="bg-purple-600 hover:bg-purple-500 text-white px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2 disabled:opacity-50"
              >
                <Cpu className="w-4 h-4" />
                {aiLoading ? "AI SOC Analyst Writing Report (Wait ~10s)..." : "2. Generate AI IR Report"}
              </button>
            </div>
          </div>
          <textarea
            value={logText}
            onChange={(e) => setLogText(e.target.value)}
            rows={6}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-emerald-400 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {incidents.length > 0 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="w-5 h-5" /> Detected Security Incidents ({incidents.length})
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {incidents.map((inc, idx) => (
                <div key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-slate-100">{inc.threat_type}</span>
                    <span
                      className={`text-xs px-2.5 py-1 rounded-full font-bold ${
                        inc.severity === "CRITICAL"
                          ? "bg-red-500/20 text-red-400 border border-red-500/40"
                          : inc.severity === "HIGH"
                          ? "bg-orange-500/20 text-orange-400 border border-orange-500/40"
                          : "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40"
                      }`}
                    >
                      {inc.severity} (HTTP {inc.status_code})
                    </span>
                  </div>
                  <p className="text-xs text-purple-400 font-mono">MITRE: {inc.mitre_attack}</p>
                  <p className="text-xs text-cyan-400 font-mono">
                    IP: {inc.ip} — {inc.osint?.country} ({inc.osint?.isp})
                  </p>
                  <div className="bg-slate-950 p-2 rounded border border-slate-800 font-mono text-xs text-amber-300 break-all">
                    {inc.payload}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {aiReport && (
          <div className="bg-slate-900 border border-purple-500/40 rounded-xl p-6 space-y-4">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h2 className="text-lg font-bold text-purple-400 flex items-center gap-2">
                <FileText className="w-5 h-5" /> Autonomous Tier-3 SOC Incident Response Report
              </h2>
              <button
                onClick={downloadReport}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs flex items-center gap-2"
              >
                <Download className="w-4 h-4 text-purple-400" /> Download .MD Report
              </button>
            </div>
            <pre className="whitespace-pre-wrap font-mono text-xs text-slate-200 bg-slate-950 p-4 rounded-lg border border-slate-800 max-h-[600px] overflow-y-auto leading-relaxed">
              {aiReport}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}