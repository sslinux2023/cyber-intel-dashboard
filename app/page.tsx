"use client";

import { useState, useEffect } from "react";
import { Shield, Search, AlertTriangle, CheckCircle2, Loader2, Bug } from "lucide-react";

type ScanResult = {
  target: string;
  type: "ip" | "domain";
  virustotal: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    reputation: number;
  } | null;
  abuseipdb: {
    abuseConfidenceScore: number;
    totalReports: number;
    countryCode: string;
    isp: string;
    isWhitelisted: boolean;
  } | null;
  vtError: string | null;
  abuseError: string | null;
};

type Cve = {
  id: string;
  description: string;
  published: string;
  score: number | null;
  severity: string;
};

function extractHost(input: string): string {
  let value = input.trim();
  if (!value) return value;
  try {
    const withProto = /^https?:\/\//i.test(value) ? value : `http://${value}`;
    const url = new URL(withProto);
    return url.hostname;
  } catch {
    return value
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .split("?")[0]
      .split("#")[0];
  }
}

function severityColor(sev: string) {
  switch (sev?.toUpperCase()) {
    case "CRITICAL":
      return "#ff3860";
    case "HIGH":
      return "#ff6b35";
    case "MEDIUM":
      return "#ffb800";
    case "LOW":
      return "#00ff9d";
    default:
      return "#6b7280";
  }
}

export default function Home() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");

  const [cves, setCves] = useState<Cve[]>([]);
  const [cvesLoading, setCvesLoading] = useState(true);
  const [cvesError, setCvesError] = useState("");

  useEffect(() => {
    const loadCves = async () => {
      try {
        const res = await fetch("/api/cves");
        const data = await res.json();
        if (!res.ok) {
          setCvesError(data.error || "Failed to load CVE feed");
        } else {
          setCves(data.cves ?? []);
        }
      } catch {
        setCvesError("Network error loading CVE feed");
      } finally {
        setCvesLoading(false);
      }
    };
    loadCves();
  }, []);

  const handleScan = async () => {
    const cleaned = extractHost(target);
    if (!cleaned) return;

    setTarget(cleaned);
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: cleaned }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Something went wrong");
      } else {
        setResult(data);
      }
    } catch (e) {
      setError("Network error — check your connection");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen px-4 py-10 flex flex-col items-center" suppressHydrationWarning>
      <div className="w-full max-w-2xl">
        {/* Header */}
        <div className="flex items-center gap-3 mb-8">
          <Shield className="w-8 h-8 neon-text" />
          <h1 className="text-2xl font-bold tracking-tight">
            Cyber-Intel <span className="neon-text">Dashboard</span>
          </h1>
        </div>

        {/* Search */}
        <div className="flex gap-2 mb-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleScan()}
            placeholder="Enter domain or IP (e.g. google.com, 8.8.8.8)"
            className="flex-1 bg-[#0e0e16] glow-border rounded-lg px-4 py-3 text-sm outline-none focus:border-[#00ff9d] transition-colors"
          />
          <button
            onClick={handleScan}
            disabled={loading}
            className="bg-[#00ff9d] text-black font-semibold px-5 rounded-lg flex items-center gap-2 disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Scan
          </button>
        </div>
        <p className="text-xs text-gray-600 mb-6">
          Paste a full URL or just the domain/IP — it's cleaned automatically.
        </p>

        {error && (
          <div className="glow-border rounded-lg p-4 mb-6 border-[#ff3860]/40 bg-[#ff3860]/10 text-[#ff3860] text-sm">
            {error}
          </div>
        )}

        {/* Scan Results */}
        {result && (
          <div className="space-y-4 mb-10">
            <p className="text-sm text-gray-500">
              Results for <span className="text-gray-200 font-mono">{result.target}</span>{" "}
              <span className="uppercase text-xs bg-[#1e1e2e] px-2 py-1 rounded">{result.type}</span>
            </p>

            <div className="glow-border rounded-xl p-5 bg-[#0e0e16]">
              <h2 className="font-semibold mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4 neon-text" /> VirusTotal
              </h2>
              {result.virustotal ? (
                <div className="grid grid-cols-4 gap-3 text-center">
                  <Stat label="Malicious" value={result.virustotal.malicious} color="#ff3860" />
                  <Stat label="Suspicious" value={result.virustotal.suspicious} color="#ffb800" />
                  <Stat label="Harmless" value={result.virustotal.harmless} color="#00ff9d" />
                  <Stat label="Undetected" value={result.virustotal.undetected} color="#6b7280" />
                </div>
              ) : (
                <p className="text-sm text-gray-500 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" /> {result.vtError}
                </p>
              )}
            </div>

            <div className="glow-border rounded-xl p-5 bg-[#0e0e16]">
              <h2 className="font-semibold mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4 text-[#00d9ff]" /> AbuseIPDB
              </h2>
              {result.abuseipdb ? (
                <div className="space-y-2 text-sm">
                  <Row label="Abuse Confidence" value={`${result.abuseipdb.abuseConfidenceScore}%`} />
                  <Row label="Total Reports" value={result.abuseipdb.totalReports} />
                  <Row label="Country" value={result.abuseipdb.countryCode} />
                  <Row label="ISP" value={result.abuseipdb.isp} />
                  <Row
                    label="Whitelisted"
                    value={
                      result.abuseipdb.isWhitelisted ? (
                        <span className="flex items-center gap-1 text-[#00ff9d]">
                          <CheckCircle2 className="w-4 h-4" /> Yes
                        </span>
                      ) : (
                        "No"
                      )
                    }
                  />
                </div>
              ) : (
                <p className="text-sm text-gray-500 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" /> {result.abuseError}
                </p>
              )}
            </div>
          </div>
        )}

        {/* CVE Feed */}
        <div>
          <div className="flex items-center gap-2 mb-4">
            <Bug className="w-5 h-5 text-[#ff6b35]" />
            <h2 className="font-semibold text-lg">Latest CVEs</h2>
            <span className="text-xs text-gray-600">(last 7 days)</span>
          </div>

          {cvesLoading && (
            <p className="text-sm text-gray-500 flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading feed...
            </p>
          )}

          {cvesError && !cvesLoading && (
            <p className="text-sm text-[#ff3860] flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" /> {cvesError}
            </p>
          )}

          {!cvesLoading && !cvesError && cves.length === 0 && (
            <p className="text-sm text-gray-500">No CVEs published in the last 7 days.</p>
          )}

          <div className="space-y-3">
            {cves.map((cve) => (
              <div key={cve.id} className="glow-border rounded-lg p-4 bg-[#0e0e16]">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-sm text-[#00d9ff]">{cve.id}</span>
                  {cve.score !== null && (
                    <span
                      className="text-xs font-semibold px-2 py-1 rounded"
                      style={{
                        color: severityColor(cve.severity),
                        border: `1px solid ${severityColor(cve.severity)}40`,
                      }}
                    >
                      {cve.severity} · {cve.score}
                    </span>
                  )}
                </div>
                <p className="text-sm text-gray-400 line-clamp-3">{cve.description}</p>
                <p className="text-xs text-gray-600 mt-2">
                  {new Date(cve.published).toLocaleDateString()}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </main>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div>
      <p className="text-2xl font-bold" style={{ color }}>
        {value}
      </p>
      <p className="text-xs text-gray-500">{label}</p>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between border-b border-[#1e1e2e] pb-2">
      <span className="text-gray-500">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}
