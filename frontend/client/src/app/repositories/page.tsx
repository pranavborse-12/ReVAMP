import React, { useEffect, useState } from "react";
import { Link } from "wouter";

const API_BASE_URL = "http://localhost:8000";

// Types
interface Toast {
  id: number;
  message: string;
  type?: "success" | "error" | "info";
}

interface Profile {
  login: string;
  name?: string;
  avatar_url?: string;
  bio?: string;
}

interface Owner {
  login?: string;
  avatar_url?: string;
  html_url?: string;
}

interface Repo {
  id: number;
  name: string;
  full_name?: string;
  html_url?: string;
  private: boolean;
  visibility?: string;
  description?: string;
  updated_at?: string;
  stargazers_count?: number;
  forks_count?: number;
  language?: string;
  owner?: Owner;
  size?: number;
}

interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  warning: number;
}

interface Vulnerability {
  scanner: string;
  rule_id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "WARNING";
  message: string;
  vulnerability_type: string;
  location: {
    file: string;
    start_line: number;
    end_line: number;
  };
  code_snippet?: string;
  cwe?: string[];
  owasp?: string[];
}

interface ScanResult {
  scan_id: string;
  repo_owner: string;
  repo_name: string;
  status: string;
  total_issues: number;
  severity_summary: SeveritySummary;
  vulnerabilities: Vulnerability[];
  scan_duration?: number;
  completed_at?: string;
  scanner_used?: string;
  detected_languages?: string[];
}

interface ScanStatus {
  scan_id: string;
  status: string;
  message: string;
  progress: string;
  repo_name?: string;
}

// Toast Component
function Toasts({ 
  toasts, 
  removeToast 
}: { 
  toasts: Toast[]; 
  removeToast: (id: number) => void 
}) {
  return (
    <div className="fixed top-5 right-5 flex flex-col gap-2 z-50 max-w-md">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`px-5 py-3 rounded-lg shadow-2xl text-sm cursor-pointer transition-all transform hover:scale-105 border ${
            t.type === "error" 
              ? "bg-red-500 text-white border-red-600" 
              : t.type === "info"
              ? "bg-blue-500 text-white border-blue-600"
              : "bg-green-500 text-white border-green-600"
          }`}
          onClick={() => removeToast(t.id)}
        >
          <div className="flex items-center gap-2">
            <span className="text-lg">
              {t.type === "error" ? "❌" : t.type === "info" ? "ℹ️" : "✅"}
            </span>
            <span className="font-medium">{t.message}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

// Utility Functions
function timeAgo(iso?: string) {
  if (!iso) return "";
  const dt = new Date(iso);
  const diff = (Date.now() - dt.getTime()) / 1000;
  const map: [number, string][] = [
    [60, "seconds"],
    [60, "minutes"],
    [24, "hours"],
    [30, "days"],
    [12, "months"],
  ];
  let unit = "seconds";
  let val = diff;
  for (let i = 0; i < map.length; i++) {
    const [k, name] = map[i];
    if (val < k) {
      unit = name;
      break;
    }
    val = val / k;
    unit = name;
  }
  return `${Math.floor(val)} ${unit} ago`;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + " " + sizes[i];
}

// Enhanced Severity Colors
function getSeverityStyles(severity: string) {
  switch (severity) {
    case "CRITICAL":
      return {
        bg: "bg-gradient-to-r from-red-600 to-red-700",
        border: "border-red-500",
        text: "text-red-100",
        badge: "bg-red-600 text-white",
        icon: "🔴",
        glow: "shadow-red-500/50"
      };
    case "HIGH":
      return {
        bg: "bg-gradient-to-r from-orange-600 to-orange-700",
        border: "border-orange-500",
        text: "text-orange-100",
        badge: "bg-orange-600 text-white",
        icon: "🟠",
        glow: "shadow-orange-500/50"
      };
    case "MEDIUM":
      return {
        bg: "bg-gradient-to-r from-yellow-600 to-yellow-700",
        border: "border-yellow-500",
        text: "text-yellow-100",
        badge: "bg-yellow-600 text-white",
        icon: "🟡",
        glow: "shadow-yellow-500/50"
      };
    case "LOW":
      return {
        bg: "bg-gradient-to-r from-blue-600 to-blue-700",
        border: "border-blue-500",
        text: "text-blue-100",
        badge: "bg-blue-600 text-white",
        icon: "🔵",
        glow: "shadow-blue-500/50"
      };
    case "INFO":
      return {
        bg: "bg-gradient-to-r from-gray-600 to-gray-700",
        border: "border-gray-500",
        text: "text-gray-100",
        badge: "bg-gray-600 text-white",
        icon: "⚪",
        glow: "shadow-gray-500/50"
      };
    case "WARNING":
      return {
        bg: "bg-gradient-to-r from-amber-600 to-amber-700",
        border: "border-amber-500",
        text: "text-amber-100",
        badge: "bg-amber-600 text-white",
        icon: "🟠",
        glow: "shadow-amber-500/50"
      };
    default:
      return {
        bg: "bg-gradient-to-r from-gray-600 to-gray-700",
        border: "border-gray-500",
        text: "text-gray-100",
        badge: "bg-gray-600 text-white",
        icon: "⚪",
        glow: "shadow-gray-500/50"
      };
  }
}

// Enhanced Scan Results Modal
function ScanResultsModal({
  result,
  onClose,
}: {
  result: ScanResult;
  onClose: () => void;
}) {
  const [filteredSeverity, setFilteredSeverity] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  const filteredVulns = result.vulnerabilities.filter((v) => {
    const matchesSeverity = !filteredSeverity || v.severity === filteredSeverity;
    const matchesSearch = !searchTerm || 
      v.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      v.vulnerability_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      v.location.file.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  const severities: Array<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "WARNING"> = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
    "WARNING",
  ];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 backdrop-blur-sm z-50 flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-gradient-to-br from-slate-900 to-slate-800 rounded-2xl max-w-7xl w-full my-8 border-2 border-slate-700 shadow-2xl">
        {/* Enhanced Header */}
        <div className="bg-gradient-to-r from-slate-800 to-slate-900 border-b-2 border-slate-700 p-6 rounded-t-2xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center text-2xl shadow-lg">
                🛡️
              </div>
              <div>
                <h2 className="text-3xl font-bold text-white">
                  {result.repo_name}
                </h2>
                <div className="flex items-center gap-3 mt-2">
                  <span className="text-sm text-slate-300">
                    {result.status === "completed"
                      ? `✅ Completed in ${result.scan_duration?.toFixed(2)}s`
                      : result.status}
                  </span>
                  {result.scanner_used && (
                    <span className="px-3 py-1 bg-slate-700 rounded-full text-xs font-medium text-slate-200">
                      {result.scanner_used}
                    </span>
                  )}
                  {result.detected_languages && result.detected_languages.length > 0 && (
                    <span className="px-3 py-1 bg-slate-700 rounded-full text-xs font-medium text-slate-200">
                      {result.detected_languages.join(", ")}
                    </span>
                  )}
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white text-3xl transition-colors hover:rotate-90 transform duration-300"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="p-6 border-b border-slate-700">
          <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
            <span>📊</span> Security Overview
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {severities.map((sev) => {
              const count =
                result.severity_summary[
                  sev.toLowerCase() as keyof SeveritySummary
                ] || 0;
              const styles = getSeverityStyles(sev);
              return (
                <div
                  key={sev}
                  className={`${styles.bg} ${styles.border} rounded-xl p-4 cursor-pointer transition-all transform hover:scale-105 border-2 shadow-lg ${styles.glow} ${
                    filteredSeverity === sev
                      ? "ring-4 ring-white scale-105"
                      : "hover:ring-2 hover:ring-white"
                  }`}
                  onClick={() =>
                    setFilteredSeverity(filteredSeverity === sev ? null : sev)
                  }
                >
                  <div className="text-center">
                    <div className="text-2xl mb-1">{styles.icon}</div>
                    <div className="text-xs font-bold uppercase tracking-wide opacity-90">
                      {sev}
                    </div>
                    <div className="text-3xl font-bold mt-2">{count}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Search and Filter */}
        <div className="p-6 border-b border-slate-700 bg-slate-800/50">
          <div className="flex flex-col md:flex-row gap-3">
            <input
              type="text"
              placeholder="🔍 Search vulnerabilities, files, or types..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="flex-1 bg-slate-900 border-2 border-slate-600 rounded-lg px-4 py-3 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            {filteredSeverity && (
              <button
                onClick={() => setFilteredSeverity(null)}
                className="px-6 py-3 bg-slate-700 hover:bg-slate-600 rounded-lg text-white font-medium transition-colors"
              >
                Clear Filter
              </button>
            )}
          </div>
        </div>

        {/* Vulnerabilities List */}
        <div className="p-6 max-h-[60vh] overflow-y-auto">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-white flex items-center gap-2">
              <span>🔍</span> Issues Found: {filteredVulns.length}
            </h3>
            {result.total_issues === 0 && (
              <div className="px-4 py-2 bg-green-600 rounded-lg text-white font-medium">
                ✅ No vulnerabilities found!
              </div>
            )}
          </div>

          {filteredVulns.length === 0 ? (
            <div className="text-center py-12">
              <div className="text-6xl mb-4">
                {result.total_issues === 0 ? "🎉" : "🔍"}
              </div>
              <div className="text-xl text-slate-300 font-medium">
                {result.total_issues === 0
                  ? "Great job! No security issues found."
                  : filteredSeverity
                  ? `No ${filteredSeverity} severity issues found`
                  : "No matches for your search"}
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredVulns.map((vuln, idx) => (
                <VulnerabilityCard
                  key={idx}
                  vuln={vuln}
                  onClick={() => setSelectedVuln(vuln)}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Detailed Vulnerability Modal */}
      {selectedVuln && (
        <VulnerabilityDetailModal
          vuln={selectedVuln}
          onClose={() => setSelectedVuln(null)}
        />
      )}
    </div>
  );
}

// Enhanced Vulnerability Card
function VulnerabilityCard({
  vuln,
  onClick,
}: {
  vuln: Vulnerability;
  onClick: () => void;
}) {
  const styles = getSeverityStyles(vuln.severity);

  return (
    <div
      className={`${styles.bg} ${styles.border} rounded-xl border-2 p-5 cursor-pointer transition-all transform hover:scale-102 hover:shadow-2xl ${styles.glow}`}
      onClick={onClick}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-2xl">{styles.icon}</span>
            <h4 className="text-lg font-bold text-white">
              {vuln.vulnerability_type}
            </h4>
            <span className={`${styles.badge} px-3 py-1 rounded-full text-xs font-bold uppercase`}>
              {vuln.severity}
            </span>
          </div>
          <p className="text-sm text-white opacity-90 mb-3 leading-relaxed">
            {vuln.message}
          </p>
          <div className="flex items-center gap-4 text-xs text-white opacity-75">
            <span className="flex items-center gap-1">
              📄 {vuln.location.file}
            </span>
            <span className="flex items-center gap-1 font-mono bg-black bg-opacity-30 px-2 py-1 rounded">
              📍 Line {vuln.location.start_line}
              {vuln.location.end_line !== vuln.location.start_line &&
                `-${vuln.location.end_line}`}
            </span>
          </div>
        </div>
        <div className="flex flex-col items-end gap-2">
          <span className="text-xs font-bold bg-black bg-opacity-30 px-3 py-1 rounded-full text-white">
            {vuln.scanner}
          </span>
          <button className="text-white opacity-75 hover:opacity-100 transition-opacity text-sm">
            View Details →
          </button>
        </div>
      </div>
    </div>
  );
}

// Vulnerability Detail Modal
function VulnerabilityDetailModal({
  vuln,
  onClose,
}: {
  vuln: Vulnerability;
  onClose: () => void;
}) {
  const styles = getSeverityStyles(vuln.severity);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-80 backdrop-blur-sm z-[60] flex items-center justify-center p-4">
      <div className="bg-slate-900 rounded-2xl max-w-4xl w-full border-2 border-slate-700 shadow-2xl max-h-[90vh] overflow-y-auto">
        <div className={`${styles.bg} p-6 rounded-t-2xl border-b-2 ${styles.border}`}>
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <span className="text-3xl">{styles.icon}</span>
                <h3 className="text-2xl font-bold text-white">
                  {vuln.vulnerability_type}
                </h3>
              </div>
              <span className={`${styles.badge} px-4 py-2 rounded-full text-sm font-bold uppercase inline-block`}>
                {vuln.severity}
              </span>
            </div>
            <button
              onClick={onClose}
              className="text-white hover:text-slate-200 text-3xl transition-colors"
            >
              ✕
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Description */}
          <div>
            <h4 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
              📝 Description
            </h4>
            <p className="text-slate-300 leading-relaxed bg-slate-800 p-4 rounded-lg">
              {vuln.message}
            </p>
          </div>

          {/* Location */}
          <div>
            <h4 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
              📍 Location
            </h4>
            <div className="bg-slate-800 p-4 rounded-lg space-y-2">
              <div className="flex items-center gap-2 text-slate-300">
                <span className="font-bold">File:</span>
                <code className="bg-slate-900 px-3 py-1 rounded font-mono text-sm">
                  {vuln.location.file}
                </code>
              </div>
              <div className="flex items-center gap-2 text-slate-300">
                <span className="font-bold">Lines:</span>
                <code className={`${styles.badge} px-3 py-1 rounded font-mono text-sm font-bold`}>
                  {vuln.location.start_line}
                  {vuln.location.end_line !== vuln.location.start_line &&
                    ` - ${vuln.location.end_line}`}
                </code>
              </div>
            </div>
          </div>

          {/* Technical Details */}
          <div>
            <h4 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
              🔬 Technical Details
            </h4>
            <div className="bg-slate-800 p-4 rounded-lg space-y-3">
              <div>
                <span className="text-slate-400 text-sm">Scanner:</span>
                <div className="text-white font-medium mt-1">{vuln.scanner}</div>
              </div>
              <div>
                <span className="text-slate-400 text-sm">Rule ID:</span>
                <code className="block text-white font-mono text-sm mt-1 bg-slate-900 px-3 py-2 rounded">
                  {vuln.rule_id}
                </code>
              </div>
              {vuln.cwe && vuln.cwe.length > 0 && (
                <div>
                  <span className="text-slate-400 text-sm">CWE:</span>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {vuln.cwe.map((cwe, idx) => (
                      <span
                        key={idx}
                        className="bg-blue-600 text-white px-3 py-1 rounded-full text-xs font-medium"
                      >
                        {cwe}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {vuln.owasp && vuln.owasp.length > 0 && (
                <div>
                  <span className="text-slate-400 text-sm">OWASP:</span>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {vuln.owasp.map((owasp, idx) => (
                      <span
                        key={idx}
                        className="bg-purple-600 text-white px-3 py-1 rounded-full text-xs font-medium"
                      >
                        {owasp}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Code Snippet */}
          {vuln.code_snippet && (
            <div>
              <h4 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
                💻 Code Snippet
              </h4>
              <pre className="bg-slate-950 text-slate-300 p-4 rounded-lg overflow-x-auto font-mono text-sm border-2 border-slate-700">
                {vuln.code_snippet}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Enhanced Scan Progress Component
function ScanProgress({
  scanId,
  repoName,
  onComplete,
}: {
  scanId: string;
  repoName: string;
  onComplete: (result: ScanResult) => void;
}) {
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let pollInterval: number | null = null;

    const pollStatus = async () => {
      try {
        const res = await fetch(
          `${API_BASE_URL}/api/scanning/scans/${scanId}/status`,
          { credentials: "include" }
        );

        if (!res.ok) throw new Error("Failed to fetch status");
        const data = await res.json();
        setStatus(data);

        if (data.status === "completed" || data.status === "failed") {
          if (pollInterval) clearInterval(pollInterval);

          if (data.status === "completed") {
            const resultRes = await fetch(
              `${API_BASE_URL}/api/scanning/scans/${scanId}`,
              { credentials: "include" }
            );
            const result = await resultRes.json();
            onComplete(result);
          } else {
            setError("Scan failed. Please try again.");
          }
        }
      } catch (err) {
        console.error(err);
        setError(err instanceof Error ? err.message : "Unknown error");
        if (pollInterval) clearInterval(pollInterval);
      }
    };

    pollStatus();
    pollInterval = setInterval(pollStatus, 2000);

    return () => {
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [scanId, onComplete]);

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center p-4">
        <div className="bg-red-600 text-white p-8 rounded-2xl max-w-md w-full text-center shadow-2xl border-2 border-red-500">
          <div className="text-6xl mb-4">❌</div>
          <h3 className="text-2xl font-bold mb-2">Scan Failed</h3>
          <p className="text-red-100">{error}</p>
        </div>
      </div>
    );
  }

  const progressNum = parseInt(status?.progress || "0");

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-purple-900 flex items-center justify-center p-4">
      <div className="bg-slate-800 bg-opacity-90 backdrop-blur-lg rounded-2xl p-8 max-w-2xl w-full shadow-2xl border-2 border-slate-700">
        <div className="text-center">
          {/* Animated Scanner Icon */}
          <div className="mb-6 flex justify-center">
            <div className="relative">
              <div className="w-24 h-24 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-5xl animate-pulse shadow-2xl">
                🛡️
              </div>
              <div className="absolute inset-0 rounded-full bg-blue-400 opacity-25 animate-ping"></div>
            </div>
          </div>

          <h2 className="text-3xl font-bold text-white mb-2">
            Scanning Repository
          </h2>
          <p className="text-xl text-slate-300 mb-6">{repoName}</p>

          {status && (
            <>
              <div className="mb-6">
                <p className="text-lg text-slate-200 mb-4 font-medium">
                  {status.message}
                </p>
                
                {/* Enhanced Progress Bar */}
                <div className="w-full bg-slate-900 rounded-full h-6 overflow-hidden border-2 border-slate-700 shadow-inner">
                  <div
                    className="h-full bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 transition-all duration-500 flex items-center justify-center text-white text-xs font-bold shadow-lg"
                    style={{ width: status.progress }}
                  >
                    {progressNum > 10 && status.progress}
                  </div>
                </div>
                <p className="text-sm text-slate-400 mt-3">
                  Progress: {status.progress}
                </p>
              </div>

              {/* Status Stages */}
              <div className="grid grid-cols-4 gap-3 text-xs">
                {[
                  { name: "Queue", status: "queued", icon: "⏳" },
                  { name: "Clone", status: "cloning", icon: "📥" },
                  { name: "Analyze", status: "analyzing", icon: "🔍" },
                  { name: "Scan", status: "scanning", icon: "🛡️" },
                ].map((stage) => {
                  const isActive = status.status === stage.status;
                  const isPast =
                    progressNum >
                    (stage.status === "queued"
                      ? 0
                      : stage.status === "cloning"
                      ? 10
                      : stage.status === "analyzing"
                      ? 20
                      : 30);
                  return (
                    <div
                      key={stage.status}
                      className={`p-3 rounded-lg transition-all ${
                        isActive
                          ? "bg-blue-600 text-white scale-105"
                          : isPast
                          ? "bg-green-600 text-white"
                          : "bg-slate-700 text-slate-400"
                      }`}
                    >
                      <div className="text-2xl mb-1">{stage.icon}</div>
                      <div className="font-medium">{stage.name}</div>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// Main Page (Repository List)
export default function RepositoriesPage() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [type, setType] = useState("all");
  const [page, setPage] = useState(1);
  const per_page = 30;

  const [toasts, setToasts] = useState<Toast[]>([]);
  const [activeScan, setActiveScan] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const addToast = (message: string, type?: "success" | "error" | "info") => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => removeToast(id), 5000);
  };

  const removeToast = (id: number) =>
    setToasts((prev) => prev.filter((t) => t.id !== id));

  const fetchData = async () => {
    setLoading(true);
    setError(null);

    try {
      const profileRes = await fetch(`${API_BASE_URL}/api/github/profile`, {
        credentials: "include",
      });

      if (profileRes.status === 401) {
        setError("not-connected");
        setLoading(false);
        return;
      }

      if (!profileRes.ok) {
        throw new Error(`Profile API error: ${profileRes.status}`);
      }

      const profileData = await profileRes.json();
      setProfile(profileData);

      const params = new URLSearchParams({
        query,
        type,
        sort: "updated",
        direction: "desc",
        page: page.toString(),
        per_page: per_page.toString(),
      });

      const reposRes = await fetch(
        `${API_BASE_URL}/api/github/repos?${params}`,
        { credentials: "include" }
      );

      if (!reposRes.ok) {
        throw new Error(`Repos API error: ${reposRes.status}`);
      }

      const reposData = await reposRes.json();
      setRepos(reposData);
    } catch (e: any) {
      const errorMessage = e.message || "Failed to load data";
      setError(errorMessage);
      addToast(errorMessage, "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [query, type, page]);

  const handleConnectGitHub = () => {
    window.location.href = `${API_BASE_URL}/auth/github/login?redirect_to=/repositories`;
  };

  if (activeScan && !scanResult) {
    const repoName = repos.find((r) => r.id.toString() === activeScan)?.name || "repository";
    return (
      <ScanProgress
        scanId={activeScan}
        repoName={repoName}
        onComplete={(result) => {
          setScanResult(result);
          addToast(`✅ Scan completed! Found ${result.total_issues} issues`, "success");
        }}
      />
    );
  }

  if (scanResult) {
    return (
      <>
        <Toasts toasts={toasts} removeToast={removeToast} />
        <ScanResultsModal
          result={scanResult}
          onClose={() => {
            setScanResult(null);
            setActiveScan(null);
          }}
        />
      </>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-slate-100">
      <Toasts toasts={toasts} removeToast={removeToast} />

      {/* Enhanced Header */}
      <div className="border-b-2 border-slate-700 bg-slate-900 bg-opacity-80 backdrop-blur-lg sticky top-0 z-30 shadow-lg">
        <div className="mx-auto max-w-7xl px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center text-xl shadow-lg">
              🛡️
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">SecureScan</h1>
              <p className="text-xs text-slate-400">
                {profile?.login || "User"}'s Repositories
              </p>
            </div>
          </div>
          {profile && (
            <div className="flex items-center gap-2">
              <img
                src={profile.avatar_url}
                alt={profile.login}
                className="w-10 h-10 rounded-full border-2 border-slate-600"
              />
            </div>
          )}
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-4 py-6">
        {/* Profile Section */}
        {profile && !error && (
          <div className="bg-slate-800 bg-opacity-50 backdrop-blur-sm rounded-2xl p-6 mb-6 border-2 border-slate-700 shadow-xl">
            <div className="flex flex-col md:flex-row items-center md:items-start gap-6">
              <div className="w-24 h-24 rounded-full overflow-hidden border-4 border-slate-600 shadow-lg">
                <img
                  src={profile.avatar_url}
                  alt="avatar"
                  className="w-full h-full object-cover"
                />
              </div>
              <div className="flex-1 text-center md:text-left">
                <h2 className="text-3xl font-bold text-white mb-2">
                  {profile.name || profile.login}
                </h2>
                {profile.name && (
                  <p className="text-slate-400 mb-2">@{profile.login}</p>
                )}
                {profile.bio && (
                  <p className="text-slate-300 leading-relaxed">{profile.bio}</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Search and Filters */}
        {!error && (
          <div className="flex flex-col md:flex-row gap-3 mb-6">
            <input
              placeholder="🔍 Search repositories..."
              value={query}
              onChange={(e) => {
                setPage(1);
                setQuery(e.target.value);
              }}
              className="flex-1 bg-slate-800 border-2 border-slate-600 rounded-lg px-4 py-3 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent shadow-lg"
            />
            <select
              value={type}
              onChange={(e) => {
                setPage(1);
                setType(e.target.value);
              }}
              className="bg-slate-800 border-2 border-slate-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-blue-500 shadow-lg"
            >
              <option value="all">All Repositories</option>
              <option value="owner">Owner</option>
              <option value="member">Member</option>
            </select>
          </div>
        )}

        {/* Not Connected State */}
        {error === "not-connected" && (
          <div className="bg-gradient-to-br from-blue-600 to-purple-600 rounded-2xl p-8 text-center shadow-2xl border-2 border-blue-500">
            <div className="text-6xl mb-4">🔒</div>
            <h3 className="text-2xl font-bold text-white mb-3">
              Connect Your GitHub Account
            </h3>
            <p className="text-blue-100 mb-6 max-w-md mx-auto">
              Link your GitHub account to scan your repositories for security vulnerabilities
            </p>
            <button
              onClick={handleConnectGitHub}
              className="bg-white text-blue-600 hover:bg-blue-50 rounded-lg px-8 py-3 font-bold transition-colors shadow-lg transform hover:scale-105"
            >
              Connect GitHub
            </button>
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="text-center py-12">
            <div className="inline-block animate-spin h-12 w-12 border-4 border-blue-500 border-t-transparent rounded-full mb-4"></div>
            <p className="text-slate-400">Loading repositories...</p>
          </div>
        )}

        {/* Error State */}
        {error && error !== "not-connected" && (
          <div className="bg-red-600 rounded-2xl p-6 text-center shadow-xl border-2 border-red-500">
            <div className="text-4xl mb-3">❌</div>
            <p className="text-white font-medium">{error}</p>
          </div>
        )}

        {/* Repository List */}
        {!loading && !error && (
          <div className="space-y-4">
            {repos.length === 0 ? (
              <div className="bg-slate-800 rounded-2xl p-12 text-center border-2 border-slate-700">
                <div className="text-6xl mb-4">📁</div>
                <p className="text-xl text-slate-400">No repositories found</p>
              </div>
            ) : (
              <>
                {repos.map((repo) => (
                  <RepoCard
                    key={repo.id}
                    repo={repo}
                    addToast={addToast}
                    onScanStart={(scanId) => setActiveScan(scanId)}
                  />
                ))}

                {/* Pagination */}
                <div className="flex items-center justify-center gap-4 mt-8 pb-8">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="bg-slate-700 hover:bg-slate-600 disabled:opacity-40 disabled:cursor-not-allowed border-2 border-slate-600 rounded-lg px-6 py-3 font-medium transition-all transform hover:scale-105 disabled:hover:scale-100 shadow-lg"
                  >
                    ← Previous
                  </button>
                  <span className="text-slate-300 px-4 py-2 bg-slate-800 rounded-lg border-2 border-slate-700 font-medium">
                    Page {page}
                  </span>
                  <button
                    onClick={() => setPage((p) => p + 1)}
                    disabled={repos.length < per_page}
                    className="bg-slate-700 hover:bg-slate-600 disabled:opacity-40 disabled:cursor-not-allowed border-2 border-slate-600 rounded-lg px-6 py-3 font-medium transition-all transform hover:scale-105 disabled:hover:scale-100 shadow-lg"
                  >
                    Next →
                  </button>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// Enhanced Repository Card
function RepoCard({
  repo,
  addToast,
  onScanStart,
}: {
  repo: Repo;
  addToast: (msg: string, type?: "success" | "error" | "info") => void;
  onScanStart: (scanId: string) => void;
}) {
  const [scanning, setScanning] = useState(false);

  const visibility = repo.private
    ? "Private"
    : repo.visibility
    ? repo.visibility[0].toUpperCase() + repo.visibility.slice(1)
    : "Public";

  const handleScan = async () => {
    setScanning(true);
    try {
      const owner = repo.owner?.login || repo.full_name?.split("/")[0];

      const res = await fetch(
        `${API_BASE_URL}/api/scanning/repos/${owner}/${repo.name}/scan?branch=main&scanner=auto`,
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
        }
      );

      if (!res.ok) {
        const error = await res.text();
        throw new Error(`Scan failed: ${res.status}`);
      }

      const data = await res.json();
      addToast(`🚀 Scan initiated for ${repo.name}`, "info");
      onScanStart(data.scan_id);
    } catch (err: any) {
      console.error(err);
      addToast(`❌ Scan failed: ${err.message}`, "error");
      setScanning(false);
    }
  };

  return (
    <div className="bg-slate-800 bg-opacity-70 backdrop-blur-sm border-2 border-slate-700 rounded-xl hover:border-blue-500 transition-all shadow-lg hover:shadow-2xl transform hover:scale-[1.02]">
      <div className="p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap mb-3">
              {repo.owner?.avatar_url && (
                <img
                  src={repo.owner.avatar_url}
                  alt={repo.owner.login}
                  className="w-8 h-8 rounded-full border-2 border-slate-600"
                />
              )}
              <a
                href={repo.html_url ?? "#"}
                target="_blank"
                rel="noreferrer"
                className="text-blue-400 hover:text-blue-300 hover:underline text-xl font-bold truncate transition-colors"
              >
                {repo.name}
              </a>
              <span className={`text-xs px-3 py-1 rounded-full font-medium ${
                repo.private
                  ? "bg-yellow-600 text-white"
                  : "bg-green-600 text-white"
              }`}>
                {visibility}
              </span>
            </div>

            {repo.description && (
              <p className="text-sm text-slate-300 mb-4 leading-relaxed">
                {repo.description}
              </p>
            )}

            <div className="flex gap-4 items-center flex-wrap text-sm text-slate-400">
              {repo.language && (
                <span className="flex items-center gap-2 bg-slate-700 px-3 py-1 rounded-full">
                  <span className="w-3 h-3 rounded-full bg-yellow-400"></span>
                  {repo.language}
                </span>
              )}
              <span className="flex items-center gap-1">⭐ {repo.stargazers_count ?? 0}</span>
              <span className="flex items-center gap-1">🔱 {repo.forks_count ?? 0}</span>
              {repo.size && (
                <span className="flex items-center gap-1">
                  📦 {formatBytes(repo.size * 1024)}
                </span>
              )}
              {repo.updated_at && (
                <span>Updated {timeAgo(repo.updated_at)}</span>
              )}
            </div>
          </div>

          <button
            onClick={handleScan}
            disabled={scanning}
            className={`px-6 py-3 rounded-lg font-bold transition-all transform shadow-lg ${
              scanning
                ? "bg-slate-600 text-slate-400 cursor-not-allowed"
                : "bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white hover:scale-105 hover:shadow-2xl"
            }`}
          >
            {scanning ? (
              <span className="flex items-center gap-2">
                <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                Scanning...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                🛡️ Scan
              </span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}