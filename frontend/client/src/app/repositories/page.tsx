import React, { useEffect, useMemo, useState } from "react";
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

interface RepoFile {
  path: string;
  name: string;
  type: string;
  sha: string;
  size: number;
  url: string;
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
    <div className="fixed top-5 right-5 flex flex-col gap-2 z-50">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`px-4 py-2 rounded shadow-md text-sm cursor-pointer transition-opacity hover:opacity-80 ${
            t.type === "error" 
              ? "bg-red-600 text-white" 
              : t.type === "info"
              ? "bg-blue-600 text-white"
              : "bg-green-600 text-white"
          }`}
          onClick={() => removeToast(t.id)}
        >
          {t.message}
        </div>
      ))}
    </div>
  );
}

// Utility: Time ago
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

// Utility: Format bytes
function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + " " + sizes[i];
}

// Severity Color Mapping
function getSeverityColor(severity: string): string {
  switch (severity) {
    case "CRITICAL":
      return "bg-red-900 text-red-100";
    case "HIGH":
      return "bg-orange-900 text-orange-100";
    case "MEDIUM":
      return "bg-yellow-900 text-yellow-100";
    case "LOW":
      return "bg-blue-900 text-blue-100";
    case "INFO":
      return "bg-gray-700 text-gray-100";
    case "WARNING":
      return "bg-amber-900 text-amber-100";
    default:
      return "bg-gray-700 text-gray-100";
  }
}

// Scan Results Modal
function ScanResultsModal({
  result,
  onClose,
}: {
  result: ScanResult;
  onClose: () => void;
}) {
  const [filteredSeverity, setFilteredSeverity] = useState<string | null>(null);

  const filteredVulns = filteredSeverity
    ? result.vulnerabilities.filter((v) => v.severity === filteredSeverity)
    : result.vulnerabilities;

  const severities: Array<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "WARNING"> = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
    "WARNING",
  ];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1117] rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto border border-[#30363d]">
        {/* Header */}
        <div className="sticky top-0 bg-[#161b22] border-b border-[#30363d] p-6 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-[#c9d1d9]">
              {result.repo_name} Scan Results
            </h2>
            <p className="text-sm text-[#8b949e] mt-1">
              {result.status === "completed"
                ? `Completed in ${result.scan_duration?.toFixed(2)}s`
                : result.status}
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-[#8b949e] hover:text-[#c9d1d9] text-2xl"
          >
            ✕
          </button>
        </div>

        {/* Severity Summary */}
        <div className="p-6 border-b border-[#30363d]">
          <h3 className="text-lg font-semibold text-[#c9d1d9] mb-4">Summary</h3>
          <div className="grid grid-cols-3 md:grid-cols-6 gap-4">
            {severities.map((sev) => {
              const count =
                result.severity_summary[
                  sev.toLowerCase() as keyof SeveritySummary
                ] || 0;
              return (
                <div
                  key={sev}
                  className={`rounded-lg p-3 text-center cursor-pointer transition-all ${getSeverityColor(
                    sev
                  )} ${
                    filteredSeverity === sev
                      ? "ring-2 ring-white"
                      : "hover:ring-2 hover:ring-white"
                  }`}
                  onClick={() =>
                    setFilteredSeverity(
                      filteredSeverity === sev ? null : sev
                    )
                  }
                >
                  <div className="text-xs font-semibold">{sev}</div>
                  <div className="text-xl font-bold mt-1">{count}</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Vulnerabilities List */}
        <div className="p-6">
          <h3 className="text-lg font-semibold text-[#c9d1d9] mb-4">
            Issues Found: {filteredVulns.length}
          </h3>
          {filteredVulns.length === 0 ? (
            <div className="text-center text-[#8b949e] py-8">
              {filteredSeverity
                ? `No ${filteredSeverity} issues found`
                : "No vulnerabilities found"}
            </div>
          ) : (
            <div className="space-y-3">
              {filteredVulns.map((vuln, idx) => (
                <VulnerabilityCard key={idx} vuln={vuln} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Vulnerability Card Component
function VulnerabilityCard({ vuln }: { vuln: Vulnerability }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`rounded-lg border p-4 cursor-pointer transition-all ${getSeverityColor(
      vuln.severity
    )}`}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <h4 className="font-semibold">{vuln.vulnerability_type}</h4>
          <p className="text-sm opacity-90 mt-1">{vuln.message}</p>
          <div className="text-xs opacity-75 mt-2">
            {vuln.location.file}:{vuln.location.start_line}
          </div>
        </div>
        <div className="text-xs font-bold ml-2">{vuln.scanner}</div>
      </div>

      {expanded && (
        <div className="mt-4 pt-4 border-t border-current border-opacity-30 space-y-2">
          <div>
            <span className="text-xs font-semibold opacity-75">Rule ID:</span>
            <code className="text-xs block opacity-90 font-mono mt-1">
              {vuln.rule_id}
            </code>
          </div>
          {vuln.code_snippet && (
            <div>
              <span className="text-xs font-semibold opacity-75">Code:</span>
              <pre className="text-xs opacity-90 font-mono mt-1 bg-black bg-opacity-30 p-2 rounded overflow-x-auto">
                {vuln.code_snippet}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Scan Progress Component
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
          }
        }
      } catch (err) {
        console.error(err);
        setError(err instanceof Error ? err.message : "Unknown error");
      }
    };

    pollStatus();
    pollInterval = setInterval(pollStatus, 1000);

    return () => {
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [scanId, onComplete]);

  if (error) {
    return (
      <div className="bg-red-900 text-red-100 p-4 rounded-lg">
        Error: {error}
      </div>
    );
  }

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-6">
      <div className="text-center">
        <div className="text-2xl font-bold text-[#c9d1d9] mb-2">
          Scanning {repoName}
        </div>
        {status && (
          <>
            <div className="text-lg text-[#8b949e] mb-4">{status.message}</div>
            <div className="w-full bg-[#0d1117] rounded-full h-3 overflow-hidden">
              <div
                className="bg-gradient-to-r from-blue-500 to-purple-500 h-full transition-all duration-500"
                style={{
                  width: status.progress,
                }}
              />
            </div>
            <div className="text-sm text-[#8b949e] mt-2">{status.progress}</div>
          </>
        )}
      </div>
    </div>
  );
}

// Main Page
export default function RepositoriesPage() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [type, setType] = useState("all");
  const [sort, setSort] = useState("updated");
  const [direction, setDirection] = useState("desc");
  const [page, setPage] = useState(1);
  const per_page = 30;

  const [toasts, setToasts] = useState<Toast[]>([]);
  const [activeScan, setActiveScan] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const addToast = (message: string, type?: "success" | "error" | "info") => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => removeToast(id), 4000);
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
        sort,
        direction,
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
  }, [query, type, sort, direction, page]);

  const handleConnectGitHub = () => {
    window.location.href = `${API_BASE_URL}/auth/github/login?redirect_to=/repositories`;
  };

  if (activeScan && !scanResult) {
    const repoName = repos.find((r) => r.id.toString() === activeScan)?.name || "repo";
    return (
      <div className="min-h-screen bg-[#0d1117] text-[#c9d1d9] p-4">
        <ScanProgress
          scanId={activeScan}
          repoName={repoName}
          onComplete={(result) => {
            setScanResult(result);
            addToast("Scan completed!", "success");
          }}
        />
      </div>
    );
  }

  if (scanResult) {
    return (
      <div className="min-h-screen bg-[#0d1117]">
        <ScanResultsModal
          result={scanResult}
          onClose={() => {
            setScanResult(null);
            setActiveScan(null);
          }}
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#c9d1d9]">
      <Toasts toasts={toasts} removeToast={removeToast} />

      <div className="border-b border-[#21262d] bg-[#0d1117] sticky top-0 z-30">
        <div className="mx-auto max-w-7xl px-4 py-2 flex items-center gap-3">
          <div className="text-sm opacity-70">
            {profile?.login || "user"} · Repositories
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-4 py-4 grid grid-cols-12 gap-6">
        <aside className="col-span-12 md:col-span-4 lg:col-span-3 flex flex-col items-center md:items-start gap-4">
          <div className="w-32 h-32 rounded-full overflow-hidden bg-[#161b22] border border-[#30363d]">
            {profile?.avatar_url ? (
              <img
                src={profile.avatar_url}
                alt="avatar"
                className="w-full h-full object-cover"
              />
            ) : (
              <div className="w-full h-full flex items-center justify-center text-4xl">
                👤
              </div>
            )}
          </div>
          <div className="text-center md:text-left w-full">
            <div className="text-2xl font-bold leading-tight">
              {profile?.name || profile?.login || "—"}
            </div>
            {profile?.name && (
              <div className="text-[#8b949e] -mt-1">{profile.login}</div>
            )}
          </div>
          {profile?.bio && (
            <p className="text-sm text-[#8b949e] text-center md:text-left">
              {profile.bio}
            </p>
          )}
        </aside>

        <main className="col-span-12 md:col-span-8 lg:col-span-9">
          {!error && (
            <div className="flex flex-col md:flex-row gap-3 md:items-center mb-4">
              <input
                placeholder="Find a repository..."
                value={query}
                onChange={(e) => {
                  setPage(1);
                  setQuery(e.target.value);
                }}
                className="flex-1 bg-[#0d1117] border border-[#30363d] rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#1f6feb]"
              />
              <select
                value={type}
                onChange={(e) => {
                  setPage(1);
                  setType(e.target.value);
                }}
                className="bg-[#0d1117] border border-[#30363d] rounded-md px-3 py-2 text-sm"
              >
                <option value="all">Type: All</option>
                <option value="owner">Owner</option>
                <option value="member">Member</option>
              </select>
            </div>
          )}

          {error === "not-connected" && (
            <div className="border border-[#30363d] rounded-md p-6 bg-[#161b22]">
              <div className="text-sm text-[#8b949e] mb-4">
                Connect your GitHub account to view and scan repositories.
              </div>
              <button
                onClick={handleConnectGitHub}
                className="bg-[#238636] hover:bg-[#2ea043] text-white rounded-md px-4 py-2 text-sm transition-colors"
              >
                Connect GitHub Account
              </button>
            </div>
          )}

          {loading && (
            <div className="text-[#8b949e] text-sm flex items-center gap-2">
              <div className="animate-spin h-4 w-4 border-2 border-[#8b949e] border-t-transparent rounded-full"></div>
              Loading repositories...
            </div>
          )}

          {error && error !== "not-connected" && (
            <div className="text-sm text-red-400 bg-[#161b22] border border-red-900 rounded-md p-4">
              {error}
            </div>
          )}

          {!loading && !error && (
            <div className="space-y-4">
              {repos.length === 0 ? (
                <div className="text-sm text-[#8b949e] p-6 text-center border border-[#21262d] rounded-md">
                  No repositories found.
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

                  <div className="flex items-center justify-center gap-3 mt-8">
                    <button
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                      disabled={page === 1}
                      className="bg-[#21262d] hover:bg-[#30363d] disabled:opacity-40 disabled:cursor-not-allowed border border-[#30363d] rounded-md px-4 py-2 text-sm transition-colors"
                    >
                      ← Previous
                    </button>
                    <span className="text-sm text-[#8b949e] px-2">
                      Page {page}
                    </span>
                    <button
                      onClick={() => setPage((p) => p + 1)}
                      disabled={repos.length < per_page}
                      className="bg-[#21262d] hover:bg-[#30363d] disabled:opacity-40 disabled:cursor-not-allowed border border-[#30363d] rounded-md px-4 py-2 text-sm transition-colors"
                    >
                      Next →
                    </button>
                  </div>
                </>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

// Repository Card Component
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
      addToast(`Scan started for ${repo.name}`, "info");
      onScanStart(data.scan_id);
    } catch (err: any) {
      console.error(err);
      addToast(`Scan failed: ${err.message}`, "error");
      setScanning(false);
    }
  };

  return (
    <div className="border border-[#30363d] rounded-lg bg-[#0d1117] hover:border-[#8b949e] transition-colors">
      <div className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              {repo.owner?.avatar_url && (
                <img
                  src={repo.owner.avatar_url}
                  alt={repo.owner.login}
                  className="w-5 h-5 rounded-full"
                />
              )}
              <a
                href={repo.html_url ?? "#"}
                target="_blank"
                rel="noreferrer"
                className="text-[#58a6ff] hover:underline text-lg font-semibold truncate"
              >
                {repo.name}
              </a>
              <span className="text-xs border border-[#30363d] text-[#8b949e] rounded-full px-2 py-0.5">
                {visibility}
              </span>
            </div>

            {repo.description && (
              <p className="text-sm text-[#8b949e] mt-2 line-clamp-2">
                {repo.description}
              </p>
            )}

            <div className="text-xs text-[#8b949e] mt-3 flex gap-4 items-center flex-wrap">
              {repo.language && (
                <span className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded-full bg-[#f1e05a]"></span>
                  {repo.language}
                </span>
              )}
              <span>⭐ {repo.stargazers_count ?? 0}</span>
              <span>🔱 {repo.forks_count ?? 0}</span>
              {repo.size && (
                <span>📦 {formatBytes(repo.size * 1024)}</span>
              )}
              {repo.updated_at && (
                <span>Updated {timeAgo(repo.updated_at)}</span>
              )}
            </div>
          </div>

          <button
            onClick={handleScan}
            disabled={scanning}
            className={`border border-[#30363d] rounded-md px-4 py-2 text-sm transition-colors whitespace-nowrap font-medium ${
              scanning
                ? "bg-[#8b949e] text-[#0d1117] cursor-not-allowed"
                : "bg-[#238636] hover:bg-[#2ea043] text-white"
            }`}
          >
            {scanning ? "Scanning..." : "🔐 Scan"}
          </button>
        </div>
      </div>
    </div>
  );
}