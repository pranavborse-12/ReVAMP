import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";

const API = "http://localhost:8000";

interface Repo {
  id: string;
  name: string;
  full_name: string;
  description: string;
  language: string;
  private: boolean;
  stargazers_count: number;
  updated_at: string;
  default_branch: string;
}

interface ScanState {
  scanId: string;
  status: string;
  progress: string[];
  total_vulnerabilities: number;
  error?: string;
}

const LANG_COLORS: Record<string, string> = {
  Python: "#3572A5", JavaScript: "#f1e05a", TypeScript: "#2b7489",
  Java: "#b07219", Go: "#00ADD8", Rust: "#dea584", Ruby: "#701516",
  "C++": "#f34b7d", C: "#555555", PHP: "#4F5D95", Swift: "#ffac45",
};

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const days = Math.floor(diff / 86400000);
  const hours = Math.floor(diff / 3600000);
  const mins = Math.floor(diff / 60000);
  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  return `${mins}m ago`;
}

const STATUS_MESSAGES: Record<string, string> = {
  queued: "Waiting in queue...",
  cloning: "Cloning repository...",
  analyzing: "Detecting languages...",
  scanning: "Running security scanners...",
  completed: "Scan complete!",
  failed: "Scan failed",
};

export default function CodeScanner() {
  const navigate = useNavigate();
  const [repos, setRepos] = useState<Repo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [branches, setBranches] = useState<Record<string, string>>({});
  const [scans, setScans] = useState<Record<string, ScanState>>({});
  const pollRefs = useRef<Record<string, ReturnType<typeof setInterval>>>({});

  useEffect(() => {
    fetch(`${API}/api/github/repos?sort=updated&per_page=50`, { credentials: "include" })
      .then(r => { if (!r.ok) throw new Error(); return r.json(); })
      .then(data => {
        const list: Repo[] = data.repositories || data || [];
        setRepos(list);
        const defaultBranches: Record<string, string> = {};
        list.forEach(r => { defaultBranches[r.full_name] = r.default_branch || "main"; });
        setBranches(defaultBranches);
      })
      .catch(() => setError("Failed to load repositories"))
      .finally(() => setLoading(false));

    return () => { Object.values(pollRefs.current).forEach(clearInterval); };
  }, []);

  const startScan = async (repo: Repo) => {
    const branch = branches[repo.full_name] || repo.default_branch || "main";
    const [owner, repoName] = repo.full_name.split("/");

    setScans(prev => ({
      ...prev,
      [repo.full_name]: { scanId: "", status: "queued", progress: ["Initiating scan..."], total_vulnerabilities: 0 }
    }));

    try {
      const res = await fetch(`${API}/api/scanning/repos/${owner}/${repoName}/scan?branch=${branch}`, {
        method: "POST", credentials: "include"
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      const scanId = data.scan_id;

      setScans(prev => ({
        ...prev,
        [repo.full_name]: { scanId, status: "queued", progress: ["Scan queued", "Waiting to start..."], total_vulnerabilities: 0 }
      }));

      // Poll status
      const poll = setInterval(async () => {
        try {
          const r = await fetch(`${API}/api/scanning/scans/${scanId}/status`, { credentials: "include" });
          const d = await r.json();
          const status = d.status;
          const msg = STATUS_MESSAGES[status] || status;

          setScans(prev => {
            const current = prev[repo.full_name];
            const newProgress = current.progress.includes(msg) ? current.progress : [...current.progress, msg];
            return {
              ...prev,
              [repo.full_name]: {
                ...current,
                status,
                progress: newProgress,
                total_vulnerabilities: d.total_vulnerabilities || 0,
                error: d.error_message,
              }
            };
          });

          if (["completed", "failed", "cancelled"].includes(status)) {
            clearInterval(poll);
            delete pollRefs.current[repo.full_name];

            if (status === "completed") {
              // Fetch full result
              const full = await fetch(`${API}/api/scanning/scans/${scanId}`, { credentials: "include" });
              const fullData = await full.json();
              setScans(prev => ({
                ...prev,
                [repo.full_name]: {
                  ...prev[repo.full_name],
                  total_vulnerabilities: fullData.total_vulnerabilities || 0,
                  progress: [...prev[repo.full_name].progress, `Found ${fullData.total_vulnerabilities || 0} vulnerabilities`],
                }
              }));
            }
          }
        } catch { }
      }, 2000);

      pollRefs.current[repo.full_name] = poll;
    } catch (e: any) {
      setScans(prev => ({
        ...prev,
        [repo.full_name]: { scanId: "", status: "failed", progress: ["Scan failed to start"], total_vulnerabilities: 0, error: e.message }
      }));
    }
  };

  const filtered = repos.filter(r =>
    !search || r.full_name.toLowerCase().includes(search.toLowerCase()) || (r.language || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ background: "#0a0a0f", minHeight: "100vh", color: "#e2e8f0", fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
      {/* Header */}
      <div style={{ padding: "28px 32px 20px", borderBottom: "1px solid #1e2030" }}>
        <div style={{ fontSize: 10, color: "#6366f1", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 6 }}>Security Platform</div>
        <h1 style={{ margin: 0, fontSize: 24, fontWeight: 800, color: "#e2e8f0" }}>Code Scanner</h1>
        <p style={{ margin: "6px 0 0", fontSize: 12, color: "#4a5568" }}>Run security scans on your GitHub repositories</p>
      </div>

      {/* Scanner config bar */}
      <div style={{ padding: "14px 32px", borderBottom: "1px solid #1e2030", background: "#0d0f1a", display: "flex", alignItems: "center", gap: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#06d6a0", boxShadow: "0 0 6px #06d6a0" }} />
          <span style={{ fontSize: 11, color: "#06d6a0" }}>Semgrep active</span>
        </div>
        <div style={{ width: 1, height: 16, background: "#1e2030" }} />
        <span style={{ fontSize: 11, color: "#4a5568" }}>Auto-detect languages</span>
        <div style={{ width: 1, height: 16, background: "#1e2030" }} />
        <span style={{ fontSize: 11, color: "#4a5568" }}>OWASP Top 10 · Secrets · Language rules</span>
        <div style={{ flex: 1 }} />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter repositories..."
          style={{ background: "#0f111a", border: "1px solid #1e2030", borderRadius: 8, padding: "7px 12px", color: "#e2e8f0", fontSize: 11, outline: "none", width: 220 }}
        />
      </div>

      {/* Repo Grid */}
      <div style={{ padding: "24px 32px" }}>
        {error && (
          <div style={{ background: "rgba(255,77,77,0.1)", border: "1px solid rgba(255,77,77,0.3)", borderRadius: 10, padding: 16, marginBottom: 20, color: "#ff4d4d", fontSize: 12 }}>
            ✗ {error}
          </div>
        )}

        {loading ? (
          <div style={{ color: "#4a5568", fontSize: 12 }}>Loading repositories...</div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: "center", padding: "60px 20px", color: "#4a5568" }}>
            <div style={{ fontSize: 40, marginBottom: 12 }}>📦</div>
            <div style={{ fontSize: 14 }}>No repositories found</div>
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(440px, 1fr))", gap: 16 }}>
            {filtered.map(repo => {
              const scanState = scans[repo.full_name];
              const isScanning = scanState && !["completed", "failed", "cancelled"].includes(scanState.status) && scanState.status !== "";
              const isDone = scanState?.status === "completed";
              const isFailed = scanState?.status === "failed";
              const branch = branches[repo.full_name] || repo.default_branch || "main";

              return (
                <div
                  key={repo.full_name}
                  style={{
                    background: "#0f111a",
                    border: `1px solid ${isDone ? "rgba(6,214,160,0.3)" : isFailed ? "rgba(255,77,77,0.3)" : "#1e2030"}`,
                    borderRadius: 12,
                    overflow: "hidden",
                    transition: "border-color 0.3s",
                  }}
                >
                  {/* Repo header */}
                  <div style={{ padding: "16px 20px" }}>
                    <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                          <span style={{ fontSize: 13, fontWeight: 700, color: "#e2e8f0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {repo.name}
                          </span>
                          {repo.private && (
                            <span style={{ fontSize: 9, padding: "1px 6px", background: "rgba(99,102,241,0.1)", color: "#6366f1", borderRadius: 3, border: "1px solid rgba(99,102,241,0.3)", flexShrink: 0 }}>Private</span>
                          )}
                        </div>
                        <div style={{ fontSize: 10, color: "#4a5568", marginBottom: 6 }}>{repo.full_name}</div>
                        {repo.description && (
                          <div style={{ fontSize: 11, color: "#718096", marginBottom: 8, overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                            {repo.description}
                          </div>
                        )}
                        <div style={{ display: "flex", gap: 12, fontSize: 10, color: "#4a5568", alignItems: "center" }}>
                          {repo.language && (
                            <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                              <span style={{ width: 8, height: 8, borderRadius: "50%", background: LANG_COLORS[repo.language] || "#4a5568" }} />
                              {repo.language}
                            </span>
                          )}
                          {repo.stargazers_count > 0 && <span>★ {repo.stargazers_count}</span>}
                          <span>{timeAgo(repo.updated_at)}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Scan terminal output */}
                  {scanState && (
                    <div style={{ margin: "0 16px", background: "#060709", border: "1px solid #1a1a2e", borderRadius: 8, padding: "10px 14px", marginBottom: 12, maxHeight: 100, overflowY: "auto" }}>
                      {scanState.progress.map((line, i) => (
                        <div key={i} style={{ fontSize: 10, color: i === scanState.progress.length - 1 ? "#06d6a0" : "#4a5568", lineHeight: 1.8 }}>
                          <span style={{ color: "#6366f1" }}>$ </span>{line}
                          {i === scanState.progress.length - 1 && isScanning && <span style={{ animation: "blink 1s infinite" }}>▌</span>}
                        </div>
                      ))}
                      {isDone && (
                        <div style={{ fontSize: 10, color: "#06d6a0", marginTop: 4 }}>
                          ✓ {scanState.total_vulnerabilities} vulnerabilities found
                        </div>
                      )}
                    </div>
                  )}

                  {/* Branch + Scan button */}
                  <div style={{ padding: "0 16px 16px", display: "flex", gap: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", background: "#060709", border: "1px solid #1e2030", borderRadius: 8, padding: "0 10px", flex: 1 }}>
                      <span style={{ fontSize: 10, color: "#4a5568", marginRight: 6 }}>⎇</span>
                      <input
                        value={branch}
                        onChange={e => setBranches(prev => ({ ...prev, [repo.full_name]: e.target.value }))}
                        style={{ flex: 1, background: "transparent", border: "none", color: "#a0aec0", fontSize: 11, outline: "none", padding: "8px 0" }}
                        placeholder="branch"
                      />
                    </div>

                    {isDone ? (
                      <button
                        onClick={() => navigate(`/vulnerabilities?scan_id=${scanState.scanId}`)}
                        style={{ padding: "0 16px", background: "rgba(6,214,160,0.1)", border: "1px solid rgba(6,214,160,0.3)", borderRadius: 8, color: "#06d6a0", fontSize: 11, cursor: "pointer", whiteSpace: "nowrap" }}
                      >
                        View Results →
                      </button>
                    ) : (
                      <button
                        onClick={() => !isScanning && startScan(repo)}
                        disabled={isScanning}
                        style={{
                          padding: "0 20px",
                          background: isScanning ? "rgba(99,102,241,0.05)" : "rgba(99,102,241,0.15)",
                          border: `1px solid ${isScanning ? "rgba(99,102,241,0.2)" : "rgba(99,102,241,0.4)"}`,
                          borderRadius: 8, color: isScanning ? "#4a5568" : "#6366f1",
                          fontSize: 11, cursor: isScanning ? "not-allowed" : "pointer",
                          whiteSpace: "nowrap", fontFamily: "inherit",
                        }}
                      >
                        {isScanning ? "Scanning..." : "Scan Now"}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <style>{`
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}