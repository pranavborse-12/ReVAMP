import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";

const API = "http://localhost:8000";

// ── Pure Black Enterprise Palette ──────────────────────────
const C = {
  bg:          "#000000",   // Pure black background
  surface:     "#0a0a0a",   // Level 1 surface
  surface2:    "#141414",   // Level 2 hover surface
  border:      "#262626",   // Crisp borders
  borderHover: "#3f3f46",   // Hover borders
  text:        "#f4f4f5",   // High-contrast text
  muted:       "#a1a1aa",   // Secondary text
  subtle:      "#52525b",   // Placeholder / dim
  accent:      "#3b82f6",   // Professional blue
  indigo:      "#6366f1",   // Accent for headers
};

interface Scan {
  scan_id: string;
  repo_owner: string;
  repo_name: string;
  branch_name: string;
  scanner_used: string;
  status: string;
  total_vulnerabilities: number;
  total_issues: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  warning_count: number;
  files_scanned: number;
  scan_duration_seconds: number;
  scan_duration: number;
  queued_at: string;
  started_at: string;
  completed_at: string;
  error_message: string;
  detected_languages: string[];
  last_commit_sha: string;
  severity_summary: Record<string, number>;
}

// ── SVG Icons replacing text emojis ──
const ICONS = {
  check: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>,
  cross: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>,
  sync: <svg className="spin-anim" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.59-10.36l5.25 4.79"></path></svg>,
  clock: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>,
  cancel: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>,
};

const STATUS_CONFIG: Record<string, { color: string; bg: string; label: string; icon: JSX.Element }> = {
  completed: { color: "#10b981", bg: "rgba(16, 185, 129, 0.1)",  label: "Completed", icon: ICONS.check },
  failed:    { color: "#ef4444", bg: "rgba(239, 68, 68, 0.1)",   label: "Failed",    icon: ICONS.cross },
  running:   { color: "#3b82f6", bg: "rgba(59, 130, 246, 0.1)",  label: "Running",   icon: ICONS.sync },
  queued:    { color: "#f59e0b", bg: "rgba(245, 158, 11, 0.1)",  label: "Queued",    icon: ICONS.clock },
  scanning:  { color: "#3b82f6", bg: "rgba(59, 130, 246, 0.1)",  label: "Scanning",  icon: ICONS.sync },
  cloning:   { color: "#3b82f6", bg: "rgba(59, 130, 246, 0.1)",  label: "Cloning",   icon: ICONS.sync },
  cancelled: { color: "#a1a1aa", bg: "rgba(161, 161, 170, 0.1)", label: "Cancelled", icon: ICONS.cancel },
};

function getStatus(s: string) {
  return STATUS_CONFIG[s?.toLowerCase()] || STATUS_CONFIG.queued;
}

function formatDuration(seconds: number) {
  if (!seconds) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

function formatDate(iso: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return (
    d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }) +
    " " +
    d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
  );
}

function timeAgo(iso: string) {
  if (!iso) return "";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  const hours = Math.floor(mins / 60);
  const days = Math.floor(hours / 24);
  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (mins > 0) return `${mins}m ago`;
  return "just now";
}

export default function ScanHistory() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [filtered, setFiltered] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [deleting, setDeleting] = useState<string | null>(null);
  const [stats, setStats] = useState({ total: 0, completed: 0, failed: 0, running: 0 });

  const loadScans = () => {
    setLoading(true);
    setError("");
    fetch(`${API}/api/scanning/scans/history`, { credentials: "include" })
      .then((r) => {
        if (!r.ok) throw new Error(`${r.status}`);
        return r.json();
      })
      .then((data) => {
        const list: Scan[] = data.scans || [];
        list.sort((a, b) => new Date(b.queued_at).getTime() - new Date(a.queued_at).getTime());
        setScans(list);
        setStats({
          total: list.length,
          completed: list.filter((s) => s.status === "completed").length,
          failed: list.filter((s) => s.status === "failed").length,
          running: list.filter((s) =>
            ["running", "scanning", "cloning", "queued"].includes(s.status)
          ).length,
        });
      })
      .catch((e) => setError(`Failed to fetch scan history (${e.message})`))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadScans();
  }, []);

  useEffect(() => {
    let result = [...scans];
    if (statusFilter !== "all") result = result.filter((s) => s.status === statusFilter);
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (s) =>
          s.scan_id?.toLowerCase().includes(q) ||
          s.branch_name?.toLowerCase().includes(q) ||
          s.scanner_used?.toLowerCase().includes(q)
      );
    }
    setFiltered(result);
  }, [scans, statusFilter, search]);

  const deleteScan = async (scanId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Delete this scan and all its vulnerability data?")) return;
    setDeleting(scanId);
    try {
      await fetch(`${API}/api/scanning/scans/${scanId}`, {
        method: "DELETE",
        credentials: "include",
      });
      setScans((prev) => prev.filter((s) => s.scan_id !== scanId));
    } catch {
      alert("Failed to delete scan");
    } finally {
      setDeleting(null);
    }
  };

  const statCards = [
    { label: "Total Scans", value: stats.total,     color: C.text },
    { label: "Completed",   value: stats.completed, color: "#10b981" },
    { label: "Failed",      value: stats.failed,    color: "#ef4444" },
    { label: "Running",     value: stats.running,   color: C.accent },
  ];

  return (
    <div style={{ background: C.bg, minHeight: "100vh", color: C.text, fontFamily: "'Inter', system-ui, -apple-system, sans-serif" }}>
      
      {/* CSS for smooth animations */}
      <style>{`
        @keyframes spin { 100% { transform: rotate(360deg); } }
        .spin-anim { animation: spin 2s linear infinite; }
      `}</style>

      {/* ── Header ─────────────────────────────────────────── */}
      <div style={{ padding: "32px 40px 0", maxWidth: "1400px", margin: "0 auto" }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontSize: 11, color: C.subtle, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 8, fontWeight: 600 }}>
              Security Engine
            </div>
            <h1 style={{ margin: 0, fontSize: 28, fontWeight: 600, color: C.text, letterSpacing: "-0.02em" }}>Scan History</h1>
            <p style={{ margin: "6px 0 0", fontSize: 13, color: C.muted }}>Review and manage historical repository security scans</p>
          </div>
          <button
            onClick={loadScans}
            style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "8px 16px",
              background: C.surface,
              border: `1px solid ${C.border}`,
              borderRadius: 6,
              color: C.text,
              fontSize: 13,
              fontWeight: 500,
              cursor: "pointer",
              transition: "all 0.15s ease",
            }}
            onMouseOver={(e) => { e.currentTarget.style.borderColor = C.borderHover; e.currentTarget.style.background = C.surface2; }}
            onMouseOut={(e) => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.background = C.surface; }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.59-10.36l5.25 4.79"></path></svg>
            Refresh Data
          </button>
        </div>

        {/* Stat Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16, marginTop: 32 }}>
          {statCards.map((card) => (
            <div
              key={card.label}
              style={{ 
                background: C.surface, 
                border: `1px solid ${C.border}`, 
                borderRadius: 8, 
                padding: "20px",
                transition: "transform 0.2s ease, border-color 0.2s ease",
                cursor: "default"
              }}
              onMouseOver={(e) => { e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.borderColor = C.borderHover; }}
              onMouseOut={(e) => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.borderColor = C.border; }}
            >
              <div style={{ fontSize: 12, color: C.muted, fontWeight: 500, marginBottom: 8 }}>
                {card.label}
              </div>
              <div style={{ fontSize: 28, fontWeight: 600, color: card.color, letterSpacing: "-0.03em" }}>
                {loading ? "—" : card.value}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Filters ─────────────────────────────────────────── */}
      <div style={{ padding: "32px 40px 16px", maxWidth: "1400px", margin: "0 auto", display: "flex", gap: 16, borderBottom: `1px solid ${C.border}` }}>
        
        {/* Search */}
        <div style={{ position: "relative", flex: 1, maxWidth: 400 }}>
          <svg style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={C.subtle} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search scan ID, branch, or scanner..."
            style={{
              width: "100%",
              background: C.surface,
              border: `1px solid ${C.border}`,
              borderRadius: 6,
              padding: "8px 36px",
              color: C.text,
              fontSize: 13,
              outline: "none",
              boxSizing: "border-box",
              transition: "border-color 0.15s ease, background 0.15s ease",
            }}
            onFocus={(e) => { e.target.style.borderColor = C.accent; e.target.style.background = C.bg; }}
            onBlur={(e) => { e.target.style.borderColor = C.border; e.target.style.background = C.surface; }}
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: C.muted, cursor: "pointer", padding: 4 }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
          )}
        </div>

        {/* Status Filter */}
        <div style={{ position: "relative" }}>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{
              appearance: "none",
              background: C.surface,
              border: `1px solid ${C.border}`,
              borderRadius: 6,
              padding: "8px 36px 8px 12px",
              color: C.text,
              fontSize: 13,
              fontWeight: 500,
              outline: "none",
              cursor: "pointer",
              minWidth: 160,
              transition: "border-color 0.15s ease",
            }}
            onMouseOver={(e) => e.currentTarget.style.borderColor = C.borderHover}
            onMouseOut={(e) => e.currentTarget.style.borderColor = C.border}
          >
            <option value="all">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="running">Running</option>
            <option value="queued">Queued</option>
          </select>
          <svg style={{ position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={C.muted} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
        </div>
      </div>

      {/* ── Scan List ───────────────────────────────────────── */}
      <div style={{ padding: "24px 40px", maxWidth: "1400px", margin: "0 auto" }}>
        {error && (
          <div
            style={{
              background: "rgba(239, 68, 68, 0.05)",
              border: "1px solid rgba(239, 68, 68, 0.2)",
              borderRadius: 8,
              padding: "16px 20px",
              marginBottom: 24,
              color: "#ef4444",
              fontSize: 13,
              display: "flex",
              alignItems: "center",
              gap: 12,
            }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            {error}
            <button
              onClick={loadScans}
              style={{
                marginLeft: "auto",
                padding: "6px 12px",
                background: "rgba(239, 68, 68, 0.1)",
                border: "1px solid rgba(239, 68, 68, 0.2)",
                borderRadius: 4,
                color: "#ef4444",
                fontSize: 12,
                cursor: "pointer",
                fontWeight: 500,
                transition: "background 0.15s ease"
              }}
              onMouseOver={(e) => e.currentTarget.style.background = "rgba(239, 68, 68, 0.15)"}
              onMouseOut={(e) => e.currentTarget.style.background = "rgba(239, 68, 68, 0.1)"}
            >
              Try again
            </button>
          </div>
        )}

        {loading ? (
          <div style={{ display: "flex", justifyContent: "center", padding: "60px 0" }}>
            <div style={{ color: C.subtle, fontSize: 13 }}>Fetching scans...</div>
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: "center", padding: "80px 20px", border: `1px dashed ${C.border}`, borderRadius: 8 }}>
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke={C.subtle} strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: 16 }}><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
            <div style={{ fontSize: 14, color: C.text, fontWeight: 500, marginBottom: 8 }}>
              {scans.length === 0 ? "No scan history available" : "No matches found"}
            </div>
            <div style={{ fontSize: 13, color: C.muted }}>
              {scans.length === 0 ? "Start a new scan from the Repositories tab." : "Try adjusting your search or filters."}
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {filtered.map((scan) => {
              const st = getStatus(scan.status);
              const isDeleting = deleting === scan.scan_id;
              
              return (
                <div
                  key={scan.scan_id}
                  onClick={() => scan.status === "completed" && navigate(`/vulnerabilities?scan_id=${scan.scan_id}`)}
                  style={{
                    background: C.surface,
                    border: `1px solid ${C.border}`,
                    borderRadius: 8,
                    padding: "20px 24px",
                    cursor: scan.status === "completed" ? "pointer" : "default",
                    transition: "all 0.2s ease",
                    opacity: isDeleting ? 0.5 : 1,
                    display: "grid",
                    gridTemplateColumns: "auto 1fr auto",
                    gap: 20,
                    alignItems: "center",
                  }}
                  onMouseEnter={(e) => {
                    if (scan.status === "completed") {
                      (e.currentTarget as HTMLDivElement).style.borderColor = C.borderHover;
                      (e.currentTarget as HTMLDivElement).style.background = C.surface2;
                      (e.currentTarget as HTMLDivElement).style.transform = "translateY(-1px)";
                    }
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLDivElement).style.borderColor = C.border;
                    (e.currentTarget as HTMLDivElement).style.background = C.surface;
                    (e.currentTarget as HTMLDivElement).style.transform = "translateY(0)";
                  }}
                >
                  {/* Status indicator */}
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8, width: 64 }}>
                    <div
                      style={{
                        width: 40, height: 40, borderRadius: "50%",
                        background: st.bg,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        color: st.color,
                        boxShadow: `0 0 0 1px ${st.color}33`,
                      }}
                    >
                      {st.icon}
                    </div>
                    <span style={{ fontSize: 10, color: st.color, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                      {st.label}
                    </span>
                  </div>

                  {/* Main info */}
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
                      <code style={{ fontSize: 12, color: C.muted, fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
                        {scan.scan_id.substring(0, 8)}
                      </code>
                      <span style={{ fontSize: 11, color: C.borderHover }}>|</span>
                      <span style={{ fontSize: 15, color: C.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {scan.repo_name || scan.repo_owner}
                      </span>
                      {scan.branch_name && (
                        <>
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={C.subtle} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="6" y1="3" x2="6" y2="15"></line><circle cx="18" cy="6" r="3"></circle><circle cx="6" cy="18" r="3"></circle><path d="M18 9a9 9 0 0 1-9 9"></path></svg>
                          <span style={{ fontSize: 12, color: C.muted }}>{scan.branch_name}</span>
                        </>
                      )}
                      <span style={{ fontSize: 12, color: C.subtle, marginLeft: "auto" }}>
                        {timeAgo(scan.completed_at || scan.started_at)}
                      </span>
                    </div>

                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
                      {scan.severity_summary?.CRITICAL > 0 && (
                        <span style={{ fontSize: 11, fontWeight: 500, padding: "2px 8px", background: "rgba(239, 68, 68, 0.08)", color: "#ef4444", borderRadius: 4, border: "1px solid rgba(239, 68, 68, 0.2)" }}>
                          {scan.severity_summary.CRITICAL} Critical
                        </span>
                      )}
                      {scan.severity_summary?.HIGH > 0 && (
                        <span style={{ fontSize: 11, fontWeight: 500, padding: "2px 8px", background: "rgba(245, 158, 11, 0.08)", color: "#f59e0b", borderRadius: 4, border: "1px solid rgba(245, 158, 11, 0.2)" }}>
                          {scan.severity_summary.HIGH} High
                        </span>
                      )}
                      {scan.severity_summary?.MEDIUM > 0 && (
                        <span style={{ fontSize: 11, fontWeight: 500, padding: "2px 8px", background: "rgba(59, 130, 246, 0.08)", color: C.accent, borderRadius: 4, border: "1px solid rgba(59, 130, 246, 0.2)" }}>
                          {scan.severity_summary.MEDIUM} Medium
                        </span>
                      )}
                      {!scan.severity_summary && (scan.total_issues || scan.total_vulnerabilities) > 0 && (
                        <span style={{ fontSize: 11, fontWeight: 500, padding: "2px 8px", background: C.surface2, color: C.muted, borderRadius: 4, border: `1px solid ${C.border}` }}>
                          {scan.total_issues || scan.total_vulnerabilities} Issues
                        </span>
                      )}
                      {scan.status === "completed" && (scan.total_issues || scan.total_vulnerabilities || 0) === 0 && (
                        <span style={{ fontSize: 11, fontWeight: 500, padding: "2px 8px", background: "rgba(16, 185, 129, 0.08)", color: "#10b981", borderRadius: 4, border: "1px solid rgba(16, 185, 129, 0.2)" }}>
                          Clean Codebase
                        </span>
                      )}
                    </div>

                    <div style={{ display: "flex", gap: 20, fontSize: 11, color: C.subtle }}>
                      {scan.scan_duration && (
                        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                          {formatDuration(scan.scan_duration)}
                        </div>
                      )}
                      {scan.completed_at && (
                        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                          {formatDate(scan.completed_at)}
                        </div>
                      )}
                      {scan.scanner_used && (
                        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"></path><path d="M2 17l10 5 10-5"></path><path d="M2 12l10 5 10-5"></path></svg>
                          {scan.scanner_used}
                        </div>
                      )}
                    </div>

                    {scan.error_message && (
                      <div
                        style={{
                          marginTop: 12,
                          fontSize: 12,
                          color: "#ef4444",
                          background: "rgba(239, 68, 68, 0.05)",
                          padding: "8px 12px",
                          borderRadius: 4,
                          border: "1px solid rgba(239, 68, 68, 0.2)",
                          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                        }}
                      >
                        {scan.error_message}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {scan.status === "completed" && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/vulnerabilities?scan_id=${scan.scan_id}`);
                        }}
                        style={{
                          display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
                          padding: "8px 16px",
                          background: C.text,
                          border: "none",
                          borderRadius: 6,
                          color: C.bg,
                          fontSize: 12,
                          fontWeight: 600,
                          cursor: "pointer",
                          transition: "background 0.15s ease",
                        }}
                        onMouseOver={(e) => e.currentTarget.style.background = "#d4d4d8"}
                        onMouseOut={(e) => e.currentTarget.style.background = C.text}
                      >
                        View Report
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                      </button>
                    )}
                    <button
                      onClick={(e) => deleteScan(scan.scan_id, e)}
                      disabled={isDeleting}
                      style={{
                        padding: "8px 16px",
                        background: "transparent",
                        border: `1px solid ${C.border}`,
                        borderRadius: 6,
                        color: C.subtle,
                        fontSize: 12,
                        fontWeight: 500,
                        cursor: "pointer",
                        transition: "all 0.15s ease",
                      }}
                      onMouseOver={(e) => { e.currentTarget.style.borderColor = "#ef4444"; e.currentTarget.style.color = "#ef4444"; e.currentTarget.style.background = "rgba(239, 68, 68, 0.05)"; }}
                      onMouseOut={(e) => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.subtle; e.currentTarget.style.background = "transparent"; }}
                    >
                      {isDeleting ? "Deleting..." : "Delete Scan"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}