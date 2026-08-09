import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";

const API = "http://localhost:8000";

// Pure Black Enterprise Palette
const C = {
  bg:      "#000000", // Pure black background
  surface: "#0a0a0a", // Elevated surface level 1
  surface2: "#141414", // Elevated surface level 2 (hover states)
  border:  "#262626", // Crisp, subtle borders
  borderH: "#3f3f46", // Hover borders
  text:    "#f4f4f5", // High-contrast text
  muted:   "#a1a1aa", // Secondary text
  subtle:  "#52525b", // Tertiary/disabled text
  accent:  "#3b82f6", // Professional primary blue
};

interface Vulnerability {
  id: string;
  rule_id: string;
  scanner_name: string;
  severity: string;
  message: string;
  vulnerability_type: string;
  confidence: string;
  file_path: string;
  start_line: number;
  end_line: number;
  code_snippet: string;
  cwe_ids: string[];
  owasp_categories: string[];
}

interface Scan {
  scan_id: string;
  repo_owner: string;
  repo_name: string;
  status: string;
  total_issues: number;
  severity_summary: Record<string, number>;
  completed_at: string;
}

// Calibrated severities for pure black background
const SEV: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "#ef4444", bg: "rgba(239, 68, 68, 0.08)",  border: "rgba(239, 68, 68, 0.25)" },
  high:     { color: "#f59e0b", bg: "rgba(245, 158, 11, 0.08)", border: "rgba(245, 158, 11, 0.25)" },
  medium:   { color: "#3b82f6", bg: "rgba(59, 130, 246, 0.08)", border: "rgba(59, 130, 246, 0.25)" },
  low:      { color: "#10b981", bg: "rgba(16, 185, 129, 0.08)", border: "rgba(16, 185, 129, 0.25)" },
  info:     { color: "#a1a1aa", bg: "rgba(161, 161, 170, 0.08)", border: "rgba(161, 161, 170, 0.25)" },
  warning:  { color: "#f59e0b", bg: "rgba(245, 158, 11, 0.08)", border: "rgba(245, 158, 11, 0.25)" },
};

function s(sev: string) { return SEV[sev?.toLowerCase()] || SEV.info; }

function timeAgo(iso: string) {
  if (!iso) return "";
  const diff = Date.now() - new Date(iso).getTime();
  const d = Math.floor(diff / 86400000);
  const h = Math.floor(diff / 3600000);
  const m = Math.floor(diff / 60000);
  if (d > 0) return `${d}d ago`;
  if (h > 0) return `${h}h ago`;
  return `${m}m ago`;
}

export default function Vulnerabilities() {
  const [searchParams] = useSearchParams();
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [filtered, setFiltered] = useState<Vulnerability[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadingVulns, setLoadingVulns] = useState(false);
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("all");

  // --- LOGIC AND CONNECTIONS REMAINS UNTOUCHED ---
  useEffect(() => {
    fetch(`${API}/api/scanning/scans/history`, { credentials: "include" })
      .then((r) => r.json())
      .then((data) => {
        const completed = (data.scans || []).filter((sc: Scan) => sc.status === "completed");
        setScans(completed);
        const paramId = searchParams.get("scan_id");
        const toSelect = paramId
          ? completed.find((sc: Scan) => sc.scan_id === paramId)
          : completed[0];
        if (toSelect) setSelectedScan(toSelect);
      })
      .finally(() => setLoadingScans(false));
  }, []);

  useEffect(() => {
    if (!selectedScan) return;
    setLoadingVulns(true);
    setExpanded(null);
    fetch(`${API}/api/scanning/scans/${selectedScan.scan_id}`, { credentials: "include" })
      .then((r) => r.json())
      .then((data) => setVulnerabilities(data.vulnerabilities || []))
      .finally(() => setLoadingVulns(false));
  }, [selectedScan]);

  useEffect(() => {
    let result = [...vulnerabilities];
    if (sevFilter !== "all") result = result.filter((v) => v.severity?.toLowerCase() === sevFilter);
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (v) =>
          v.file_path?.toLowerCase().includes(q) ||
          v.message?.toLowerCase().includes(q) ||
          v.rule_id?.toLowerCase().includes(q)
      );
    }
    setFiltered(result);
  }, [vulnerabilities, sevFilter, search]);

  const counts = {
    all:      vulnerabilities.length,
    critical: vulnerabilities.filter((v) => v.severity?.toLowerCase() === "critical").length,
    high:     vulnerabilities.filter((v) => v.severity?.toLowerCase() === "high").length,
    medium:   vulnerabilities.filter((v) => v.severity?.toLowerCase() === "medium").length,
    low:      vulnerabilities.filter((v) => v.severity?.toLowerCase() === "low").length,
  };

  const TABS = [
    { key: "all",      label: "All Issues", accent: C.text },
    { key: "critical", label: "Critical",   accent: SEV.critical.color },
    { key: "high",     label: "High",       accent: SEV.high.color },
    { key: "medium",   label: "Medium",     accent: SEV.medium.color },
    { key: "low",      label: "Low",        accent: SEV.low.color },
  ];

  return (
    <div style={{ background: C.bg, minHeight: "100vh", color: C.text, fontFamily: "'Inter', system-ui, -apple-system, sans-serif" }}>

      {/* ── Header Area ── */}
      <div style={{ padding: "32px 40px 0", maxWidth: "1400px", margin: "0 auto" }}>
        
        {/* Title & Dropdown Row */}
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 32 }}>
          <div>
            <h1 style={{ margin: 0, fontSize: 24, fontWeight: 600, color: C.text, letterSpacing: "-0.02em" }}>
              Vulnerabilities
            </h1>
            <p style={{ margin: "6px 0 0", fontSize: 13, color: C.muted }}>
              {selectedScan
                ? `Reviewing ${counts.all} issue${counts.all !== 1 ? "s" : ""} found in ${selectedScan.repo_name || selectedScan.scan_id.substring(0, 8)}`
                : "Select a completed scan to inspect results"}
            </p>
          </div>

          {!loadingScans && scans.length > 0 && (
            <div style={{ position: "relative" }}>
              <select
                value={selectedScan?.scan_id || ""}
                onChange={(e) => {
                  const found = scans.find((x) => x.scan_id === e.target.value);
                  if (found) { setSelectedScan(found); setSevFilter("all"); setSearch(""); }
                }}
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
                  minWidth: 260,
                  transition: "border-color 0.15s ease",
                }}
                onMouseOver={(e) => e.currentTarget.style.borderColor = C.borderH}
                onMouseOut={(e) => e.currentTarget.style.borderColor = C.border}
              >
                {scans.map((sc) => (
                  <option key={sc.scan_id} value={sc.scan_id}>
                    {sc.repo_name || sc.scan_id.substring(0, 8)} • {timeAgo(sc.completed_at)}
                  </option>
                ))}
              </select>
              <svg style={{ position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={C.muted} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
            </div>
          )}
        </div>

        {/* Toolbar: Filters & Search */}
        {selectedScan && (
          <div style={{ 
            display: "flex", 
            justifyContent: "space-between", 
            alignItems: "center", 
            paddingBottom: 16,
            borderBottom: `1px solid ${C.border}`,
            flexWrap: "wrap",
            gap: 16
          }}>
            {/* Segmented Controls (Tabs) */}
            <div style={{ display: "flex", gap: 4, background: C.surface, padding: 4, borderRadius: 8, border: `1px solid ${C.border}` }}>
              {TABS.map((tab) => {
                const active = sevFilter === tab.key;
                const count = counts[tab.key as keyof typeof counts];
                return (
                  <button
                    key={tab.key}
                    onClick={() => setSevFilter(tab.key)}
                    style={{
                      padding: "6px 12px",
                      background: active ? C.surface2 : "transparent",
                      border: "none",
                      borderRadius: 4,
                      color: active ? tab.accent : C.muted,
                      fontSize: 13,
                      fontWeight: active ? 500 : 400,
                      cursor: "pointer",
                      transition: "all 0.15s ease",
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                    }}
                  >
                    {tab.label}
                    <span style={{
                      fontSize: 11,
                      padding: "1px 6px",
                      borderRadius: 10,
                      background: active ? (tab.key === 'all' ? C.border : s(tab.key).color + "22") : "transparent",
                      color: active ? tab.accent : C.subtle,
                    }}>
                      {count}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Search Input */}
            <div style={{ position: "relative", width: 300 }}>
              <svg style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={C.subtle} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search rule ID, file, or message..."
                style={{
                  width: "100%",
                  background: C.surface,
                  border: `1px solid ${C.border}`,
                  borderRadius: 6,
                  padding: "7px 32px",
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
                  style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: C.muted, cursor: "pointer", padding: 2 }}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Content Area ── */}
      <div style={{ padding: "24px 40px", maxWidth: "1400px", margin: "0 auto" }}>
        {loadingScans ? (
          <div style={{ display: "flex", justifyContent: "center", padding: "60px 0" }}>
             <div style={{ color: C.subtle, fontSize: 13 }}>Fetching scan history...</div>
          </div>
        ) : !selectedScan ? (
          <div style={{ textAlign: "center", padding: "80px 20px", border: `1px dashed ${C.border}`, borderRadius: 8 }}>
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke={C.subtle} strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: 16 }}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            <div style={{ fontSize: 14, fontWeight: 500, color: C.text, marginBottom: 8 }}>No Scan Selected</div>
            <div style={{ fontSize: 13, color: C.muted }}>Navigate to the Repositories tab and run a scan to generate a report.</div>
          </div>
        ) : loadingVulns ? (
          <div style={{ display: "flex", justifyContent: "center", padding: "60px 0" }}>
             <div style={{ color: C.subtle, fontSize: 13 }}>Analyzing vulnerabilities...</div>
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: "center", padding: "80px 20px", border: `1px solid ${C.border}`, borderRadius: 8 }}>
            {search ? (
              <>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke={C.subtle} strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: 16 }}><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                <div style={{ fontSize: 14, color: C.text, marginBottom: 16 }}>
                  No matches found for <span style={{ color: C.text, fontWeight: 500 }}>"{search}"</span>
                </div>
                <button
                  onClick={() => { setSearch(""); setSevFilter("all"); }}
                  style={{ padding: "6px 14px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, color: C.text, fontSize: 12, cursor: "pointer" }}
                >
                  Clear filters
                </button>
              </>
            ) : sevFilter !== "all" ? (
              <>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke={s(sevFilter).color} strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: 16 }}><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                <div style={{ fontSize: 14, color: C.text, marginBottom: 16 }}>No {sevFilter} vulnerabilities found.</div>
                <button
                  onClick={() => setSevFilter("all")}
                  style={{ padding: "6px 14px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, color: C.text, fontSize: 12, cursor: "pointer" }}
                >
                  View all issues
                </button>
              </>
            ) : (
              <>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: 16 }}><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                <div style={{ fontSize: 14, fontWeight: 500, color: "#10b981", marginBottom: 4 }}>Zero vulnerabilities detected</div>
                <div style={{ fontSize: 13, color: C.muted }}>Your codebase is currently secure.</div>
              </>
            )}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            
            {/* List Header/Metadata */}
            <div style={{ fontSize: 12, color: C.subtle, paddingBottom: 8 }}>
              Showing {filtered.length} result{filtered.length !== 1 ? 's' : ''}
            </div>

            {/* List Content */}
            {filtered.map((vuln) => {
              const sv = s(vuln.severity);
              const isOpen = expanded === vuln.id;
              const fileName = vuln.file_path?.split(/[\\/]/).pop() || vuln.file_path;

              return (
                <div
                  key={vuln.id}
                  style={{
                    background: C.bg,
                    border: `1px solid ${isOpen ? sv.border : C.border}`,
                    borderLeft: `3px solid ${sv.color}`,
                    borderRadius: 6,
                    overflow: "hidden",
                    transition: "border-color 0.15s ease",
                  }}
                >
                  {/* Card Header (Clickable) */}
                  <div
                    onClick={() => setExpanded(isOpen ? null : vuln.id)}
                    style={{ 
                      padding: "12px 16px", 
                      cursor: "pointer", 
                      display: "flex", 
                      alignItems: "center", 
                      gap: 16, 
                      userSelect: "none",
                      background: isOpen ? sv.bg : C.surface,
                    }}
                    onMouseEnter={(e) => { if(!isOpen) e.currentTarget.style.background = C.surface2; }}
                    onMouseLeave={(e) => { if(!isOpen) e.currentTarget.style.background = C.surface; }}
                  >
                    {/* Severity Badge */}
                    <div style={{
                      width: 50, flexShrink: 0,
                      color: sv.color, 
                      fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em",
                    }}>
                      {vuln.severity || "UNKN"}
                    </div>

                    {/* Main Info */}
                    <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 2 }}>
                      <div style={{ fontSize: 13, fontWeight: 500, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {vuln.message}
                      </div>
                      <div style={{ fontSize: 12, color: C.subtle, display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontFamily: "'JetBrains Mono', 'Fira Code', monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "40vw", color: C.muted }}>
                          {fileName}
                        </span>
                        {vuln.start_line > 0 && (
                          <>
                            <span style={{ color: C.border }}>|</span>
                            <span>Line {vuln.start_line}</span>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Right side context */}
                    <div style={{ display: "flex", alignItems: "center", gap: 16, flexShrink: 0 }}>
                      <div style={{ fontSize: 11, color: C.subtle, fontFamily: "'JetBrains Mono', 'Fira Code', monospace", background: C.bg, padding: "2px 6px", borderRadius: 4, border: `1px solid ${C.border}` }}>
                        {vuln.rule_id}
                      </div>
                      <svg 
                        width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={C.subtle} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
                        style={{ transition: "transform 0.2s ease", transform: isOpen ? "rotate(180deg)" : "rotate(0deg)" }}
                      >
                        <polyline points="6 9 12 15 18 9"></polyline>
                      </svg>
                    </div>
                  </div>

                  {/* Expanded Detail Panel */}
                  {isOpen && (
                    <div style={{ borderTop: `1px solid ${isOpen ? sv.border : C.border}`, background: C.bg, padding: "20px 24px", display: "flex", flexDirection: "column", gap: 24 }}>

                      {/* Code Snippet */}
                      {vuln.code_snippet && (
                        <div>
                          <div style={{ fontSize: 11, fontWeight: 500, color: C.subtle, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8 }}>
                            Vulnerable Code Area
                          </div>
                          <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, overflow: "hidden" }}>
                            <div style={{ background: C.surface, padding: "6px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 11, color: C.muted, fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
                              {vuln.file_path}
                            </div>
                            <pre style={{ 
                              padding: "16px", fontSize: 12, color: "#d1d5db", margin: 0, 
                              overflowX: "auto", lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-word", 
                              fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace" 
                            }}>
                              {vuln.code_snippet}
                            </pre>
                          </div>
                        </div>
                      )}

                      {/* Metadata Grid */}
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16 }}>
                        {[
                          { label: "Rule ID",    value: vuln.rule_id,            color: C.text },
                          { label: "Vulnerability Type", value: vuln.vulnerability_type, color: C.text },
                          { label: "Confidence", value: vuln.confidence,         color: C.text },
                          { label: "Scanner Engine", value: vuln.scanner_name,       color: C.text },
                        ].filter((m) => m.value).map((m) => (
                          <div key={m.label}>
                            <div style={{ fontSize: 11, color: C.subtle, marginBottom: 4 }}>{m.label}</div>
                            <div style={{ fontSize: 13, color: m.color, wordBreak: "break-all" }}>{m.value}</div>
                          </div>
                        ))}
                      </div>

                      {/* Tags (CWE/OWASP) */}
                      {(vuln.cwe_ids?.length > 0 || vuln.owasp_categories?.length > 0) && (
                        <div style={{ display: "flex", gap: 32, flexWrap: "wrap", paddingTop: 16, borderTop: `1px solid ${C.border}` }}>
                          {vuln.cwe_ids?.length > 0 && (
                            <div>
                              <div style={{ fontSize: 11, color: C.subtle, marginBottom: 8 }}>CWE References</div>
                              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                                {vuln.cwe_ids.map((c) => (
                                  <span key={c} style={{ fontSize: 11, padding: "4px 8px", background: C.surface, color: C.muted, borderRadius: 4, border: `1px solid ${C.border}` }}>{c}</span>
                                ))}
                              </div>
                            </div>
                          )}
                          {vuln.owasp_categories?.length > 0 && (
                            <div>
                              <div style={{ fontSize: 11, color: C.subtle, marginBottom: 8 }}>OWASP Categories</div>
                              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                                {vuln.owasp_categories.map((o) => (
                                  <span key={o} style={{ fontSize: 11, padding: "4px 8px", background: C.surface, color: C.muted, borderRadius: 4, border: `1px solid ${C.border}` }}>{o}</span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}