import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";

const API = "http://localhost:8000";

const C = {
  bg:      "#0d1117",
  surface: "#161b22",
  border:  "#21262d",
  borderH: "#30363d",
  text:    "#e6edf3",
  muted:   "#8b949e",
  subtle:  "#6e7681",
  accent:  "#58a6ff",
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

const SEV: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "#f85149", bg: "rgba(248,81,73,0.08)",   border: "rgba(248,81,73,0.25)" },
  high:     { color: "#d29922", bg: "rgba(210,153,34,0.08)",  border: "rgba(210,153,34,0.25)" },
  medium:   { color: "#58a6ff", bg: "rgba(88,166,255,0.08)",  border: "rgba(88,166,255,0.25)" },
  low:      { color: "#3fb950", bg: "rgba(63,185,80,0.08)",   border: "rgba(63,185,80,0.25)" },
  info:     { color: "#8b949e", bg: "rgba(139,148,158,0.08)", border: "rgba(139,148,158,0.25)" },
  warning:  { color: "#d29922", bg: "rgba(210,153,34,0.08)",  border: "rgba(210,153,34,0.25)" },
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
    { key: "all",      label: "All",      accent: C.accent },
    { key: "critical", label: "Critical", accent: SEV.critical.color },
    { key: "high",     label: "High",     accent: SEV.high.color },
    { key: "medium",   label: "Medium",   accent: SEV.medium.color },
    { key: "low",      label: "Low",      accent: SEV.low.color },
  ];

  return (
    <div style={{ background: C.bg, minHeight: "100vh", color: C.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>

      {/* ── Header — no top padding so it sits flush ── */}
      <div style={{ padding: "0 32px", borderBottom: `1px solid ${C.border}` }}>

        {/* Title row */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "20px 0 16px" }}>
          <div>
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: C.text, letterSpacing: "-0.3px" }}>
              Vulnerabilities
            </h1>
            <p style={{ margin: "3px 0 0", fontSize: 13, color: C.muted }}>
              {selectedScan
                ? `${selectedScan.repo_name || selectedScan.scan_id.substring(0, 8)} — ${counts.all} issue${counts.all !== 1 ? "s" : ""} found`
                : "Select a scan to inspect"}
            </p>
          </div>

          {/* Scan picker */}
          {!loadingScans && scans.length > 0 && (
            <select
              value={selectedScan?.scan_id || ""}
              onChange={(e) => {
                const found = scans.find((x) => x.scan_id === e.target.value);
                if (found) { setSelectedScan(found); setSevFilter("all"); setSearch(""); }
              }}
              style={{
                background: C.surface,
                border: `1px solid ${C.border}`,
                borderRadius: 8,
                padding: "8px 14px",
                color: C.text,
                fontSize: 13,
                outline: "none",
                cursor: "pointer",
                minWidth: 240,
              }}
            >
              {scans.map((sc) => (
                <option key={sc.scan_id} value={sc.scan_id}>
                  {sc.repo_name || sc.scan_id.substring(0, 8)} · {timeAgo(sc.completed_at)}
                </option>
              ))}
            </select>
          )}
        </div>

        {/* Severity filter tabs */}
        {selectedScan && !loadingVulns && (
          <div style={{ display: "flex", gap: 0, marginTop: 2 }}>
            {TABS.map((tab) => {
              const active = sevFilter === tab.key;
              const count = counts[tab.key as keyof typeof counts];
              return (
                <button
                  key={tab.key}
                  onClick={() => setSevFilter(tab.key)}
                  style={{
                    padding: "9px 16px",
                    background: "transparent",
                    border: "none",
                    borderBottom: active ? `2px solid ${tab.accent}` : "2px solid transparent",
                    color: active ? tab.accent : C.muted,
                    fontSize: 13,
                    cursor: "pointer",
                    fontFamily: "inherit",
                    transition: "color 0.15s, border-color 0.15s",
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                  }}
                >
                  {tab.label}
                  {count > 0 && (
                    <span style={{
                      fontSize: 10,
                      padding: "1px 6px",
                      borderRadius: 10,
                      background: active ? `${tab.accent}22` : C.surface,
                      color: active ? tab.accent : C.subtle,
                      border: `1px solid ${active ? tab.accent + "44" : C.border}`,
                    }}>
                      {count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Search bar ── */}
      {selectedScan && (
        <div style={{ padding: "12px 32px", borderBottom: `1px solid ${C.border}`, background: C.bg }}>
          <div style={{ position: "relative" }}>
            <span style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", color: C.subtle, fontSize: 14 }}>⌕</span>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search file path, message, rule ID..."
              style={{
                width: "100%",
                background: C.surface,
                border: `1px solid ${C.border}`,
                borderRadius: 8,
                padding: "8px 36px",
                color: C.text,
                fontSize: 13,
                outline: "none",
                boxSizing: "border-box",
              }}
            />
            {search && (
              <button
                onClick={() => setSearch("")}
                style={{ position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 14 }}
              >✕</button>
            )}
          </div>
        </div>
      )}

      {/* ── Content ── */}
      <div style={{ padding: "20px 32px" }}>
        {loadingScans ? (
          <div style={{ color: C.muted, fontSize: 13 }}>Loading scans...</div>
        ) : !selectedScan ? (
          <div style={{ textAlign: "center", padding: "80px 20px", color: C.muted }}>
            <div style={{ fontSize: 40, marginBottom: 12 }}>🔒</div>
            <div style={{ fontSize: 15, fontWeight: 600, color: C.text, marginBottom: 8 }}>No completed scans yet</div>
            <div style={{ fontSize: 13 }}>Go to Repositories and run a scan to see vulnerabilities here.</div>
          </div>
        ) : loadingVulns ? (
          <div style={{ color: C.muted, fontSize: 13, padding: 20 }}>Loading vulnerabilities...</div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: "center", padding: "60px 20px", color: C.muted }}>
            {search ? (
              <>
                <div style={{ fontSize: 32, marginBottom: 12 }}>🔎</div>
                <div style={{ fontSize: 14, color: C.text, marginBottom: 16 }}>
                  No vulnerabilities match <span style={{ color: C.accent }}>"{search}"</span>
                </div>
                <button
                  onClick={() => { setSearch(""); setSevFilter("all"); }}
                  style={{ padding: "7px 16px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 7, color: C.text, fontSize: 13, cursor: "pointer" }}
                >
                  Clear search
                </button>
              </>
            ) : sevFilter !== "all" ? (
              <>
                <div style={{ fontSize: 32, marginBottom: 12 }}>🔍</div>
                <div style={{ fontSize: 14, marginBottom: 16 }}>No {sevFilter} vulnerabilities in this scan.</div>
                <button
                  onClick={() => setSevFilter("all")}
                  style={{ padding: "7px 16px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 7, color: C.text, fontSize: 13, cursor: "pointer" }}
                >
                  Show all severities
                </button>
              </>
            ) : (
              <>
                <div style={{ fontSize: 40, marginBottom: 12 }}>✅</div>
                <div style={{ fontSize: 15, fontWeight: 600, color: "#3fb950" }}>
                  No vulnerabilities found — this scan is clean!
                </div>
              </>
            )}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <div style={{ fontSize: 12, color: C.muted, marginBottom: 8 }}>
              Showing {filtered.length} of {vulnerabilities.length} vulnerabilities
              {search && ` matching "${search}"`}
            </div>

            {filtered.map((vuln) => {
              const sv = s(vuln.severity);
              const isOpen = expanded === vuln.id;
              const fileName = vuln.file_path?.split(/[\\/]/).pop() || vuln.file_path;

              return (
                <div
                  key={vuln.id}
                  style={{
                    background: isOpen ? sv.bg : C.surface,
                    border: `1px solid ${isOpen ? sv.border : C.border}`,
                    borderLeft: `3px solid ${sv.color}`,
                    borderRadius: 8,
                    overflow: "hidden",
                    transition: "border-color 0.15s, background 0.15s",
                  }}
                >
                  {/* Row */}
                  <div
                    onClick={() => setExpanded(isOpen ? null : vuln.id)}
                    style={{ padding: "12px 18px", cursor: "pointer", display: "flex", alignItems: "center", gap: 12, userSelect: "none" }}
                  >
                    <span style={{
                      fontSize: 10, padding: "3px 8px", borderRadius: 4, fontWeight: 700, flexShrink: 0,
                      background: sv.bg, color: sv.color, border: `1px solid ${sv.border}`,
                      textTransform: "uppercase", letterSpacing: "0.06em",
                    }}>
                      {vuln.severity || "?"}
                    </span>

                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: 2 }}>
                        {vuln.message}
                      </div>
                      <div style={{ fontSize: 11, color: C.muted, display: "flex", gap: 10 }}>
                        <span style={{ color: C.accent, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 300 }}>{fileName}</span>
                        <span>L{vuln.start_line}</span>
                        {vuln.vulnerability_type && <span style={{ color: C.subtle }}>{vuln.vulnerability_type}</span>}
                      </div>
                    </div>

                    <div style={{ display: "flex", gap: 4, flexShrink: 0 }}>
                      {vuln.cwe_ids?.slice(0, 2).map((c) => (
                        <span key={c} style={{ fontSize: 10, padding: "2px 7px", background: "rgba(88,166,255,0.08)", color: C.accent, borderRadius: 4, border: "1px solid rgba(88,166,255,0.2)" }}>
                          {c}
                        </span>
                      ))}
                    </div>

                    <span style={{ color: C.muted, fontSize: 11, flexShrink: 0, display: "inline-block", transition: "transform 0.2s", transform: isOpen ? "rotate(180deg)" : "rotate(0deg)" }}>▾</span>
                  </div>

                  {/* Expanded detail */}
                  {isOpen && (
                    <div style={{ borderTop: `1px solid ${sv.border}`, padding: "18px 20px", display: "flex", flexDirection: "column", gap: 14 }}>

                      {(vuln.file_path || vuln.start_line) && (
                        <div style={{ background: C.bg, borderRadius: 7, padding: "9px 13px", fontSize: 12, color: C.muted, fontFamily: "'Fira Code', 'Courier New', monospace", border: `1px solid ${C.border}` }}>
                          📄 <span style={{ color: vuln.file_path ? C.text : C.subtle }}>
                            {vuln.file_path || "File path not recorded by scanner"}
                          </span>
                          {vuln.start_line > 0 && (
                            <>
                              <span style={{ color: C.subtle, margin: "0 8px" }}>·</span>
                              Line {vuln.start_line}{vuln.end_line && vuln.end_line !== vuln.start_line ? `–${vuln.end_line}` : ""}
                            </>
                          )}
                        </div>
                      )}

                      {vuln.code_snippet && (
                        <div>
                          <div style={{ fontSize: 10, color: C.subtle, textTransform: "uppercase", letterSpacing: "0.12em", marginBottom: 7 }}>
                            Flagged Code — the exact line(s) identified as vulnerable
                          </div>
                          <pre style={{ background: C.bg, border: `1px solid ${sv.border}`, borderRadius: 8, padding: "13px 16px", fontSize: 12, color: C.text, margin: 0, overflowX: "auto", lineHeight: 1.8, whiteSpace: "pre-wrap", wordBreak: "break-word", fontFamily: "'Fira Code', 'Courier New', monospace" }}>
                            {vuln.code_snippet}
                          </pre>
                        </div>
                      )}

                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 8 }}>
                        {[
                          { label: "Rule ID",    value: vuln.rule_id,            color: C.accent },
                          { label: "Type",       value: vuln.vulnerability_type, color: C.text },
                          { label: "Confidence", value: vuln.confidence,         color: C.text },
                          { label: "Scanner",    value: vuln.scanner_name,       color: C.text },
                        ].filter((m) => m.value).map((m) => (
                          <div key={m.label} style={{ background: C.bg, borderRadius: 7, padding: "9px 13px", border: `1px solid ${C.border}` }}>
                            <div style={{ fontSize: 10, color: C.subtle, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 4 }}>{m.label}</div>
                            <div style={{ fontSize: 12, color: m.color, wordBreak: "break-all" }}>{m.value}</div>
                          </div>
                        ))}
                      </div>

                      {(vuln.cwe_ids?.length > 0 || vuln.owasp_categories?.length > 0) && (
                        <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
                          {vuln.cwe_ids?.length > 0 && (
                            <div>
                              <div style={{ fontSize: 10, color: C.subtle, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 6 }}>CWE</div>
                              <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                                {vuln.cwe_ids.map((c) => (
                                  <span key={c} style={{ fontSize: 11, padding: "3px 9px", background: "rgba(88,166,255,0.08)", color: C.accent, borderRadius: 4, border: "1px solid rgba(88,166,255,0.2)" }}>{c}</span>
                                ))}
                              </div>
                            </div>
                          )}
                          {vuln.owasp_categories?.length > 0 && (
                            <div>
                              <div style={{ fontSize: 10, color: C.subtle, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 6 }}>OWASP</div>
                              <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                                {vuln.owasp_categories.map((o) => (
                                  <span key={o} style={{ fontSize: 11, padding: "3px 9px", background: "rgba(210,153,34,0.08)", color: "#d29922", borderRadius: 4, border: "1px solid rgba(210,153,34,0.2)" }}>{o}</span>
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