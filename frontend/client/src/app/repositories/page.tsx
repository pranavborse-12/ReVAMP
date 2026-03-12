import React, { useEffect, useState, useMemo, useCallback } from "react";
import { Link } from "wouter";

const API_BASE_URL = "http://localhost:8000";

// --- ICONS ---
const Icons = {
  Github: () => (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
  ),
  Star: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" /></svg>
  ),
  Fork: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z" /></svg>
  ),
  Shield: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
  ),
  Search: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
  ),
  Close: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
  ),
  File: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
  ),
  Sparkles: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
    </svg>
  ),
  Check: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
  ),
  Code: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
    </svg>
  ),
  Copy: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
    </svg>
  ),
  Link: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
    </svg>
  ),
  Warning: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  ),
  Wand: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
    </svg>
  ),
};

// --- TYPES ---
interface Toast { id: number; message: string; type?: "success" | "error" | "info"; }
interface Profile { login: string; name?: string; avatar_url?: string; bio?: string; }
interface Owner { login?: string; avatar_url?: string; html_url?: string; }
interface Repo {
  id: number; name: string; full_name?: string; html_url?: string;
  private: boolean; visibility?: string; description?: string;
  updated_at?: string; stargazers_count?: number; forks_count?: number;
  language?: string; owner?: Owner; size?: number;
}
interface SeveritySummary { critical: number; high: number; medium: number; low: number; info: number; warning: number; }
interface Vulnerability {
  scanner: string; rule_id: string; severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "WARNING";
  message: string; vulnerability_type: string;
  location: { file: string; start_line: number; end_line: number; };
  code_snippet?: string; cwe?: string[]; owasp?: string[];
}
interface ScanResult {
  scan_id: string; repo_owner: string; repo_name: string; status: string;
  total_issues: number; severity_summary: SeveritySummary; vulnerabilities: Vulnerability[];
  scan_duration?: number; completed_at?: string; scanner_used?: string; detected_languages?: string[];
}
interface ScanStatus {
  scan_id: string; status: string; message: string; progress: string; repo_name?: string;
}
interface AIFixResult {
  success: boolean;
  vulnerability_analysis: string;
  code_analysis: string;
  fix_explanation: string;
  original_code: string;
  fixed_code: string;
  changes_made: string[];
  security_improvement: string;
}

// --- UTILS ---
function timeAgo(iso?: string) {
  if (!iso) return "";
  const dt = new Date(iso);
  const diff = (Date.now() - dt.getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const SEVERITY_CONFIG = {
  CRITICAL: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/25", dot: "bg-red-500", label: "Critical" },
  HIGH:     { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/25", dot: "bg-orange-500", label: "High" },
  MEDIUM:   { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/25", dot: "bg-yellow-400", label: "Medium" },
  LOW:      { color: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/25", dot: "bg-sky-400", label: "Low" },
  WARNING:  { color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/25", dot: "bg-amber-400", label: "Warning" },
  INFO:     { color: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-600/40", dot: "bg-slate-500", label: "Info" },
};

function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.INFO;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] uppercase font-semibold tracking-widest border ${style.bg} ${style.color} ${style.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
      {style.label}
    </span>
  );
}

// ─── COPY BUTTON with feedback ────────────────────────────────────────────────
function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      onClick={handleCopy}
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 border ${
        copied
          ? "bg-emerald-500/15 border-emerald-500/30 text-emerald-400"
          : "bg-zinc-800/80 border-zinc-700/50 text-zinc-400 hover:text-zinc-200 hover:border-zinc-600"
      }`}
    >
      {copied ? <Icons.Check /> : <Icons.Copy />}
      {copied ? "Copied!" : label}
    </button>
  );
}

// ─── TOASTS ───────────────────────────────────────────────────────────────────
function Toasts({ toasts, removeToast }: { toasts: Toast[]; removeToast: (id: number) => void }) {
  return (
    <div className="fixed bottom-5 right-5 flex flex-col gap-2 z-[100] max-w-sm w-full pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`px-4 py-3 rounded-lg shadow-xl border backdrop-blur-md flex items-center gap-3 pointer-events-auto cursor-pointer transition-all ${
            t.type === "error"   ? "bg-red-950/90 border-red-800/60 text-red-200"
            : t.type === "info" ? "bg-zinc-900/90 border-zinc-700/60 text-zinc-200"
            : "bg-emerald-950/90 border-emerald-800/60 text-emerald-200"
          }`}
          onClick={() => removeToast(t.id)}
        >
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
            t.type === "error" ? "bg-red-400" : t.type === "info" ? "bg-zinc-400" : "bg-emerald-400"
          }`} />
          <span className="text-sm font-medium">{t.message}</span>
        </div>
      ))}
    </div>
  );
}

// ─── AI FIX BUTTON ────────────────────────────────────────────────────────────
// Clean, professional — fits the dark security tool aesthetic
function AIFixButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="group flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold
                 bg-indigo-600/20 border border-indigo-500/30 text-indigo-300
                 hover:bg-indigo-600/30 hover:border-indigo-400/50 hover:text-indigo-200
                 transition-all duration-200 active:scale-[0.97]"
    >
      <Icons.Wand />
      <span>Fix with AI</span>
    </button>
  );
}

// ─── LOADING STAGES (replaces bare spinner) ───────────────────────────────────
const AI_STAGES = [
  { id: 0, label: "Fetching vulnerable file from GitHub", icon: "📥" },
  { id: 1, label: "Resolving imported dependencies", icon: "🔗" },
  { id: 2, label: "Analysing security context", icon: "🔍" },
  { id: 3, label: "Generating secure patch", icon: "🛡️" },
];

function AILoadingPanel({ filePath }: { filePath: string }) {
  const [stage, setStage] = useState(0);

  useEffect(() => {
    const timings = [1200, 2400, 3800];
    const timers = timings.map((ms, i) =>
      setTimeout(() => setStage(i + 1), ms)
    );
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div className="flex-1 flex flex-col items-center justify-center px-8 py-12 select-none">
      {/* Animated icon cluster */}
      <div className="relative w-20 h-20 mb-8">
        <div className="absolute inset-0 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
          <span className="text-3xl">🛡️</span>
        </div>
        <div className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-indigo-500/20 border border-indigo-400/40 flex items-center justify-center">
          <div className="w-2 h-2 rounded-full bg-indigo-400 animate-ping" />
        </div>
      </div>

      <p className="text-zinc-300 font-semibold text-base mb-1">Analysing vulnerability</p>
      <p className="text-zinc-500 text-sm font-mono mb-10 truncate max-w-xs">{filePath}</p>

      {/* Stage list */}
      <div className="w-full max-w-sm space-y-3">
        {AI_STAGES.map((s) => {
          const isDone    = stage > s.id;
          const isActive  = stage === s.id;
          const isPending = stage < s.id;
          return (
            <div key={s.id} className={`flex items-center gap-3 px-4 py-3 rounded-lg border transition-all duration-500 ${
              isDone   ? "bg-emerald-500/8 border-emerald-500/20 opacity-70"
              : isActive ? "bg-indigo-500/10 border-indigo-500/25"
              : "bg-zinc-900/30 border-zinc-800/50 opacity-40"
            }`}>
              <span className="text-base w-5 text-center">
                {isDone ? "✓" : isActive ? s.icon : "○"}
              </span>
              <span className={`text-sm font-medium ${
                isDone ? "text-emerald-400" : isActive ? "text-zinc-200" : "text-zinc-600"
              }`}>{s.label}</span>
              {isActive && (
                <div className="ml-auto flex gap-0.5">
                  {[0,1,2].map(i => (
                    <div key={i} className="w-1 h-1 rounded-full bg-indigo-400 animate-bounce"
                      style={{ animationDelay: `${i * 150}ms` }} />
                  ))}
                </div>
              )}
              {isDone && <div className="ml-auto w-4 h-4 text-emerald-500"><Icons.Check /></div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── CODE BLOCK with line numbers + copy ─────────────────────────────────────
function CodeBlock({ code, label, variant }: { code: string; label: string; variant: "danger" | "safe" }) {
  const lines = code.split("\n");
  const headerClass = variant === "danger"
    ? "bg-red-950/40 border-red-900/40 text-red-400"
    : "bg-emerald-950/40 border-emerald-900/40 text-emerald-400";
  const lineClass = variant === "danger" ? "text-zinc-500" : "text-zinc-200";

  return (
    <div className="flex flex-col h-full min-h-0 overflow-hidden">
      <div className={`flex items-center justify-between px-4 py-2 border-b text-xs font-semibold tracking-widest uppercase ${headerClass}`}>
        <span>{label}</span>
        <CopyButton text={code} />
      </div>
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs font-mono border-collapse">
          <tbody>
            {lines.map((line, i) => (
              <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                <td className="select-none w-12 pl-4 pr-3 py-0.5 text-right text-zinc-700 border-r border-zinc-800/50 align-top">
                  {i + 1}
                </td>
                <td className={`pl-4 pr-6 py-0.5 whitespace-pre align-top leading-5 ${lineClass}`}>
                  {line || " "}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── AI FIX MODAL (fully redesigned) ─────────────────────────────────────────
function AIFixModal({
  vulnerability, repoOwner, repoName, onClose,
}: {
  vulnerability: Vulnerability; repoOwner: string; repoName: string; onClose: () => void;
}) {
  const [isLoading, setIsLoading] = useState(true);
  const [result, setResult] = useState<AIFixResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"diff" | "analysis">("diff");

  useEffect(() => {
    const fetchFix = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/ai/fix-vulnerability`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            vulnerability,
            repo_owner: repoOwner,
            repo_name: repoName,
            file_path: vulnerability.location.file,
          }),
        });

        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.detail || `Server returned ${response.status}`);
        }

        const data = await response.json();
        setResult(data);
      } catch (err: any) {
        setError(err.message || "Failed to generate AI fix");
      } finally {
        setIsLoading(false);
      }
    };
    fetchFix();
  }, [vulnerability, repoOwner, repoName]);

  const sev = SEVERITY_CONFIG[vulnerability.severity] || SEVERITY_CONFIG.INFO;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/80 backdrop-blur-sm p-3 lg:p-8">
      <div
        className="bg-[#0e0e10] border border-zinc-800/80 rounded-2xl w-full max-w-6xl shadow-2xl flex flex-col overflow-hidden"
        style={{ height: "min(88vh, 820px)" }}
      >
        {/* ── Header ── */}
        <div className="flex-shrink-0 border-b border-zinc-800/80 px-5 py-4 flex items-center gap-4 bg-[#0e0e10]">
          <div className="w-9 h-9 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 flex-shrink-0">
            <Icons.Wand />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <span className="text-xs font-bold text-zinc-300 uppercase tracking-widest">AI Security Patch</span>
              <SeverityBadge severity={vulnerability.severity} />
            </div>
            <p className="text-xs text-zinc-500 font-mono truncate">
              {repoOwner}/{repoName} · {vulnerability.location.file}:{vulnerability.location.start_line}
            </p>
          </div>
          <button
            onClick={onClose}
            className="ml-auto flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800 transition-all"
          >
            <Icons.Close />
          </button>
        </div>

        {/* ── Vulnerability type bar ── */}
        <div className="flex-shrink-0 px-5 py-2.5 bg-zinc-900/40 border-b border-zinc-800/50 flex items-center gap-3">
          <span className="text-sm font-semibold text-zinc-200 truncate">{vulnerability.vulnerability_type}</span>
          <span className="text-zinc-700">·</span>
          <span className="text-xs text-zinc-500 font-mono truncate">{vulnerability.rule_id}</span>
        </div>

        {/* ── Body ── */}
        <div className="flex-1 min-h-0 flex overflow-hidden">
          {isLoading ? (
            <AILoadingPanel filePath={vulnerability.location.file} />
          ) : error ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
              <div className="w-12 h-12 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400 mb-4">
                <Icons.Warning />
              </div>
              <p className="text-zinc-300 font-semibold mb-2">Fix generation failed</p>
              <p className="text-red-400 text-sm font-mono max-w-md">{error}</p>
            </div>
          ) : result ? (
            <div className="flex-1 min-h-0 flex flex-col overflow-hidden">
              {/* Tab bar */}
              <div className="flex-shrink-0 flex border-b border-zinc-800/60 px-5 gap-1 bg-[#0e0e10]">
                {(["diff", "analysis"] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-4 py-3 text-xs font-semibold uppercase tracking-wider transition-all border-b-2 -mb-px ${
                      activeTab === tab
                        ? "text-indigo-400 border-indigo-500"
                        : "text-zinc-500 border-transparent hover:text-zinc-300"
                    }`}
                  >
                    {tab === "diff" ? "Code Comparison" : "Analysis & Changes"}
                  </button>
                ))}
              </div>

              {activeTab === "diff" ? (
                /* ── Side-by-side diff ── */
                <div className="flex-1 min-h-0 grid grid-cols-2 divide-x divide-zinc-800/60 overflow-hidden">
                  <CodeBlock code={result.original_code} label="Vulnerable" variant="danger" />
                  <CodeBlock code={result.fixed_code} label="Secure Patch" variant="safe" />
                </div>
              ) : (
                /* ── Analysis panel ── */
                <div className="flex-1 min-h-0 overflow-y-auto p-6 space-y-6">
                  {/* Vulnerability analysis */}
                  <section>
                    <h3 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-3">Vulnerability Analysis</h3>
                    <div className="bg-red-500/5 border border-red-500/15 rounded-xl p-4 text-sm text-zinc-300 leading-relaxed">
                      {result.vulnerability_analysis}
                    </div>
                  </section>

                  {/* Code context */}
                  {result.code_analysis && (
                    <section>
                      <h3 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-3">Code Context</h3>
                      <div className="bg-zinc-900/40 border border-zinc-800/50 rounded-xl p-4 text-sm text-zinc-300 leading-relaxed">
                        {result.code_analysis}
                      </div>
                    </section>
                  )}

                  {/* Changes made */}
                  <section>
                    <h3 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-3">Changes Applied</h3>
                    <div className="space-y-2">
                      {result.changes_made.map((change, i) => (
                        <div key={i} className="flex items-start gap-3 px-4 py-3 bg-emerald-500/5 border border-emerald-500/15 rounded-xl">
                          <div className="mt-0.5 text-emerald-500 flex-shrink-0"><Icons.Check /></div>
                          <p className="text-sm text-zinc-300 leading-relaxed">{change}</p>
                        </div>
                      ))}
                    </div>
                  </section>

                  {/* Security improvement */}
                  <section>
                    <h3 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-3">Security Impact</h3>
                    <div className="bg-indigo-500/5 border border-indigo-500/15 rounded-xl p-4 text-sm text-zinc-300 leading-relaxed">
                      {result.security_improvement}
                    </div>
                  </section>
                </div>
              )}

              {/* Footer action bar */}
              <div className="flex-shrink-0 border-t border-zinc-800/60 px-5 py-3 flex items-center justify-between bg-[#0e0e10]">
                <p className="text-xs text-zinc-600 font-mono">
                  {vulnerability.location.file} · L{vulnerability.location.start_line}–{vulnerability.location.end_line}
                </p>
                <CopyButton text={result.fixed_code} label="Copy Patch" />
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

// ─── SCAN RESULTS MODAL ───────────────────────────────────────────────────────
function ScanResultsModal({ result, onClose }: { result: ScanResult; onClose: () => void }) {
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [filterSev, setFilterSev] = useState<string | null>(null);
  const [fixingVuln, setFixingVuln] = useState<Vulnerability | null>(null);

  useEffect(() => {
    if (result.vulnerabilities.length > 0 && !selectedVuln) {
      setSelectedVuln(result.vulnerabilities[0]);
    }
  }, [result]);

  const filteredVulns = useMemo(() => {
    return result.vulnerabilities.filter(v => !filterSev || v.severity === filterSev);
  }, [result.vulnerabilities, filterSev]);

  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARNING", "INFO"];

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-zinc-950 text-zinc-100">
      {/* Header */}
      <div className="h-14 border-b border-zinc-800 flex items-center justify-between px-5 bg-zinc-950 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="bg-zinc-800/80 p-1.5 rounded-lg text-zinc-400"><Icons.Shield /></div>
          <div>
            <h2 className="text-sm font-bold">{result.repo_name}</h2>
            <p className="text-xs text-zinc-500">
              {result.total_issues} issues · {result.scan_duration?.toFixed(1)}s
            </p>
          </div>
        </div>
        <button onClick={onClose} className="p-2 hover:bg-zinc-800 rounded-lg transition-colors text-zinc-400 hover:text-white">
          <Icons.Close />
        </button>
      </div>

      <div className="flex-1 flex overflow-hidden min-h-0">
        {/* Left: vuln list */}
        <div className="w-full md:w-[360px] border-r border-zinc-800 flex flex-col flex-shrink-0 bg-zinc-950">
          {/* Severity filters */}
          <div className="p-3 border-b border-zinc-800 flex gap-1.5 overflow-x-auto flex-shrink-0">
            <button
              onClick={() => setFilterSev(null)}
              className={`px-3 py-1 rounded-md text-xs font-medium whitespace-nowrap transition-all border ${
                !filterSev ? "bg-zinc-100 text-zinc-900 border-zinc-100" : "text-zinc-400 border-zinc-800 hover:border-zinc-700"
              }`}
            >All</button>
            {severities.map(sev => {
              const count = result.severity_summary[sev.toLowerCase() as keyof SeveritySummary] || 0;
              if (count === 0) return null;
              const style = SEVERITY_CONFIG[sev as keyof typeof SEVERITY_CONFIG];
              const active = filterSev === sev;
              return (
                <button key={sev} onClick={() => setFilterSev(active ? null : sev)}
                  className={`px-3 py-1 rounded-md text-xs font-medium whitespace-nowrap transition-all border flex items-center gap-1.5 ${
                    active ? `${style.bg} ${style.color} ${style.border}` : "text-zinc-500 border-zinc-800 hover:border-zinc-700 hover:text-zinc-300"
                  }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                  {sev.charAt(0) + sev.slice(1).toLowerCase()}
                  <span className="opacity-50">{count}</span>
                </button>
              );
            })}
          </div>
          {/* Vuln list */}
          <div className="flex-1 overflow-y-auto">
            {filteredVulns.length === 0 ? (
              <div className="p-8 text-center text-zinc-600 text-sm">No issues matching filter.</div>
            ) : filteredVulns.map((vuln, idx) => {
              const sev = SEVERITY_CONFIG[vuln.severity] || SEVERITY_CONFIG.INFO;
              return (
                <div key={idx} onClick={() => setSelectedVuln(vuln)}
                  className={`p-4 border-b border-zinc-800/40 cursor-pointer transition-all hover:bg-zinc-900/60 ${
                    selectedVuln === vuln ? "bg-zinc-900 border-l-2 border-l-indigo-500" : "border-l-2 border-l-transparent"
                  }`}>
                  <div className="flex justify-between items-start mb-1.5">
                    <span className="text-sm font-semibold text-zinc-200 line-clamp-1 pr-2">{vuln.vulnerability_type}</span>
                    <SeverityBadge severity={vuln.severity} />
                  </div>
                  <p className="text-xs text-zinc-500 line-clamp-2 mb-2 leading-relaxed">{vuln.message}</p>
                  <div className="flex items-center gap-1.5 text-[10px] text-zinc-600 font-mono">
                    <Icons.File />
                    <span className="truncate">{vuln.location.file}:{vuln.location.start_line}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: detail */}
        <div className="flex-1 bg-zinc-950 overflow-y-auto hidden md:block">
          {selectedVuln ? (
            <div className="p-8 max-w-3xl mx-auto">
              {/* Title row with AI fix button */}
              <div className="flex items-start justify-between gap-4 mb-6 pb-6 border-b border-zinc-800">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-3">
                    <SeverityBadge severity={selectedVuln.severity} />
                    <span className="text-xs font-mono text-zinc-600 px-2 py-0.5 bg-zinc-900 rounded border border-zinc-800">
                      {selectedVuln.rule_id}
                    </span>
                  </div>
                  <h1 className="text-xl font-bold text-zinc-100 mb-2">{selectedVuln.vulnerability_type}</h1>
                  <p className="text-zinc-400 text-sm leading-relaxed">{selectedVuln.message}</p>
                </div>
                {/* ← Clean, professional AI fix button */}
                <div className="flex-shrink-0 mt-1">
                  <AIFixButton onClick={() => setFixingVuln(selectedVuln)} />
                </div>
              </div>

              {/* Location */}
              <div className="bg-zinc-900/30 rounded-xl border border-zinc-800 p-4 mb-5">
                <h3 className="text-xs font-bold text-zinc-400 mb-2 uppercase tracking-wider flex items-center gap-2">
                  <Icons.File /> Location
                </h3>
                <div className="font-mono text-sm flex justify-between items-center text-zinc-400 bg-zinc-950 px-3 py-2.5 rounded-lg border border-zinc-800/50">
                  <span>{selectedVuln.location.file}</span>
                  <span className="text-zinc-600 text-xs">L{selectedVuln.location.start_line}–{selectedVuln.location.end_line}</span>
                </div>
              </div>

              {/* Code snippet */}
              {selectedVuln.code_snippet && (
                <div className="mb-5">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-xs font-bold text-zinc-400 uppercase tracking-wider">Code Evidence</h3>
                    <CopyButton text={selectedVuln.code_snippet} />
                  </div>
                  <pre className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 overflow-x-auto text-xs font-mono text-zinc-300 leading-relaxed">
                    {selectedVuln.code_snippet}
                  </pre>
                </div>
              )}

              {/* Meta */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-xl bg-zinc-900/30 border border-zinc-800">
                  <span className="text-[10px] text-zinc-600 uppercase tracking-wider font-semibold block mb-1">Scanner</span>
                  <p className="text-zinc-300 font-mono text-sm">{selectedVuln.scanner}</p>
                </div>
                {selectedVuln.cwe && selectedVuln.cwe.length > 0 && (
                  <div className="p-3 rounded-xl bg-zinc-900/30 border border-zinc-800">
                    <span className="text-[10px] text-zinc-600 uppercase tracking-wider font-semibold block mb-1">CWE</span>
                    <div className="flex gap-1.5 flex-wrap">
                      {selectedVuln.cwe.map(c => (
                        <span key={c} className="text-sky-400 text-xs font-mono bg-sky-950/40 px-2 py-0.5 rounded border border-sky-900/40">{c}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-zinc-700">
              <Icons.Shield />
              <p className="mt-3 text-sm">Select an issue to view details</p>
            </div>
          )}
        </div>
      </div>

      {fixingVuln && (
        <AIFixModal
          vulnerability={fixingVuln}
          repoOwner={result.repo_owner}
          repoName={result.repo_name}
          onClose={() => setFixingVuln(null)}
        />
      )}
    </div>
  );
}

// ─── SCAN PROGRESS ────────────────────────────────────────────────────────────
function ScanProgress({ scanId, repoName, onComplete }: {
  scanId: string; repoName: string; onComplete: (result: ScanResult) => void;
}) {
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let pollInterval: NodeJS.Timeout;
    let consecutiveErrors = 0;
    const MAX_ERRORS = 5;

    const pollStatus = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/scanning/scans/${scanId}/status`, { credentials: "include" });
        if (res.status === 404) { consecutiveErrors = 0; return; }
        if (!res.ok) {
          consecutiveErrors++;
          if (consecutiveErrors >= MAX_ERRORS) { clearInterval(pollInterval); setError(`Status check failed (${res.status})`); }
          return;
        }
        consecutiveErrors = 0;
        const data = await res.json();
        setStatus(data);
        if (data.status === "completed") {
          clearInterval(pollInterval);
          const resultRes = await fetch(`${API_BASE_URL}/api/scanning/scans/${scanId}`, { credentials: "include" });
          onComplete(await resultRes.json());
        } else if (data.status === "failed") {
          clearInterval(pollInterval);
          setError(data.message || "Scan failed.");
        }
      } catch (err: any) {
        consecutiveErrors++;
        if (consecutiveErrors >= MAX_ERRORS) { clearInterval(pollInterval); setError(err.message || "Cannot reach server."); }
      }
    };
    pollStatus();
    pollInterval = setInterval(pollStatus, 1500);
    return () => clearInterval(pollInterval);
  }, [scanId]);

  if (error) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
        <div className="bg-red-950/20 border border-red-900/40 p-6 rounded-2xl max-w-md w-full text-center">
          <p className="text-red-400 font-semibold mb-2">Scan Failed</p>
          <p className="text-zinc-500 text-sm">{error}</p>
        </div>
      </div>
    );
  }

  const progress = parseInt(status?.progress || "0");
  const steps = ["Queued", "Cloning", "Analyzing", "Finalizing"];
  const stepIdx = status?.status === "queued" ? 0 : status?.status === "cloning" ? 1 : status?.status === "analyzing" ? 2 : 3;

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-10">
          <div className="w-16 h-16 bg-indigo-500/10 rounded-2xl flex items-center justify-center mx-auto mb-5 text-indigo-400 border border-indigo-500/20">
            <Icons.Shield />
          </div>
          <h2 className="text-xl font-bold text-zinc-100 mb-1.5">Scanning {repoName}</h2>
          <p className="text-zinc-500 text-sm">{status?.message || "Analysing your codebase for vulnerabilities…"}</p>
        </div>
        <div className="space-y-6">
          <div className="h-0.5 w-full bg-zinc-900 rounded-full overflow-hidden">
            <div className="h-full bg-indigo-500 transition-all duration-700 ease-out" style={{ width: `${progress}%` }} />
          </div>
          <div className="grid grid-cols-4 gap-2">
            {steps.map((step, idx) => (
              <div key={step} className={`flex flex-col items-center gap-2 ${idx <= stepIdx ? "text-indigo-400" : "text-zinc-700"}`}>
                <div className={`w-2.5 h-2.5 rounded-full ${
                  idx === stepIdx ? "bg-indigo-500 animate-pulse" : idx < stepIdx ? "bg-indigo-500" : "bg-zinc-800"
                }`} />
                <span className="text-[10px] font-medium uppercase tracking-wider text-center">{step}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── REPO CARD ────────────────────────────────────────────────────────────────
function RepoCard({ repo, onScanStart, scanning }: { repo: Repo; onScanStart: () => void; scanning: boolean }) {
  return (
    <div className="group bg-zinc-900/40 hover:bg-zinc-900/70 border border-zinc-800 hover:border-zinc-700 rounded-xl p-5 transition-all duration-200">
      <div className="flex justify-between items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2.5 mb-2">
            <div className="p-1.5 bg-zinc-800 rounded-lg text-zinc-400"><Icons.Github /></div>
            <a href={repo.html_url} target="_blank"
              className="text-sm font-semibold text-zinc-200 hover:text-indigo-400 truncate transition-colors">
              {repo.name}
            </a>
            <span className={`px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider border rounded-full flex-shrink-0 ${
              repo.private ? "bg-amber-500/8 text-amber-500 border-amber-500/20" : "bg-emerald-500/8 text-emerald-400 border-emerald-500/20"
            }`}>
              {repo.private ? "Private" : "Public"}
            </span>
          </div>
          <p className="text-xs text-zinc-500 line-clamp-2 mb-4 leading-relaxed h-8">
            {repo.description || "No description provided."}
          </p>
          <div className="flex items-center gap-4 text-xs text-zinc-600">
            {repo.language && (
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-indigo-500/60" />
                {repo.language}
              </span>
            )}
            <span className="flex items-center gap-1"><Icons.Star /> {repo.stargazers_count}</span>
            <span className="flex items-center gap-1"><Icons.Fork /> {repo.forks_count}</span>
            <span className="hidden sm:inline">{timeAgo(repo.updated_at)}</span>
          </div>
        </div>
        <button
          onClick={onScanStart}
          disabled={scanning}
          className={`flex-shrink-0 px-4 py-2 rounded-lg text-xs font-semibold transition-all duration-200 ${
            scanning
              ? "bg-zinc-800 text-zinc-600 cursor-not-allowed"
              : "bg-zinc-100 text-zinc-900 hover:bg-white active:scale-95 shadow-md"
          }`}
        >
          {scanning ? "Scanning…" : "Scan Now"}
        </button>
      </div>
    </div>
  );
}

// ─── MAIN PAGE ────────────────────────────────────────────────────────────────
export default function RepositoriesPage() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [activeScanRepo, setActiveScanRepo] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const filteredRepos = useMemo(() =>
    repos.filter(r =>
      r.name.toLowerCase().includes(query.toLowerCase()) ||
      (r.description && r.description.toLowerCase().includes(query.toLowerCase()))
    ), [repos, query]);

  const addToast = useCallback((message: string, type: Toast["type"] = "info") => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000);
  }, []);

  const removeToast = useCallback((id: number) => setToasts(prev => prev.filter(t => t.id !== id)), []);

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      try {
        const pRes = await fetch(`${API_BASE_URL}/api/github/profile`, { credentials: "include" });
        if (pRes.status === 401) { setError("auth"); return; }
        setProfile(await pRes.json());

        const rRes = await fetch(`${API_BASE_URL}/api/github/repos?sort=updated&per_page=50`, { credentials: "include" });
        if (!rRes.ok) throw new Error("Failed to load repositories");
        const rData = await rRes.json();
        setRepos(Array.isArray(rData) ? rData : (rData.repositories || []));
      } catch {
        setError("Failed to load data");
      } finally {
        setLoading(false);
      }
    };
    init();
  }, []);

  const handleScanStart = async (repo: Repo) => {
    const owner = repo.owner?.login || repo.full_name?.split("/")[0] || "";
    const repoKey = `${owner}/${repo.name}`;
    if (activeScanRepo === repoKey) return;

    try {
      const eligibilityRes = await fetch(
        `${API_BASE_URL}/api/scanning/repos/${owner}/${repo.name}/check-eligibility?branch=main`,
        { method: "POST", credentials: "include" }
      );

      if (!eligibilityRes.ok) {
        const err = await eligibilityRes.json().catch(() => ({ detail: eligibilityRes.statusText }));
        addToast(`Eligibility check failed: ${err.detail}`, "error");
        return;
      }

      const eligibility = await eligibilityRes.json();

      if (!eligibility || typeof eligibility.eligible === "undefined") {
        addToast("Could not verify eligibility — starting scan anyway.", "info");
      } else if (!eligibility.eligible) {
        const confirmed = window.confirm(
          `⚠️ ${eligibility.reason}\n\n` +
          `Last scanned: ${eligibility.last_scanned_commit || "Never"}\n` +
          `Latest commit: ${eligibility.latest_commit}\n\n` +
          `Force scan anyway?`
        );
        if (!confirmed) { addToast("Scan cancelled.", "info"); return; }

        setActiveScanRepo(repoKey);
        try {
          const res = await fetch(
            `${API_BASE_URL}/api/scanning/repos/${owner}/${repo.name}/scan?branch=main&force=true`,
            { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include" }
          );
          if (!res.ok) { const e = await res.json().catch(() => ({ detail: res.statusText })); throw new Error(e.detail); }
          setActiveScanId((await res.json()).scan_id);
        } catch (e: any) {
          addToast(e.message || "Failed to start forced scan", "error");
          setActiveScanRepo(null);
        }
        return;
      } else if (eligibility.has_new_commits) {
        addToast(`${eligibility.new_commits_count} new commit(s) — scanning…`, "success");
      }

      setActiveScanRepo(repoKey);
      const res = await fetch(
        `${API_BASE_URL}/api/scanning/repos/${owner}/${repo.name}/scan?branch=main`,
        { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include" }
      );
      if (!res.ok) { const e = await res.json().catch(() => ({ detail: res.statusText })); throw new Error(e.detail); }
      setActiveScanId((await res.json()).scan_id);

    } catch (err: any) {
      addToast(err.message || "Failed to initiate scan", "error");
      setActiveScanRepo(null);
    }
  };

  if (activeScanId && activeScanRepo && !scanResult) {
    return (
      <>
        <Toasts toasts={toasts} removeToast={removeToast} />
        <ScanProgress
          scanId={activeScanId}
          repoName={activeScanRepo.split("/")[1] || activeScanRepo}
          onComplete={(r) => { setScanResult(r); setActiveScanId(null); setActiveScanRepo(null); }}
        />
      </>
    );
  }

  if (scanResult) {
    return (
      <>
        <Toasts toasts={toasts} removeToast={removeToast} />
        <ScanResultsModal result={scanResult} onClose={() => setScanResult(null)} />
      </>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-sans selection:bg-indigo-500/30">
      <Toasts toasts={toasts} removeToast={removeToast} />

      <header className="sticky top-0 z-20 bg-zinc-950/90 backdrop-blur-md border-b border-zinc-800/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="bg-indigo-600 w-7 h-7 rounded-lg flex items-center justify-center text-white">
              <Icons.Shield />
            </div>
            <span className="font-bold text-sm tracking-tight">ReVAMP</span>
          </div>
          {profile && (
            <div className="flex items-center gap-2.5 pl-5 border-l border-zinc-800">
              <p className="text-xs font-medium text-zinc-400 hidden sm:block">{profile.name || profile.login}</p>
              <img src={profile.avatar_url} alt="" className="w-7 h-7 rounded-full ring-1 ring-zinc-700" />
            </div>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error === "auth" ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <div className="w-16 h-16 bg-zinc-900 rounded-2xl flex items-center justify-center mb-5 text-zinc-500 border border-zinc-800">
              <Icons.Github />
            </div>
            <h2 className="text-xl font-bold mb-2">Connect to GitHub</h2>
            <p className="text-zinc-500 max-w-sm mb-7 text-sm">Authorize GitHub to access your repositories and start scanning.</p>
            <button
              onClick={() => window.location.href = `${API_BASE_URL}/auth/github/login?redirect_to=/repositories`}
              className="px-6 py-2.5 bg-zinc-100 text-zinc-900 font-semibold rounded-xl hover:bg-white transition-colors text-sm"
            >
              Authorize GitHub
            </button>
          </div>
        ) : (
          <>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-7">
              <div>
                <h1 className="text-xl font-bold text-zinc-100">Repositories</h1>
                <p className="text-zinc-500 text-sm mt-0.5">Scan your codebases for vulnerabilities.</p>
              </div>
              <div className="relative group w-full md:w-80">
                <div className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600 group-focus-within:text-indigo-400 transition-colors">
                  <Icons.Search />
                </div>
                <input
                  type="text"
                  placeholder="Search repositories…"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  className="w-full bg-zinc-900/60 border border-zinc-800 text-sm text-zinc-200 rounded-xl pl-10 pr-4 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500/40 transition-all placeholder:text-zinc-600"
                />
              </div>
            </div>

            {loading ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[1,2,3,4].map(i => (
                  <div key={i} className="h-36 bg-zinc-900/30 rounded-xl animate-pulse border border-zinc-800/50" />
                ))}
              </div>
            ) : filteredRepos.length === 0 ? (
              <div className="text-center py-16 border-2 border-dashed border-zinc-800/50 rounded-2xl">
                <p className="text-zinc-600 text-sm">No repositories found{query ? ` for "${query}"` : "."}</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {filteredRepos.map(repo => {
                  const owner = repo.owner?.login || repo.full_name?.split("/")[0] || "";
                  const repoKey = `${owner}/${repo.name}`;
                  return (
                    <RepoCard
                      key={repo.id}
                      repo={repo}
                      scanning={activeScanRepo === repoKey}
                      onScanStart={() => handleScanStart(repo)}
                    />
                  );
                })}
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}