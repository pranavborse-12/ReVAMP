import React, { useEffect, useState, useMemo } from "react";
import { Link } from "wouter";

const API_BASE_URL = "http://localhost:8000";

// --- ICONS (Inline SVGs for Professional Look) ---
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
    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
  ),
  ChevronRight: () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
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
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
  ),
  Code: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
    </svg>
  ),
  ArrowRight: () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
    </svg>
  )
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
interface AIFixRequest {
  vulnerability: Vulnerability;
  repo_owner: string;
  repo_name: string;
  file_path: string;
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

interface AIFixState {
  isOpen: boolean;
  isLoading: boolean;
  result: AIFixResult | null;
  error: string | null;
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

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 10) / 10 + " " + sizes[i];
}

const SEVERITY_CONFIG = {
  CRITICAL: { color: "text-red-500", bg: "bg-red-500/10", border: "border-red-500/20", label: "Critical" },
  HIGH: { color: "text-orange-500", bg: "bg-orange-500/10", border: "border-orange-500/20", label: "High" },
  MEDIUM: { color: "text-yellow-500", bg: "bg-yellow-500/10", border: "border-yellow-500/20", label: "Medium" },
  LOW: { color: "text-blue-500", bg: "bg-blue-500/10", border: "border-blue-500/20", label: "Low" },
  WARNING: { color: "text-amber-500", bg: "bg-amber-500/10", border: "border-amber-500/20", label: "Warning" },
  INFO: { color: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/20", label: "Info" },
};

function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.INFO;
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider border ${style.bg} ${style.color} ${style.border}`}>
      {style.label}
    </span>
  );
}

// --- COMPONENTS ---

function Toasts({ toasts, removeToast }: { toasts: Toast[]; removeToast: (id: number) => void }) {
  return (
    <div className="fixed bottom-5 right-5 flex flex-col gap-3 z-[100] max-w-sm w-full">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`px-4 py-3 rounded-md shadow-lg border backdrop-blur-md flex items-center justify-between animate-slide-up ${
            t.type === "error" ? "bg-red-950/80 border-red-800 text-red-100" :
            t.type === "info" ? "bg-blue-950/80 border-blue-800 text-blue-100" :
            "bg-emerald-950/80 border-emerald-800 text-emerald-100"
          }`}
          onClick={() => removeToast(t.id)}
        >
          <span className="text-sm font-medium">{t.message}</span>
        </div>
      ))}
    </div>
  );
}

// --- SCAN RESULTS (Master-Detail View) ---
function ScanResultsModal({ result, onClose }: { result: ScanResult; onClose: () => void }) {
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [filterSev, setFilterSev] = useState<string | null>(null);
  const [fixingVuln, setFixingVuln] = useState<Vulnerability | null>(null);

  // Default to first vuln if exists
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
      <div className="h-16 border-b border-zinc-800 flex items-center justify-between px-6 bg-zinc-900/50 backdrop-blur-sm">
        <div className="flex items-center gap-4">
          <div className="bg-zinc-800 p-2 rounded-lg">
            <Icons.Shield />
          </div>
          <div>
            <h2 className="text-lg font-bold leading-none">{result.repo_name}</h2>
            <div className="flex items-center gap-2 text-xs text-zinc-400 mt-1">
              <span>{result.total_issues} issues detected</span>
              <span>â€¢</span>
              <span>{result.scan_duration?.toFixed(2)}s scan time</span>
            </div>
          </div>
        </div>
        <button onClick={onClose} className="p-2 hover:bg-zinc-800 rounded-full transition-colors text-zinc-400 hover:text-white">
          <Icons.Close />
        </button>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex overflow-hidden">
        
        {/* Sidebar (List) */}
        <div className="w-full md:w-[400px] border-r border-zinc-800 flex flex-col bg-zinc-900/20">
          {/* Filters */}
          <div className="p-4 border-b border-zinc-800 overflow-x-auto">
            <div className="flex gap-2">
              <button 
                onClick={() => setFilterSev(null)}
                className={`px-3 py-1 rounded text-xs font-medium whitespace-nowrap transition-colors border ${
                  !filterSev ? "bg-zinc-100 text-zinc-900 border-zinc-100" : "bg-transparent text-zinc-400 border-zinc-700 hover:border-zinc-500"
                }`}
              >
                All
              </button>
              {severities.map(sev => {
                const count = result.severity_summary[sev.toLowerCase() as keyof SeveritySummary] || 0;
                if (count === 0) return null;
                const style = SEVERITY_CONFIG[sev as keyof typeof SEVERITY_CONFIG];
                const active = filterSev === sev;
                return (
                  <button
                    key={sev}
                    onClick={() => setFilterSev(active ? null : sev)}
                    className={`px-3 py-1 rounded text-xs font-medium whitespace-nowrap transition-colors border flex items-center gap-2 ${
                      active ? `${style.bg} ${style.color} ${style.border} ring-1 ring-inset` : "bg-transparent text-zinc-400 border-zinc-800 hover:bg-zinc-800"
                    }`}
                  >
                    {sev.charAt(0) + sev.slice(1).toLowerCase()} 
                    <span className="opacity-60">{count}</span>
                  </button>
                )
              })}
            </div>
          </div>

          {/* List */}
          <div className="flex-1 overflow-y-auto">
            {filteredVulns.length === 0 ? (
              <div className="p-8 text-center text-zinc-500 text-sm">No issues found matching filters.</div>
            ) : (
              filteredVulns.map((vuln, idx) => (
                <div
                  key={idx}
                  onClick={() => setSelectedVuln(vuln)}
                  className={`p-4 border-b border-zinc-800/50 cursor-pointer transition-colors hover:bg-zinc-800/50 ${
                    selectedVuln === vuln ? "bg-zinc-800 border-l-2 border-l-blue-500" : "border-l-2 border-l-transparent"
                  }`}
                >
                  <div className="flex justify-between items-start mb-1">
                    <span className="text-sm font-semibold text-zinc-200 line-clamp-1 pr-2">{vuln.vulnerability_type}</span>
                    <SeverityBadge severity={vuln.severity} />
                  </div>
                  <p className="text-xs text-zinc-500 line-clamp-2 mb-2">{vuln.message}</p>
                  <div className="flex items-center gap-2 text-[10px] text-zinc-600 font-mono">
                    <Icons.File />
                    <span className="truncate">{vuln.location.file}:{vuln.location.start_line}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Detail View */}
        <div className="flex-1 bg-zinc-950 overflow-y-auto relative hidden md:block">
          {selectedVuln ? (
            <div className="p-8 max-w-4xl mx-auto">
              <div className="mb-6 flex justify-end">
                <button
                onClick={() => setFixingVuln(selectedVuln)}
                className="group relative px-6 py-3 bg-zinc-100 hover:bg-white text-zinc-950 rounded-xl font-bold transition-all duration-300 shadow-[0_0_20px_rgba(59,130,246,0.5)] hover:shadow-[0_0_30px_rgba(59,130,246,0.8)] flex items-center gap-3 overflow-hidden"
                >
                  <div className="absolute inset-0 w-full h-full bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:animate-[shimmer_1.5s_infinite]" />
                  <div className="relative flex items-center gap-2"></div>    
                  <Icons.Sparkles />
                  <span className="tracking-tight">Auto-Fix with AI</span>
                  <Icons.ArrowRight />
                  <div className="relative flex items-center justify-center w-6 h-6 bg-zinc-900 rounded-lg group-hover:translate-x-1 transition-transform duration-300">
                    <Icons.ArrowRight />
                    </div>
                  </button>
                </div>
              <div className="mb-6 pb-6 border-b border-zinc-800">
                <div className="flex items-center gap-3 mb-4">
                  <SeverityBadge severity={selectedVuln.severity} />
                  <span className="text-xs font-mono text-zinc-500 px-2 py-1 bg-zinc-900 rounded">{selectedVuln.rule_id}</span>
                </div>
                <h1 className="text-2xl font-bold text-zinc-100 mb-2">{selectedVuln.vulnerability_type}</h1>
                <p className="text-zinc-400 leading-relaxed">{selectedVuln.message}</p>
              </div>

              {/* Location Card */}
              <div className="bg-zinc-900/30 rounded-lg border border-zinc-800 p-4 mb-6">
                <h3 className="text-sm font-bold text-zinc-300 mb-3 flex items-center gap-2">
                  <Icons.File /> Location
                </h3>
                <div className="font-mono text-sm text-zinc-400 bg-zinc-950 p-3 rounded border border-zinc-800/50 flex justify-between">
                  <span>{selectedVuln.location.file}</span>
                  <span className="text-zinc-500">Lines {selectedVuln.location.start_line} - {selectedVuln.location.end_line}</span>
                </div>
              </div>

              {/* Code Snippet */}
              {selectedVuln.code_snippet && (
                <div className="mb-6">
                   <h3 className="text-sm font-bold text-zinc-300 mb-3">Code Evidence</h3>
                   <div className="relative group">
                     <pre className="bg-zinc-900 rounded-lg border border-zinc-800 p-4 overflow-x-auto text-sm font-mono text-zinc-300 leading-relaxed">
                       {selectedVuln.code_snippet}
                     </pre>
                   </div>
                </div>
              )}

              {/* Metadata */}
              <div className="grid grid-cols-2 gap-4">
                 <div className="p-4 rounded-lg bg-zinc-900/20 border border-zinc-800">
                   <span className="text-xs text-zinc-500 uppercase tracking-wider font-semibold">Scanner</span>
                   <p className="text-zinc-200 mt-1 font-mono text-sm">{selectedVuln.scanner}</p>
                 </div>
                 {selectedVuln.cwe && selectedVuln.cwe.length > 0 && (
                   <div className="p-4 rounded-lg bg-zinc-900/20 border border-zinc-800">
                     <span className="text-xs text-zinc-500 uppercase tracking-wider font-semibold">CWE</span>
                     <div className="flex gap-2 mt-1">
                       {selectedVuln.cwe.map(c => (
                         <span key={c} className="text-blue-400 text-xs font-mono bg-blue-950/30 px-2 py-1 rounded">{c}</span>
                       ))}
                     </div>
                   </div>
                 )}
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-zinc-600">
              <Icons.Shield />
              <p className="mt-4 text-sm">Select an issue to view details</p>
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
// AI Vulnerability fixes
function AIFixModal({ 
  vulnerability, 
  repoOwner, 
  repoName, 
  onClose 
}: { 
  vulnerability: Vulnerability; 
  repoOwner: string; 
  repoName: string; 
  onClose: () => void;
}) {
  const [state, setState] = useState<AIFixState>({
    isOpen: true,
    isLoading: true,
    result: null,
    error: null
  });

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
            file_path: vulnerability.location.file
          })
        });

        if (!response.ok) {
          throw new Error("Failed to generate fix");
        }

        const result = await response.json();
        setState(prev => ({ ...prev, isLoading: false, result }));
      } catch (error: any) {
        setState(prev => ({ 
          ...prev, 
          isLoading: false, 
          error: error.message || "Failed to generate AI fix" 
        }));
      }
    };

    fetchFix();
  }, [vulnerability, repoOwner, repoName]);

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/90 backdrop-blur-md p-4 lg:p-12">
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-7xl h-full max-h-[850px] overflow-hidden shadow-2xl flex flex-col">
        
        {/* Header - Minimal & Clean */}
        <div className="border-b border-zinc-800 p-5 flex items-center justify-between bg-zinc-900">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 bg-blue-500/10 rounded-xl flex items-center justify-center text-blue-400 border border-blue-500/20">
              <Icons.Sparkles />
            </div>
            <div>
              <h2 className="text-sm font-bold text-zinc-100 uppercase tracking-widest">AI Security Engineer</h2>
              <p className="text-xs text-zinc-500 font-mono">Patching: {vulnerability.location.file}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-zinc-800 rounded-full transition-colors text-zinc-500"><Icons.Close /></button>
        </div>

        <div className="flex-1 flex overflow-hidden">
          {state.isLoading ? (
             <div className="flex-1 flex flex-col items-center justify-center space-y-4">
                <div className="w-12 h-12 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-zinc-400 font-mono text-sm animate-pulse">Generating secure patch...</p>
             </div>
          ) : state.result ? (
            <>
              {/* Left Panel: The Explanation (The "Chat") */}
              <div className="w-full lg:w-[400px] border-r border-zinc-800 flex flex-col bg-zinc-950/50">
                <div className="p-6 overflow-y-auto space-y-8">
                  
                  {/* Insight Section */}
                  <section>
                    <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest block mb-3">Vulnerability Analysis</label>
                    <div className="text-sm text-zinc-300 leading-relaxed bg-zinc-900/50 p-4 rounded-xl border border-zinc-800">
                      {state.result.vulnerability_analysis}
                    </div>
                  </section>

                  {/* Fix Logic Section */}
                  <section>
                    <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest block mb-3">Proposed Solution</label>
                    <div className="space-y-3">
                      {state.result.changes_made.map((change, i) => (
                        <div key={i} className="flex gap-3 text-xs text-zinc-400">
                          <div className="mt-1 text-emerald-500"><Icons.Check /></div>
                          <span>{change}</span>
                        </div>
                      ))}
                    </div>
                  </section>

                  <div className="bg-blue-500/5 border border-blue-500/10 p-4 rounded-xl">
                    <p className="text-xs text-blue-400 leading-relaxed italic">
                      "I've updated the logic to sanitize inputs and prevent potential {vulnerability.vulnerability_type} escalations."
                    </p>
                  </div>
                </div>

                <div className="p-4 border-t border-zinc-800 bg-zinc-900/50">
                  <button 
                    onClick={() => navigator.clipboard.writeText(state.result!.fixed_code)}
                    className="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm font-bold transition-all flex items-center justify-center gap-2"
                  >
                    <Icons.Code /> Copy Fixed Code
                  </button>
                </div>
              </div>

              {/* Right Panel: The Code (Interactive Diff) */}
              <div className="hidden lg:flex flex-1 flex-col bg-zinc-950">
                <div className="flex-1 overflow-hidden flex flex-col">
                  {/* Code Header */}
                  <div className="flex border-b border-zinc-900">
                    <div className="px-6 py-3 border-r border-zinc-800 bg-zinc-900 text-xs font-mono text-zinc-300">Comparison View</div>
                  </div>
                  
                  {/* Code Content */}
                  <div className="flex-1 overflow-y-auto grid grid-cols-2">
                    <div className="border-r border-zinc-900">
                      <div className="p-3 bg-red-500/10 text-red-500 text-[10px] font-bold uppercase sticky top-0">Vulnerable Code</div>
                      <pre className="p-6 text-[11px] font-mono text-zinc-500 whitespace-pre-wrap">{state.result.original_code}</pre>
                    </div>
                    <div>
                      <div className="p-3 bg-emerald-500/10 text-emerald-500 text-[10px] font-bold uppercase sticky top-0">AI Secure Fix</div>
                      <pre className="p-6 text-[11px] font-mono text-zinc-200 whitespace-pre-wrap">{state.result.fixed_code}</pre>
                    </div>
                  </div>
                </div>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
}


// --- SCAN PROGRESS ---
function ScanProgress({ scanId, repoName, onComplete }: { scanId: string; repoName: string; onComplete: (result: ScanResult) => void; }) {
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let pollInterval: NodeJS.Timeout;
    const pollStatus = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/scanning/scans/${scanId}/status`, { credentials: "include" });
        if (!res.ok) throw new Error("Status check failed");
        const data = await res.json();
        setStatus(data);

        if (data.status === "completed") {
          clearInterval(pollInterval);
          const resultRes = await fetch(`${API_BASE_URL}/api/scanning/scans/${scanId}`, { credentials: "include" });
          const result = await resultRes.json();
          onComplete(result);
        } else if (data.status === "failed") {
          clearInterval(pollInterval);
          setError("Scan execution failed.");
        }
      } catch (err: any) {
        setError(err.message);
        clearInterval(pollInterval);
      }
    };
    pollStatus();
    pollInterval = setInterval(pollStatus, 1500);
    return () => clearInterval(pollInterval);
  }, [scanId]);

  if (error) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
        <div className="bg-red-950/20 border border-red-900/50 p-6 rounded-lg max-w-md w-full text-center">
          <h3 className="text-red-400 font-bold mb-2">Scan Failed</h3>
          <p className="text-zinc-400 text-sm">{error}</p>
        </div>
      </div>
    );
  }

  const progress = parseInt(status?.progress || "0");
  const steps = ["Queued", "Cloning", "Analyzing", "Finalizing"];
  const stepIdx = status?.status === "queued" ? 0 : status?.status === "cloning" ? 1 : status?.status === "analyzing" ? 2 : 3;

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
      <div className="w-full max-w-lg">
        <div className="text-center mb-10">
          <div className="w-16 h-16 bg-blue-500/10 rounded-2xl flex items-center justify-center mx-auto mb-6 text-blue-500 animate-pulse">
            <Icons.Shield />
          </div>
          <h2 className="text-2xl font-bold text-zinc-100 mb-2">Scanning {repoName}</h2>
          <p className="text-zinc-500 text-sm">Please wait while we analyze your codebase.</p>
        </div>

        <div className="space-y-8">
           {/* Progress Bar */}
           <div className="h-1 w-full bg-zinc-900 rounded-full overflow-hidden">
             <div 
               className="h-full bg-blue-500 transition-all duration-500 ease-out" 
               style={{ width: `${progress}%` }}
             ></div>
           </div>

           {/* Steps */}
           <div className="grid grid-cols-4 gap-2">
             {steps.map((step, idx) => (
               <div key={step} className={`flex flex-col items-center gap-2 ${idx <= stepIdx ? "text-blue-400" : "text-zinc-700"}`}>
                 <div className={`w-3 h-3 rounded-full ${idx === stepIdx ? "bg-blue-500 animate-ping" : idx < stepIdx ? "bg-blue-500" : "bg-zinc-800"}`} />
                 <span className="text-[10px] font-medium uppercase tracking-wider">{step}</span>
               </div>
             ))}
           </div>
        </div>
      </div>
    </div>
  );
}

// --- REPOSITORY CARD ---
function RepoCard({ repo, onScanStart, scanning }: { repo: Repo; onScanStart: () => void; scanning: boolean }) {
  return (
    <div className="group bg-zinc-900/40 hover:bg-zinc-900 border border-zinc-800 hover:border-zinc-700 rounded-lg p-5 transition-all duration-200">
      <div className="flex justify-between items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-1.5 bg-zinc-800 rounded text-zinc-400">
              <Icons.Github />
            </div>
            <a href={repo.html_url} target="_blank" className="text-base font-semibold text-zinc-200 hover:text-blue-400 truncate transition-colors">
              {repo.name}
            </a>
            <span className={`px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider border rounded-full ${
              repo.private 
              ? "bg-amber-500/10 text-amber-500 border-amber-500/20" 
              : "bg-emerald-500/10 text-emerald-500 border-emerald-500/20"
            }`}>
              {repo.private ? "Private" : "Public"}
            </span>
          </div>
          
          <p className="text-sm text-zinc-500 line-clamp-2 mb-4 h-10">
            {repo.description || "No description provided."}
          </p>

          <div className="flex items-center gap-4 text-xs text-zinc-500 font-mono">
             {repo.language && (
               <span className="flex items-center gap-1.5">
                 <span className="w-2 h-2 rounded-full bg-blue-500/50"></span>
                 {repo.language}
               </span>
             )}
             <span className="flex items-center gap-1"><Icons.Star /> {repo.stargazers_count}</span>
             <span className="flex items-center gap-1"><Icons.Fork /> {repo.forks_count}</span>
             <span className="hidden sm:inline">Updated {timeAgo(repo.updated_at)}</span>
          </div>
        </div>

        <button
          onClick={onScanStart}
          disabled={scanning}
          className={`shrink-0 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            scanning 
            ? "bg-zinc-800 text-zinc-500 cursor-not-allowed" 
            : "bg-zinc-100 text-zinc-900 hover:bg-white shadow-lg hover:shadow-xl"
          }`}
        >
          {scanning ? "Starting..." : "Scan Now"}
        </button>
      </div>
    </div>
  );
}

// --- MAIN PAGE ---
export default function RepositoriesPage() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const filteredRepos = useMemo(() => {
    return repos.filter(repo =>
      repo.name.toLowerCase().includes(query.toLowerCase()) ||
      (repo.description && repo.description.toLowerCase().includes(query.toLowerCase()))
    );
  }, [repos, query]);

  const addToast = (message: string, type: "success" | "error" | "info" = "info") => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
  };

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      try {
        const pRes = await fetch(`${API_BASE_URL}/api/github/profile`, { credentials: "include" });
        if (pRes.status === 401) { setError("auth"); return; }
        const pData = await pRes.json();
        setProfile(pData);

        const rRes = await fetch(`${API_BASE_URL}/api/github/repos?sort=updated&per_page=50`, { credentials: "include" });
        if (!rRes.ok) throw new Error("Failed to load repositories");
        const rData = await rRes.json();
        // Ensure rData is an array (handle both direct array and nested data responses)
        const reposArray = Array.isArray(rData) ? rData : (rData.repositories || []);
        setRepos(reposArray);
      } catch (err) {
        setError("Failed to load data");
      } finally {
        setLoading(false);
      }
    };
    init();
  }, []);
  
  const handleScanStart = async (repo: Repo) => {
    try {
      const owner = repo.owner?.login || repo.full_name?.split("/")[0] || "";
      const eligibilityRes = await fetch(
        `${API_BASE_URL}/api/scanning/repos/${owner}/${repo.name}/check-eligibility?branch=main`,
        { method: "POST", credentials: "include" }
      );
      if (!eligibilityRes.ok) {
      const errorText = await eligibilityRes.text();
      addToast(`Failed to check eligibility: ${errorText}`, "error");
      return;
    }
    const eligibility = await eligibilityRes.json();
    
    // ✅ FIXED: Validate response structure
    if (!eligibility || typeof eligibility.eligible === 'undefined') {
      console.error("Invalid eligibility response:", eligibility);
      addToast("Received invalid response from server. Starting scan anyway...", "info");
      // Continue with scan anyway
    } else if (!eligibility.eligible) {
      // Step 2: Show appropriate messages for ineligible repos
      const shouldForce = window.confirm(
        `⚠️ ${eligibility.reason}\n\n` +
        `Last scanned: ${eligibility.last_scanned_commit || 'Never'}\n` +
        `Latest commit: ${eligibility.latest_commit}\n` +
        `Message: ${eligibility.commit_message || 'No message'}\n\n` +
        `Do you want to force scan anyway?`
      );
      
      if (!shouldForce) {
        addToast("Scan cancelled - no new commits detected", "info");
        return;
      }
    } else if (eligibility.has_new_commits) {
      addToast(
        `✅ ${eligibility.new_commits_count} new commit(s) detected! Starting scan...`,
        "success"
      );
    } else if (!eligibility.is_first_scan) {
      addToast(
        `⚠️ No new commits. ${eligibility.remaining_scans} rescan(s) remaining.`,
        "info"
      );
    }
    
    // Step 3: Initiate scan
    const shouldForce = eligibility && !eligibility.eligible;
    const scanUrl = shouldForce
      ? `${API_BASE_URL}/api/scanning/repos/${owner}/${repo.name}/scan?branch=main&force=true`
      : `${API_BASE_URL}/api/scanning/repos/${owner}/${repo.name}/scan?branch=main`;
    
    const res = await fetch(scanUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include"
    });
    
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.detail || "Failed to start scan");
    }
    
    const data = await res.json();
    setActiveScanId(data.scan_id);
    
  } catch (err: any) {
    console.error("Scan start error:", err);
    addToast(err.message || "Failed to initiate scan", "error");
  }
};

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-sans selection:bg-blue-500/30">
      <Toasts toasts={toasts} removeToast={(id) => setToasts(prev => prev.filter(t => t.id !== id))} />
      
      {/* Navbar */}
      <header className="sticky top-0 z-20 bg-zinc-950/80 backdrop-blur-md border-b border-zinc-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-blue-600 w-8 h-8 rounded-lg flex items-center justify-center text-white shadow-lg shadow-blue-900/20">
              <Icons.Shield />
            </div>
            <span className="font-bold text-lg tracking-tight">ReVAMP</span>
          </div>
          {profile && (
            <div className="flex items-center gap-3 pl-6 border-l border-zinc-800">
              <div className="text-right hidden sm:block">
                <p className="text-sm font-medium text-zinc-200">{profile.name || profile.login}</p>
              </div>
              <img src={profile.avatar_url} alt="" className="w-8 h-8 rounded-full ring-2 ring-zinc-800" />
            </div>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error === "auth" ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <div className="w-20 h-20 bg-zinc-900 rounded-full flex items-center justify-center mb-6 text-zinc-500">
               <Icons.Github />
            </div>
            <h2 className="text-2xl font-bold mb-4">Connect to GitHub</h2>
            <p className="text-zinc-400 max-w-md mb-8">Connect your account to access your repositories and start scanning for vulnerabilities.</p>
            <button 
              onClick={() => window.location.href = `${API_BASE_URL}/auth/github/login?redirect_to=/repositories`}
              className="px-6 py-3 bg-zinc-100 text-zinc-900 font-semibold rounded-lg hover:bg-white transition-colors"
            >
              Authorize GitHub
            </button>
          </div>
        ) : (
          <>
            {/* Header & Controls */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
               <div>
                 <h1 className="text-2xl font-bold text-zinc-100">Repositories</h1>
                 <p className="text-zinc-400 text-sm mt-1">Manage and scan your codebases.</p>
               </div>
               <div className="relative group w-full md:w-96">
                 <div className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 group-focus-within:text-blue-400 transition-colors">
                   <Icons.Search />
                 </div>
                 <input 
                    type="text" 
                    placeholder="Search repositories..." 
                    value={query}
                    onChange={e => setQuery(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-800 text-sm text-zinc-200 rounded-lg pl-10 pr-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500/50 transition-all placeholder:text-zinc-600"
                 />
               </div>
            </div>

            {loading ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {[1,2,3,4,5,6].map(i => (
                  <div key={i} className="h-40 bg-zinc-900/30 rounded-lg animate-pulse" />
                ))}
              </div>
            ) : filteredRepos.length === 0 ? (
               <div className="text-center py-20 border-2 border-dashed border-zinc-800 rounded-xl">
                 <p className="text-zinc-500 font-medium">No repositories found matching "{query}"</p>
               </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {filteredRepos.map(repo => (
                  <RepoCard 
                    key={repo.id} 
                    repo={repo} 
                    scanning={activeScanId === repo.id.toString()}
                    onScanStart={() => handleScanStart(repo)} 
                  />
                ))}
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}