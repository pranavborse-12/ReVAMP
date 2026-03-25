// src/pages/documentation.tsx
import React, { useState } from "react";
import { Search, ExternalLink } from "lucide-react";

// ── Color tokens matching repositories.tsx ──────────────────
const C = {
  bg:      "#0d1117",
  surface: "#161b22",
  border:  "#21262d",
  borderH: "#30363d",
  text:    "#c9d1d9",
  muted:   "#8b949e",
  subtle:  "#6e7681",
  accent:  "#58a6ff",
};

const nav = [
  {
    section: "Getting Started",
    articles: [
      {
        title: "Quick Start Guide",
        slug: "quick-start",
        content: (
          <div>
            <h1>Quick Start Guide</h1>
            <p>Get up and running with ReVAMP in under 5 minutes.</p>

            <h2>1. Sign in with GitHub</h2>
            <p>Click <strong>Sign in with GitHub</strong> on the home page. ReVAMP requests read access to your repositories so it can clone them for scanning. No code is stored permanently.</p>

            <h2>2. Go to Repositories</h2>
            <p>After signing in, navigate to <strong>Repositories</strong> in the sidebar. You'll see all your GitHub repos listed with their language and last updated date.</p>

            <h2>3. Start a Scan</h2>
            <p>Click <strong>Scan Now</strong> on any repository. ReVAMP will clone the repo, detect languages, and run all applicable scanners in parallel. Scans typically take 3–4 minutes.</p>

            <h2>4. View Results</h2>
            <p>Once the scan completes, go to <strong>Vulnerabilities</strong> in the sidebar. Select your scan from the dropdown at the top right to see all findings. Click any card to expand the full detail including the flagged code snippet.</p>

            <h2>What gets scanned?</h2>
            <p>ReVAMP runs three scanners simultaneously:</p>
            <ul>
              <li><strong>Semgrep</strong> — OWASP Top 10, secrets detection, and language-specific rules. Runs on all languages.</li>
              <li><strong>Bandit</strong> — Deep Python security analysis. Only runs if Python is detected.</li>
              <li><strong>ESLint Security</strong> — JavaScript and TypeScript security rules. Only runs if JS/TS is detected.</li>
            </ul>
          </div>
        ),
      },
      {
        title: "Severity Levels",
        slug: "severity",
        content: (
          <div>
            <h1>Severity Levels</h1>
            <p>Every vulnerability is assigned one of four severity levels based on exploitability and impact.</p>

            <h2>CRITICAL</h2>
            <p>Immediate exploitation risk with no prerequisites. Examples: SQL injection, Remote Code Execution, XML External Entity (XXE) injection. Fix these first.</p>

            <h2>HIGH</h2>
            <p>Serious security weakness that is exploitable under common conditions. Examples: Cross-site Scripting (XSS), CSRF, hardcoded secrets, insecure deserialization.</p>

            <h2>MEDIUM</h2>
            <p>Moderate risk that may require specific conditions to exploit. Examples: Weak cryptography (MD5/SHA1), missing input validation, insecure redirects.</p>

            <h2>LOW</h2>
            <p>Minor issues with limited direct impact. Examples: Deprecated function usage, information disclosure in error messages, missing security headers.</p>

            <h2>Risk Score</h2>
            <p>Your dashboard Risk Score is calculated from the latest scan of each repository:</p>
            <pre>(Critical × 10) + (High × 5) + (Medium × 2) + (Low × 0.5)</pre>
            <p>A score above 50 is flagged as HIGH RISK. A score of 0 means no vulnerabilities were detected.</p>
          </div>
        ),
      },
    ],
  },
  {
    section: "Scanning",
    articles: [
      {
        title: "How Scanning Works",
        slug: "scan-pipeline",
        content: (
          <div>
            <h1>How Scanning Works</h1>
            <p>Every scan goes through a fixed pipeline from clone to results.</p>

            <h2>Pipeline</h2>
            <ol>
              <li><strong>Clone</strong> — The repository is cloned to a temporary directory using your GitHub token. The temp directory is deleted immediately after the scan.</li>
              <li><strong>Language Detection</strong> — File extensions and config files are analyzed to determine which scanners to run.</li>
              <li><strong>Parallel Scanning</strong> — All applicable scanners run simultaneously. Total scan time equals the slowest scanner, not the sum.</li>
              <li><strong>Deduplication</strong> — If multiple scanners find the same issue, the highest-severity version is kept.</li>
              <li><strong>Results</strong> — Findings are saved to the database and immediately available in the Vulnerabilities page.</li>
            </ol>

            <h2>Limits</h2>
            <ul>
              <li>Maximum repository size: <strong>500 MB</strong></li>
              <li>Clone timeout: <strong>120 seconds</strong></li>
              <li>Semgrep timeout: <strong>300 seconds</strong></li>
              <li>Maximum concurrent scans: <strong>5</strong></li>
              <li>Scan allowance per repository: <strong>5 scans</strong> — resets when new commits are pushed</li>
            </ul>

            <h2>Scan Allowance</h2>
            <p>Each repository gets 5 scan allowances. Once used, you'll need new commits to trigger another scan. This prevents redundant scans on unchanged code. The allowance resets automatically when ReVAMP detects a new commit SHA on the branch.</p>
          </div>
        ),
      },
      {
        title: "Branches",
        slug: "branches",
        content: (
          <div>
            <h1>Branches</h1>
            <p>By default, ReVAMP scans the <code>main</code> branch. You can scan any branch.</p>

            <h2>Scanning a Different Branch</h2>
            <ol>
              <li>Go to <strong>Repositories</strong></li>
              <li>Find the repository you want to scan</li>
              <li>Edit the branch field (defaults to <code>main</code>)</li>
              <li>Click <strong>Scan Now</strong></li>
            </ol>

            <h2>Common Branch Names</h2>
            <p>If your default branch isn't <code>main</code>, try <code>master</code>, <code>develop</code>, or check your GitHub repository settings. If the branch doesn't exist, the scan will fail at the clone step with a "branch not found" error.</p>
          </div>
        ),
      },
    ],
  },
  {
    section: "Vulnerabilities",
    articles: [
      {
        title: "Reading a Finding",
        slug: "reading-findings",
        content: (
          <div>
            <h1>Reading a Finding</h1>
            <p>Each vulnerability card on the Vulnerabilities page contains everything you need to understand and fix the issue.</p>

            <h2>Fields</h2>
            <ul>
              <li><strong>Severity</strong> — CRITICAL, HIGH, MEDIUM, or LOW. Shown as a colored badge.</li>
              <li><strong>Message</strong> — A human-readable description of the vulnerability.</li>
              <li><strong>File</strong> — The file where the issue was detected, with line numbers.</li>
              <li><strong>Flagged Code</strong> — The exact lines Semgrep identified as vulnerable. This is the real code from your repository.</li>
              <li><strong>Rule ID</strong> — The specific scanner rule that triggered. Search this on semgrep.dev for full remediation guidance.</li>
              <li><strong>Type</strong> — The vulnerability category (e.g. Cryptographic Issue, SQL Injection).</li>
              <li><strong>CWE</strong> — Common Weakness Enumeration ID. Links to MITRE's database for detailed context.</li>
              <li><strong>OWASP</strong> — The related OWASP Top 10 category if applicable.</li>
            </ul>

            <h2>Filtering</h2>
            <p>Use the tabs (All / Critical / High / Medium / Low) to filter by severity. Use the search bar to filter by file name, message text, or rule ID.</p>
          </div>
        ),
      },
    ],
  },
  {
    section: "API Reference",
    articles: [
      {
        title: "REST API",
        slug: "rest-api",
        content: (
          <div>
            <h1>REST API</h1>
            <p>All endpoints are available at <code>http://localhost:8000</code>. Authentication uses session cookies set during GitHub OAuth.</p>

            <h2>Authentication</h2>
            <pre>{`GET  /api/github/connect        Redirect to GitHub OAuth
GET  /api/github/callback        OAuth callback
GET  /api/github/profile         Get your GitHub profile`}</pre>

            <h2>Scanning</h2>
            <pre>{`POST /api/scanning/repos/{owner}/{repo}/scan   Start a scan
GET  /api/scanning/scans/{scan_id}             Get full results
GET  /api/scanning/scans/{scan_id}/status      Poll status
GET  /api/scanning/scans/history               List all scans
DELETE /api/scanning/scans/{scan_id}           Delete a scan`}</pre>

            <h2>Dashboard</h2>
            <pre>{`GET  /api/scanning/dashboard/stats             Summary stats
GET  /api/scanning/dashboard/trends?days=7     Vulnerability trends
GET  /api/scanning/dashboard/recent-scans      Recent activity
GET  /api/scanning/dashboard/vulnerable-files  Top vulnerable files`}</pre>

            <h2>Polling a Scan</h2>
            <p>After starting a scan, poll the status endpoint every 2 seconds until <code>status</code> is <code>completed</code> or <code>failed</code>. Possible status values: <code>queued</code>, <code>cloning</code>, <code>analyzing</code>, <code>scanning</code>, <code>completed</code>, <code>failed</code>.</p>
          </div>
        ),
      },
    ],
  },
];

export default function Documentation() {
  const [active, setActive]   = useState({ section: 0, article: 0 });
  const [search, setSearch]   = useState("");

  const allArticles = nav.flatMap((s, si) =>
    s.articles.map((a, ai) => ({ ...a, si, ai, section: s.section }))
  );
  const results = search.length > 1
    ? allArticles.filter(
        (a) =>
          a.title.toLowerCase().includes(search.toLowerCase()) ||
          a.section.toLowerCase().includes(search.toLowerCase())
      )
    : [];

  const current = nav[active.section]?.articles[active.article];

  return (
    <div style={{ display: "flex", height: "100vh", background: C.bg, color: C.text, overflow: "hidden", width: "100%", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>

      {/* ── Sidebar ─────────────────────────────────────── */}
      <div style={{ width: 240, borderRight: `1px solid ${C.border}`, display: "flex", flexDirection: "column", flexShrink: 0, overflowY: "auto" }}>
        <div style={{ padding: "20px 16px 12px" }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: C.text, marginBottom: 12 }}>Documentation</div>
          <div style={{ position: "relative" }}>
            <Search style={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", width: 11, height: 11, color: C.subtle }} />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search..."
              style={{
                width: "100%",
                background: C.surface,
                border: `1px solid ${C.border}`,
                borderRadius: 6,
                padding: "7px 8px 7px 28px",
                color: C.text,
                fontSize: 12,
                outline: "none",
                boxSizing: "border-box",
                fontFamily: "inherit",
              }}
            />
          </div>

          {/* Search results */}
          {search.length > 1 && (
            <div style={{ marginTop: 8 }}>
              {results.length === 0 ? (
                <div style={{ fontSize: 12, color: C.muted, padding: "4px 0" }}>No results</div>
              ) : (
                results.map((a, i) => (
                  <button
                    key={i}
                    onClick={() => { setActive({ section: a.si, article: a.ai }); setSearch(""); }}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: "6px 8px",
                      background: C.surface,
                      border: `1px solid ${C.border}`,
                      borderRadius: 6,
                      cursor: "pointer",
                      marginBottom: 3,
                      fontFamily: "inherit",
                    }}
                  >
                    <div style={{ fontSize: 12, color: C.text }}>{a.title}</div>
                    <div style={{ fontSize: 11, color: C.muted }}>{a.section}</div>
                  </button>
                ))
              )}
            </div>
          )}
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: "4px 12px 16px" }}>
          {nav.map((s, si) => (
            <div key={si} style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 10, color: C.subtle, textTransform: "uppercase", letterSpacing: "0.12em", fontWeight: 700, padding: "0 4px", marginBottom: 4 }}>
                {s.section}
              </div>
              {s.articles.map((a, ai) => {
                const isActive = active.section === si && active.article === ai;
                return (
                  <button
                    key={ai}
                    onClick={() => setActive({ section: si, article: ai })}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: "6px 8px",
                      borderRadius: 6,
                      border: "none",
                      cursor: "pointer",
                      fontFamily: "inherit",
                      background: isActive ? C.surface : "transparent",
                      color: isActive ? C.text : C.muted,
                      fontSize: 13,
                      display: "block",
                      transition: "all 0.1s",
                    }}
                  >
                    {a.title}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        {/* Resources */}
        <div style={{ padding: "12px 16px", borderTop: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 10, color: C.subtle, textTransform: "uppercase", letterSpacing: "0.12em", marginBottom: 8 }}>
            Resources
          </div>
          {[
            { label: "Semgrep Rules", href: "https://semgrep.dev/r" },
            { label: "OWASP Top 10",  href: "https://owasp.org/Top10" },
            { label: "CWE Database",  href: "https://cwe.mitre.org" },
          ].map(({ label, href }) => (
            <a
              key={label}
              href={href}
              target="_blank"
              rel="noreferrer"
              style={{ display: "flex", alignItems: "center", gap: 5, padding: "4px 0", fontSize: 12, color: C.muted, textDecoration: "none" }}
            >
              <ExternalLink style={{ width: 10, height: 10 }} /> {label}
            </a>
          ))}
        </div>
      </div>

      {/* ── Content ─────────────────────────────────────── */}
      <div style={{ flex: 1, overflowY: "auto", padding: "36px 48px", minWidth: 0 }}>
        <style>{`
          .doc-content h1 { font-size: 26px; font-weight: 800; color: ${C.text}; margin: 0 0 8px; line-height: 1.2; }
          .doc-content > div > p:first-of-type { font-size: 15px; color: ${C.muted}; margin: 0 0 32px; line-height: 1.7; border-bottom: 1px solid ${C.border}; padding-bottom: 24px; }
          .doc-content h2 { font-size: 15px; font-weight: 700; color: ${C.text}; margin: 28px 0 10px; }
          .doc-content p { font-size: 13px; color: ${C.muted}; line-height: 1.8; margin: 0 0 14px; }
          .doc-content ul, .doc-content ol { padding-left: 20px; margin: 0 0 16px; }
          .doc-content li { font-size: 13px; color: ${C.muted}; line-height: 1.8; margin-bottom: 4px; }
          .doc-content strong { color: ${C.text}; font-weight: 600; }
          .doc-content code { font-size: 12px; background: ${C.surface}; border: 1px solid ${C.border}; padding: 2px 6px; border-radius: 4px; color: ${C.accent}; font-family: 'Fira Code', monospace; }
          .doc-content pre { background: ${C.surface}; border: 1px solid ${C.border}; border-radius: 8px; padding: 16px 18px; font-size: 12px; color: ${C.text}; line-height: 1.8; overflow-x: auto; margin: 0 0 16px; font-family: 'Fira Code', 'Courier New', monospace; white-space: pre; }
        `}</style>
        <div className="doc-content">
          {current?.content}
        </div>

        {/* Prev / Next */}
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 48, paddingTop: 20, borderTop: `1px solid ${C.border}` }}>
          {active.article > 0 ? (
            <button
              onClick={() => setActive((p) => ({ ...p, article: p.article - 1 }))}
              style={{ fontSize: 13, color: C.muted, background: "none", border: "none", cursor: "pointer", fontFamily: "inherit" }}
            >
              ← {nav[active.section].articles[active.article - 1].title}
            </button>
          ) : <div />}
          {active.article < nav[active.section].articles.length - 1 && (
            <button
              onClick={() => setActive((p) => ({ ...p, article: p.article + 1 }))}
              style={{ fontSize: 13, color: C.muted, background: "none", border: "none", cursor: "pointer", fontFamily: "inherit" }}
            >
              {nav[active.section].articles[active.article + 1].title} →
            </button>
          )}
        </div>
      </div>
    </div>
  );
}