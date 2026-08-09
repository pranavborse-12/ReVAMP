import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthProvider";
import { User, Settings, Bell, Shield, Key, Mail, Github, LogOut, Check, AlertTriangle } from "lucide-react";

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
  danger:      "#ef4444",   // Destructive actions
  success:     "#10b981",   // Success states
  warning:     "#f59e0b",   // Warnings
};

const NAV_GROUPS = [
  {
    label: null,
    items: [
      { id: "profile",       icon: User,     label: "Public profile" },
      { id: "account",       icon: Settings, label: "Account" },
      { id: "notifications", icon: Bell,     label: "Notifications" },
    ]
  },
  {
    label: "Access",
    items: [
      { id: "emails",   icon: Mail,   label: "Emails" },
      { id: "security", icon: Shield, label: "Password and authentication" },
      { id: "sessions", icon: Key,    label: "Sessions" },
    ]
  },
  {
    label: "Integrations",
    items: [
      { id: "github-apps", icon: Github, label: "GitHub Apps" },
    ]
  }
];

// Read-only display field
function ReadRow({ label, value, badge }: { label: string; value: string; badge?: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", padding: "14px 16px", borderBottom: `1px solid ${C.border}` }}>
      <span style={{ fontSize: 13, fontWeight: 500, color: C.muted, width: 200, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 13, color: C.text, flex: 1 }}>{value}</span>
      {badge}
    </div>
  );
}

function Divider() {
  return <div style={{ borderTop: `1px solid ${C.border}`, margin: "32px 0" }} />;
}

function SaveBtn({ onClick, saved }: { onClick: () => void; saved: boolean }) {
  return (
    <button onClick={onClick} style={{
      padding: "8px 16px",
      background: saved ? "transparent" : C.text,
      border: `1px solid ${saved ? C.success : C.text}`,
      borderRadius: 6, 
      color: saved ? C.success : C.bg,
      fontSize: 13, 
      fontWeight: 500,
      cursor: "pointer", 
      display: "flex", 
      alignItems: "center", 
      gap: 8, 
      transition: "all 0.2s ease",
    }}
    onMouseOver={(e) => { if(!saved) e.currentTarget.style.background = "#d4d4d8"; }}
    onMouseOut={(e) => { if(!saved) e.currentTarget.style.background = C.text; }}
    >
      {saved ? <><Check size={14} strokeWidth={3} /> Saved</> : "Save changes"}
    </button>
  );
}

function Toggle({ on, onChange }: { on: boolean; onChange: () => void }) {
  return (
    <button onClick={onChange} style={{
      width: 36, height: 20, borderRadius: 10, border: "none", cursor: "pointer",
      position: "relative", background: on ? C.accent : C.border, transition: "background 0.2s ease",
    }}>
      <div style={{ 
        position: "absolute", top: 2, left: on ? 18 : 2, width: 16, height: 16, 
        borderRadius: "50%", background: "#fff", transition: "left 0.2s cubic-bezier(0.4, 0.0, 0.2, 1)",
        boxShadow: "0 2px 4px rgba(0,0,0,0.2)"
      }} />
    </button>
  );
}

interface GHProfile {
  login: string;
  name: string | null;
  avatar_url: string;
  html_url: string;
  bio: string | null;
  location: string | null;
}

export default function SettingsPage() {
  const { user, logout } = useAuth();
  const [activeId, setActiveId]       = useState("profile");
  const [saved, setSaved]             = useState(false);
  const [profileName, setProfileName] = useState("");
  const [profileBio, setProfileBio]   = useState("");
  const [gh, setGh]                   = useState<GHProfile | null>(null);
  const [notifications, setNotifications] = useState({
    scanComplete: true, criticalVulns: true, weeklyReport: false, newFeatures: false,
  });

  // Fetch GitHub profile on mount — /api/github/user returns raw GitHub API JSON
  useEffect(() => {
    fetch(`${API}/api/github/user`, { credentials: "include" })
      .then(r => {
        if (!r.ok) throw new Error(`${r.status}`);
        return r.json();
      })
      .then((data: GHProfile) => {
        setGh(data);
        // Pre-fill editable fields from GitHub
        setProfileName(data.name || data.login || "");
        setProfileBio(data.bio || "");
      })
      .catch(err => console.error("GitHub profile fetch failed:", err));
  }, []);

  const save  = () => { setSaved(true); setTimeout(() => setSaved(false), 2500); };
  const toggle = (k: keyof typeof notifications) => setNotifications(p => ({ ...p, [k]: !p[k] }));

  const toLocal = (iso?: string) => {
    if (!iso) return "Never";
    return new Date(iso).toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit", hour12: true,
    });
  };

  const memberSince = (iso?: string) => {
    if (!iso) return "—";
    return new Date(iso).toLocaleDateString(undefined, { month: "long", year: "numeric" });
  };

  const initials = user?.email?.[0]?.toUpperCase() || "U";

  const inputStyle: React.CSSProperties = {
    width: "100%", background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 6, padding: "8px 12px", color: C.text, fontSize: 13,
    outline: "none", boxSizing: "border-box", fontFamily: "inherit",
    transition: "border-color 0.15s ease, background 0.15s ease",
  };

  const readonlyStyle: React.CSSProperties = {
    ...inputStyle, background: "transparent", color: C.muted, cursor: "default", borderStyle: "dashed",
  };

  const fieldWrap = (label: string, children: React.ReactNode, desc?: string) => (
    <div style={{ marginBottom: 24 }}>
      <label style={{ display: "block", fontSize: 13, fontWeight: 500, color: C.text, marginBottom: 8 }}>{label}</label>
      {children}
      {desc && <p style={{ fontSize: 12, color: C.subtle, marginTop: 6, lineHeight: 1.5 }}>{desc}</p>}
    </div>
  );

  return (
    <div style={{ display: "flex", minHeight: "100vh", width: "100%", background: C.bg, color: C.text, fontFamily: "'Inter', system-ui, -apple-system, sans-serif" }}>

      {/* ── Sidebar ── */}
      <div style={{ width: 260, flexShrink: 0, borderRight: `1px solid ${C.border}`, padding: "32px 16px", display: "flex", flexDirection: "column" }}>

        {/* Identity */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "0 12px 24px", borderBottom: `1px solid ${C.border}`, marginBottom: 24 }}>
          {gh?.avatar_url
            ? <img src={gh.avatar_url} alt="avatar" style={{ width: 36, height: 36, borderRadius: 8, objectFit: "cover", flexShrink: 0, border: `1px solid ${C.border}` }} />
            : <div style={{ width: 36, height: 36, borderRadius: 8, background: C.surface, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 600, color: C.accent, flexShrink: 0, border: `1px solid ${C.border}` }}>{initials}</div>
          }
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {gh?.login || user?.email?.split("@")[0] || "User"}
            </div>
            <div style={{ fontSize: 12, color: C.subtle }}>Personal account</div>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1 }}>
          {NAV_GROUPS.map((group, gi) => (
            <div key={gi} style={{ marginBottom: 24 }}>
              {group.label && (
                <div style={{ fontSize: 11, fontWeight: 600, color: C.subtle, textTransform: "uppercase", letterSpacing: "0.05em", padding: "0 12px", marginBottom: 8 }}>
                  {group.label}
                </div>
              )}
              {group.items.map(item => (
                <button key={item.id} onClick={() => setActiveId(item.id)} style={{
                  width: "100%", display: "flex", alignItems: "center", gap: 10,
                  padding: "8px 12px", borderRadius: 6, border: "none", cursor: "pointer",
                  fontFamily: "inherit", fontSize: 13, fontWeight: activeId === item.id ? 500 : 400, textAlign: "left", marginBottom: 2,
                  background: activeId === item.id ? C.surface : "transparent",
                  color: activeId === item.id ? C.text : C.muted,
                  transition: "all 0.15s ease",
                }}
                onMouseOver={(e) => { if(activeId !== item.id) e.currentTarget.style.color = C.text; }}
                onMouseOut={(e) => { if(activeId !== item.id) e.currentTarget.style.color = C.muted; }}
                >
                  {item.icon && <item.icon size={16} strokeWidth={activeId === item.id ? 2.5 : 2} style={{ flexShrink: 0, color: activeId === item.id ? C.accent : "inherit" }} />}
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </nav>

        {/* Sign out */}
        <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 24 }}>
          <button onClick={logout} style={{
            width: "100%", display: "flex", alignItems: "center", gap: 10,
            padding: "8px 12px", borderRadius: 6, border: "none", cursor: "pointer",
            fontFamily: "inherit", fontSize: 13, fontWeight: 500, background: "transparent", color: C.muted, transition: "color 0.15s, background 0.15s",
          }}
            onMouseOver={e => { e.currentTarget.style.color = C.danger; e.currentTarget.style.background = "rgba(239, 68, 68, 0.05)"; }}
            onMouseOut={e => { e.currentTarget.style.color = C.muted; e.currentTarget.style.background = "transparent"; }}
          >
            <LogOut size={16} /> Sign out
          </button>
        </div>
      </div>

      {/* ── Content ── */}
      <div style={{ flex: 1, padding: "40px 64px", overflowY: "auto", minWidth: 0, maxWidth: "1000px" }}>

        {/* PUBLIC PROFILE */}
        {activeId === "profile" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <h2 style={{ fontSize: 24, fontWeight: 600, margin: "0 0 32px", color: C.text, letterSpacing: "-0.02em" }}>Public profile</h2>
            <div style={{ display: "flex", gap: 48, flexWrap: "wrap-reverse" }}>
              <div style={{ flex: 1, minWidth: 300 }}>
                {fieldWrap("Name",
                  <input value={profileName} onChange={e => setProfileName(e.target.value)} placeholder="Your display name" style={inputStyle} 
                  onFocus={(e) => { e.target.style.borderColor = C.accent; e.target.style.background = C.bg; }}
                  onBlur={(e) => { e.target.style.borderColor = C.border; e.target.style.background = C.surface; }}/>,
                  "Your name may appear around ReVAMP where you contribute or are mentioned."
                )}
                {fieldWrap("Email",
                  <input value={user?.email || ""} readOnly style={readonlyStyle} />,
                  "This is your primary account email used for authentication."
                )}
                {fieldWrap("Bio",
                  <textarea value={profileBio} onChange={e => setProfileBio(e.target.value)} placeholder="Tell others about yourself..." rows={4} style={{ ...inputStyle, resize: "vertical" }} 
                  onFocus={(e) => { e.target.style.borderColor = C.accent; e.target.style.background = C.bg; }}
                  onBlur={(e) => { e.target.style.borderColor = C.border; e.target.style.background = C.surface; }}/>,
                  "Tell others a little about yourself."
                )}
                {fieldWrap("GitHub username",
                  <input value={gh?.login || "Loading..."} readOnly style={readonlyStyle} />,
                  "Fetched from your GitHub account — cannot be changed here."
                )}
                {fieldWrap("GitHub profile URL",
                  <div style={{ display: "flex", gap: 12 }}>
                    <input value={gh ? `https://github.com/${gh.login}` : "Loading..."} readOnly style={{ ...readonlyStyle, flex: 1 }} />
                    {gh?.login && (
                      <a href={`https://github.com/${gh.login}`} target="_blank" rel="noreferrer"
                        style={{ padding: "8px 16px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontSize: 13, fontWeight: 500, textDecoration: "none", flexShrink: 0, display: "flex", alignItems: "center", transition: "all 0.15s" }}
                        onMouseOver={(e) => { e.currentTarget.style.borderColor = C.borderHover; e.currentTarget.style.background = C.surface2; }}
                        onMouseOut={(e) => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.background = C.surface; }}
                      >
                        Visit Profile ↗
                      </a>
                    )}
                  </div>
                )}
                <Divider />
                <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
                  <SaveBtn onClick={save} saved={saved} />
                  <span style={{ fontSize: 12, color: C.subtle }}>Name and bio are saved locally.</span>
                </div>
              </div>

              {/* Avatar */}
              <div style={{ width: 200, flexShrink: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 500, color: C.text, marginBottom: 16 }}>Profile picture</div>
                {gh?.avatar_url
                  ? <img src={gh.avatar_url} alt="avatar" style={{ width: 160, height: 160, borderRadius: "50%", objectFit: "cover", border: `1px solid ${C.border}`, display: "block", marginBottom: 16 }} />
                  : <div style={{ width: 160, height: 160, borderRadius: "50%", background: C.surface, border: `1px dashed ${C.borderHover}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 48, fontWeight: 600, color: C.muted, marginBottom: 16 }}>{initials}</div>
                }
                <div style={{ fontSize: 12, color: C.subtle, lineHeight: 1.5 }}>Sourced directly from your GitHub account profile.</div>
                {gh?.location && <div style={{ fontSize: 12, color: C.muted, marginTop: 12, display: "flex", alignItems: "center", gap: 6 }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg>
                  {gh.location}
                </div>}
              </div>
            </div>
          </div>
        )}

        {/* ACCOUNT */}
        {activeId === "account" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <h2 style={{ fontSize: 24, fontWeight: 600, margin: "0 0 8px", color: C.text, letterSpacing: "-0.02em" }}>Account</h2>
            <p style={{ fontSize: 14, color: C.muted, margin: "0 0 32px", lineHeight: 1.6 }}>
              These details come from GitHub OAuth and are read-only. To change them, update your{" "}
              <a href="https://github.com/settings/profile" target="_blank" rel="noreferrer" style={{ color: C.accent, textDecoration: "none" }}>GitHub profile ↗</a>
            </p>

            <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden", marginBottom: 32 }}>
              <ReadRow label="GitHub username"  value={gh?.login || "—"} />
              <ReadRow label="Display name"     value={gh?.name || "Not set"} />
              <ReadRow label="Email address"    value={user?.email || "—"}
                badge={user?.email_verified
                  ? <span style={{ fontSize: 11, fontWeight: 500, padding: "2px 8px", background: "rgba(16, 185, 129, 0.1)", color: C.success, border: "1px solid rgba(16, 185, 129, 0.2)", borderRadius: 4, display: "flex", alignItems: "center", gap: 4 }}><Check size={12} strokeWidth={3} /> Verified</span>
                  : undefined}
              />
              <ReadRow label="Member since"    value={memberSince(user?.created_at)} />
              <ReadRow label="Last login"      value={toLocal(user?.last_login)} />
              <ReadRow label="GitHub profile"  value={gh ? `github.com/${gh.login}` : "—"} />
            </div>

            <Divider />

            <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
              <div style={{ padding: "20px", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 24 }}>
                <div>
                  <div style={{ fontSize: 15, fontWeight: 500, color: C.text, marginBottom: 4 }}>Delete account</div>
                  <div style={{ fontSize: 13, color: C.subtle }}>Permanently remove your account and all associated scan data. This action cannot be undone.</div>
                </div>
                <button style={{ 
                  padding: "8px 16px", background: "rgba(239, 68, 68, 0.05)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: 6, 
                  color: C.danger, fontSize: 13, fontWeight: 500, cursor: "pointer", flexShrink: 0, transition: "all 0.15s ease" 
                }}
                onMouseOver={e => { e.currentTarget.style.background = "rgba(239, 68, 68, 0.1)"; }}
                onMouseOut={e => { e.currentTarget.style.background = "rgba(239, 68, 68, 0.05)"; }}
                >
                  Delete account
                </button>
              </div>
            </div>
          </div>
        )}

        {/* NOTIFICATIONS */}
        {activeId === "notifications" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <h2 style={{ fontSize: 24, fontWeight: 600, margin: "0 0 8px", color: C.text, letterSpacing: "-0.02em" }}>Notifications</h2>
            <p style={{ fontSize: 14, color: C.muted, margin: "0 0 32px", lineHeight: 1.6 }}>Choose what you want to be notified about. Email delivery requires SMTP configuration.</p>
            {[
              { section: "Scanning", items: [
                { key: "scanComplete",  label: "Scan completion",          desc: "Receive an alert when a repository scan finishes running." },
                { key: "criticalVulns", label: "Critical vulnerabilities", desc: "Get notified immediately if CRITICAL severity issues are detected." },
              ]},
              { section: "Reports", items: [
                { key: "weeklyReport", label: "Weekly security digest", desc: "A summary digest of your codebase security sent every Monday." },
                { key: "newFeatures",  label: "Product updates",        desc: "New features, engine updates, and platform announcements." },
              ]},
            ].map(group => (
              <div key={group.section} style={{ marginBottom: 32 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 8, paddingBottom: 12, borderBottom: `1px solid ${C.border}` }}>
                  {group.section}
                </div>
                {group.items.map(({ key, label, desc }) => (
                  <div key={key} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 0", borderBottom: `1px solid ${C.border}` }}>
                    <div style={{ paddingRight: 32 }}>
                      <div style={{ fontSize: 14, fontWeight: 500, color: C.text, marginBottom: 4 }}>{label}</div>
                      <div style={{ fontSize: 13, color: C.muted }}>{desc}</div>
                    </div>
                    <Toggle on={notifications[key as keyof typeof notifications]} onChange={() => toggle(key as keyof typeof notifications)} />
                  </div>
                ))}
              </div>
            ))}
            <SaveBtn onClick={save} saved={saved} />
          </div>
        )}

        {/* EMAILS */}
        {activeId === "emails" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <h2 style={{ fontSize: 24, fontWeight: 600, margin: "0 0 8px", color: C.text, letterSpacing: "-0.02em" }}>Emails</h2>
            <p style={{ fontSize: 14, color: C.muted, margin: "0 0 32px", lineHeight: 1.6 }}>Manage the email addresses associated with your account.</p>
            <div style={{ marginBottom: 24 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, color: C.text, marginBottom: 8 }}>Primary email address</label>
              <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                <input value={user?.email || ""} readOnly style={{ ...readonlyStyle, flex: 1, maxWidth: 400 }} />
                {user?.email_verified && (
                  <span style={{ fontSize: 12, fontWeight: 500, padding: "4px 10px", background: "rgba(16, 185, 129, 0.1)", color: C.success, border: "1px solid rgba(16, 185, 129, 0.2)", borderRadius: 6, display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
                    <Check size={14} strokeWidth={3} /> Primary Address
                  </span>
                )}
              </div>
            </div>
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px", display: "flex", gap: 16, alignItems: "flex-start" }}>
              <AlertTriangle size={18} color={C.muted} style={{ flexShrink: 0, marginTop: 2 }} />
              <div style={{ fontSize: 13, color: C.muted, lineHeight: 1.6 }}>
                Your email is sourced directly from your connected GitHub OAuth app. It cannot be changed here. To update your email, change it in your GitHub settings and sign in again.
              </div>
            </div>
          </div>
        )}

        {/* SECURITY */}
        {activeId === "security" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <h2 style={{ fontSize: 24, fontWeight: 600, margin: "0 0 8px", color: C.text, letterSpacing: "-0.02em" }}>Authentication & Security</h2>
            <p style={{ fontSize: 14, color: C.muted, margin: "0 0 32px", lineHeight: 1.6 }}>Your account is secured via GitHub OAuth. No passwords are stored locally.</p>
            <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden", marginBottom: 24 }}>
              {[
                { label: "GitHub OAuth 2.0", sub: "Passwordless, secure authentication", badge: <span style={{ fontSize: 11, fontWeight: 500, padding: "2px 8px", background: "rgba(16, 185, 129, 0.1)", color: C.success, border: "1px solid rgba(16, 185, 129, 0.2)", borderRadius: 4 }}>Active</span> },
                { label: "Two-factor authentication", sub: "Managed entirely by your GitHub account settings", badge: <a href="https://github.com/settings/security" target="_blank" rel="noreferrer" style={{ fontSize: 12, fontWeight: 500, color: C.accent, textDecoration: "none" }}>Configure on GitHub ↗</a> },
                { label: "Access Token", sub: "GitHub token expires after 8 hours · Read-only repo access", badge: <span style={{ fontSize: 11, fontWeight: 500, padding: "2px 8px", background: "rgba(245, 158, 11, 0.1)", color: C.warning, border: "1px solid rgba(245, 158, 11, 0.2)", borderRadius: 4 }}>Read Only</span> },
              ].map((row, i, arr) => (
                <div key={row.label} style={{ padding: "16px 20px", borderBottom: i < arr.length - 1 ? `1px solid ${C.border}` : "none", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 500, color: C.text }}>{row.label}</div>
                    <div style={{ fontSize: 13, color: C.muted, marginTop: 4 }}>{row.sub}</div>
                  </div>
                  {row.badge}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* SESSIONS */}
        {activeId === "sessions" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <h2 style={{ fontSize: 24, fontWeight: 600, margin: "0 0 8px", color: C.text, letterSpacing: "-0.02em" }}>Active Sessions</h2>
            <p style={{ fontSize: 14, color: C.muted, margin: "0 0 32px", lineHeight: 1.6 }}>Manage the devices that are currently logged into your account.</p>
            <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, padding: 20, marginBottom: 24, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
                  <div style={{ fontSize: 14, fontWeight: 500, color: C.text }}>Current Session</div>
                  <span style={{ fontSize: 10, fontWeight: 600, padding: "2px 6px", background: "rgba(16, 185, 129, 0.1)", color: C.success, border: "1px solid rgba(16, 185, 129, 0.2)", borderRadius: 4, textTransform: "uppercase", letterSpacing: "0.05em" }}>Active Now</span>
                </div>
                <div style={{ fontSize: 13, color: C.muted }}>Authenticated via GitHub OAuth · {toLocal(user?.last_login)}</div>
              </div>
            </div>
            <button onClick={logout} style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 16px", background: "transparent", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: 6, color: C.danger, fontSize: 13, fontWeight: 500, cursor: "pointer", transition: "background 0.15s ease" }}
             onMouseOver={e => { e.currentTarget.style.background = "rgba(239, 68, 68, 0.05)"; }}
             onMouseOut={e => { e.currentTarget.style.background = "transparent"; }}
            >
              <LogOut size={16} /> Revoke all sessions
            </button>
          </div>
        )}

        {/* GITHUB APPS */}
        {activeId === "github-apps" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <h2 style={{ fontSize: 24, fontWeight: 600, margin: "0 0 8px", color: C.text, letterSpacing: "-0.02em" }}>Authorized Applications</h2>
            <p style={{ fontSize: 14, color: C.muted, margin: "0 0 32px", lineHeight: 1.6 }}>Third-party applications connected to your account via GitHub OAuth.</p>
            <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, padding: 20, display: "flex", alignItems: "flex-start", gap: 16 }}>
              <div style={{ width: 48, height: 48, borderRadius: 8, background: C.surface, border: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <Shield size={24} color={C.text} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
                  <div style={{ fontSize: 15, fontWeight: 600, color: C.text }}>ReVAMP Security Engine</div>
                  <span style={{ fontSize: 11, fontWeight: 500, padding: "2px 8px", background: "rgba(16, 185, 129, 0.1)", color: C.success, border: "1px solid rgba(16, 185, 129, 0.2)", borderRadius: 4 }}>Connected</span>
                </div>
                <div style={{ fontSize: 13, color: C.muted, marginBottom: 8 }}>Security scanning platform providing vulnerability analysis.</div>
                <div style={{ fontSize: 12, color: C.subtle, fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>Permissions: repo (read-only), user:email</div>
              </div>
            </div>
          </div>
        )}

      </div>

      {/* Basic Keyframes for smooth tab switching */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(4px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}