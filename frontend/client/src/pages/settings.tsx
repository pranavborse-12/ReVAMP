// src/pages/settings.tsx
import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthProvider";
import { User, Settings, Bell, Shield, Key, Mail, Github, LogOut, Check, AlertTriangle } from "lucide-react";

const API = "http://localhost:8000";

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
    <div style={{ display: "flex", alignItems: "center", padding: "12px 16px", borderBottom: "1px solid #1e2030" }}>
      <span style={{ fontSize: 12, color: "#718096", width: 160, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 13, color: "#a0aec0", flex: 1 }}>{value}</span>
      {badge}
    </div>
  );
}

function Divider() {
  return <div style={{ borderTop: "1px solid #1e2030", margin: "28px 0" }} />;
}

function SaveBtn({ onClick, saved }: { onClick: () => void; saved: boolean }) {
  return (
    <button onClick={onClick} style={{
      padding: "8px 18px",
      background: saved ? "rgba(6,214,160,0.15)" : "rgba(99,102,241,0.15)",
      border: `1px solid ${saved ? "rgba(6,214,160,0.3)" : "rgba(99,102,241,0.3)"}`,
      borderRadius: 6, color: saved ? "#06d6a0" : "#a5b4fc",
      fontSize: 12, cursor: "pointer", fontFamily: "inherit",
      display: "flex", alignItems: "center", gap: 6, transition: "all 0.2s",
    }}>
      {saved ? <><Check style={{ width: 11, height: 11 }} /> Saved</> : "Save changes"}
    </button>
  );
}

function Toggle({ on, onChange }: { on: boolean; onChange: () => void }) {
  return (
    <button onClick={onChange} style={{
      width: 40, height: 22, borderRadius: 11, border: "none", cursor: "pointer",
      position: "relative", background: on ? "#6366f1" : "#1e2030", transition: "background 0.2s",
    }}>
      <div style={{ position: "absolute", top: 2, left: on ? 20 : 2, width: 18, height: 18, borderRadius: "50%", background: "#e2e8f0", transition: "left 0.2s" }} />
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
    width: "100%", background: "#0f111a", border: "1px solid #1e2030",
    borderRadius: 6, padding: "8px 12px", color: "#e2e8f0", fontSize: 13,
    outline: "none", boxSizing: "border-box", fontFamily: "inherit",
  };

  const readonlyStyle: React.CSSProperties = {
    ...inputStyle, background: "#060709", color: "#4a5568", cursor: "default",
  };

  const fieldWrap = (label: string, children: React.ReactNode, desc?: string) => (
    <div style={{ marginBottom: 20 }}>
      <label style={{ display: "block", fontSize: 13, fontWeight: 600, color: "#e2e8f0", marginBottom: 6 }}>{label}</label>
      {children}
      {desc && <p style={{ fontSize: 11, color: "#4a5568", marginTop: 5, lineHeight: 1.6 }}>{desc}</p>}
    </div>
  );

  return (
    <div style={{ display: "flex", minHeight: "100vh", width: "100%", background: "#0a0a0f", color: "#e2e8f0", fontFamily: "'JetBrains Mono','Fira Code',monospace" }}>

      {/* ── Sidebar ── */}
      <div style={{ width: 220, flexShrink: 0, borderRight: "1px solid #1e2030", padding: "24px 12px", display: "flex", flexDirection: "column" }}>

        {/* Identity */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 8px 20px", borderBottom: "1px solid #1e2030", marginBottom: 16 }}>
          {gh?.avatar_url
            ? <img src={gh.avatar_url} alt="avatar" style={{ width: 32, height: 32, borderRadius: 6, objectFit: "cover", flexShrink: 0 }} />
            : <div style={{ width: 32, height: 32, borderRadius: 6, background: "#1e2030", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 800, color: "#6366f1", flexShrink: 0 }}>{initials}</div>
          }
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: "#e2e8f0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {gh?.login || user?.email?.split("@")[0] || "User"}
            </div>
            <div style={{ fontSize: 10, color: "#4a5568" }}>Personal account</div>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1 }}>
          {NAV_GROUPS.map((group, gi) => (
            <div key={gi} style={{ marginBottom: 20 }}>
              {group.label && (
                <div style={{ fontSize: 10, fontWeight: 700, color: "#4a5568", textTransform: "uppercase", letterSpacing: "0.12em", padding: "0 8px", marginBottom: 4 }}>
                  {group.label}
                </div>
              )}
              {group.items.map(item => (
                <button key={item.id} onClick={() => setActiveId(item.id)} style={{
                  width: "100%", display: "flex", alignItems: "center", gap: 8,
                  padding: "7px 10px", borderRadius: 6, border: "none", cursor: "pointer",
                  fontFamily: "inherit", fontSize: 12, textAlign: "left", marginBottom: 1,
                  background: activeId === item.id ? "rgba(99,102,241,0.12)" : "transparent",
                  color: activeId === item.id ? "#a5b4fc" : "#718096",
                  borderLeft: activeId === item.id ? "2px solid #6366f1" : "2px solid transparent",
                  transition: "all 0.1s",
                }}>
                  {item.icon && <item.icon style={{ width: 13, height: 13, flexShrink: 0 }} />}
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </nav>

        {/* Sign out */}
        <div style={{ borderTop: "1px solid #1e2030", paddingTop: 16 }}>
          <button onClick={logout} style={{
            width: "100%", display: "flex", alignItems: "center", gap: 8,
            padding: "7px 10px", borderRadius: 6, border: "none", cursor: "pointer",
            fontFamily: "inherit", fontSize: 12, background: "transparent", color: "#4a5568", transition: "color 0.15s",
          }}
            onMouseEnter={e => (e.currentTarget.style.color = "#ff4d4d")}
            onMouseLeave={e => (e.currentTarget.style.color = "#4a5568")}
          >
            <LogOut style={{ width: 13, height: 13 }} /> Sign out
          </button>
        </div>
      </div>

      {/* ── Content ── */}
      <div style={{ flex: 1, padding: "32px 48px", overflowY: "auto", minWidth: 0 }}>

        {/* PUBLIC PROFILE */}
        {activeId === "profile" && (
          <>
            <h2 style={{ fontSize: 20, fontWeight: 800, margin: "0 0 24px", color: "#e2e8f0" }}>Public profile</h2>
            <div style={{ display: "flex", gap: 32 }}>
              <div style={{ flex: 1 }}>
                {fieldWrap("Name",
                  <input value={profileName} onChange={e => setProfileName(e.target.value)} placeholder="Your display name" style={inputStyle} />,
                  "Your name may appear around ReVAMP where you contribute or are mentioned."
                )}
                {fieldWrap("Email",
                  <input value={user?.email || ""} readOnly style={readonlyStyle} />,
                  "This is your primary account email used for authentication."
                )}
                {fieldWrap("Bio",
                  <textarea value={profileBio} onChange={e => setProfileBio(e.target.value)} placeholder="Tell others about yourself..." rows={4} style={{ ...inputStyle, resize: "vertical" }} />,
                  "Tell others a little about yourself."
                )}
                {fieldWrap("GitHub username",
                  <input value={gh?.login || "Loading..."} readOnly style={readonlyStyle} />,
                  "Fetched from your GitHub account — cannot be changed here."
                )}
                {fieldWrap("GitHub profile URL",
                  <div style={{ display: "flex", gap: 8 }}>
                    <input value={gh ? `https://github.com/${gh.login}` : "Loading..."} readOnly style={{ ...readonlyStyle, flex: 1 }} />
                    {gh?.login && (
                      <a href={`https://github.com/${gh.login}`} target="_blank" rel="noreferrer"
                        style={{ padding: "8px 14px", background: "rgba(99,102,241,0.08)", border: "1px solid rgba(99,102,241,0.25)", borderRadius: 6, color: "#a5b4fc", fontSize: 12, textDecoration: "none", flexShrink: 0, display: "flex", alignItems: "center" }}>
                        View →
                      </a>
                    )}
                  </div>
                )}
                <Divider />
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <SaveBtn onClick={save} saved={saved} />
                  <span style={{ fontSize: 11, color: "#4a5568" }}>Name and bio are saved locally.</span>
                </div>
              </div>

              {/* Avatar */}
              <div style={{ width: 140, flexShrink: 0 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: "#e2e8f0", marginBottom: 10 }}>Profile picture</div>
                {gh?.avatar_url
                  ? <img src={gh.avatar_url} alt="avatar" style={{ width: 100, height: 100, borderRadius: "50%", objectFit: "cover", border: "2px solid #1e2030", display: "block", marginBottom: 10 }} />
                  : <div style={{ width: 100, height: 100, borderRadius: "50%", background: "#1e2030", border: "2px solid #2d3154", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 36, fontWeight: 800, color: "#6366f1", marginBottom: 10 }}>{initials}</div>
                }
                <div style={{ fontSize: 10, color: "#4a5568", lineHeight: 1.6 }}>Sourced from your GitHub account.</div>
                {gh?.location && <div style={{ fontSize: 11, color: "#718096", marginTop: 8 }}>📍 {gh.location}</div>}
              </div>
            </div>
          </>
        )}

        {/* ACCOUNT */}
        {activeId === "account" && (
          <>
            <h2 style={{ fontSize: 20, fontWeight: 800, margin: "0 0 4px", color: "#e2e8f0" }}>Account</h2>
            <p style={{ fontSize: 13, color: "#4a5568", margin: "0 0 24px", lineHeight: 1.7 }}>
              These details come from GitHub OAuth and are read-only. To change them, update your{" "}
              <a href="https://github.com/settings/profile" target="_blank" rel="noreferrer" style={{ color: "#6366f1", textDecoration: "none" }}>GitHub profile →</a>
            </p>

            <div style={{ border: "1px solid #1e2030", borderRadius: 8, overflow: "hidden", marginBottom: 24 }}>
              <ReadRow label="GitHub username"  value={gh?.login || "—"} />
              <ReadRow label="Display name"     value={gh?.name || "Not set"} />
              <ReadRow label="Email address"    value={user?.email || "—"}
                badge={user?.email_verified
                  ? <span style={{ fontSize: 10, padding: "2px 8px", background: "rgba(6,214,160,0.1)", color: "#06d6a0", border: "1px solid rgba(6,214,160,0.2)", borderRadius: 10, display: "flex", alignItems: "center", gap: 4 }}><Check style={{ width: 9, height: 9 }} /> Verified</span>
                  : undefined}
              />
              <ReadRow label="Member since"    value={memberSince(user?.created_at)} />
              <ReadRow label="Last login"      value={toLocal(user?.last_login)} />
              <ReadRow label="GitHub profile"  value={gh ? `github.com/${gh.login}` : "—"} />
            </div>

            <Divider />

            <div style={{ border: "1px solid rgba(255,77,77,0.2)", borderRadius: 8, overflow: "hidden" }}>
              <div style={{ background: "rgba(255,77,77,0.06)", padding: "12px 16px", borderBottom: "1px solid rgba(255,77,77,0.2)", display: "flex", alignItems: "center", gap: 6 }}>
                <AlertTriangle style={{ width: 13, height: 13, color: "#ff4d4d" }} />
                <span style={{ fontSize: 12, fontWeight: 700, color: "#ff4d4d" }}>Danger zone</span>
              </div>
              <div style={{ padding: 16, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16 }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: "#e2e8f0", marginBottom: 3 }}>Delete this account</div>
                  <div style={{ fontSize: 12, color: "#4a5568" }}>Once deleted, all your scan data is permanently removed.</div>
                </div>
                <button style={{ padding: "7px 14px", background: "transparent", border: "1px solid rgba(255,77,77,0.4)", borderRadius: 6, color: "#ff4d4d", fontSize: 12, cursor: "pointer", fontFamily: "inherit", flexShrink: 0 }}>
                  Delete account
                </button>
              </div>
            </div>
          </>
        )}

        {/* NOTIFICATIONS */}
        {activeId === "notifications" && (
          <>
            <h2 style={{ fontSize: 20, fontWeight: 800, margin: "0 0 8px", color: "#e2e8f0" }}>Notifications</h2>
            <p style={{ fontSize: 13, color: "#4a5568", margin: "0 0 28px", lineHeight: 1.7 }}>Choose what you want to be notified about. Email delivery requires SMTP configuration.</p>
            {[
              { section: "Scanning", items: [
                { key: "scanComplete",  label: "Scan complete",            desc: "When a repository scan finishes running" },
                { key: "criticalVulns", label: "Critical vulnerabilities", desc: "When CRITICAL severity issues are detected" },
              ]},
              { section: "Reports", items: [
                { key: "weeklyReport", label: "Weekly security report", desc: "A summary digest sent every Monday" },
                { key: "newFeatures",  label: "Product updates",        desc: "New features and platform announcements" },
              ]},
            ].map(group => (
              <div key={group.section} style={{ marginBottom: 28 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#4a5568", textTransform: "uppercase", letterSpacing: "0.12em", marginBottom: 4, paddingBottom: 8, borderBottom: "1px solid #1e2030" }}>
                  {group.section}
                </div>
                {group.items.map(({ key, label, desc }) => (
                  <div key={key} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 0", borderBottom: "1px solid #1a1a2e" }}>
                    <div>
                      <div style={{ fontSize: 13, color: "#e2e8f0", marginBottom: 2 }}>{label}</div>
                      <div style={{ fontSize: 11, color: "#4a5568" }}>{desc}</div>
                    </div>
                    <Toggle on={notifications[key as keyof typeof notifications]} onChange={() => toggle(key as keyof typeof notifications)} />
                  </div>
                ))}
              </div>
            ))}
            <SaveBtn onClick={save} saved={saved} />
          </>
        )}

        {/* EMAILS */}
        {activeId === "emails" && (
          <>
            <h2 style={{ fontSize: 20, fontWeight: 800, margin: "0 0 8px", color: "#e2e8f0" }}>Emails</h2>
            <p style={{ fontSize: 13, color: "#4a5568", margin: "0 0 28px", lineHeight: 1.7 }}>Manage your email addresses associated with your account.</p>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 600, color: "#e2e8f0", marginBottom: 6 }}>Primary email address</label>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input value={user?.email || ""} readOnly style={{ ...readonlyStyle, flex: 1 }} />
                {user?.email_verified && (
                  <span style={{ fontSize: 11, padding: "4px 10px", background: "rgba(6,214,160,0.1)", color: "#06d6a0", border: "1px solid rgba(6,214,160,0.2)", borderRadius: 6, display: "flex", alignItems: "center", gap: 4, flexShrink: 0 }}>
                    <Check style={{ width: 10, height: 10 }} /> Primary
                  </span>
                )}
              </div>
            </div>
            <div style={{ background: "rgba(99,102,241,0.05)", border: "1px solid rgba(99,102,241,0.15)", borderRadius: 8, padding: "14px 16px", fontSize: 12, color: "#718096", lineHeight: 1.7 }}>
              ℹ Your email is sourced from GitHub OAuth and cannot be changed here. Update it on GitHub and sign in again to reflect changes.
            </div>
          </>
        )}

        {/* SECURITY */}
        {activeId === "security" && (
          <>
            <h2 style={{ fontSize: 20, fontWeight: 800, margin: "0 0 8px", color: "#e2e8f0" }}>Password and authentication</h2>
            <p style={{ fontSize: 13, color: "#4a5568", margin: "0 0 28px", lineHeight: 1.7 }}>Your account uses GitHub OAuth — no password is stored by ReVAMP.</p>
            <div style={{ border: "1px solid #1e2030", borderRadius: 8, overflow: "hidden", marginBottom: 20 }}>
              {[
                { label: "GitHub OAuth 2.0", sub: "Passwordless, secure authentication", badge: <span style={{ fontSize: 10, padding: "3px 9px", background: "rgba(6,214,160,0.1)", color: "#06d6a0", border: "1px solid rgba(6,214,160,0.2)", borderRadius: 10 }}>Active</span> },
                { label: "Two-factor authentication", sub: "Managed by your GitHub account settings", badge: <a href="https://github.com/settings/security" target="_blank" rel="noreferrer" style={{ fontSize: 11, color: "#6366f1", textDecoration: "none" }}>Configure on GitHub →</a> },
                { label: "Access token", sub: "GitHub token expires after 8 hours · Read-only repo access", badge: <span style={{ fontSize: 10, padding: "3px 9px", background: "rgba(255,209,102,0.1)", color: "#ffd166", border: "1px solid rgba(255,209,102,0.2)", borderRadius: 10 }}>Read only</span> },
              ].map((row, i, arr) => (
                <div key={row.label} style={{ padding: "14px 16px", borderBottom: i < arr.length - 1 ? "1px solid #1e2030" : "none", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: "#e2e8f0" }}>{row.label}</div>
                    <div style={{ fontSize: 11, color: "#4a5568", marginTop: 2 }}>{row.sub}</div>
                  </div>
                  {row.badge}
                </div>
              ))}
            </div>
          </>
        )}

        {/* SESSIONS */}
        {activeId === "sessions" && (
          <>
            <h2 style={{ fontSize: 20, fontWeight: 800, margin: "0 0 8px", color: "#e2e8f0" }}>Sessions</h2>
            <p style={{ fontSize: 13, color: "#4a5568", margin: "0 0 28px", lineHeight: 1.7 }}>Devices that have logged into your account. Revoke any sessions you don't recognize.</p>
            <div style={{ border: "1px solid #1e2030", borderRadius: 8, padding: 16, marginBottom: 20 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "#e2e8f0" }}>Current session</div>
                <span style={{ fontSize: 9, padding: "2px 8px", background: "rgba(6,214,160,0.1)", color: "#06d6a0", border: "1px solid rgba(6,214,160,0.2)", borderRadius: 10 }}>Active now</span>
              </div>
              <div style={{ fontSize: 11, color: "#4a5568" }}>Last login: {toLocal(user?.last_login)}</div>
            </div>
            <button onClick={logout} style={{ display: "flex", alignItems: "center", gap: 7, padding: "8px 16px", background: "transparent", border: "1px solid rgba(255,77,77,0.3)", borderRadius: 6, color: "#ff4d4d", fontSize: 12, cursor: "pointer", fontFamily: "inherit" }}>
              <LogOut style={{ width: 12, height: 12 }} /> Sign out of all sessions
            </button>
          </>
        )}

        {/* GITHUB APPS */}
        {activeId === "github-apps" && (
          <>
            <h2 style={{ fontSize: 20, fontWeight: 800, margin: "0 0 8px", color: "#e2e8f0" }}>GitHub Apps</h2>
            <p style={{ fontSize: 13, color: "#4a5568", margin: "0 0 28px", lineHeight: 1.7 }}>Applications connected to your account via GitHub OAuth.</p>
            <div style={{ border: "1px solid #1e2030", borderRadius: 8, padding: 16, display: "flex", alignItems: "center", gap: 14 }}>
              <div style={{ width: 40, height: 40, borderRadius: 8, background: "#1e2030", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <Shield style={{ width: 20, height: 20, color: "#6366f1" }} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "#e2e8f0" }}>ReVAMP</div>
                <div style={{ fontSize: 11, color: "#4a5568", marginTop: 2 }}>Security scanning platform · repo (read) access</div>
              </div>
              <span style={{ fontSize: 10, padding: "3px 9px", background: "rgba(6,214,160,0.1)", color: "#06d6a0", border: "1px solid rgba(6,214,160,0.2)", borderRadius: 10 }}>Connected</span>
            </div>
          </>
        )}

      </div>
    </div>
  );
}