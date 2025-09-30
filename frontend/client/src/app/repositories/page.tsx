import React, { useEffect, useMemo, useState } from "react";
import { Link } from "wouter";

// API Configuration
const API_BASE_URL = "http://localhost:8000";

// Types
interface Toast {
  id: number;
  message: string;
  type?: "success" | "error";
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

interface RepoFilesData {
  repository: string;
  owner: string;
  branch: string;
  total_files: number;
  total_directories: number;
  files: RepoFile[];
  directories: RepoFile[];
}

// Toast Component
function Toasts({ toasts, removeToast }: { toasts: Toast[]; removeToast: (id: number) => void }) {
  return (
    <div className="fixed top-5 right-5 flex flex-col gap-2 z-50">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`px-4 py-2 rounded shadow-md text-sm cursor-pointer transition-opacity hover:opacity-80 ${
            t.type === "error" ? "bg-red-600 text-white" : "bg-green-600 text-white"
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
  const addToast = (message: string, type?: "success" | "error") => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => removeToast(id), 4000);
  };
  const removeToast = (id: number) => setToasts((prev) => prev.filter((t) => t.id !== id));

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    
    try {
      console.log('Fetching profile from:', `${API_BASE_URL}/api/github/profile`);
      
      // Fetch profile
      const profileRes = await fetch(`${API_BASE_URL}/api/github/profile`, {
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      });

      console.log('Profile response status:', profileRes.status);

      if (profileRes.status === 401) {
        setError("not-connected");
        setLoading(false);
        return;
      }

      if (!profileRes.ok) {
        const errorText = await profileRes.text();
        console.error('Profile error:', errorText);
        throw new Error(`Profile API error: ${profileRes.status} - ${errorText}`);
      }

      const profileData = await profileRes.json();
      console.log('Profile data:', profileData);
      setProfile(profileData);

      // Fetch repositories
      const params = new URLSearchParams({
        query,
        type,
        sort,
        direction,
        page: page.toString(),
        per_page: per_page.toString()
      });

      console.log('Fetching repos with params:', params.toString());
      
      const reposRes = await fetch(
        `${API_BASE_URL}/api/github/repos?${params}`,
        {
          credentials: 'include',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          }
        }
      );

      console.log('Repos response status:', reposRes.status);

      if (!reposRes.ok) {
        const errorText = await reposRes.text();
        console.error('Repos error:', errorText);
        throw new Error(`Repos API error: ${reposRes.status} - ${errorText}`);
      }

      const reposData = await reposRes.json();
      console.log('Repos data:', reposData.length, 'repositories');
      setRepos(reposData);

    } catch (e: any) {
      console.error('Fetch error:', e);
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

  const title = useMemo(() => `${profile?.login || "User"} · Repositories`, [profile]);

  const handleConnectGitHub = () => {
    window.location.href = `${API_BASE_URL}/auth/github/login?redirect_to=/repositories`;
  };

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#c9d1d9] relative">
      <Toasts toasts={toasts} removeToast={removeToast} />
      
      {/* Header - Modified */}
      <div className="border-b border-[#21262d] bg-[#0d1117] sticky top-0 z-30">
        <div className="mx-auto max-w-7xl px-4 py-2 flex items-center gap-3">
          <div className="text-sm opacity-70">{profile?.login || "pranavborse-12"} · Repositories</div>
        </div>
      </div>

      {/* Content - Modified padding */}
      <div className="mx-auto max-w-7xl px-4 py-4 grid grid-cols-12 gap-6">
        {/* Sidebar - Modified sizes */}
        <aside className="col-span-12 md:col-span-4 lg:col-span-3 flex flex-col items-center md:items-start gap-4">
          <div className="relative">
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
          </div>
          <div className="text-center md:text-left w-full">
            <div className="text-2xl font-bold leading-tight">
              {profile?.name || profile?.login || "—"}
            </div>
            {profile?.name && <div className="text-[#8b949e] -mt-1">{profile.login}</div>}
          </div>
          {profile?.bio && <p className="text-sm text-[#8b949e] text-center md:text-left">{profile.bio}</p>}
        </aside>

        {/* Main panel - Replace the entire main section */}
        <main className="col-span-12 md:col-span-8 lg:col-span-9">
          {/* Controls */}
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
              <select
                value={sort}
                onChange={(e) => {
                  setPage(1);
                  setSort(e.target.value);
                }}
                className="bg-[#0d1117] border border-[#30363d] rounded-md px-3 py-2 text-sm"
              >
                <option value="updated">Sort: Last updated</option>
                <option value="full_name">Name</option>
                <option value="created">Recently created</option>
              </select>
              <button
                onClick={() => setDirection((d) => (d === "desc" ? "asc" : "desc"))}
                className="bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] rounded-md px-3 py-2 text-sm transition-colors"
              >
                {direction === "desc" ? "↓ Desc" : "↑ Asc"}
              </button>
            </div>
          )}

          {/* Not Connected State */}
          {error === "not-connected" && (
            <div className="border border-[#30363d] rounded-md p-6 bg-[#161b22]">
              <div className="text-sm text-[#8b949e] mb-4">
                Your GitHub account is not connected. Connect your account to view and scan your repositories.
              </div>
              <button
                onClick={handleConnectGitHub}
                className="bg-[#238636] hover:bg-[#2ea043] text-white rounded-md px-4 py-2 text-sm transition-colors"
              >
                Connect GitHub Account
              </button>
            </div>
          )}

          {/* Loading State */}
          {loading && (
            <div className="text-[#8b949e] text-sm flex items-center gap-2">
              <div className="animate-spin h-4 w-4 border-2 border-[#8b949e] border-t-transparent rounded-full"></div>
              Loading repositories...
            </div>
          )}

          {/* Error State */}
          {error && error !== "not-connected" && (
            <div className="text-sm text-red-400 bg-[#161b22] border border-red-900 rounded-md p-4">
              {error}
            </div>
          )}

          {/* Repository List */}
          {!loading && !error && (
            <div className="space-y-4">
              {repos.length === 0 ? (
                <div className="text-sm text-[#8b949e] p-6 text-center border border-[#21262d] rounded-md">
                  No repositories found.
                </div>
              ) : (
                <>
                  {repos.map((repo) => (
                    <RepoCard key={repo.id} repo={repo} addToast={addToast} />
                  ))}
                  
                  {/* Pagination */}
                  <div className="flex items-center justify-center gap-3 mt-8">
                    <button
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                      disabled={page === 1}
                      className="bg-[#21262d] hover:bg-[#30363d] disabled:opacity-40 disabled:cursor-not-allowed border border-[#30363d] rounded-md px-4 py-2 text-sm transition-colors"
                    >
                      ← Previous
                    </button>
                    <span className="text-sm text-[#8b949e] px-2">Page {page}</span>
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
function RepoCard({ repo, addToast }: { repo: Repo; addToast: (msg: string, type?: "success" | "error") => void }) {
  const [expanded, setExpanded] = useState(false);
  const [files, setFiles] = useState<RepoFilesData | null>(null);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [scanning, setScanning] = useState(false);

  const visibility = repo.private
    ? "Private"
    : repo.visibility
    ? repo.visibility[0].toUpperCase() + repo.visibility.slice(1)
    : "Public";

  const fetchFiles = async () => {
    if (files) {
      setExpanded(!expanded);
      return;
    }

    setLoadingFiles(true);
    setExpanded(true);
    try {
      const owner = repo.owner?.login || repo.full_name?.split("/")[0];
      const res = await fetch(
        `${API_BASE_URL}/api/github/repos/${owner}/${repo.name}/files?recursive=true`,
        { credentials: "include" }
      );
      
      if (!res.ok) {
        throw new Error(`Failed to fetch files: ${res.status}`);
      }
      
      const data = await res.json();
      setFiles(data);
      addToast(`Loaded ${data.total_files} files from ${repo.name}`, "success");
    } catch (err: any) {
      console.error(err);
      addToast(`Failed to load files: ${err.message}`, "error");
      setExpanded(false);
    } finally {
      setLoadingFiles(false);
    }
  };

  const handleScan = async () => {
    setScanning(true);
    try {
      const owner = repo.owner?.login || repo.full_name?.split("/")[0];
      const res = await fetch(
        `${API_BASE_URL}/api/github/repos/${owner}/${repo.name}/scan`,
        { method: "POST", credentials: "include" }
      );
      
      if (!res.ok) {
        throw new Error(`Scan failed: ${res.status}`);
      }
      
      const data = await res.json();
      addToast(`Scan initiated for ${repo.full_name ?? repo.name}`, "success");
    } catch (err: any) {
      console.error(err);
      addToast(`Scan failed: ${err.message}`, "error");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="border border-[#30363d] rounded-lg bg-[#0d1117] hover:border-[#8b949e] transition-colors">
      {/* Header */}
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
              <p className="text-sm text-[#8b949e] mt-2 line-clamp-2">{repo.description}</p>
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
              {repo.size && <span>📦 {formatBytes(repo.size * 1024)}</span>}
              {repo.updated_at && <span>Updated {timeAgo(repo.updated_at)}</span>}
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={fetchFiles}
              disabled={loadingFiles}
              className="border border-[#30363d] hover:bg-[#21262d] rounded-md px-3 py-1.5 text-sm transition-colors whitespace-nowrap"
            >
              {loadingFiles ? "Loading..." : expanded ? "Hide Files" : "View Files"}
            </button>
            <button
              onClick={handleScan}
              disabled={scanning}
              className={`border border-[#30363d] rounded-md px-3 py-1.5 text-sm transition-colors whitespace-nowrap ${
                scanning
                  ? "bg-[#8b949e] text-[#0d1117] cursor-not-allowed"
                  : "bg-[#238636] hover:bg-[#2ea043] text-white"
              }`}
            >
              {scanning ? "Scanning..." : "Scan"}
            </button>
          </div>
        </div>
      </div>

      {/* Files Section */}
      {expanded && files && (
        <div className="border-t border-[#30363d] bg-[#161b22] p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="text-sm font-semibold">
              📁 {files.total_files} files · {files.total_directories} directories
            </div>
            <div className="text-xs text-[#8b949e]">Branch: {files.branch}</div>
          </div>
          
          <div className="max-h-96 overflow-y-auto space-y-1">
            {files.files.slice(0, 100).map((file, idx) => (
              <div
                key={idx}
                className="flex items-center gap-2 text-xs text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#21262d] px-2 py-1 rounded transition-colors"
              >
                <span className="text-[#8b949e]">📄</span>
                <span className="flex-1 truncate font-mono">{file.path}</span>
                <span className="text-[#6e7681]">{formatBytes(file.size)}</span>
              </div>
            ))}
            {files.files.length > 100 && (
              <div className="text-xs text-[#6e7681] text-center py-2">
                ... and {files.files.length - 100} more files
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}