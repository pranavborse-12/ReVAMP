import React, { useEffect, useMemo, useState } from "react";
import { Link } from "wouter";

// ------------------------
// Toast Component
// ------------------------
interface Toast {
  id: number;
  message: string;
  type?: "success" | "error";
}
function Toasts({ toasts, removeToast }: { toasts: Toast[]; removeToast: (id: number) => void }) {
  return (
    <div className="fixed top-5 right-5 flex flex-col gap-2 z-50">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`px-4 py-2 rounded shadow-md text-sm ${
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

// ------------------------
// Small Utilities
// ------------------------
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

// ------------------------
// Types
// ------------------------
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
  language?: string;
  owner?: Owner;
}

// ------------------------
// Main Page
// ------------------------
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

  // Toasts
  const [toasts, setToasts] = useState<Toast[]>([]);
  const addToast = (message: string, type?: "success" | "error") => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => removeToast(id), 3000);
  };
  const removeToast = (id: number) => setToasts((prev) => prev.filter((t) => t.id !== id));

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [pRes, rRes] = await Promise.all([
        fetch(`/api/github/profile`, { credentials: "include" }),
        fetch(
          `/api/github/repos?query=${encodeURIComponent(
            query
          )}&type=${type}&sort=${sort}&direction=${direction}&page=${page}&per_page=${per_page}`,
          { credentials: "include" }
        ),
      ]);
      if (pRes.status === 401 || rRes.status === 401) {
        setError("not-connected");
        setLoading(false);
        return;
      }
      if (!pRes.ok) throw new Error(`Profile error ${pRes.status}`);
      if (!rRes.ok) throw new Error(`Repos error ${rRes.status}`);
      setProfile(await pRes.json());
      setRepos(await rRes.json());
    } catch (e: any) {
      setError(e.message || "Failed to load");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [query, type, sort, direction, page]);

  const title = useMemo(() => `${profile?.login || "User"} · Repositories`, [profile]);

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#c9d1d9] relative">
      <Toasts toasts={toasts} removeToast={removeToast} />
      {/* Header */}
      <div className="border-b border-[#21262d] bg-[#0d1117] sticky top-0 z-30">
        <div className="mx-auto max-w-6xl px-4 py-3 flex items-center gap-3">
          <span className="font-semibold text-lg">SecureScan</span>
          <div className="ml-auto text-sm opacity-70">{title}</div>
        </div>
      </div>

      {/* Content */}
      <div className="mx-auto max-w-6xl px-4 py-6 grid grid-cols-12 gap-6">
        {/* Sidebar */}
        <aside className="col-span-12 md:col-span-4 lg:col-span-3 flex flex-col items-center md:items-start gap-4">
          <div className="relative">
            <div className="w-48 h-48 rounded-full overflow-hidden bg-[#161b22] border border-[#30363d]" />
            {profile?.avatar_url && (
              <img
                src={profile.avatar_url}
                alt="avatar"
                className="w-48 h-48 rounded-full object-cover border border-[#30363d] absolute inset-0"
              />
            )}
          </div>
          <div>
            <div className="text-2xl font-bold leading-tight">{profile?.name || profile?.login || "—"}</div>
            {profile?.name && <div className="text-[#8b949e] -mt-1">{profile.login}</div>}
          </div>
          {profile?.bio && <p className="text-sm text-[#8b949e]">{profile.bio}</p>}
        </aside>

        {/* Main panel */}
        <main className="col-span-12 md:col-span-8 lg:col-span-9">
          {/* Tabs */}
          <div className="border-b border-[#21262d] flex items-center gap-6 text-sm mb-4 sticky top-[48px] bg-[#0d1117] z-20">
            {[
              { name: "Overview", to: "/overview" },
              { name: "Repositories", to: "/repositories", active: true },
              { name: "Projects", to: "/projects" },
              { name: "Packages", to: "/packages" },
              { name: "Stars", to: "/stars" },
            ].map((t) => (
              <Link
                key={t.name}
                href={t.to}
                className={`py-3 border-b-2 ${
                  t.active
                    ? "border-[#f78166] text-white"
                    : "border-transparent text-[#8b949e] hover:text-[#c9d1d9]"
                }`}
              >
                {t.name}
              </Link>
            ))}
          </div>

          {/* Controls */}
          <div className="flex flex-col md:flex-row gap-3 md:items-center mb-4">
            <input
              placeholder="Find a repository…"
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
              className="bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] rounded-md px-3 py-2 text-sm"
            >
              {direction === "desc" ? "Desc" : "Asc"}
            </button>
          </div>

          {/* Loading / Error */}
          {loading && <div className="text-[#8b949e] text-sm">Loading repositories…</div>}
          {error === "not-connected" && (
            <div className="border border-[#30363d] rounded-md p-4 bg-[#0d1117]">
              <div className="text-sm text-[#8b949e]">Your GitHub account is not connected.</div>
              <button
                onClick={() => (window.location.href = "/api/github/connect")}
                className="mt-3 bg-[#238636] hover:bg-[#2ea043] text-white rounded-md px-3 py-2 text-sm"
              >
                Connect GitHub
              </button>
            </div>
          )}
          {error && error !== "not-connected" && <div className="text-sm text-red-400">{error}</div>}

          {/* Repo list */}
          {!loading && !error && (
            <div className="divide-y divide-[#21262d] border-y border-[#21262d] max-h-[calc(100vh-200px)] overflow-y-auto">
              {repos.length === 0 && <div className="text-sm text-[#8b949e] p-6">No repositories found.</div>}
              {repos.map((r) => (
                <RepoRow key={r.id} repo={r} addToast={addToast} />
              ))}
            </div>
          )}

          {/* Pagination */}
          {!loading && !error && (
            <div className="flex items-center gap-2 mt-6">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="bg-[#21262d] hover:bg-[#30363d] disabled:opacity-50 border border-[#30363d] rounded-md px-3 py-1.5 text-sm"
              >
                Previous
              </button>
              <span className="text-xs text-[#8b949e]">Page {page}</span>
              <button
                onClick={() => setPage((p) => p + 1)}
                className="bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] rounded-md px-3 py-1.5 text-sm"
              >
                Next
              </button>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

// ------------------------
// RepoRow Component
// ------------------------
function RepoRow({ repo, addToast }: { repo: Repo; addToast: (msg: string, type?: "success" | "error") => void }) {
  const visibility = repo.private
    ? "Private"
    : repo.visibility
    ? repo.visibility[0].toUpperCase() + repo.visibility.slice(1)
    : "Public";

  const [scanning, setScanning] = useState(false);

  const handleScan = async () => {
    setScanning(true);
    try {
      // Replace with your actual scan API call
      await new Promise((res) => setTimeout(res, 1500));
      addToast(`Scan completed for ${repo.full_name ?? repo.name}`, "success");
    } catch (err) {
      console.error(err);
      addToast(`Scan failed for ${repo.full_name ?? repo.name}`, "error");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="py-4 px-2 hover:bg-[#161b22] transition-colors rounded-md flex justify-between items-start">
      <div>
        <div className="flex items-center gap-2">
          {repo.owner?.avatar_url && (
            <a href={repo.owner?.html_url ?? "#"} target="_blank" rel="noreferrer">
              <img
                src={repo.owner?.avatar_url}
                alt={repo.owner?.login ?? "owner"}
                className="w-6 h-6 rounded-full"
              />
            </a>
          )}
          <a
            href={repo.html_url ?? "#"}
            target="_blank"
            rel="noreferrer"
            className="text-[#58a6ff] hover:underline text-lg font-semibold"
          >
            {repo.name}
          </a>
          <span className="ml-2 text-xs border border-[#30363d] text-[#8b949e] rounded-full px-2 py-0.5 align-middle">
            {visibility}
          </span>
        </div>

        {repo.description && <p className="text-sm text-[#8b949e] mt-1">{repo.description}</p>}

        <div className="text-xs text-[#8b949e] mt-2 flex gap-4 items-center">
          {repo.language && <span>{repo.language}</span>}
          <span>⭐ {repo.stargazers_count ?? 0}</span>
          {repo.updated_at && <span>Updated {timeAgo(repo.updated_at)}</span>}
        </div>
      </div>

      <button
        onClick={handleScan}
        disabled={scanning}
        className={`border border-[#30363d] rounded-md px-3 py-1 text-sm ${
          scanning ? "bg-[#8b949e] text-[#0d1117] cursor-not-allowed" : "bg-[#238636] hover:bg-[#2ea043] text-white"
        }`}
      >
        {scanning ? "Scanning..." : "Scan"}
      </button>
    </div>
  );
}
