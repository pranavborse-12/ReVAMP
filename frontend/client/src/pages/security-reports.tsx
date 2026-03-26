// src/pages/security-reports.tsx
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  FileText, Download, Shield, AlertTriangle, CheckCircle2,
  TrendingUp, BarChart2, Clock, RefreshCw, Loader2, XCircle
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, Legend
} from "recharts";

const API_BASE = "http://localhost:8000";

interface DashboardStats {
  totalRepos: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
  filesScanned: number;
  recentAlerts: number;
  totalScans?: number;
  completedScans?: number;
}

interface RecentScan {
  scan_id: string;
  repo_owner: string;
  repo_name: string;
  status: string;
  total_issues: number;
  completed_at?: string;
  severity_summary?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

const COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#8b5cf6",
};

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-zinc-900 border border-zinc-700 p-3 rounded-lg text-xs shadow-xl">
        <p className="text-zinc-300 font-semibold mb-1">{label}</p>
        {payload.map((entry: any, i: number) => (
          <div key={i} className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.fill || entry.color }} />
            <span className="text-zinc-400 capitalize">{entry.name}:</span>
            <span className="text-white font-mono">{entry.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function SecurityReports() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [trends, setTrends] = useState<any[]>([]);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, trendsRes, scansRes] = await Promise.all([
        fetch(`${API_BASE}/api/scanning/dashboard/stats`, { credentials: "include" }),
        fetch(`${API_BASE}/api/scanning/dashboard/trends?days=14`, { credentials: "include" }),
        fetch(`${API_BASE}/api/scanning/dashboard/recent-scans?limit=10`, { credentials: "include" }),
      ]);

      if (statsRes.ok) {
        const d = await statsRes.json();
        setStats(d.stats || d);
      }
      if (trendsRes.ok) {
        const d = await trendsRes.json();
        setTrends(d.trends || []);
      }
      if (scansRes.ok) {
        const d = await scansRes.json();
        setRecentScans(d.recentScans || d.scans || []);
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const severityData = stats ? [
    { name: "Critical", value: stats.criticalVulns || 0, fill: COLORS.critical },
    { name: "High", value: stats.highVulns || 0, fill: COLORS.high },
    { name: "Medium", value: stats.mediumVulns || 0, fill: COLORS.medium },
    { name: "Low", value: stats.lowVulns || 0, fill: COLORS.low },
  ].filter(d => d.value > 0) : [];

  const totalVulns = severityData.reduce((a, b) => a + b.value, 0);
  const riskScore = stats
    ? Math.min(100, Math.round(
        ((stats.criticalVulns || 0) * 10 +
         (stats.highVulns || 0) * 5 +
         (stats.mediumVulns || 0) * 2 +
         (stats.lowVulns || 0) * 0.5)
      ))
    : 0;

  const riskLevel = riskScore >= 50 ? { label: "HIGH RISK", color: "text-red-400" }
    : riskScore >= 20 ? { label: "MEDIUM RISK", color: "text-yellow-400" }
    : { label: "LOW RISK", color: "text-emerald-400" };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-zinc-600">
        <Loader2 className="h-8 w-8 animate-spin mb-3" />
        <p className="text-sm">Generating security report...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-8 text-center m-6">
        <XCircle className="h-8 w-8 text-red-400 mx-auto mb-3" />
        <p className="text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="w-full min-h-screen bg-black text-zinc-100 p-6 lg:p-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Reports</h1>
          <p className="text-zinc-500 text-sm mt-1">
            Generated {new Date().toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" })}
          </p>
        </div>
        <div className="flex gap-3">
          <button onClick={fetchData} className="flex items-center gap-2 px-4 py-2 bg-zinc-900 border border-zinc-800 hover:border-zinc-600 text-zinc-300 hover:text-white text-sm rounded-lg transition-all">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium rounded-lg transition-all">
            <Download className="h-4 w-4" />
            Export PDF
          </button>
        </div>
      </div>

      {/* Risk Score Banner */}
      <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-6 mb-8 flex flex-col md:flex-row items-start md:items-center gap-6">
        <div className="flex items-center gap-4">
          <div className="relative w-20 h-20">
            <svg viewBox="0 0 36 36" className="w-20 h-20 -rotate-90">
              <circle cx="18" cy="18" r="15.9" fill="none" stroke="#27272a" strokeWidth="3" />
              <circle
                cx="18" cy="18" r="15.9" fill="none"
                stroke={riskScore >= 50 ? "#ef4444" : riskScore >= 20 ? "#eab308" : "#10b981"}
                strokeWidth="3"
                strokeDasharray={`${riskScore} ${100 - riskScore}`}
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-lg font-bold text-white">{riskScore}</span>
            </div>
          </div>
          <div>
            <p className="text-zinc-500 text-xs uppercase tracking-wider mb-1">Risk Score</p>
            <p className={`text-xl font-bold ${riskLevel.color}`}>{riskLevel.label}</p>
            <p className="text-zinc-600 text-xs mt-1">Based on vulnerability severity weighting</p>
          </div>
        </div>
        <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: "Repositories", value: stats?.totalRepos ?? 0, icon: Shield },
            { label: "Total Vulns", value: totalVulns, icon: AlertTriangle },
            { label: "Files Scanned", value: (stats?.filesScanned ?? 0).toLocaleString(), icon: FileText },
            { label: "Scans Run", value: stats?.totalScans ?? recentScans.length, icon: BarChart2 },
          ].map(({ label, value, icon: Icon }) => (
            <div key={label} className="bg-zinc-800/40 rounded-xl p-3">
              <div className="flex items-center gap-2 mb-1">
                <Icon className="h-3.5 w-3.5 text-zinc-500" />
                <p className="text-zinc-500 text-xs">{label}</p>
              </div>
              <p className="text-xl font-bold text-white">{value}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Trends Chart */}
        <div className="lg:col-span-2 bg-zinc-900/40 border border-zinc-800 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-5">
            <div>
              <h3 className="font-semibold text-white">Vulnerability Trends</h3>
              <p className="text-zinc-500 text-xs">Last 14 days</p>
            </div>
            <TrendingUp className="h-4 w-4 text-zinc-600" />
          </div>
          {trends.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={trends} barSize={12}>
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: "#52525b", fontSize: 11 }} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: "#52525b", fontSize: 11 }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="critical" fill={COLORS.critical} radius={[4, 4, 0, 0]} />
                <Bar dataKey="high" fill={COLORS.high} radius={[4, 4, 0, 0]} />
                <Bar dataKey="medium" fill={COLORS.medium} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[220px] text-zinc-700 text-sm">
              No trend data available yet
            </div>
          )}
        </div>

        {/* Severity Breakdown */}
        <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl p-6">
          <h3 className="font-semibold text-white mb-1">Severity Breakdown</h3>
          <p className="text-zinc-500 text-xs mb-5">Distribution of issues</p>
          {severityData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={severityData} cx="50%" cy="50%" innerRadius={45} outerRadius={65}
                    paddingAngle={4} dataKey="value" stroke="none">
                    {severityData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2 mt-4">
                {severityData.map((item) => (
                  <div key={item.name} className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.fill }} />
                    <span className="text-zinc-400 text-xs flex-1">{item.name}</span>
                    <span className="text-white text-xs font-mono">{item.value}</span>
                    <span className="text-zinc-600 text-xs">
                      {totalVulns > 0 ? `${Math.round((item.value / totalVulns) * 100)}%` : "0%"}
                    </span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-[160px] text-zinc-700">
              <CheckCircle2 className="h-8 w-8 mb-2 text-emerald-700" />
              <p className="text-sm text-emerald-700">No vulnerabilities found</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="font-semibold text-white">Recent Scan Results</h3>
            <p className="text-zinc-500 text-xs">Click a row to view vulnerabilities</p>
          </div>
          <Clock className="h-4 w-4 text-zinc-600" />
        </div>

        {recentScans.length === 0 ? (
          <div className="text-center py-12 text-zinc-700">
            <FileText className="h-8 w-8 mx-auto mb-3 opacity-40" />
            <p className="text-sm">No scans yet. Go to Repositories to start scanning.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800">
                  {["Repository", "Status", "Critical", "High", "Medium", "Low", "Total", "Date"].map((h) => (
                    <th key={h} className="text-left pb-3 text-xs text-zinc-500 font-medium pr-4">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {recentScans.map((scan) => (
                  <tr
                    key={scan.scan_id}
                    onClick={() => navigate(`/vulnerabilities?scan_id=${scan.scan_id}`)}
                    className="hover:bg-zinc-800/30 cursor-pointer transition-colors"
                  >
                    <td className="py-3 pr-4 font-medium text-zinc-200">
                      {scan.repo_owner}/{scan.repo_name}
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                        scan.status === "completed" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" :
                        scan.status === "failed" ? "bg-red-500/10 text-red-400 border-red-500/20" :
                        "bg-blue-500/10 text-blue-400 border-blue-500/20"
                      }`}>
                        {scan.status?.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-red-400 font-mono">{scan.severity_summary?.critical ?? 0}</td>
                    <td className="py-3 pr-4 text-orange-400 font-mono">{scan.severity_summary?.high ?? 0}</td>
                    <td className="py-3 pr-4 text-yellow-400 font-mono">{scan.severity_summary?.medium ?? 0}</td>
                    <td className="py-3 pr-4 text-blue-400 font-mono">{scan.severity_summary?.low ?? 0}</td>
                    <td className="py-3 pr-4 text-white font-mono font-semibold">{scan.total_issues}</td>
                    <td className="py-3 text-zinc-500 text-xs">
                      {scan.completed_at ? new Date(scan.completed_at).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}