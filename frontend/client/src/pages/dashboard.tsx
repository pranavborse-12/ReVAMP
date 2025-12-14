import React, { useEffect, useState } from "react";
import { 
  Area, 
  AreaChart, 
  Cell, 
  Pie, 
  PieChart, 
  ResponsiveContainer, 
  Tooltip, 
  XAxis, 
  YAxis 
} from "recharts";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Bell,
  Box,
  Calendar,
  CheckCircle2,
  FileCode,
  Files,
  Filter,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Download
} from "lucide-react";

// --- MOCK DATA GENERATOR (Simulating API Response) ---
// In a real app, you would fetch this from http://localhost:8000/api/dashboard/stats
const generateData = () => {
  return {
    stats: {
      totalRepos: 12,
      criticalVulns: 24,
      filesScanned: 1458,
      recentAlerts: 8,
    },
    trends: [
      { name: "Mon", critical: 4, high: 12, medium: 20 },
      { name: "Tue", critical: 3, high: 15, medium: 18 },
      { name: "Wed", critical: 5, high: 10, medium: 25 },
      { name: "Thu", critical: 2, high: 8, medium: 22 },
      { name: "Fri", critical: 8, high: 18, medium: 30 },
      { name: "Sat", critical: 6, high: 14, medium: 28 },
      { name: "Sun", critical: 4, high: 12, medium: 24 },
    ],
    severity: [
      { name: "Critical", value: 24, color: "#ef4444" }, // Red-500
      { name: "High", value: 45, color: "#f97316" },     // Orange-500
      { name: "Medium", value: 67, color: "#eab308" },   // Yellow-500
      { name: "Low", value: 120, color: "#3b82f6" },    // Blue-500
    ],
    recentActivity: [
      { id: 1, repo: "backend-api", status: "failed", time: "2 min ago", issues: 5 },
      { id: 2, repo: "frontend-ui", status: "completed", time: "15 min ago", issues: 0 },
      { id: 3, repo: "auth-service", status: "completed", time: "1 hour ago", issues: 12 },
      { id: 4, repo: "payment-gateway", status: "scanning", time: "Just now", issues: 0 },
    ],
    vulnerableFiles: [
      { file: "src/auth/login.ts", type: "SQL Injection", severity: "CRITICAL" },
      { file: "src/api/user.js", type: "XSS", severity: "HIGH" },
      { file: "config/database.yml", type: "Exposed Secret", severity: "CRITICAL" },
      { file: "src/components/Input.tsx", type: "Prop Drilling", severity: "LOW" },
    ]
  };
};

// --- COMPONENTS ---

const StatCard = ({ title, value, icon: Icon, trend, color }: any) => (
  <div className="relative overflow-hidden rounded-2xl bg-[#09090b] border border-white/5 p-6 group hover:border-white/10 transition-all duration-300">
    <div className={`absolute -right-6 -top-6 h-24 w-24 rounded-full opacity-5 blur-2xl transition-all group-hover:opacity-10 ${color}`}></div>
    <div className="flex justify-between items-start mb-4">
      <div className={`p-3 rounded-xl bg-white/5 border border-white/5 ${color.replace('bg-', 'text-')}`}>
        <Icon size={20} />
      </div>
      {trend && (
        <div className="flex items-center gap-1 text-emerald-400 text-xs font-medium bg-emerald-400/10 px-2 py-1 rounded-full">
          <ArrowUpRight size={12} /> {trend}
        </div>
      )}
    </div>
    <h3 className="text-zinc-400 text-sm font-medium mb-1">{title}</h3>
    <div className="text-3xl font-bold text-white tracking-tight">{value}</div>
  </div>
);

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#09090b] border border-white/10 p-3 rounded-lg shadow-xl backdrop-blur-md">
        <p className="text-zinc-300 text-xs mb-2 font-bold">{label}</p>
        {payload.map((entry: any, index: number) => (
          <div key={index} className="flex items-center gap-2 text-xs mb-1">
            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }}></div>
            <span className="text-zinc-400 capitalize">{entry.name}:</span>
            <span className="text-white font-mono">{entry.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function Dashboard() {
  const [data, setData] = useState(generateData());
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Simulate Data Fetching
  const fetchData = () => {
    setLoading(true);
    // In real app: fetch('/api/stats').then(...)
    setTimeout(() => {
      setData(generateData()); // Regenerate random data to simulate real-time updates
      setLoading(false);
      setRefreshing(false);
    }, 800);
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 font-sans selection:bg-indigo-500/30 p-6 lg:p-8">
      {/* --- HEADER --- */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-8">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white mb-1">Security Overview</h1>
          <p className="text-zinc-400 text-sm flex items-center gap-2">
            <Calendar size={14} /> Last updated: {new Date().toLocaleTimeString()}
          </p>
        </div>
        
        <div className="flex items-center gap-3">
          <div className="relative hidden md:block group">
             <Search className="absolute left-3 top-2.5 text-zinc-500 w-4 h-4 group-focus-within:text-indigo-400 transition-colors" />
             <input 
               placeholder="Search analytics..." 
               className="bg-zinc-900/50 border border-white/10 rounded-lg py-2 pl-9 pr-4 text-sm focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 w-64 transition-all"
             />
          </div>
          <button className="p-2 text-zinc-400 hover:text-white hover:bg-white/5 rounded-lg border border-transparent hover:border-white/5 transition-all">
            <Bell size={20} />
          </button>
          <button 
            onClick={handleRefresh}
            className={`flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold rounded-lg transition-all shadow-lg shadow-indigo-900/20 ${refreshing ? 'opacity-70 cursor-wait' : ''}`}
          >
            <RefreshCw size={16} className={refreshing ? "animate-spin" : ""} />
            {refreshing ? "Updating..." : "Refresh Data"}
          </button>
        </div>
      </div>

      {/* --- STATS GRID --- */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard 
          title="Total Repositories" 
          value={data.stats.totalRepos} 
          icon={Box} 
          trend="+2 New" 
          color="bg-blue-500" 
        />
        <StatCard 
          title="Critical Vulnerabilities" 
          value={data.stats.criticalVulns} 
          icon={ShieldAlert} 
          trend="+12%" 
          color="bg-red-500" 
        />
        <StatCard 
          title="Files Scanned" 
          value={data.stats.filesScanned.toLocaleString()} 
          icon={Files} 
          color="bg-indigo-500" 
        />
        <StatCard 
          title="Security Alerts" 
          value={data.stats.recentAlerts} 
          icon={AlertTriangle} 
          trend="Last 24h" 
          color="bg-amber-500" 
        />
      </div>

      {/* --- MAIN CHARTS SECTION --- */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        
        {/* Trend Chart (Left 2/3) */}
        <div className="lg:col-span-2 bg-[#09090b] border border-white/5 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="font-bold text-white text-lg">Vulnerability Trends</h3>
              <p className="text-zinc-500 text-xs">New issues detected over the last 7 days</p>
            </div>
            <button className="p-2 hover:bg-white/5 rounded-lg text-zinc-500 hover:text-white transition-colors">
              <Download size={16} />
            </button>
          </div>
          
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.trends}>
                <defs>
                  <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{fill: '#52525b', fontSize: 12}} />
                <YAxis axisLine={false} tickLine={false} tick={{fill: '#52525b', fontSize: 12}} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fillOpacity={1} fill="url(#colorCritical)" strokeWidth={2} />
                <Area type="monotone" dataKey="high" stroke="#f97316" fillOpacity={1} fill="url(#colorHigh)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Chart (Right 1/3) */}
        <div className="bg-[#09090b] border border-white/5 rounded-2xl p-6">
          <h3 className="font-bold text-white text-lg mb-1">Severity Distribution</h3>
          <p className="text-zinc-500 text-xs mb-6">Breakdown by threat level</p>
          
          <div className="h-[200px] w-full relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data.severity}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {data.severity.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            {/* Center Text */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-3xl font-bold text-white">{data.stats.criticalVulns + 45 + 67}</span>
              <span className="text-xs text-zinc-500 uppercase tracking-widest">Issues</span>
            </div>
          </div>

          {/* Legend */}
          <div className="grid grid-cols-2 gap-3 mt-6">
            {data.severity.map((item) => (
              <div key={item.name} className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }}></div>
                <span className="text-zinc-400 text-xs">{item.name}</span>
                <span className="ml-auto text-white text-xs font-mono">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* --- BOTTOM SECTION --- */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* File Security Tree (List View) */}
        <div className="bg-[#09090b] border border-white/5 rounded-2xl p-6 flex flex-col">
          <div className="flex items-center justify-between mb-6">
             <div>
               <h3 className="font-bold text-white text-lg">Top Vulnerable Files</h3>
               <p className="text-zinc-500 text-xs">Files requiring immediate attention</p>
             </div>
             <Filter size={16} className="text-zinc-500 hover:text-white cursor-pointer" />
          </div>

          <div className="space-y-3">
            {data.vulnerableFiles.map((file, i) => (
              <div key={i} className="flex items-center justify-between p-3 rounded-xl bg-zinc-900/30 border border-white/5 hover:bg-zinc-900/60 transition-colors group cursor-pointer">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-zinc-800 rounded-lg text-indigo-400 group-hover:text-indigo-300">
                    <FileCode size={18} />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-zinc-200 group-hover:text-white font-mono">{file.file}</div>
                    <div className="text-xs text-zinc-500">{file.type}</div>
                  </div>
                </div>
                <span className={`text-[10px] font-bold px-2 py-1 rounded border ${
                  file.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 
                  file.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-500 border-orange-500/20' : 
                  'bg-blue-500/10 text-blue-500 border-blue-500/20'
                }`}>
                  {file.severity}
                </span>
              </div>
            ))}
          </div>
          <button className="mt-4 w-full py-2 text-xs font-medium text-zinc-500 hover:text-indigo-400 border border-dashed border-zinc-800 rounded-lg hover:border-indigo-500/30 transition-colors">
            View all files
          </button>
        </div>

        {/* Repository Scan Status (Activity Feed) */}
        <div className="bg-[#09090b] border border-white/5 rounded-2xl p-6">
           <div className="flex items-center justify-between mb-6">
             <div>
               <h3 className="font-bold text-white text-lg">Recent Scans</h3>
               <p className="text-zinc-500 text-xs">Real-time scan activity logs</p>
             </div>
             <Activity size={16} className="text-zinc-500" />
          </div>

          <div className="relative border-l border-zinc-800 ml-3 space-y-6">
            {data.recentActivity.map((activity, i) => (
              <div key={i} className="relative pl-8">
                {/* Timeline Dot */}
                <div className={`absolute -left-[5px] top-1 w-2.5 h-2.5 rounded-full border-2 border-[#09090b] ${
                  activity.status === 'failed' ? 'bg-red-500' :
                  activity.status === 'scanning' ? 'bg-blue-500 animate-pulse' : 'bg-emerald-500'
                }`}></div>
                
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-sm font-bold text-zinc-200 block">{activity.repo}</span>
                    <span className="text-xs text-zinc-500 block">{activity.time}</span>
                  </div>
                  <div className="text-right">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                      activity.status === 'failed' ? 'bg-red-500/10 text-red-400' :
                      activity.status === 'scanning' ? 'bg-blue-500/10 text-blue-400' : 'bg-emerald-500/10 text-emerald-400'
                    }`}>
                      {activity.status}
                    </span>
                    {activity.issues > 0 && (
                      <div className="text-[10px] text-red-400 mt-1 font-mono">
                        {activity.issues} issues found
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}