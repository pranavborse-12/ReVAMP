import React, { useState } from "react";
import {
  Code2,
  ShieldCheck,
  Lock,
  Terminal,
  Check,
  Download,
  FileText,
  ChevronRight,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Button } from "./ui/button";
import { cn } from "../lib/utils";

const chartData = [
  { name: "Mon", vulns: 45 },
  { name: "Tue", vulns: 30 },
  { name: "Wed", vulns: 25 },
  { name: "Thu", vulns: 15 },
  { name: "Fri", vulns: 5 },
  { name: "Sat", vulns: 2 },
  { name: "Sun", vulns: 0 },
];

type Tab = "developers" | "secops" | "cisos";

export function Solutions() {
  const [activeTab, setActiveTab] = useState<Tab>("developers");

  return (
    <section
      id="solutions"
      className="relative py-32 bg-gradient-to-b from-black via-zinc-950 to-black border-t border-white/5"
    >
      <div className="max-w-7xl mx-auto px-6">
        {/* Header */}
        <div className="text-center mb-20">
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Built for <span className="text-blue-500">everyone</span>
          </h2>
          {/* <p className="text-zinc-400 max-w-2xl mx-auto">
            Tailored interfaces that empower every stakeholder in your organization
            with real-time intelligence.
          </p> */}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-16 items-start">
          {/* LEFT RAIL */}
          <div className="lg:col-span-4 space-y-3">
            {[
              {
                id: "developers",
                label: "Developers",
                desc: "Fix security issues in IDE",
                icon: Code2,
              },
              {
                id: "secops",
                label: "Security Ops",
                desc: "Orchestrate Security",
                icon: ShieldCheck,
              },
              {
                id: "cisos",
                label: "Compliance",
                desc: "Compliance on Autopilot",
                icon: Lock,
              },
            ].map((tab) => {
              const active = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as Tab)}
                  className={cn(
                    "w-full text-left p-5 rounded-xl border transition-all duration-300 flex items-center gap-4",
                    active
                      ? "bg-zinc-900 border-zinc-700 shadow-lg scale-[1.02]"
                      : "bg-transparent border-transparent hover:bg-zinc-900/40"
                  )}
                >
                  <div
                    className={cn(
                      "p-3 rounded-lg",
                      active ? "bg-blue-600 text-white" : "bg-zinc-800 text-zinc-400"
                    )}
                  >
                    <tab.icon className="w-5 h-5" />
                  </div>

                  <div className="flex-1">
                    <h3 className="font-semibold text-white">{tab.label}</h3>
                    <p className="text-xs text-zinc-500">{tab.desc}</p>
                  </div>

                  <ChevronRight
                    className={cn(
                      "w-4 h-4 transition-transform",
                      active ? "translate-x-1 text-blue-400" : "text-zinc-600"
                    )}
                  />
                </button>
              );
            })}
          </div>

          {/* RIGHT WINDOW */}
          <div className="lg:col-span-8">
            <div className="relative rounded-2xl border border-zinc-800 bg-zinc-950 shadow-2xl overflow-hidden min-h-[520px]">
              {/* Window chrome */}
              <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800 bg-zinc-900/60">
                <div className="flex gap-2">
                  <span className="w-3 h-3 rounded-full bg-zinc-700" />
                  <span className="w-3 h-3 rounded-full bg-zinc-700" />
                  <span className="w-3 h-3 rounded-full bg-zinc-700" />
                </div>
                <div className="text-[10px] tracking-widest uppercase text-zinc-500 font-mono">
                  Protocol Interface v2.0
                </div>
                <div className="w-12" />
              </div>

              {/* Grid background */}
              <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.04)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.04)_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none" />

              {/* CONTENT */}
              <div className="relative p-10">
                {/* DEVELOPERS */}
                {activeTab === "developers" && (
                  <div className="space-y-6 animate-fade-in font-mono text-sm">
                    <h3 className="text-white text-xl font-bold flex items-center gap-3 font-sans">
                      <Terminal className="w-6 h-6 text-blue-400" />
                      Developer Protocol
                    </h3>

                    <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
                      <p className="text-blue-300">
                        import authService from{" "}
                        <span className="text-emerald-400">'@core/auth'</span>;
                      </p>
                      <p className="text-zinc-500 mt-2">
                        // Critical: Unsanitized input
                      </p>
                      <p className="text-zinc-400">
                        const payload ={" "}
                        <span className="line-through text-red-400">
                          req.body.data
                        </span>
                        ;
                      </p>
                      <p className="text-emerald-400 mt-2">
                        const payload = sanitizeInput(req.body.data);
                      </p>

                      <div className="mt-4 flex items-center gap-2 text-xs text-emerald-400">
                        <Check className="w-4 h-4" />
                        Fix applied to active branch
                      </div>
                    </div>

                    <div className="flex gap-4">
                      <Button size="sm">Push to Prod</Button>
                      <Button variant="outline" size="sm">
                        Run Unit Tests
                      </Button>
                    </div>
                  </div>
                )}

                {/* SECOPS */}
                {activeTab === "secops" && (
                  <div className="space-y-6 animate-fade-in">
                    <div className="flex justify-between items-center">
                      <h3 className="text-white text-xl font-bold flex items-center gap-3">
                        <ShieldCheck className="w-6 h-6 text-blue-400" />
                        Security Posture
                      </h3>
                      <div className="text-right">
                        <div className="text-3xl font-bold text-white font-mono">
                          94%
                        </div>
                        <div className="text-xs text-emerald-400">
                          Improvement
                        </div>
                      </div>
                    </div>

                    <div className="h-[280px] bg-zinc-900/60 border border-zinc-800 rounded-xl p-4">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={chartData}>
                          <defs>
                            <linearGradient
                              id="vulnGradient"
                              x1="0"
                              y1="0"
                              x2="0"
                              y2="1"
                            >
                              <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.3} />
                              <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
                            </linearGradient>
                          </defs>
                          <XAxis dataKey="name" stroke="#52525b" />
                          <YAxis stroke="#52525b" />
                          <Tooltip />
                          <Area
                            type="monotone"
                            dataKey="vulns"
                            stroke="#3b82f6"
                            fill="url(#vulnGradient)"
                            strokeWidth={3}
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}

                {/* CISOS */}
                {activeTab === "cisos" && (
                  <div className="space-y-6 animate-fade-in">
                    <div className="flex justify-between items-center">
                      <h3 className="text-white text-xl font-bold flex items-center gap-3">
                        <Lock className="w-6 h-6 text-emerald-400" />
                        Compliance Vault
                      </h3>
                      <Button variant="outline" size="sm">
                        <Download className="w-4 h-4 mr-2" />
                        Generate SOC2
                      </Button>
                    </div>

                    <div className="grid grid-cols-2 gap-6">
                      <div className="p-5 bg-zinc-900/60 border border-zinc-800 rounded-xl">
                        <div className="text-3xl font-bold text-white font-mono">
                          100%
                        </div>
                        <div className="text-xs text-zinc-500 uppercase">
                          Regulatory Ready
                        </div>
                      </div>
                      <div className="p-5 bg-zinc-900/60 border border-zinc-800 rounded-xl">
                        <div className="text-3xl font-bold text-white font-mono">
                          0
                        </div>
                        <div className="text-xs text-zinc-500 uppercase">
                          Unmitigated Risks
                        </div>
                      </div>
                    </div>

                    {[
                      "Infrastructure_Security_Audit_Q4.pdf",
                      "ISO_27001_Compliance_Verification.pdf",
                    ].map((file) => (
                      <div
                        key={file}
                        className="flex items-center justify-between p-4 border border-zinc-800 bg-zinc-900/60 rounded-xl"
                      >
                        <div className="flex items-center gap-3">
                          <FileText className="w-5 h-5 text-zinc-400" />
                          <span className="text-zinc-300">{file}</span>
                        </div>
                        <Check className="w-5 h-5 text-emerald-400" />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
