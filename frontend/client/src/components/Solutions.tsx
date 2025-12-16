import { useState } from "react";
// Make sure these icons are imported from lucide-react
import { Terminal, Shield, Lock, Activity, Check } from "lucide-react";
import { cn } from "../lib/utils"; // Ensure this path points to your utils file

const solutions = [
  {
    id: "devs",
    label: "Developers",
    icon: Terminal,
    title: "Fix security issues in IDE",
    description: "Real-time feedback in VS Code and GitHub PRs.",
    features: ["IDE Plugin Support", "Auto-fix Pull Requests"],
    // We render the visual inline to avoid complex object passing issues
  },
  {
    id: "secops",
    label: "SecOps",
    icon: Shield,
    title: "Orchestrate Security",
    description: "Unified dashboard for SAST, DAST, and secrets.",
    features: ["Custom Rule Engine", "Compliance Mapping"],
  },
  {
    id: "ciso",
    label: "CISOs",
    icon: Lock,
    title: "Compliance on Autopilot",
    description: "Generate SOC2 and ISO 27001 reports in one click.",
    features: ["Executive PDF Reports", "Audit Logs"],
  }
];

export function Solutions() {
  const [activeTab, setActiveTab] = useState("devs");
  
  // Safe find to prevent crashes
  const activeSolution = solutions.find(s => s.id === activeTab) || solutions[0];

  return (
    <section id="solutions" className="py-24 bg-zinc-950 relative overflow-hidden">
      <div className="container max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Built for <span className="text-blue-500">everyone</span>
          </h2>
        </div>

        <div className="grid lg:grid-cols-2 gap-12 items-center">
          {/* Navigation */}
          <div className="space-y-4">
            {solutions.map((s) => (
              <button
                key={s.id}
                onClick={() => setActiveTab(s.id)}
                className={cn(
                  "w-full group flex items-center gap-4 p-4 rounded-xl text-left transition-all duration-300 border",
                  activeTab === s.id 
                    ? "bg-zinc-900 border-blue-500/50 shadow-lg" 
                    : "bg-transparent border-transparent hover:bg-zinc-900/50"
                )}
              >
                <div className={cn(
                  "p-3 rounded-lg transition-colors",
                  activeTab === s.id ? "bg-blue-500 text-white" : "bg-zinc-800 text-zinc-400"
                )}>
                  <s.icon className="h-6 w-6" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">{s.label}</h3>
                  <p className="text-sm text-zinc-400">{s.title}</p>
                </div>
              </button>
            ))}
          </div>

          {/* 3D Visual Display */}
          <div className="relative h-[400px] perspective-1000 w-full">
            <div className="absolute inset-0 bg-blue-600/10 blur-3xl -z-10" />
            
            <div className="bg-black/90 border border-zinc-800 rounded-3xl p-8 h-full flex flex-col justify-between shadow-2xl">
              <div>
                <h3 className="text-2xl font-bold text-white mb-2">{activeSolution.title}</h3>
                <p className="text-zinc-400 mb-6">{activeSolution.description}</p>
                <div className="grid grid-cols-2 gap-3">
                  {activeSolution.features.map((f, i) => (
                    <div key={i} className="flex items-center gap-2 text-sm text-zinc-300">
                      <Check className="h-4 w-4 text-emerald-500" /> {f}
                    </div>
                  ))}
                </div>
              </div>

              {/* Dynamic Visual based on active tab */}
              <div className="mt-6 p-4 bg-zinc-900 rounded-lg border border-zinc-800 h-32 flex items-center justify-center relative overflow-hidden">
                {activeTab === 'devs' && (
                   <div className="font-mono text-xs text-zinc-400 w-full">
                     <span className="text-blue-400">const</span> user = <span className="text-red-400">await db.query(...)</span>;
                     <div className="mt-2 text-emerald-500">✓ Auto-fix applied</div>
                   </div>
                )}
                {activeTab === 'secops' && <Activity className="h-12 w-12 text-blue-500 animate-pulse" />}
                {activeTab === 'ciso' && <Shield className="h-12 w-12 text-emerald-500" />}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}