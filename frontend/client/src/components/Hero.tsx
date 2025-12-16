import { ArrowRight, Github, Shield, Terminal, Zap } from "lucide-react";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { CardBody, CardContainer, CardItem } from "./ui/3d-card";
import { useEffect, useState } from "react";

// Fake terminal code
const CODE_SNIPPETS = [
  { text: "Scanning src/auth/login.ts...", color: "text-zinc-400" },
  { text: "Detected: SQL Injection (Critical)", color: "text-red-500" },
  { text: "Patching vulnerability...", color: "text-blue-400" },
  { text: "Re-running tests: PASS", color: "text-emerald-400" },
];

export function Hero() {
  const [codeIndex, setCodeIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCodeIndex((prev) => (prev + 1) % CODE_SNIPPETS.length);
    }, 1500);
    return () => clearInterval(interval);
  }, []);

  const handleGetStarted = () => {
    window.location.href = `${import.meta.env.VITE_API_URL || ''}/auth/github/login`;
  };

  return (
    <section className="relative min-h-[110vh] flex flex-col justify-center overflow-hidden bg-black pt-20">
      
      {/* 3D Background Grid - Floor Effect */}
      <div className="absolute inset-0 z-0 perspective-1000">
        <div className="absolute inset-0 bg-grid-white/[0.05] bg-[size:40px_40px] [transform:rotateX(60deg)_translateY(-200px)_scale(2)] opacity-50 origin-top"></div>
        <div className="absolute inset-0 bg-gradient-to-t from-black via-black/90 to-transparent"></div>
        
        {/* Glowing Orbs */}
        <div className="absolute top-[-10%] left-[-10%] w-[500px] h-[500px] rounded-full bg-blue-600/20 blur-[120px] animate-pulse"></div>
        <div className="absolute bottom-[0%] right-[-10%] w-[600px] h-[600px] rounded-full bg-cyan-600/10 blur-[100px]"></div>
      </div>

      <div className="container max-w-7xl mx-auto px-6 relative z-10 grid lg:grid-cols-2 gap-12 items-center">
        
        {/* Left Content */}
        <div className="space-y-8">
          <Badge variant="outline" className="border-blue-500/30 text-blue-400 bg-blue-500/10 px-4 py-1.5 text-sm backdrop-blur-md">
            <span className="mr-2 relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
            </span>
            Automated Security Intelligence
          </Badge>
          
          <h1 className="text-6xl md:text-7xl font-bold tracking-tight text-white leading-tight">
            Code Security <br/>
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-500 via-cyan-400 to-white">
              Reimagined.
            </span>
          </h1>

          <p className="text-xl text-zinc-400 max-w-lg leading-relaxed">
            Stop vulnerabilities before they commit. The only platform that combines 
            static analysis with real-time AI remediation.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 pt-4">
            <Button
              onClick={handleGetStarted}
              size="lg"
              className="h-14 px-8 text-base bg-white text-black hover:bg-zinc-200 transition-all hover:scale-105 font-semibold"
            >
              <Github className="mr-2 h-5 w-5" />
              Sign in with GitHub
            </Button>
            <Button
              size="lg"
              variant="outline"
              className="h-14 px-8 text-base border-zinc-800 text-zinc-300 hover:text-white hover:bg-zinc-900 bg-black/50 backdrop-blur-sm"
            >
              View Documentation
            </Button>
          </div>

          <div className="flex items-center gap-6 pt-8 text-sm text-zinc-500">
             <div className="flex items-center gap-2">
               <Shield className="h-4 w-4 text-blue-500" />
               <span>SOC2 Compliant</span>
             </div>
             <div className="flex items-center gap-2">
               <Zap className="h-4 w-4 text-yellow-500" />
               <span>&lt;20ms Latency</span>
             </div>
          </div>
        </div>

        {/* Right Content - 3D Floating Component */}
        <div className="relative w-full h-[500px] flex items-center justify-center">
          <CardContainer containerClassName="w-full h-full" className="w-full">
            <CardBody className="bg-zinc-900/40 relative group/card dark:hover:shadow-2xl dark:hover:shadow-blue-500/[0.1] dark:bg-black dark:border-white/[0.1] border-black/[0.1] w-full h-auto rounded-xl p-6 border transition-all duration-300">
              
              {/* Floating Header */}
              <CardItem
                translateZ="50"
                className="text-xl font-bold text-neutral-600 dark:text-white w-full"
              >
                <div className="flex items-center justify-between w-full border-b border-zinc-800 pb-4">
                  <div className="flex items-center gap-2">
                    <div className="h-3 w-3 rounded-full bg-red-500" />
                    <div className="h-3 w-3 rounded-full bg-yellow-500" />
                    <div className="h-3 w-3 rounded-full bg-green-500" />
                  </div>
                  <div className="text-xs font-mono text-zinc-500 flex items-center gap-2">
                    <Terminal className="h-3 w-3" />
                    security-scanner
                  </div>
                </div>
              </CardItem>
              
              {/* Main Code Area */}
              <CardItem
                as="div"
                translateZ="60"
                className="w-full mt-4"
              >
                 <div className="bg-black/50 rounded-lg p-6 font-mono text-sm border border-zinc-800 h-[200px] overflow-hidden relative">
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-blue-500 to-transparent opacity-50 animate-scan-line"></div>
                    
                    {CODE_SNIPPETS.map((snippet, idx) => (
                      <div 
                        key={idx} 
                        className={`mb-3 transition-opacity duration-500 ${idx > codeIndex ? 'opacity-0' : 'opacity-100'}`}
                      >
                         <span className="text-zinc-600 mr-2">$</span>
                         <span className={snippet.color}>{snippet.text}</span>
                      </div>
                    ))}
                    
                    {codeIndex === CODE_SNIPPETS.length - 1 && (
                       <div className="mt-4 p-2 bg-emerald-500/10 border border-emerald-500/20 rounded text-emerald-400 text-xs animate-pulse">
                         System Secure. No threats found.
                       </div>
                    )}
                 </div>
              </CardItem>

              {/* Floating Action Buttons */}
              <div className="flex justify-between items-center mt-8">
                <CardItem
                  translateZ={40}
                  className="px-4 py-2 rounded-xl text-xs font-normal dark:text-white bg-zinc-800"
                >
                  Running on main branch
                </CardItem>
                <CardItem
                  translateZ={80}
                  as="button"
                  className="px-4 py-2 rounded-lg bg-blue-600 dark:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-500/50 hover:bg-blue-600"
                >
                  View Full Report
                </CardItem>
              </div>
            </CardBody>
          </CardContainer>

          {/* Decorative Elements around the card */}
          <div className="absolute -z-10 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[120%] h-[120%] bg-blue-500/5 blur-3xl rounded-full pointer-events-none"></div>
        </div>
      </div>
    </section>
  );
}