import React, { useEffect, useRef, useState } from 'react';
import { GitGraph, Shield, AlertOctagon, CheckCircle, Activity } from 'lucide-react';

interface Node {
  x: number;
  y: number;
  z: number;
  id: number;
  status: 'safe' | 'infected' | 'patching';
  connections: number[];
}

const NeuralDefense: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [log, setLog] = useState<{msg: string, type: 'info'|'alert'|'success'} | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = canvas.width = canvas.offsetWidth;
    let height = canvas.height = canvas.offsetHeight;
    
    // 3D Network State
    const nodes: Node[] = [];
    const nodeCount = 30;
    const connectionProb = 0.15;
    const rotationSpeed = 0.002;
    let rotation = 0;

    // Initialize Nodes in a sphere
    for (let i = 0; i < nodeCount; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos((Math.random() * 2) - 1);
      const radius = 200 + Math.random() * 100;
      
      nodes.push({
        id: i,
        x: radius * Math.sin(phi) * Math.cos(theta),
        y: radius * Math.sin(phi) * Math.sin(theta),
        z: radius * Math.cos(phi),
        status: 'safe',
        connections: []
      });
    }

    // Connect Nodes
    nodes.forEach((node, i) => {
      nodes.forEach((target, j) => {
        if (i !== j && Math.random() < connectionProb) {
           // Limit connections to avoid mess
           if (node.connections.length < 3) {
             node.connections.push(j);
           }
        }
      });
    });

    // Simulation Loop Variables
    let activeAlertNode: number | null = null;
    let patchTimer = 0;

    const project = (x: number, y: number, z: number) => {
      const scale = 400 / (400 + z);
      const x2d = (x * scale) + width / 2;
      const y2d = (y * scale) + height / 2;
      return { x: x2d, y: y2d, scale };
    };

    const animate = () => {
      ctx.fillStyle = '#06080f';
      ctx.fillRect(0, 0, width, height);

      // Grid Background
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.025)';
      ctx.beginPath();
      for (let i=0; i<width; i+=40) { ctx.moveTo(i, 0); ctx.lineTo(i, height); }
      ctx.stroke();

      rotation += rotationSpeed;

      // Simulation Logic: Random Vulnerability
      if (activeAlertNode === null && Math.random() > 0.99) {
        activeAlertNode = Math.floor(Math.random() * nodes.length);
        nodes[activeAlertNode].status = 'infected';
        setLog({ msg: `VULNERABILITY DETECTED: MODULE_${activeAlertNode}`, type: 'alert' });
        patchTimer = 100; // Frames until patch
      }

      // Simulation Logic: Patching
      if (activeAlertNode !== null) {
        patchTimer--;
        if (patchTimer === 50) {
           nodes[activeAlertNode].status = 'patching';
           setLog({ msg: `DEPLOYING HOTFIX TO MODULE_${activeAlertNode}...`, type: 'info' });
        }
        if (patchTimer <= 0) {
           nodes[activeAlertNode].status = 'safe';
           setLog({ msg: `MODULE_${activeAlertNode} SECURED`, type: 'success' });
           activeAlertNode = null;
        }
      }

      // 3D Rotation Calculation
      const sinR = Math.sin(rotation);
      const cosR = Math.cos(rotation);

      // Draw Connections (Lines)
      ctx.lineWidth = 1;
      nodes.forEach(node => {
        const x = node.x * cosR - node.z * sinR;
        const z = node.z * cosR + node.x * sinR;
        const pos = project(x, node.y, z);

        node.connections.forEach(connIdx => {
          const target = nodes[connIdx];
          const tx = target.x * cosR - target.z * sinR;
          const tz = target.z * cosR + target.x * sinR;
          const tPos = project(tx, target.y, tz);

          // Depth check
          if (pos.scale > 0 && tPos.scale > 0) {
            const alpha = (pos.scale + tPos.scale) / 2 * 0.3;
            
            // Infection Spread Effect
            if (node.status === 'infected' || target.status === 'infected') {
               ctx.strokeStyle = `rgba(239, 68, 68, ${alpha})`;
            } else {
               ctx.strokeStyle = `rgba(0, 240, 255, ${alpha * 0.5})`;
            }
            
            ctx.beginPath();
            ctx.moveTo(pos.x, pos.y);
            ctx.lineTo(tPos.x, tPos.y);
            ctx.stroke();

            // Packet Flow
            const time = Date.now() / 1000;
            const offset = (time * 2 + node.id) % 1;
            const px = pos.x + (tPos.x - pos.x) * offset;
            const py = pos.y + (tPos.y - pos.y) * offset;
            
            ctx.fillStyle = node.status === 'infected' ? '#ef4444' : '#ffffff';
            ctx.beginPath();
            ctx.arc(px, py, 1.5 * pos.scale, 0, Math.PI*2);
            ctx.fill();
          }
        });
      });

      // Draw Nodes
      nodes.forEach(node => {
        const x = node.x * cosR - node.z * sinR;
        const z = node.z * cosR + node.x * sinR;
        const pos = project(x, node.y, z);

        if (pos.scale > 0) {
          const size = 4 * pos.scale;
          
          let color = '#0ea5e9'; // Blue (Safe)
          let glow = 'rgba(14, 165, 233, 0.5)';

          if (node.status === 'infected') {
            color = '#ef4444'; // Red
            glow = 'rgba(239, 68, 68, 0.8)';
          } else if (node.status === 'patching') {
            color = '#eab308'; // Yellow
            glow = 'rgba(234, 179, 8, 0.8)';
          }

          // Node Glow
          const gradient = ctx.createRadialGradient(pos.x, pos.y, 0, pos.x, pos.y, size * 4);
          gradient.addColorStop(0, color);
          gradient.addColorStop(1, 'transparent');
          ctx.fillStyle = gradient;
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, size * 4, 0, Math.PI * 2);
          ctx.fill();

          // Node Core
          ctx.fillStyle = '#fff';
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, size, 0, Math.PI * 2);
          ctx.fill();

          // Scanning Ring Effect for Patching/Infected
          if (node.status !== 'safe') {
             ctx.strokeStyle = color;
             ctx.lineWidth = 1;
             ctx.beginPath();
             ctx.arc(pos.x, pos.y, size * 6 * Math.abs(Math.sin(Date.now() / 200)), 0, Math.PI*2);
             ctx.stroke();
          }
        }
      });

      requestAnimationFrame(animate);
    };

    const animFrame = requestAnimationFrame(animate);

    const handleResize = () => {
      width = canvas.width = canvas.offsetWidth;
      height = canvas.height = canvas.offsetHeight;
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animFrame);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return (
    <section id="intelligence" className="relative h-[800px] bg-gradient-to-b from-black via-zinc-950 to-black overflow-hidden flex flex-col items-center justify-center border-t border-b border-white/5">
      
      <div className="absolute top-0 left-0 w-full h-full z-0">
        <canvas ref={canvasRef} className="w-full h-full" />
      </div>

      <div className="relative z-10 w-full max-w-7xl mx-auto px-6 pointer-events-none">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center h-full pt-20 pb-20">
          
          {/* Left Panel: Architecture Info */}
          <div className="bg-black/60 backdrop-blur-xl border border-white/10 p-6 rounded-xl space-y-6 max-w-sm animate-float shadow-2xl">
             <div>
                <h3 className="text-white font-bold text-xl flex items-center gap-2 mb-1">
                   <GitGraph className="w-5 h-5 text-cyan-400"/> Live Dependency Graph
                </h3>
                <p className="text-gray-400 text-sm">Visualizing real-time data flow between microservices.</p>
             </div>
             
             <div className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-white/5">
                   <div className="flex items-center gap-3">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_10px_#22d3ee]"></div>
                      <span className="text-sm font-mono text-gray-300">Active Services</span>
                   </div>
                   <span className="text-cyan-400 font-mono font-bold">42</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-white/5">
                   <div className="flex items-center gap-3">
                      <div className="w-2 h-2 rounded-full bg-violet-400 shadow-[0_0_10px_#a78bfa]"></div>
                      <span className="text-sm font-mono text-gray-300">Encrypted Packets</span>
                   </div>
                   <span className="text-violet-400 font-mono font-bold">1.2M/s</span>
                </div>
             </div>
          </div>

          {/* Right Panel: Security Log */}
          <div className="bg-black/60 backdrop-blur-xl border border-white/10 p-6 rounded-xl space-y-4 max-w-sm mt-6 md:mt-0 animate-float-delayed shadow-2xl">
             <h3 className="text-white font-bold text-lg flex items-center gap-2 border-b border-white/10 pb-3">
                <Activity className="w-5 h-5 text-emerald-400"/> Security Events
             </h3>
             <div className="font-mono text-xs space-y-3 h-32 overflow-hidden relative">
                 {/* Current Log Message */}
                 {log && (
                   <div className={`flex items-center gap-2 p-2 rounded ${
                     log.type === 'alert' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 
                     log.type === 'success' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                     'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                   } animate-fade-in`}>
                      {log.type === 'alert' ? <AlertOctagon className="w-3 h-3"/> : <CheckCircle className="w-3 h-3"/>}
                      {log.msg}
                   </div>
                 )}
                 
                 {/* Static Logs */}
                 <div className="text-gray-500 opacity-50 flex items-center gap-2">
                    <span>14:02:22</span> <span>SCANNING NODE_04...</span>
                 </div>
                 <div className="text-gray-500 opacity-50 flex items-center gap-2">
                    <span>14:02:20</span> <span>DEPENDENCY CHECK PASS</span>
                 </div>
                 
                 <div className="absolute inset-0 bg-gradient-to-t from-black/80 to-transparent pointer-events-none"></div>
             </div>
             
             <div className="pt-2">
                <div className="w-full bg-gray-800 h-1 rounded-full overflow-hidden">
                   <div className="bg-cyan-400 h-full w-[45%] animate-[pulse_2s_infinite]"></div>
                </div>
                <div className="flex justify-between text-[10px] text-gray-500 font-mono mt-1">
                   <span>AI LOAD</span>
                   <span>45%</span>
                </div>
             </div>
          </div>

        </div>

        <div className="absolute bottom-12 left-1/2 -translate-x-1/2 text-center w-full">
           <h2 className="text-3xl md:text-5xl font-bold text-white mb-4 text-neon">TOTAL VISIBILITY</h2>
           <p className="text-gray-400 max-w-xl mx-auto text-sm md:text-base">
             ReVAMP maps your entire codebase in real-time, identifying 
             vulnerable dependencies and isolating threats before they spread.
           </p>
        </div>
      </div>
    </section>
  );
};

export default NeuralDefense;