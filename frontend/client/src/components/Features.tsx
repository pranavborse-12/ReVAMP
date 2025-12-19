import {
  Shield,
  Zap,
  Github,
  FileText,
  Lock,
  BarChart3,
  CheckCircle2,
} from "lucide-react";
import { useState } from "react";

const features = [
  {
    title: "OWASP Detection",
    description:
      "Automatic protection against SQLi, XSS, and the full OWASP Top 10.",
    icon: Shield,
    color: "bg-red-500/10 text-red-400",
  },
  {
    title: "CI/CD Integration",
    description:
      "Block insecure builds in GitHub Actions, GitLab CI, or Jenkins.",
    icon: Github,
    color: "bg-zinc-800 text-white",
  },
  {
    title: "Instant Remediation",
    description:
      "AI-generated pull requests to fix vulnerabilities automatically.",
    icon: Zap,
    color: "bg-yellow-500/10 text-yellow-400",
  },
  {
    title: "Compliance Reports",
    description:
      "One-click PDF generation for SOC2, HIPAA, and ISO 27001.",
    icon: FileText,
    color: "bg-blue-500/10 text-blue-400",
  },
  {
    title: "Secret Scanning",
    description:
      "Detect hardcoded API keys and credentials before they leak.",
    icon: Lock,
    color: "bg-emerald-500/10 text-emerald-400",
  },
  {
    title: "Risk Analytics",
    description:
      "Visualize your security posture trends over time.",
    icon: BarChart3,
    color: "bg-purple-500/10 text-purple-400",
  },
];

export function Features() {
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const [hoveredCard, setHoveredCard] = useState<number | null>(null);

  const handleMouseMove = (
    e: React.MouseEvent<HTMLDivElement>,
    index: number
  ) => {
    const rect = e.currentTarget.getBoundingClientRect();
    setMousePosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
    setHoveredCard(index);
  };

  return (
    <section
      id="features"
      className="py-24 bg-black relative overflow-hidden"
    >
      <div className="container max-w-7xl mx-auto px-6">
        {/* Header */}
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Security at the speed of code.
          </h2>
          <p className="text-zinc-400 text-lg max-w-2xl mx-auto">
            Everything you need to secure your application, packed into a
            beautiful dashboard.
          </p>
        </div>

        {/* Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, i) => (
            <div
              key={i}
              onMouseMove={(e) => handleMouseMove(e, i)}
              onMouseLeave={() => setHoveredCard(null)}
              className="
                relative
                rounded-2xl
                p-6
                border
                border-zinc-800
                bg-zinc-900/40
                transition-all
                duration-300
                hover:-translate-y-1
                hover:bg-zinc-900/60
                cursor-pointer
              "
              style={{
                background:
                  hoveredCard === i
                    ? `radial-gradient(
                        500px circle at ${mousePosition.x}px ${mousePosition.y}px,
                        rgba(59,130,246,0.08),
                        transparent 45%
                      )`
                    : undefined,
              }}
            >
              <div className="relative z-10">
                {/* Icon */}
                <div
                  className={`w-12 h-12 rounded-lg flex items-center justify-center mb-4 transition-transform duration-300 group-hover:scale-110 ${feature.color}`}
                >
                  <feature.icon className="h-6 w-6" />
                </div>

                {/* Title */}
                <h3 className="text-xl font-semibold text-white mb-2">
                  {feature.title}
                </h3>

                {/* Description */}
                <p className="text-zinc-400 text-sm leading-relaxed mb-4">
                  {feature.description}
                </p>

                {/* Footer */}
                <div className="flex items-center gap-2 text-xs text-zinc-500 font-mono">
                  <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                  <span className="opacity-60">// Enterprise Ready</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
