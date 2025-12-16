import { 
  Shield, Zap, Github, FileText, Lock, 
  BarChart3, CheckCircle2 
} from 'lucide-react';
import { CardBody, CardContainer, CardItem } from "./ui/3d-card";

const features = [
  {
    title: "OWASP Detection",
    description: "Automatic protection against SQLi, XSS, and the full OWASP Top 10.",
    icon: Shield,
    color: "bg-red-500/10 text-red-500"
  },
  {
    title: "CI/CD Integration",
    description: "Block insecure builds in GitHub Actions, GitLab CI, or Jenkins.",
    icon: Github,
    color: "bg-zinc-800 text-white"
  },
  {
    title: "Instant Remediation",
    description: "AI-generated pull requests to fix vulnerabilities automatically.",
    icon: Zap,
    color: "bg-yellow-500/10 text-yellow-500"
  },
  {
    title: "Compliance Reports",
    description: "One-click PDF generation for SOC2, HIPAA, and ISO 27001.",
    icon: FileText,
    color: "bg-blue-500/10 text-blue-500"
  },
  {
    title: "Secret Scanning",
    description: "Detect hardcoded API keys and credentials before they leak.",
    icon: Lock,
    color: "bg-emerald-500/10 text-emerald-500"
  },
  {
    title: "Risk Analytics",
    description: "Visualize your security posture trends over time.",
    icon: BarChart3,
    color: "bg-purple-500/10 text-purple-500"
  }
];

export function Features() {
  return (
    <section className="py-24 bg-black relative z-10">
      <div className="container max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Security at the speed of code.
          </h2>
          <p className="text-zinc-400 text-lg max-w-2xl mx-auto">
            Everything you need to secure your application, packed into a beautiful dashboard.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, i) => (
            <CardContainer key={i} className="inter-var">
              <CardBody className="bg-zinc-900 relative group/card dark:hover:shadow-2xl dark:hover:shadow-emerald-500/[0.1] dark:bg-black dark:border-white/[0.2] border-black/[0.1] w-full h-auto rounded-xl p-6 border">
                <CardItem
                  translateZ="50"
                  className="w-12 h-12 rounded-lg flex items-center justify-center mb-4 transition-colors"
                >
                  <div className={`p-3 rounded-lg ${feature.color}`}>
                    <feature.icon className="h-6 w-6" />
                  </div>
                </CardItem>
                
                <CardItem
                  translateZ="60"
                  className="text-xl font-bold text-neutral-600 dark:text-white"
                >
                  {feature.title}
                </CardItem>
                
                <CardItem
                  as="p"
                  translateZ="40"
                  className="text-neutral-500 text-sm max-w-sm mt-2 dark:text-neutral-300"
                >
                  {feature.description}
                </CardItem>

                <CardItem translateZ="30" className="mt-4 flex items-center gap-2 text-xs text-zinc-500">
                   <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                   <span>Enterprise Ready</span>
                </CardItem>
              </CardBody>
            </CardContainer>
          ))}
        </div>
      </div>
    </section>
  );
}