import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { 
  Shield, 
  Zap, 
  Github, 
  FileText, 
  AlertTriangle, 
  CheckCircle,
  Clock,
  Users,
  Lock
} from 'lucide-react';

const features = [
  {
    icon: Shield,
    title: 'OWASP Top 10 Detection',
    description: 'Comprehensive scanning for all OWASP Top 10 security vulnerabilities including injection attacks, broken authentication, and sensitive data exposure.',
    badge: 'Core Feature'
  },
  {
    icon: Zap,
    title: 'Lightning Fast Scans',
    description: 'Advanced pattern matching engine delivers complete security reports in seconds, not hours. Perfect for CI/CD integration.',
    badge: 'Performance'
  },
  {
    icon: Github,
    title: 'GitHub Integration',
    description: 'Seamless integration with your GitHub repositories. Automatic scanning on push, pull request analysis, and status checks.',
    badge: 'Integration'
  },
  {
    icon: FileText,
    title: 'Detailed Reports',
    description: 'Get comprehensive vulnerability reports with exact file locations, severity ratings, and step-by-step remediation guidance.',
    badge: 'Reporting'
  },
  {
    icon: AlertTriangle,
    title: 'Smart Prioritization',
    description: 'AI-powered risk assessment automatically prioritizes vulnerabilities by exploitability, impact, and your specific codebase context.',
    badge: 'AI-Powered'
  },
  {
    icon: CheckCircle,
    title: 'Compliance Ready',
    description: 'Built-in compliance checks for SOC 2, GDPR, HIPAA, and other security standards. Generate audit-ready documentation.',
    badge: 'Compliance'
  }
];

const stats = [
  { icon: Clock, value: '2.3s', label: 'Average Scan Time' },
  { icon: Shield, value: '99.2%', label: 'Detection Accuracy' },
  { icon: Users, value: '10k+', label: 'Repositories Scanned' },
  { icon: Lock, value: 'SOC 2', label: 'Security Certified' }
];

export function Features() {
  return (
    <section className="py-24 bg-muted/30">
      <div className="container max-w-7xl mx-auto px-6">
        <div className="text-center space-y-4 mb-16">
          <Badge variant="outline" className="w-fit mx-auto">
            <Shield className="h-3 w-3 mr-1" />
            Security Features
          </Badge>
          <h2 className="text-4xl font-bold">
            Enterprise-Grade Security Detection
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Our advanced security engine combines static analysis, dynamic testing, and AI-powered 
            risk assessment to protect your code from the most sophisticated threats.
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          {stats.map((stat, index) => (
            <Card key={index} className="text-center p-6">
              <CardContent className="space-y-3 p-0">
                <stat.icon className="h-8 w-8 text-primary mx-auto" />
                <div>
                  <div className="text-3xl font-bold">{stat.value}</div>
                  <div className="text-sm text-muted-foreground">{stat.label}</div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <Card key={index} className="relative hover-elevate">
              <CardHeader>
                <div className="flex items-center justify-between mb-4">
                  <feature.icon className="h-8 w-8 text-primary" />
                  <Badge variant="secondary" className="text-xs">
                    {feature.badge}
                  </Badge>
                </div>
                <CardTitle className="text-xl">{feature.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground leading-relaxed">
                  {feature.description}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Bottom CTA */}
        <div className="text-center pt-16">
          <Card className="max-w-2xl mx-auto p-8">
            <CardContent className="space-y-6 p-0">
              <div className="space-y-4">
                <h3 className="text-2xl font-bold">Ready to Secure Your Code?</h3>
                <p className="text-muted-foreground">
                  Join thousands of developers who trust ReVAMP to protect their applications. 
                  Start scanning your repositories in under 60 seconds.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}