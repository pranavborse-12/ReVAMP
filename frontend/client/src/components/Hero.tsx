import { ArrowRight, Eye, Github, Shield, Zap } from "lucide-react";
import { SecurityLevelIndicator, SecurityLevelText } from "./SecurityLevel";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";

export function Hero() {
  const handleGetStarted = () => {
    window.location.href = `${import.meta.env.VITE_API_URL}/auth/github/login`;
  };

  const handleLearnMore = () => {
    console.log("Learn more triggered"); // todo: remove mock functionality
    // todo: implement scroll to features section
  };

  return (
    <section className="relative min-h-[90vh] flex items-center bg-gradient-to-br from-background via-background to-background/80">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent" />

      <div className="container max-w-7xl mx-auto px-6 py-24 relative z-10">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div className="space-y-8">
            <div className="space-y-4">
              <Badge variant="outline" className="w-fit">
                <Shield className="h-3 w-3 mr-1" />
                Enterprise Security
              </Badge>

              <h1 className="text-5xl lg:text-6xl font-bold leading-tight">
                Advanced Security
                <span className="text-highlight-primary block">
                  Vulnerability Detection
                </span>
              </h1>

              <p className="text-xl text-muted-foreground max-w-lg">
                Scan your GitHub repositories for OWASP Top 10 vulnerabilities
                and security issues with our advanced pattern matching engine.
                Get detailed reports and remediation guidance.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-4">
              <Button
                size="lg"
                onClick={handleGetStarted}
                className="flex items-center gap-2 glow-primary"
                data-testid="button-get-started"
              >
                <Github className="h-5 w-5" />
                Get Started with ReVAMP
                <ArrowRight className="h-4 w-4" />
              </Button>

              <Button
                size="lg"
                variant="outline"
                onClick={handleLearnMore}
                data-testid="button-learn-more"
              >
                Learn More
              </Button>
            </div>

            <div className="flex items-center gap-8 pt-4">
              <div className="flex items-center gap-2">
                <SecurityLevelIndicator
                  level="low"
                  showDot={true}
                  dotSize="md"
                  data-testid="status-low-risk"
                />
                <SecurityLevelText level="low" data-testid="text-low-risk" />
              </div>
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary glow-primary" />
                <span className="text-sm text-muted-foreground">
                  Enterprise Security
                </span>
              </div>
            </div>
          </div>

          <div className="relative">
            <Card className="p-6">
              <CardContent className="space-y-4 p-0">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-lg">
                    Security Scan Report
                  </h3>
                  <Badge variant="destructive">High Priority</Badge>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                    <SecurityLevelIndicator
                      level="critical"
                      showDot={true}
                      dotSize="sm"
                      data-testid="indicator-critical"
                    />
                    <div className="flex-1">
                      <p className="text-sm font-medium">
                        SQL Injection Vulnerability
                      </p>
                      <p className="text-xs text-muted-foreground">
                        auth/login.js:42
                      </p>
                    </div>
                    <SecurityLevelIndicator
                      level="critical"
                      showBadge={true}
                      showDot={false}
                      data-testid="badge-critical"
                    />
                  </div>

                  <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                    <SecurityLevelIndicator
                      level="medium"
                      showDot={true}
                      dotSize="sm"
                      data-testid="indicator-medium"
                    />
                    <div className="flex-1">
                      <p className="text-sm font-medium">
                        XSS Prevention Missing
                      </p>
                      <p className="text-xs text-muted-foreground">
                        utils/sanitize.js:15
                      </p>
                    </div>
                    <SecurityLevelIndicator
                      level="medium"
                      showBadge={true}
                      showDot={false}
                      data-testid="badge-medium"
                    />
                  </div>

                  <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                    <SecurityLevelIndicator
                      level="low"
                      showDot={true}
                      dotSize="sm"
                      data-testid="indicator-low"
                    />
                    <div className="flex-1">
                      <p className="text-sm font-medium">
                        Insecure Direct Object Reference
                      </p>
                      <p className="text-xs text-muted-foreground">
                        api/users.js:128
                      </p>
                    </div>
                    <SecurityLevelIndicator
                      level="low"
                      showBadge={true}
                      showDot={false}
                      data-testid="badge-low"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between pt-4 border-t">
                  <div className="flex items-center gap-2">
                    <Eye className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm text-muted-foreground">
                      12 files scanned
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Zap className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm text-muted-foreground">
                      2.3s scan time
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </section>
  );
}
