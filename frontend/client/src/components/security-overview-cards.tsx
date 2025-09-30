import { AlertTriangle, CheckCircle, GitBranch, TrendingDown, TrendingUp } from "lucide-react"
import { useEffect, useState } from "react"
import { Button } from "./ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card"
import { Progress } from "./ui/progress"

const securityMetrics = [
  {
    title: "Critical Vulnerabilities",
    value: 3,
    description: "Require immediate attention",
    icon: AlertTriangle,
    trend: "down",
    trendValue: "-2",
    severity: "critical",
  },
  {
    title: "Repositories Scanned",
    value: 24,
    description: "Out of 28 total repositories",
    icon: GitBranch,
    trend: "up",
    trendValue: "+4",
    severity: "info",
    progress: 86,
  },
  {
    title: "Fixed Issues",
    value: 156,
    description: "This month",
    icon: CheckCircle,
    trend: "up",
    trendValue: "+23",
    severity: "low",
  },
]

const getSeverityColor = (severity?: string) => {
  switch (severity) {
    case "critical": return "text-red-500"
    case "high": return "text-orange-500"
    case "medium": return "text-yellow-500"
    case "low": return "text-green-500"
    default: return "text-blue-500"
  }
}

const getSeverityBadgeVariant = (severity?: string) => {
  switch (severity) {
    case "critical": return "destructive" as const
    case "high": return "destructive" as const
    case "medium": return "default" as const
    case "low": return "secondary" as const
    default: return "secondary" as const
  }
}

export function SecurityOverviewCards() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [metrics, setMetrics] = useState(securityMetrics);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        setIsLoading(true);
        // Mock API call - replace with actual API endpoint
        await new Promise(resolve => setTimeout(resolve, 1000));
        setMetrics(securityMetrics);
        setError(null);
      } catch (err) {
        setError('Failed to load security metrics');
        console.error('Error fetching security metrics:', err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchMetrics();
  }, []);

  if (error) {
    return (
      <Card className="p-6">
        <div className="flex flex-col items-center justify-center text-center">
          <AlertTriangle className="h-8 w-8 text-destructive mb-2" />
          <h3 className="font-semibold text-lg">Error Loading Metrics</h3>
          <p className="text-muted-foreground mt-1">{error}</p>
          <Button
            variant="outline"
            className="mt-4"
            onClick={() => window.location.reload()}
          >
            Try Again
          </Button>
        </div>
      </Card>
    );
  }

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
      {metrics.map((metric, index) => {
        const Icon = metric.icon
        return (
          <Card key={index} className="hover-elevate">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{metric.title}</CardTitle>
              <Icon className={`h-4 w-4 ${getSeverityColor(metric.severity)}`} />
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="animate-pulse space-y-3">
                  <div className="h-7 w-16 bg-muted rounded" />
                  <div className="h-4 w-24 bg-muted rounded" />
                  {metric.progress !== undefined && (
                    <div className="mt-2">
                      <div className="h-1 w-full bg-muted rounded" />
                    </div>
                  )}
                </div>
              ) : (
                <>
                  <div className="flex items-center justify-between">
                    <div className="text-2xl font-bold">{metric.value}</div>
                    {metric.trend && (
                      <div className="flex items-center gap-1">
                        {metric.trend === "up" ? (
                          <TrendingUp className="h-3 w-3 text-green-500" />
                        ) : (
                          <TrendingDown className="h-3 w-3 text-red-500" />
                        )}
                        <span
                          className={`text-xs ${
                            metric.trend === "up" ? "text-green-500" : "text-red-500"
                          }`}
                        >
                          {metric.trendValue}
                        </span>
                      </div>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">{metric.description}</p>
                  {metric.progress !== undefined && (
                    <div className="mt-2">
                      <Progress value={metric.progress} className="h-1" />
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}
