import { AlertTriangle, CheckCircle, Clock, RefreshCw, Shield } from "lucide-react"
import { Badge } from "./ui/badge"
import { Button } from "./ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card"
import { Progress } from "./ui/progress"

const repositories = [
  {
    id: "repo-001",
    name: "secure-app-frontend",
    owner: "myorg",
    branch: "main",
    lastScan: "2 hours ago",
    status: "completed",
    vulnerabilities: { critical: 1, high: 3, medium: 8, low: 12 },
    linesOfCode: 45632,
    filesScanned: 234,
  },
  {
    id: "repo-002",
    name: "api-gateway",
    owner: "myorg",
    branch: "develop",
    lastScan: "5 minutes ago",
    status: "scanning",
    progress: 67,
    vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
    linesOfCode: 23451,
    filesScanned: 156,
  },
  {
    id: "repo-003",
    name: "user-service",
    owner: "myorg",
    branch: "main",
    lastScan: "1 day ago",
    status: "failed",
    vulnerabilities: { critical: 2, high: 5, medium: 7, low: 9 },
    linesOfCode: 12890,
    filesScanned: 89,
  },
]

const getStatusColor = (status: string) => {
  switch (status) {
    case "completed": return "text-green-500"
    case "scanning": return "text-blue-500"
    case "failed": return "text-red-500"
    case "pending": return "text-yellow-500"
    default: return "text-gray-500"
  }
}

const getStatusIcon = (status: string) => {
  switch (status) {
    case "completed": return CheckCircle
    case "scanning": return RefreshCw
    case "failed": return AlertTriangle
    case "pending": return Clock
    default: return Shield
  }
}

const getStatusVariant = (status: string) => {
  switch (status) {
    case "completed": return "secondary" as const
    case "scanning": return "default" as const
    case "failed": return "destructive" as const
    case "pending": return "outline" as const
    default: return "outline" as const
  }
}

export function RepositoryScanStatus() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">Repository Scan Status</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="h-[450px] flex flex-col">
          <div className="flex-1 overflow-y-auto space-y-2 p-4">
            {repositories.map((repo: any) => (
              <div key={repo.id} className="bg-gray-900/50 rounded-lg p-4 border border-gray-800 hover:border-gray-700 transition-colors">
                <div className="space-y-4">
                  <div className="flex items-start justify-between">
                    <div className="space-y-2">
                      <div className="flex items-center flex-wrap gap-2">
                        <h4 className="font-medium tracking-tight">{repo.owner}/{repo.name}</h4>
                        <Badge variant="outline" className="text-xs font-normal">{repo.branch}</Badge>
                        <Badge variant={getStatusVariant(repo.status)} className="font-normal">
                          <span className={`h-2 w-2 rounded-full mr-1.5 ${getStatusColor(repo.status)}`}></span>
                          {repo.status}
                        </Badge>
                      </div>
                      <div className="flex items-center flex-wrap gap-4 text-xs text-muted-foreground">
                        <span className="inline-flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          Last scan: {repo.lastScan}
                        </span>
                        <span>{repo.linesOfCode?.toLocaleString()} lines</span>
                        <span>{repo.filesScanned} files</span>
                      </div>
                    </div>
                    <div className="flex gap-2 shrink-0 ml-4">
                      {repo.status === "scanning" ? (
                        <Button variant="outline" size="sm" className="h-8">Pause</Button>
                      ) : (
                        <Button variant="outline" size="sm" className="h-8">Scan</Button>
                      )}
                      <Button variant="ghost" size="sm" className="h-8">View</Button>
                    </div>
                  </div>
                  {repo.status === "scanning" && repo.progress && (
                    <div className="space-y-1.5">
                      <div className="flex justify-between text-xs text-muted-foreground">
                        <span>Scanning progress</span>
                        <span>{repo.progress}%</span>
                      </div>
                      <Progress value={repo.progress} className="h-2" />
                    </div>
                  )}
                  {repo.status === "completed" && (
                    <div className="flex items-center gap-4 text-xs">
                      {/* vulnerability summary badges omitted */}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
          <div className="p-4 bg-gradient-to-b from-gray-900/50 to-gray-900 border-t border-gray-800">
            <Button variant="outline" className="w-full">Manage All Repositories</Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
