import { AlertTriangle, Calendar, CheckCircle, Clock, GitBranch, MoreHorizontal, User, XCircle } from "lucide-react"
import { Badge } from "./ui/badge"
import { Button } from "./ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card"

const scanHistory = [
  {
    id: "event-001",
    type: "scan_completed",
    repository: "secure-app-frontend",
    branch: "main",
    timestamp: "2 hours ago",
    user: "john.doe",
    status: "success",
    description: "Automated security scan completed successfully",
    vulnerabilities: { found: 24, fixed: 0 },
    duration: "4m 32s",
  },
  {
    id: "event-002",
    type: "vulnerability_fixed",
    repository: "api-gateway",
    branch: "develop",
    timestamp: "4 hours ago",
    user: "jane.smith",
    status: "success",
    description: "Fixed SQL injection vulnerability in auth endpoint",
    vulnerabilities: { found: 0, fixed: 1 },
  },
  {
    id: "event-003",
    type: "scan_failed",
    repository: "user-service",
    branch: "main",
    timestamp: "6 hours ago",
    user: "system",
    status: "error",
    description: "Scan failed due to timeout - repository too large",
    duration: "10m 00s",
  },
]

const getEventIcon = (type: string, status: string) => {
  switch (type) {
    case "scan_completed": return status === "success" ? CheckCircle : AlertTriangle
    case "scan_failed": return XCircle
    case "scan_started": return Clock
    case "vulnerability_fixed": return CheckCircle
    case "repository_added": return GitBranch
    default: return Clock
  }
}

const getStatusColor = (status: string) => {
  switch (status) {
    case "success": return "text-green-500"
    case "error": return "text-red-500"
    case "warning": return "text-yellow-500"
    case "info": return "text-blue-500"
    default: return "text-gray-500"
  }
}

export function ScanHistoryTimeline() {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">Recent Scan Activity</CardTitle>
          <Button variant="outline" size="sm">View All History</Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="relative">
          <div className="absolute left-6 top-0 bottom-0 w-px bg-border"></div>
          <div className="space-y-6">
            {scanHistory.map((event: any) => {
              const Icon = getEventIcon(event.type, event.status)
              return (
                <div key={event.id} className="relative flex gap-4">
                  <div className={`relative z-10 flex h-12 w-12 items-center justify-center rounded-full border-2 bg-background ${getStatusColor(event.status).replace('text-', 'border-')}`}>
                    <Icon className={`h-5 w-5 ${getStatusColor(event.status)}`} />
                  </div>
                  <div className="flex-1 space-y-2 pb-6">
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium">{event.description}</h4>
                          <Badge variant="secondary">{event.status}</Badge>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <div className="flex items-center gap-1"><GitBranch className="h-3 w-3" /><span className="font-mono">{event.repository}/{event.branch}</span></div>
                          <div className="flex items-center gap-1"><Calendar className="h-3 w-3" /><span>{event.timestamp}</span></div>
                          {event.user && (<div className="flex items-center gap-1"><User className="h-3 w-3" /><span>{event.user}</span></div>)}
                        </div>
                      </div>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="sm">Details</Button>
                        {event.status === "error" && (<Button variant="outline" size="sm">Retry</Button>)}
                        <Button variant="ghost" size="sm"><MoreHorizontal className="h-3 w-3" /></Button>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
