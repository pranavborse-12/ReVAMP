import {
    AlertTriangle,
    BarChart3,
    BookOpen,
    CheckCircle,
    Clock,
    FileText,
    GitBranch,
    Search,
    Settings,
    Shield,
    XCircle,
    PanelLeft
} from "lucide-react"
import { NavLink } from "react-router-dom"
import { cn } from "../lib/utils"
import { Badge } from "./ui/badge"
import { Button } from "./ui/button"
import { Separator } from "./ui/separator"
import {
    Sidebar,
    SidebarContent,
    SidebarGroup,
    SidebarGroupContent,
    SidebarGroupLabel,
    SidebarHeader,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    useSidebar,
} from "./ui/sidebar"

const dashboardItems = [
  { title: "Overview", url: "/dashboard", icon: BarChart3, badge: null },
  { title: "Repositories", url: "/repositories", icon: GitBranch, badge: "12" },
  { title: "Vulnerabilities", url: "/vulnerabilities", icon: AlertTriangle, badge: "24" },
  { title: "Security Reports", url: "/reports", icon: FileText, badge: null },
]

const toolsItems = [
  { title: "Code Scanner", url: "/scanner", icon: Search, badge: null },
  { title: "Scan History", url: "/history", icon: Clock, badge: null },
  { title: "Documentation", url: "/docs", icon: BookOpen, badge: null },
  { title: "Settings", url: "/settings", icon: Settings, badge: null },
]

const recentVulnerabilities = [
  { id: "vuln-001", title: "SQL Injection Vulnerability", severity: "critical", file: "auth/login.js", discoveredAt: "2 hours ago" },
  { id: "vuln-002", title: "Cross-Site Scripting (XSS)", severity: "high", file: "utils/sanitize.js", discoveredAt: "5 hours ago" },
  { id: "vuln-003", title: "Insecure Direct Object Reference", severity: "medium", file: "api/users.js", discoveredAt: "1 day ago" },
]

const recentScanHistory = [
  { id: "event-001", repository: "secure-app-frontend", status: "success", timestamp: "2 hours ago", vulnerabilities: 24 },
  { id: "event-002", repository: "api-gateway", status: "success", timestamp: "4 hours ago", vulnerabilities: 0 },
  { id: "event-003", repository: "user-service", status: "error", timestamp: "6 hours ago", vulnerabilities: null },
]

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case "critical": return "text-red-500"
    case "high": return "text-orange-500"
    case "medium": return "text-yellow-500"
    case "low": return "text-green-500"
    default: return "text-gray-500"
  }
}

const getStatusIcon = (status: string) => {
  switch (status) {
    case "success": return CheckCircle
    case "error": return XCircle
    default: return Clock
  }
}

const getStatusColor = (status: string) => {
  switch (status) {
    case "success": return "text-green-500"
    case "error": return "text-red-500"
    default: return "text-gray-500"
  }
}

export function AppSidebar() {
  const { open, setOpen } = useSidebar()

  return (
    <>
      {/* Toggle button that appears when sidebar is closed - ChatGPT/Claude style */}
      {!open && (
        <Button
          variant="ghost"
          size="icon"
          className="fixed left-2 top-4 z-50 h-8 w-8 rounded-md border bg-background shadow-md hover:bg-accent"
          onClick={() => setOpen(true)}
        >
          <PanelLeft className="h-4 w-4" />
        </Button>
      )}

      <Sidebar>
        <SidebarHeader className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-6 w-6 text-primary" />
              <span className="font-semibold text-lg">ReVAMP</span>
            </div>
            {/* Toggle button inside sidebar to close it */}
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => setOpen(false)}
            >
              <PanelLeft className="h-4 w-4" />
            </Button>
          </div>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Dashboard</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {dashboardItems.map((item) => (
                  <SidebarMenuItem key={item.title}>
                    <SidebarMenuButton asChild>
                      <NavLink 
                        to={item.url} 
                        className={({ isActive }) => cn(
                          "flex items-center justify-between w-full p-2 rounded-md transition-colors",
                          isActive ? "bg-accent text-accent-foreground" : "hover:bg-accent/50"
                        )}
                      >
                        <div className="flex items-center gap-2">
                          <item.icon className="h-4 w-4" />
                          <span>{item.title}</span>
                        </div>
                        {item.badge && (<Badge variant="secondary" className="text-xs">{item.badge}</Badge>)}
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>

          <SidebarGroup>
            <SidebarGroupLabel>Tools & Reports</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {toolsItems.map((item) => (
                  <SidebarMenuItem key={item.title}>
                    <SidebarMenuButton asChild>
                      <NavLink 
                        to={item.url} 
                        className={({ isActive }) => cn(
                          "flex items-center justify-between w-full p-2 rounded-md transition-colors",
                          isActive ? "bg-accent text-accent-foreground" : "hover:bg-accent/50"
                        )}
                      >
                        <div className="flex items-center gap-2">
                          <item.icon className="h-4 w-4" />
                          <span>{item.title}</span>
                        </div>
                        {item.badge && (<Badge variant="secondary" className="text-xs">{item.badge}</Badge>)}
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>

          {/* Commented out sections - uncomment if needed */}
          {/* <SidebarGroup>
            <SidebarGroupLabel className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-500" />
              Recent Vulnerabilities
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <div className="space-y-2 px-2">
                {recentVulnerabilities.map((vuln, index) => (
                  <div key={vuln.id} className="space-y-1">
                    <div className="flex items-start gap-2 p-2 rounded-md hover-elevate">
                      <Shield className={`h-3 w-3 mt-0.5 ${getSeverityColor(vuln.severity)}`} />
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-medium truncate">{vuln.title}</div>
                        <div className="text-xs text-muted-foreground truncate font-mono">{vuln.file}</div>
                        <div className="text-xs text-muted-foreground">{vuln.discoveredAt}</div>
                      </div>
                      <Badge variant={vuln.severity === "critical" ? "destructive" : "secondary"} className="text-xs h-4">{vuln.severity.charAt(0).toUpperCase()}</Badge>
                    </div>
                    {index < recentVulnerabilities.length - 1 && (<Separator className="my-2" />)}
                  </div>
                ))}
                <Button variant="ghost" size="sm" className="w-full mt-2 text-xs">View All</Button>
              </div>
            </SidebarGroupContent>
          </SidebarGroup> */}

          {/* <SidebarGroup>
            <SidebarGroupLabel className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-primary" />
              Recent Scan Activity
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <div className="space-y-2 px-2">
                {recentScanHistory.map((scan, index) => {
                  const StatusIcon = getStatusIcon(scan.status)
                  return (
                    <div key={scan.id} className="space-y-1">
                      <div className="flex items-start gap-2 p-2 rounded-md hover-elevate">
                        <StatusIcon className={`h-3 w-3 mt-0.5 ${getStatusColor(scan.status)}`} />
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-medium truncate">{scan.repository}</div>
                          <div className="text-xs text-muted-foreground">{scan.timestamp}</div>
                          {scan.vulnerabilities !== null && (<div className="text-xs text-muted-foreground">{scan.vulnerabilities > 0 ? `${scan.vulnerabilities} vulnerabilities` : 'No issues'}</div>)}
                        </div>
                        <Badge variant={scan.status === "error" ? "destructive" : "secondary"} className="text-xs h-4">{scan.status === "success" ? "\u2713" : scan.status === "error" ? "\u2717" : "\u25cb"}</Badge>
                      </div>
                      {index < recentScanHistory.length - 1 && (<Separator className="my-2" />)}
                    </div>
                  )
                })}
                <Button variant="ghost" size="sm" className="w-full mt-2 text-xs">View All</Button>
              </div>
            </SidebarGroupContent>
          </SidebarGroup> */}
        </SidebarContent>
      </Sidebar>
    </>
  )
}