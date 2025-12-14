import {
    BarChart3,
    BookOpen,
    Clock,
    FileText,
    GitBranch,
    LogOut,
    PanelLeft,
    Search,
    Settings,
    Shield,
    User
} from "lucide-react"
import { NavLink } from "react-router-dom"
import { useAuth } from "../context/AuthProvider"
import { cn } from "../lib/utils"
import { Badge } from "./ui/badge"
import { Button } from "./ui/button"
import {
    Sidebar,
    SidebarContent,
    SidebarFooter,
    SidebarGroup,
    SidebarGroupContent,
    SidebarGroupLabel,
    SidebarHeader,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    useSidebar,
} from "./ui/sidebar"

// Navigation Configuration
const dashboardItems = [
  { title: "Overview", url: "/dashboard", icon: BarChart3, badge: null },
  { title: "Repositories", url: "/repositories", icon: GitBranch, badge: "12" },
  { title: "Vulnerabilities", url: "/vulnerabilities", icon: Shield, badge: "24" },
  { title: "Security Reports", url: "/reports", icon: FileText, badge: null },
]

const toolsItems = [
  { title: "Code Scanner", url: "/scanner", icon: Search, badge: null },
  { title: "Scan History", url: "/history", icon: Clock, badge: null },
  { title: "Documentation", url: "/docs", icon: BookOpen, badge: null },
  { title: "Settings", url: "/settings", icon: Settings, badge: null },
]

export function AppSidebar() {
  const { open, setOpen } = useSidebar()
  const { logout, user } = useAuth()

  const handleLogout = async () => {
    try {
      await logout()
    } catch (error) {
      console.error("Logout failed:", error)
    }
  }

  return (
    <>
      {/* Floating Toggle Button (Visible when closed) */}
      {!open && (
        <Button
          variant="ghost"
          size="icon"
          className="fixed left-3 top-3 z-50 h-9 w-9 rounded-lg border border-zinc-800 bg-zinc-950 text-zinc-400 shadow-xl hover:bg-zinc-800 hover:text-zinc-100 transition-all"
          onClick={() => setOpen(true)}
        >
          <PanelLeft className="h-4 w-4" />
        </Button>
      )}

      <Sidebar className="border-r border-zinc-800 bg-zinc-950 text-zinc-300">
        {/* Header / Brand */}
        <SidebarHeader className="h-16 flex items-center justify-between px-4 border-b border-zinc-800/50">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white shadow-lg shadow-blue-900/20">
              <Shield className="h-5 w-5" />
            </div>
            <div className="flex flex-col">
              <span className="font-bold text-sm tracking-tight text-zinc-100">ReVAMP</span>
              <span className="text-[10px] text-zinc-500 font-medium">Security Platform</span>
            </div>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800"
            onClick={() => setOpen(false)}
          >
            <PanelLeft className="h-4 w-4" />
          </Button>
        </SidebarHeader>

        <SidebarContent className="px-2 py-4">
          {/* Main Navigation */}
          <SidebarGroup>
            <SidebarGroupLabel className="px-2 text-[10px] font-bold uppercase tracking-wider text-zinc-500 mb-2">
              Platform
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {dashboardItems.map((item) => (
                  <SidebarMenuItem key={item.title} className="mb-1">
                    <SidebarMenuButton asChild>
                      <NavLink 
                        to={item.url} 
                        className={({ isActive }) => cn(
                          "group flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200",
                          isActive 
                            ? "bg-zinc-800 text-white shadow-sm" 
                            : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"
                        )}
                      >
                        {({ isActive }) => (
                          <>
                            <div className="flex items-center gap-3">
                              <item.icon className={cn("h-4 w-4 transition-colors", isActive ? "text-blue-500" : "text-zinc-500 group-hover:text-zinc-300")} />
                              <span>{item.title}</span>
                            </div>
                            {item.badge && (
                              <Badge 
                                className={cn(
                                  "h-5 px-1.5 text-[10px] border-none shadow-none",
                                  isActive ? "bg-blue-600 text-white" : "bg-zinc-800 text-zinc-400"
                                )}
                              >
                                {item.badge}
                              </Badge>
                            )}
                          </>
                        )}
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>

          {/* Tools Section */}
          <SidebarGroup className="mt-6">
            <SidebarGroupLabel className="px-2 text-[10px] font-bold uppercase tracking-wider text-zinc-500 mb-2">
              Tools & Config
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {toolsItems.map((item) => (
                  <SidebarMenuItem key={item.title} className="mb-1">
                    <SidebarMenuButton asChild>
                      <NavLink 
                        to={item.url} 
                        className={({ isActive }) => cn(
                          "group flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200",
                          isActive 
                            ? "bg-zinc-800 text-white shadow-sm" 
                            : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"
                        )}
                      >
                         {({ isActive }) => (
                          <div className="flex items-center gap-3">
                            <item.icon className={cn("h-4 w-4 transition-colors", isActive ? "text-blue-500" : "text-zinc-500 group-hover:text-zinc-300")} />
                            <span>{item.title}</span>
                          </div>
                        )}
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>

        {/* Footer / User Profile */}
        <SidebarFooter className="p-4 border-t border-zinc-800/50 bg-zinc-900/20">
          <div className="flex items-center gap-3 mb-4 px-1">
            <div className="h-8 w-8 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center text-zinc-400">
              <User className="h-4 w-4" />
            </div>
            <div className="flex flex-col min-w-0">
              <span className="text-sm font-medium text-zinc-200 truncate">
                {user?.email?.split('@')[0] || "Guest User"}
              </span>
              <span className="text-[10px] text-zinc-500 truncate">
                {user?.email || "Not connected"}
              </span>
            </div>
          </div>
          
          <Button
            variant="outline"
            className="w-full justify-start gap-2 border-zinc-800 bg-zinc-900/50 text-zinc-400 hover:bg-red-950/30 hover:text-red-400 hover:border-red-900/50 transition-all h-9 text-xs"
            onClick={handleLogout}
          >
            <LogOut className="h-3.5 w-3.5" />
            <span>Sign Out</span>
          </Button>
        </SidebarFooter>
      </Sidebar>
    </>
  )
}