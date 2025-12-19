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
  User,
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { useAuth } from "../context/AuthProvider";
import { cn } from "../lib/utils";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { useSidebar } from "./ui/sidebar";

const dashboardItems = [
  { title: "Overview", url: "/dashboard", icon: BarChart3, badge: null },
  { title: "Repositories", url: "/repositories", icon: GitBranch },
  { title: "Vulnerabilities", url: "/vulnerabilities", icon: Shield},
  { title: "Security Reports", url: "/reports", icon: FileText, badge: null },
];

const toolsItems = [
  { title: "Code Scanner", url: "/scanner", icon: Search },
  { title: "Scan History", url: "/history", icon: Clock },
  { title: "Documentation", url: "/docs", icon: BookOpen },
  { title: "Settings", url: "/settings", icon: Settings },
];

export function AppSidebar() {
  const { open, setOpen } = useSidebar();
  const { logout, user } = useAuth();

  return (
    <aside
      className={cn(
        "fixed left-0 top-0 h-screen flex flex-col z-50",
        "border-r border-zinc-800 bg-zinc-950 text-zinc-300",
        "transition-all duration-300 ease-in-out",
        open ? "w-64" : "w-16"
      )}
    >
      <div className="group relative h-16 flex items-center justify-between px-4 border-b border-zinc-800/50 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white shrink-0">
            <Shield className="h-5 w-5" />
          </div>

          {open && (
            <div className="flex flex-col min-w-0 overflow-hidden">
              <span className="font-bold text-sm text-zinc-100 truncate">ReVAMP</span>
              <span className="text-[10px] text-zinc-500 truncate">
                Security Platform
              </span>
            </div>
          )}
        </div>

        <Button
          variant="ghost"
          size="icon"
          onClick={() => setOpen(!open)}
          className={cn(
            "h-7 w-7 shrink-0",
            "text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800",
            "transition-opacity duration-200",
            open ? "opacity-100" : "opacity-0 group-hover:opacity-100"
          )}
        >
          <PanelLeft className="h-4 w-4" />
        </Button>
      </div>

      <div className="flex-1 overflow-y-auto overflow-x-hidden px-2 py-4">
        <div className="mb-6">
          {open && (
            <div className="px-2 mb-2 text-[10px] uppercase text-zinc-500 font-semibold tracking-wider">
              Platform
            </div>
          )}
          <nav className="space-y-1">
            {dashboardItems.map((item) => (
              <NavLink
                key={item.title}
                to={item.url}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-all",
                    isActive
                      ? "bg-zinc-800 text-white"
                      : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200",
                    !open && "justify-center"
                  )
                }
              >
                <item.icon className="h-4 w-4 shrink-0" />
                {open && <span className="truncate">{item.title}</span>}
              </NavLink>
            ))}
          </nav>
        </div>

        <div>
          {open && (
            <div className="px-2 mb-2 text-[10px] uppercase text-zinc-500 font-semibold tracking-wider">
              Tools & Config
            </div>
          )}
          <nav className="space-y-1">
            {toolsItems.map((item) => (
              <NavLink
                key={item.title}
                to={item.url}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-all",
                    isActive
                      ? "bg-zinc-800 text-white"
                      : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200",
                    !open && "justify-center"
                  )
                }
              >
                <item.icon className="h-4 w-4 shrink-0" />
                {open && <span className="truncate">{item.title}</span>}
              </NavLink>
            ))}
          </nav>
        </div>
      </div>

      <div className="border-t border-zinc-800/50 p-4 shrink-0">
        {open && (
          <div className="mb-3 flex items-center gap-3">
            <div className="h-8 w-8 rounded-full bg-zinc-800 flex items-center justify-center shrink-0">
              <User className="h-4 w-4" />
            </div>
            <div className="text-sm truncate text-zinc-300 min-w-0">
              {user?.email || "Guest"}
            </div>
          </div>
        )}

        <Button
          variant="outline"
          className={cn(
            "w-full gap-2 text-zinc-400 hover:text-red-400 hover:border-red-900",
            !open && "justify-center px-0"
          )}
          onClick={logout}
        >
          <LogOut className="h-4 w-4" />
          {open && "Sign Out"}
        </Button>
      </div>
    </aside>
  );
}