import { Outlet } from "react-router-dom";
import { AppSidebar } from "./app-sidebar";
import { SidebarProvider, useSidebar } from "./ui/sidebar";
import { cn } from "../lib/utils";

function LayoutContent() {
  const { open } = useSidebar();

  return (
    <div className="min-h-screen bg-[#0d1117] flex">
      <AppSidebar />

      <main
        className={cn(
          "flex-1 min-h-screen transition-all duration-300 ease-in-out overflow-auto",
          open ? "ml-64" : "ml-16"
        )}
        style={{ width: open ? "calc(100vw - 256px)" : "calc(100vw - 64px)" }}
      >
        <Outlet />
      </main>
    </div>
  );
}

export function Layout() {
  return (
    <SidebarProvider>
      <LayoutContent />
    </SidebarProvider>
  );
}