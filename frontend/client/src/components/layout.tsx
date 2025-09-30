import { Outlet } from "react-router-dom";
import { AppSidebar } from "./app-sidebar";
import { SidebarProvider } from "./ui/sidebar";

export function Layout() {
  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full max-w-full overflow-hidden">
        <AppSidebar />
        <main className="flex-1 w-full max-w-full p-8 overflow-auto">
          <Outlet />
        </main>
      </div>
    </SidebarProvider>
  );
}