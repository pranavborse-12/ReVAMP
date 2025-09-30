// src/App.tsx
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/layout";
import { ThemeProvider } from "./components/ThemeProvider";
import { Toaster } from "./components/ui/toaster";
import { TooltipProvider } from "./components/ui/tooltip";
import VerifyPage from "./components/VerifyPage";
import { AuthProvider } from "./context/AuthProvider";
import { queryClient } from "./lib/queryClient";
import Dashboard from "./pages/dashboard";
import Home from "./pages/Home";
import NotFound from "./pages/not-found";

// Correct import path for RepositoriesPage
import RepositoriesPage from "./app/repositories/page";

function Router() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/verify" element={<VerifyPage />} />
        <Route element={<Layout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/repositories" element={<RepositoriesPage />} />
          <Route path="/vulnerabilities" element={<div>Vulnerabilities</div>} />
          <Route path="/reports" element={<div>Reports</div>} />
          <Route path="/scanner" element={<div>Scanner</div>} />
          <Route path="/history" element={<div>History</div>} />
          <Route path="/docs" element={<div>Documentation</div>} />
          <Route path="/settings" element={<div>Settings</div>} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <ThemeProvider>
          <AuthProvider>
            <Toaster />
            <Router />
          </AuthProvider>
        </ThemeProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}
