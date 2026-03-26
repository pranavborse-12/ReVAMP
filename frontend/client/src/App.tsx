// src/App.tsx
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/layout";
import { ThemeProvider } from "./components/ThemeProvider";
import { Toaster } from "./components/ui/toaster";
import { TooltipProvider } from "./components/ui/tooltip";
import VerifyPage from "./components/VerifyPage";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { AuthProvider } from "./context/AuthProvider";
import { queryClient } from "./lib/queryClient";
import Dashboard from "./pages/dashboard";
import Home from "./pages/Home";
import NotFound from "./pages/not-found";
import Vulnerabilities from "./pages/vulnerabilities";
import ScanHistory from "./pages/scan-history";
import Documentation from "./pages/documentation";
import SettingsPage from "./pages/settings";
import RepositoriesPage from "./app/repositories/page";

function Router() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<Home />} />
        <Route path="/verify" element={<VerifyPage />} />

        {/* Protected Routes - wrapped in Layout */}
        <Route
          element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }
        >
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/repositories" element={<RepositoriesPage />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/docs" element={<Documentation />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>

        {/* 404 Page */}
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