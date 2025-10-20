// src/context/AuthProvider.tsx
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { AUTH_CONFIG, AuthService } from "../lib/auth";

export interface AuthUser {
  email?: string;
  email_verified?: boolean;
  created_at?: string;
  last_login?: string;
  // add other fields your app needs
}

interface AuthContextType {
  user: AuthUser | null;
  loading: boolean;
  login: (accessToken: string, refreshToken: string) => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => string | null;
}

export const AuthContext = createContext<AuthContextType | undefined>(
  undefined
);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const refreshIntervalRef = useRef<number | null>(null);
  const isLoggingOut = useRef<boolean>(false);
  const hasRedirected = useRef<boolean>(false);

  const getAccessToken = () => {
    // Try to get from localStorage first
    const localToken = localStorage.getItem("access_token");
    if (localToken) return localToken;
    
    // Try to get from cookies
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'access_token') {
        // Store in localStorage for future use
        localStorage.setItem("access_token", value);
        return value;
      }
    }
    return null;
  };

  const getRefreshToken = () => {
    // Try to get from localStorage first
    const localToken = localStorage.getItem("refresh_token");
    if (localToken) return localToken;
    
    // Try to get from cookies
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'refresh_token') {
        // Store in localStorage for future use
        localStorage.setItem("refresh_token", value);
        return value;
      }
    }
    return null;
  };

  const loadUser = useCallback(async (accessToken: string | null) => {
    if (!accessToken) {
      setUser(null);
      return false;
    }
    try {
      const resp = await fetch(`${AUTH_CONFIG.API_URL}/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
        credentials: "include",
      });
      if (!resp.ok) {
        throw new Error("Failed to fetch user");
      }
      const data = await resp.json();
      setUser(data);
      localStorage.setItem("auth_user", JSON.stringify(data));
      console.log("✅ User loaded successfully:", data.email);
      return true;
    } catch (err) {
      console.warn("⚠️ AuthProvider: loadUser failed", err);
      setUser(null);
      localStorage.removeItem("auth_user");
      return false;
    }
  }, []);

  // Attempt to refresh access token using refresh token
  const performRefresh = useCallback(async (): Promise<boolean> => {
    const refreshToken = getRefreshToken();
    if (!refreshToken) return false;
    try {
      console.log("🔄 Attempting to refresh token...");
      const data = await AuthService.refreshAccessToken(refreshToken);
      if (data && data.access_token) {
        localStorage.setItem("access_token", data.access_token);
        if (data.refresh_token) {
          localStorage.setItem("refresh_token", data.refresh_token);
        }
        await loadUser(data.access_token);
        console.log("✅ Token refreshed successfully");
        return true;
      }
      return false;
    } catch (err) {
      console.warn("⚠️ AuthProvider: token refresh failed", err);
      // If refresh fails, clear tokens
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      setUser(null);
      return false;
    }
  }, [loadUser]);

  // Setup refresh loop (every 10 minutes)
  const startRefreshLoop = useCallback(() => {
    // clear old
    if (refreshIntervalRef.current) {
      window.clearInterval(refreshIntervalRef.current);
      refreshIntervalRef.current = null;
    }
    // run every 10 minutes (600000 ms). You can adjust this if desired.
    const id = window.setInterval(() => {
      performRefresh().catch(() => {});
    }, 10 * 60 * 1000);
    refreshIntervalRef.current = id;
  }, [performRefresh]);

  const stopRefreshLoop = useCallback(() => {
    if (refreshIntervalRef.current) {
      window.clearInterval(refreshIntervalRef.current);
      refreshIntervalRef.current = null;
    }
  }, []);

  // Check for OAuth tokens in URL (from GitHub callback)
  const checkUrlForTokens = useCallback(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const accessToken = urlParams.get('access_token');
    const refreshToken = urlParams.get('refresh_token');
    
    if (accessToken && refreshToken) {
      console.log("🔐 Found OAuth tokens in URL");
      // Store tokens
      localStorage.setItem('access_token', accessToken);
      localStorage.setItem('refresh_token', refreshToken);
      
      // Clean URL
      const cleanUrl = window.location.pathname;
      window.history.replaceState({}, document.title, cleanUrl);
      
      return { accessToken, refreshToken };
    }
    
    return null;
  }, []);

  // On mount: restore tokens and load user
  useEffect(() => {
    (async () => {
      // CRITICAL: Check if we just logged out
      const justLoggedOut = sessionStorage.getItem('just_logged_out');
      if (justLoggedOut === 'true') {
        console.log("🚫 Just logged out - skipping all auth checks");
        sessionStorage.removeItem('just_logged_out');
        setLoading(false);
        return;
      }

      // CRITICAL: Skip everything if we're logging out
      if (isLoggingOut.current) {
        console.log("⏸️ Skipping auth check - logout in progress");
        setLoading(false);
        return;
      }

      try {
        console.log("🚀 AuthProvider initializing...");
        const currentPath = window.location.pathname;
        console.log("📍 Current path:", currentPath);
        
        // Check for OAuth callback tokens in URL first
        const urlTokens = checkUrlForTokens();
        if (urlTokens) {
          console.log("📝 Processing OAuth tokens from URL");
          const success = await loadUser(urlTokens.accessToken);
          if (success) {
            startRefreshLoop();
            // Redirect to dashboard after successful OAuth
            if (!hasRedirected.current) {
              hasRedirected.current = true;
              console.log("↪️ Redirecting to dashboard after OAuth");
              window.location.href = '/dashboard';
            }
            return;
          }
        }

        // Try to get tokens from cookies or localStorage
        const accessToken = getAccessToken();
        const refreshToken = getRefreshToken();

        console.log("🔍 Token check - Access:", !!accessToken, "Refresh:", !!refreshToken);
        console.log("🍪 Cookies:", document.cookie);
        console.log("💾 LocalStorage:", localStorage.getItem('access_token') ? 'has token' : 'no token');

        // First try: session endpoint (works when backend sets HttpOnly cookie)
        try {
          console.log("🔍 Checking session endpoint...");
          const resp = await fetch(`${AUTH_CONFIG.API_URL}/auth/session`, {
            credentials: "include",
          });
          console.log("📡 Session response status:", resp.status);
          
          if (resp.ok) {
            const data = await resp.json();
            console.log("✅ Session data:", JSON.stringify(data, null, 2));
            
            // CRITICAL: Check if authenticated is explicitly true
            if (data.authenticated === true && data.user && data.user.email) {
              setUser(data.user);
              localStorage.setItem("auth_user", JSON.stringify(data.user));
              
              // Store tokens in localStorage if we got them from session
              if (data.tokens) {
                if (data.tokens.access_token) {
                  localStorage.setItem("access_token", data.tokens.access_token);
                }
                if (data.tokens.refresh_token) {
                  localStorage.setItem("refresh_token", data.tokens.refresh_token);
                }
              }
              
              // Only redirect to dashboard if on home page (after GitHub OAuth redirect)
              if (currentPath === '/' && !hasRedirected.current) {
                hasRedirected.current = true;
                console.log("↪️ Redirecting to dashboard from home after authentication");
                setTimeout(() => {
                  window.location.href = '/dashboard';
                }, 100);
                return;
              }
              
              // Redirect from verify page
              if (currentPath === '/verify' && !hasRedirected.current) {
                hasRedirected.current = true;
                console.log("↪️ Redirecting to dashboard from verify page");
                setTimeout(() => {
                  window.location.href = '/dashboard';
                }, 100);
                return;
              }
              
              if (refreshToken) startRefreshLoop();
              return;
            } else {
              console.log("⚠️ Session endpoint returned but not authenticated or missing user data");
            }
          } else {
            console.log("⚠️ Session endpoint returned status:", resp.status);
          }
        } catch (err) {
          console.log("ℹ️ Session check failed:", err);
        }

        // If we have access token, try to load user
        if (accessToken) {
          console.log("🔑 Found access token, loading user");
          const success = await loadUser(accessToken);
          
          if (success) {
            // Only redirect to dashboard if on home page (after GitHub OAuth) or verify page
            if (currentPath === '/' && !hasRedirected.current) {
              hasRedirected.current = true;
              console.log("↪️ Redirecting to dashboard from home");
              window.location.href = '/dashboard';
              return;
            }
            
            if (currentPath === '/verify' && !hasRedirected.current) {
              hasRedirected.current = true;
              console.log("↪️ Redirecting to dashboard from verify page");
              window.location.href = '/dashboard';
              return;
            }
          }
        } else if (refreshToken) {
          console.log("🔄 Found refresh token, attempting refresh");
          const refreshed = await performRefresh();
          if (refreshed && currentPath === '/' && !hasRedirected.current) {
            hasRedirected.current = true;
            console.log("↪️ Redirecting to dashboard after token refresh");
            window.location.href = '/dashboard';
            return;
          }
        }
        
        // start background refresh if refresh token exists
        if (getRefreshToken()) startRefreshLoop();
      } finally {
        setLoading(false);
        console.log("✅ AuthProvider initialization complete");
      }
    })();

    return () => {
      stopRefreshLoop();
    };
  }, [loadUser, performRefresh, startRefreshLoop, stopRefreshLoop, checkUrlForTokens]);

  // Login: save tokens and fetch user
  const login = async (accessToken: string, refreshToken: string) => {
    try {
      console.log("🔐 Login initiated");
      isLoggingOut.current = false;
      hasRedirected.current = false;
      localStorage.setItem("access_token", accessToken);
      localStorage.setItem("refresh_token", refreshToken);
      await loadUser(accessToken);
      startRefreshLoop();
      console.log("✅ Login successful");
    } catch (err) {
      console.error("❌ AuthProvider: login failed", err);
      throw err;
    }
  };

  // Logout: use AuthService to call backend then clear
  const logout = async () => {
    console.log("🚪 Logout initiated");
    
    // Set flag immediately to prevent any auto-redirects during logout
    isLoggingOut.current = true;
    
    // Stop refresh loop immediately
    stopRefreshLoop();
    
    // Clear user state immediately
    setUser(null);
    
    // Call backend logout FIRST (to clear server-side cookies)
    try {
      const accessToken = localStorage.getItem('access_token') || getAccessToken();
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
      }
      
      await fetch(`${AUTH_CONFIG.API_URL}/auth/logout`, {
        method: 'POST',
        headers,
        credentials: 'include',
      });
      
      console.log("✅ Backend logout successful");
    } catch (err) {
      console.warn("⚠️ Backend logout failed:", err);
    }
    
    // Clear all storage after backend call
    localStorage.clear();
    sessionStorage.clear();
    
    // Clear all cookies aggressively
    const cookies = document.cookie.split(';');
    const domains = [
      '',
      window.location.hostname,
      `.${window.location.hostname}`,
      'localhost',
      '.localhost'
    ];
    
    for (const cookie of cookies) {
      const [name] = cookie.trim().split('=');
      // Try clearing with different domain combinations
      for (const domain of domains) {
        if (domain) {
          document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=${domain}`;
        }
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
      }
    }
    
    // Mark that we just logged out - store in sessionStorage so it persists during page reload
    sessionStorage.setItem('just_logged_out', 'true');
    
    // Wait for backend and cleanup to complete
    await new Promise(resolve => setTimeout(resolve, 300));
    
    // Reset the flag BEFORE redirect
    isLoggingOut.current = false;
    hasRedirected.current = false;
    
    console.log("🔄 Redirecting to home page");
    // Use replace instead of href to prevent back button issues
    window.location.replace('/');
  };

  return (
    <AuthContext.Provider
      value={{ user, loading, login, logout, getAccessToken }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}

export default AuthProvider;