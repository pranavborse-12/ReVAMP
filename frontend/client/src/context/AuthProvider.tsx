// src/context/AuthProvider.tsx
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
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

  const getAccessToken = () => localStorage.getItem("access_token");

  const loadUser = useCallback(async (accessToken: string | null) => {
    if (!accessToken) {
      setUser(null);
      return;
    }
    try {
      const resp = await fetch(`${AUTH_CONFIG.API_URL}/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!resp.ok) {
        throw new Error("Failed to fetch user");
      }
      const data = await resp.json();
      setUser(data);
      localStorage.setItem("auth_user", JSON.stringify(data));
    } catch (err) {
      console.warn("AuthProvider: loadUser failed", err);
      setUser(null);
      localStorage.removeItem("auth_user");
    }
  }, []);

  // Attempt to refresh access token using refresh token
  const performRefresh = useCallback(async (): Promise<boolean> => {
    const refreshToken = localStorage.getItem("refresh_token");
    if (!refreshToken) return false;
    try {
      const data = await AuthService.refreshAccessToken(refreshToken);
      if (data && data.access_token) {
        localStorage.setItem("access_token", data.access_token);
        if (data.refresh_token) {
          localStorage.setItem("refresh_token", data.refresh_token);
        }
        await loadUser(data.access_token);
        return true;
      }
      return false;
    } catch (err) {
      console.warn("AuthProvider: token refresh failed", err);
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

  // On mount: restore tokens and load user
  useEffect(() => {
    (async () => {
      try {
        // First try: session endpoint (works when backend sets HttpOnly cookie)
        try {
          const resp = await fetch(`${AUTH_CONFIG.API_URL}/auth/session`, {
            credentials: "include",
          });
          if (resp.ok) {
            const data = await resp.json();
            setUser(data);
            localStorage.setItem("auth_user", JSON.stringify(data));
            // No local tokens needed when using cookies; start refresh loop only if refresh token exists locally
            if (localStorage.getItem("refresh_token")) startRefreshLoop();
            return;
          }
        } catch (err) {
          // session endpoint may fail if no cookie/token present; fall back to local storage flow
        }

        const access = localStorage.getItem("access_token");
        const refresh = localStorage.getItem("refresh_token");

        if (access) {
          await loadUser(access);
        } else if (refresh) {
          // try to refresh if only refresh token present
          await performRefresh();
        }
        // start background refresh if refresh token exists
        if (localStorage.getItem("refresh_token")) startRefreshLoop();
      } finally {
        setLoading(false);
      }
    })();

    return () => {
      stopRefreshLoop();
    };
  }, [loadUser, performRefresh, startRefreshLoop, stopRefreshLoop]);

  // Login: save tokens and fetch user
  const login = async (accessToken: string, refreshToken: string) => {
    try {
      localStorage.setItem("access_token", accessToken);
      localStorage.setItem("refresh_token", refreshToken);
      await loadUser(accessToken);
      startRefreshLoop();
    } catch (err) {
      console.error("AuthProvider: login failed", err);
      throw err;
    }
  };

  // Logout: use AuthService to call backend then clear
  const logout = async () => {
    try {
      await AuthService.logout(); // this clears storage + redirects
    } catch (err) {
      console.warn("AuthProvider: logout failed", err);
      // ensure clear
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      localStorage.removeItem("auth_user");
      setUser(null);
    } finally {
      stopRefreshLoop();
    }
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
