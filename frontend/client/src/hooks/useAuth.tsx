// src/context/useAuth.tsx
import { useState, useEffect, createContext, useContext, ReactNode } from "react";
import { AuthService } from "../lib/auth";

interface AuthContextType {
  session: string | null;
  isAuthenticated: boolean;
  loading: boolean;
  emailHint: string;
  startGitHubAuth: () => void;
  verifyCode: (code: string) => Promise<any>;
  logout: () => Promise<void>;
  checkAuthStatus: (sessionToken: string) => Promise<void>;
  // optional helper to get access token for API calls
  getAccessToken?: () => string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

/** Simple client-side email masking */
function maskEmail(email: string | undefined | null) {
  if (!email) return "****@****";
  try {
    const [name, domain] = email.split("@");
    const shortName = name.length <= 1 ? "*" : name[0] + "*".repeat(Math.min(3, name.length - 1));
    const domainParts = domain.split(".");
    const tld = domainParts.pop();
    const domainHead = domainParts.join(".");
    const shortDomainHead =
      domainHead.length <= 1 ? "*" : domainHead[0] + "*".repeat(Math.min(3, domainHead.length - 1));
    return `${shortName}@${shortDomainHead}.${tld ?? "com"}`;
  } catch {
    return "****@****";
  }
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [session, setSession] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [emailHint, setEmailHint] = useState("");

  // helper to fetch /auth/me with access token
  const fetchMe = async (accessToken: string | null) => {
    if (!accessToken) return null;
    try {
      const resp = await fetch(`${(AuthService as any).AUTH_CONFIG?.API_URL ?? ""}/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!resp.ok) return null;
      const data = await resp.json();
      return data; // expected { email, email_verified, created_at, last_login }
    } catch (err) {
      console.warn("fetchMe failed", err);
      return null;
    }
  };

  // On mount: prefer access_token -> try refresh -> fallback to session token
  useEffect(() => {
    (async () => {
      try {
        const accessToken = localStorage.getItem("access_token");
        const refreshToken = localStorage.getItem("refresh_token");
        const savedSession = localStorage.getItem("auth_session");

        if (accessToken) {
          const me = await fetchMe(accessToken);
          if (me && me.email) {
            setIsAuthenticated(true);
            setSession(savedSession ?? null);
            setEmailHint(maskEmail(me.email));
            return;
          } else {
            // maybe access token expired, try refresh
            if (refreshToken) {
              try {
                const data = await AuthService.refreshAccessToken(refreshToken);
                if (data && data.access_token) {
                  localStorage.setItem("access_token", data.access_token);
                  if (data.refresh_token) localStorage.setItem("refresh_token", data.refresh_token);
                  const me2 = await fetchMe(data.access_token);
                  if (me2 && me2.email) {
                    setIsAuthenticated(true);
                    setSession(savedSession ?? null);
                    setEmailHint(maskEmail(me2.email));
                    return;
                  }
                }
              } catch (err) {
                // refresh failed -> fall through to session check
                console.warn("refresh failed:", err);
              }
            }
          }
        }

        // If we reach here, try session-based check (old flow)
        if (savedSession) {
          await checkAuthStatus(savedSession);
        }
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --------------------
  // Core Functions
  // --------------------
  const checkAuthStatus = async (sessionToken: string) => {
    try {
      // If we have an access_token, prefer that validation
      const accessToken = localStorage.getItem("access_token");
      if (accessToken) {
        const me = await fetchMe(accessToken);
        if (me && me.email) {
          setSession(sessionToken);
          setIsAuthenticated(true);
          setEmailHint(maskEmail(me.email));
          localStorage.setItem("auth_session", sessionToken);
          return;
        }
      }

      // Fallback to status endpoint (accepts session id or email as identifier)
      const status = await AuthService.getAuthStatus(sessionToken);

      if (status.exists && status.verified) {
        setSession(sessionToken);
        setIsAuthenticated(true);
        setEmailHint(status.email_hint || "");
        localStorage.setItem("auth_session", sessionToken);
      } else if (status.exists) {
        setSession(sessionToken);
        setEmailHint(status.email_hint || "");
        localStorage.setItem("auth_session", sessionToken);
      } else {
        clearAuth();
      }
    } catch (error) {
      console.error("Auth status check failed:", error);
      clearAuth();
    } finally {
      setLoading(false);
    }
  };

  const startGitHubAuth = () => {
    AuthService.startGitHubAuth();
  };

  const verifyCode = async (code: string) => {
    if (!session) throw new Error("No active session");

    // AuthService.verifyCode is expected to return tokens: { access_token, refresh_token, expires_in }
    const result = await AuthService.verifyCode(session, code);

    // If backend responds with tokens, store them for future requests
    if (result && result.access_token) {
      try {
        localStorage.setItem("access_token", result.access_token);
        if (result.refresh_token) localStorage.setItem("refresh_token", result.refresh_token);

        // populate emailHint using /auth/me
        const me = await fetchMe(result.access_token);
        if (me && me.email) setEmailHint(maskEmail(me.email));
      } catch (err) {
        console.warn("verifyCode: storing tokens failed", err);
      }
    }

    setIsAuthenticated(true);
    return result;
  };

  const logout = async () => {
    try {
      await AuthService.logout(); // clears tokens + redirects (per AuthService implementation)
    } catch (err) {
      console.warn("logout failed", err);
      // ensure client-side cleanup if AuthService failed
      clearAuth();
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
    }
  };

  const clearAuth = () => {
    setSession(null);
    setIsAuthenticated(false);
    setEmailHint("");
    localStorage.removeItem("auth_session");
    // do not force-remove tokens here — logout should be explicit; but remove for safety:
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("auth_user");
  };

  // --------------------
  // Context Value
  // --------------------
  const value: AuthContextType = {
    session,
    isAuthenticated,
    loading,
    emailHint,
    startGitHubAuth,
    verifyCode,
    logout,
    checkAuthStatus,
    getAccessToken: () => localStorage.getItem("access_token"),
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// --------------------
// useAuth Hook
// --------------------
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
