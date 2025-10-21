// src/lib/auth.ts
/// <reference types="vite/client" />

export const AUTH_CONFIG = {
  API_URL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
};

export class AuthService {
  // Refresh tokens
  static async refreshAccessToken(refreshToken: string) {
    const response = await fetch(`${AUTH_CONFIG.API_URL}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Failed to refresh token: ${err}`);
    }
    return await response.json(); // { access_token, refresh_token, expires_in }
  }

  // Start GitHub OAuth
  static startGitHubAuth(): void {
    const currentUrl = window.location.origin;
    const authUrl = `${AUTH_CONFIG.API_URL}/auth/github/login?redirect_to=${encodeURIComponent(currentUrl)}`;
    window.location.href = authUrl;
  }

  // Verify email code
  static async verifyCode(session: string, code: string) {
    const response = await fetch(`${AUTH_CONFIG.API_URL}/auth/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ session, code }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Verification failed' }));
      throw new Error(error.error || 'Verification failed');
    }

    return await response.json(); // expected { access_token, refresh_token, expires_in }
  }

  // Get auth status (email or session id)
  static async getAuthStatus(identifier: string) {
    const response = await fetch(`${AUTH_CONFIG.API_URL}/auth/status?identifier=${encodeURIComponent(identifier)}`);
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Failed to fetch auth status: ${err}`);
    }
    return await response.json();
  }

  // Secure logout: call backend to revoke tokens then clear local storage and redirect
  static async logout(): Promise<void> {
    const accessToken = localStorage.getItem('access_token');
    const refreshToken = localStorage.getItem('refresh_token');

    try {
      // Call backend to revoke tokens
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
      }

      await fetch(`${AUTH_CONFIG.API_URL}/auth/logout`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ refresh_token: refreshToken || null }),
        credentials: 'include', // Include cookies if using session-based auth
      }).catch((err) => {
        // Log error but continue with local cleanup
        console.warn('Logout API call failed:', err);
      });
    } finally {
      // Always clear local state regardless of API call success
      localStorage.clear(); // Clear all localStorage
      sessionStorage.clear(); // Clear sessionStorage too
      
      // Get all cookies and clear them
      const cookies = document.cookie.split(';');
      for (const cookie of cookies) {
        const [name] = cookie.trim().split('=');
        // Clear cookie for current path
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
        // Clear cookie for root domain
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=${window.location.hostname}`;
        // Clear cookie for parent domain
        const domain = window.location.hostname.split('.').slice(-2).join('.');
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=${domain}`;
      }
      
      // Small delay to ensure storage is cleared before redirect
      await new Promise(resolve => setTimeout(resolve, 200));
      
      // Force reload to clear any in-memory state
      window.location.replace('/');
    }
  }
}