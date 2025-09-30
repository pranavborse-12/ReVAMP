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
    try {
      const accessToken = localStorage.getItem('access_token');
      const refreshToken = localStorage.getItem('refresh_token');

      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
      }

      await fetch(`${AUTH_CONFIG.API_URL}/auth/logout`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ refresh_token: refreshToken || null }),
      }).catch(() => {
        // ignore network errors, still clear local state
      });
    } finally {
      // clear local state
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('auth_user');
      localStorage.removeItem('auth_session');
      // redirect to root
      window.location.href = '/';
    }
  }
}
