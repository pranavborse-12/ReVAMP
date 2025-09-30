import { Button } from './ui/button';
import { Shield, Github } from 'lucide-react';
import { AuthService } from '../lib/auth';

export function Header() {
  const handleGitHubSignIn = () => {
    AuthService.startGitHubAuth(); // ✅ uses shared logic
  };

  return (
    <header className="w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container max-w-7xl mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Brand / Logo */}
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary glow-primary" aria-hidden="true" />
            <span className="text-2xl font-bold text-highlight-primary">SecureScan</span>
          </div>

          {/* GitHub Sign-in Button */}
          <div className="flex items-center gap-4">
            <Button
              onClick={handleGitHubSignIn}
              className="flex items-center gap-2 glow-primary"
              data-testid="button-github-signin"
            >
              <Github className="h-4 w-4" aria-hidden="true" />
              Sign in with GitHub
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
}
