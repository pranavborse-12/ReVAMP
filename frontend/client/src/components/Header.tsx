import { Button } from './ui/button';
import { Github } from 'lucide-react';
import { AuthService } from '../lib/auth';
import { useState, useEffect } from 'react';
import { cn } from '../lib/utils';
import  Logo  from './Logo';

export function Header() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleGitHubSignIn = () => {
    AuthService.startGitHubAuth();
  };

  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <header
      className={cn(
        'fixed top-0 w-full z-50 transition-all duration-300 border-b border-transparent',
        scrolled ? 'bg-black/80 backdrop-blur-xl border-zinc-800' : 'bg-transparent'
      )}
    >
      <div className="container max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">

        {/* LOGO */}
        <div
         onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
         className="group cursor-pointer"
        >
         <Logo />
        </div>

        {/* CENTER PILL NAV */}
        <nav className="hidden md:flex items-center">
          <div className="flex items-center gap-1 rounded-full bg-white/5 border border-white/10 px-1 py-1 backdrop-blur-sm">
            {[
              { label: 'Features', id: 'features' },
              { label: 'Intelligence', id: 'intelligence' },
              { label: 'Solutions', id: 'solutions' },
              { label: 'Pricing', id: 'pricing' },
              { label: 'Docs', id: 'docs' },
            ].map((item) => (
              <button
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                className="px-4 py-1.5 text-sm font-medium text-zinc-400
                           hover:text-white hover:bg-white/10
                           rounded-full transition-all"
              >
                {item.label}
              </button>
            ))}
          </div>
        </nav>

        {/* RIGHT CTA */}
        <Button
          onClick={handleGitHubSignIn}
          className="bg-white text-black hover:bg-zinc-200 font-semibold"
        >
          <Github className="h-4 w-4 mr-2" />
          Sign in
        </Button>

      </div>
    </header>
  );
}
