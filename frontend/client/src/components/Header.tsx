import { Button } from './ui/button';
import { Shield, Github } from 'lucide-react';
import { AuthService } from '../lib/auth';
import { useState, useEffect } from 'react';
import { cn } from '../lib/utils';

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
    <header className={cn(
      "fixed top-0 w-full z-50 transition-all duration-300 border-b border-transparent",
      scrolled ? "bg-black/80 backdrop-blur-xl border-zinc-800" : "bg-transparent"
    )}>
      <div className="container max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        <div 
          onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
          className="flex items-center gap-2 font-bold text-xl text-white tracking-tight cursor-pointer"
        >
          <Shield className="h-6 w-6 text-blue-500 fill-blue-500/20" />
          ReVAMP
        </div>

        <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-zinc-400">
          <button onClick={() => scrollToSection('solutions')} className="hover:text-white transition-colors">Solutions</button>
          <button onClick={() => scrollToSection('pricing')} className="hover:text-white transition-colors">Pricing</button>
          <button onClick={() => scrollToSection('docs')} className="hover:text-white transition-colors">Docs</button>
        </nav>

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