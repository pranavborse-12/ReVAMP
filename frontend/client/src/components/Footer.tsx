import { Shield, Github, Twitter, Linkedin, Heart } from 'lucide-react';
import { Button } from "./ui/button";

export function Footer() {
  return (
    <footer className="bg-black border-t border-zinc-800">
      <div className="container max-w-7xl mx-auto px-6 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-8 mb-12">
          <div className="col-span-2 lg:col-span-2">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="h-6 w-6 text-blue-500" />
              <span className="text-xl font-bold text-white">ReVAMP</span>
            </div>
            <p className="text-zinc-500 text-sm max-w-xs leading-relaxed">
              Securing the internet, one repository at a time. 
              Built for developers who care about code quality.
            </p>
          </div>
          
          <div>
            <h4 className="text-white font-semibold mb-4">Product</h4>
            <ul className="space-y-2 text-sm text-zinc-500">
              <li><a href="#" className="hover:text-blue-400 transition-colors">Features</a></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Security</a></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Enterprise</a></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Changelog</a></li>
            </ul>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-4">Company</h4>
            <ul className="space-y-2 text-sm text-zinc-500">
              <li><a href="#" className="hover:text-blue-400 transition-colors">About</a></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Blog</a></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Careers</a></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Contact</a></li>
            </ul>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-4">Legal</h4>
            <ul className="space-y-2 text-sm text-zinc-500">
              <li><a href="#" className="hover:text-blue-400 transition-colors">Privacy</a></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Terms</a></li>
            </ul>
          </div>
        </div>

        <div className="pt-8 border-t border-zinc-900 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="text-zinc-600 text-sm">
            © 2025 ReVAMP Inc. All rights reserved.
          </div>
          <div className="flex gap-4">
            <Button variant="ghost" size="icon" className="text-zinc-500 hover:text-white hover:bg-zinc-800">
              <Github className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="icon" className="text-zinc-500 hover:text-white hover:bg-zinc-800">
              <Twitter className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="icon" className="text-zinc-500 hover:text-white hover:bg-zinc-800">
              <Linkedin className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
    </footer>
  );
}