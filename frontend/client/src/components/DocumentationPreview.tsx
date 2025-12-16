import { BookOpen, Terminal, Code2, Globe } from "lucide-react";
import { Button } from "./ui/button"; // Ensure you have your button component

export function DocumentationPreview() {
  return (
    <section id="docs" className="py-24 bg-black border-t border-zinc-900">
      <div className="container max-w-7xl mx-auto px-6">
        <div className="flex justify-between items-end mb-12">
          <div>
            <h2 className="text-3xl font-bold text-white mb-4">Documentation</h2>
            <p className="text-zinc-400">Everything you need to integrate security.</p>
          </div>
          <Button variant="outline">View Docs</Button>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          <div className="p-6 rounded-2xl bg-zinc-900/50 border border-zinc-800">
            <Terminal className="h-8 w-8 text-blue-500 mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">CLI Tool</h3>
            <p className="text-zinc-400 text-sm">npm install -g @revamp/cli</p>
          </div>
          <div className="p-6 rounded-2xl bg-zinc-900/50 border border-zinc-800">
            <Code2 className="h-8 w-8 text-purple-500 mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">API API</h3>
            <p className="text-zinc-400 text-sm">REST & GraphQL endpoints.</p>
          </div>
          <div className="p-6 rounded-2xl bg-zinc-900/50 border border-zinc-800">
            <Globe className="h-8 w-8 text-emerald-500 mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">Integrations</h3>
            <p className="text-zinc-400 text-sm">GitHub, GitLab, & Bitbucket.</p>
          </div>
        </div>
      </div>
    </section>
  );
}