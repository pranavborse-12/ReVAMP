import { Header } from '../components/Header'; // or ./Header depending on folder structure
import { Hero } from '../components/Hero';
import { Features } from '../components/Features';
import NeuralDefense from "./NeuralDefense";
import { Solutions } from '../components/Solutions'; // <-- Check this import
import { Pricing } from '../components/Pricing';
import { DocumentationPreview } from '../components/DocumentationPreview'; // <-- Check this import
import { Footer } from '../components/Footer';

export function LandingPage() {
  return (
    <div className="min-h-screen bg-black text-zinc-100">
      <Header />
      <main>
        <Hero />
        <Features />
        <NeuralDefense />
        <Solutions /> {/* Must be here */}
        <Pricing />
        <DocumentationPreview /> {/* Must be here */}
      </main>
      <Footer />
    </div>
  );
}