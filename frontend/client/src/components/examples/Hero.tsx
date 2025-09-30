import { Hero } from '../Hero';
import { ThemeProvider } from '../ThemeProvider';

export default function HeroExample() {
  return (
    <ThemeProvider>
      <Hero />
    </ThemeProvider>
  );
}