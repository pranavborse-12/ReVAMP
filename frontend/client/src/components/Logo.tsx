// components/Logo.tsx
import React from 'react';

interface LogoProps {
  showText?: boolean; // Controls whether to show the "ReVAMP" text
  className?: string; // Allows you to add custom margins/padding from outside
}

const Logo: React.FC<LogoProps> = ({ showText = true, className = "" }) => {
  return (
    <div className={`flex items-center gap-3 min-w-0 cursor-pointer select-none ${className}`}>
      {/* ReVAMP SVG Logo */}
      <div className="w-8 h-8 shrink-0">
        <svg
          viewBox="0 0 100 100"
          className="w-full h-full fill-none"
        >
          {/* Hexagon */}
          <path
            d="M50 5 L90 25 L90 65 L50 95 L10 65 L10 25 Z"
            stroke="currentColor"
            strokeWidth={4}
            className="text-cyan-400"
          />

          {/* Inner structure */}
          <path
            d="
              M50 25 L50 45
              M30 35 L50 45 L70 35
              M50 45 L50 75
            "
            stroke="currentColor"
            strokeWidth={3}
            strokeLinecap="round"
            strokeLinejoin="round"
            className="text-white/80"
          />

          {/* Center node */}
          <circle
            cx={50}
            cy={50}
            r={8}
            stroke="currentColor"
            strokeWidth={2}
            className="text-violet-400"
          />
        </svg>
      </div>

      {/* Brand Text */}
      {showText && (
        <div className="flex flex-col min-w-0 overflow-hidden">
          <span className="text-sm font-bold tracking-wide text-white truncate">
            Re
            <span className="text-cyan-400">VAMP</span>
          </span>
          <span className="text-[10px] text-zinc-500 truncate">
            Security Platform
          </span>
        </div>
      )}
    </div>
  );
};

export default Logo;