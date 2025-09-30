// src/lib/utils.ts
import clsx, { type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Compose class names (clsx) and merge Tailwind classes (tailwind-merge).
 * Usage: cn("p-2", isActive && "bg-blue-500", customClass)
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(...inputs));
}
