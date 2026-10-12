// Minimal stand-in. The original src/lib was never committed (an old `lib/` ignore rule hid it);
// the front-end owner can replace this file with their original at any time.
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merge class names, letting later Tailwind utilities override earlier ones. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
