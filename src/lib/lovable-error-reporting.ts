// Minimal stand-in. The original src/lib was never committed (an old `lib/` ignore rule hid it);
// the front-end owner can replace this file with their original at any time.

export type LovableErrorMeta = { boundary: string } & Record<string, unknown>;

/** Called from the root error boundary. The original forwards to Lovable's preview; this one logs. */
export function reportLovableError(error: unknown, meta: LovableErrorMeta): void {
  console.error("[lovable-error]", meta.boundary, error);
}
