// Minimal stand-in. The original src/lib was never committed (an old `lib/` ignore rule hid it);
// the front-end owner can replace this file with their original at any time.
//
// Imported for its side effect by src/server.ts: remembers the last error logged on the server so
// the SSR wrapper can report it when h3 swallows the throw into a generic 500 response.

let lastCaptured: unknown;

const originalError = console.error.bind(console);
console.error = (...args: unknown[]) => {
  lastCaptured = args.find((arg) => arg instanceof Error) ?? args[0];
  originalError(...args);
};

/** Return the most recent captured error once, then forget it. */
export function consumeLastCapturedError(): unknown {
  const error = lastCaptured;
  lastCaptured = undefined;
  return error;
}
