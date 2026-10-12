// Minimal stand-in. The original src/lib was never committed (an old `lib/` ignore rule hid it);
// the front-end owner can replace this file with their original at any time.

/** Static HTML returned by src/server.ts and src/start.ts when server rendering fails. */
export function renderErrorPage(): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Saga Security | Something went wrong</title>
    <style>
      body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #14172a; color: #e9ebf5; font-family: "IBM Plex Sans", system-ui, sans-serif; }
      main { max-width: 28rem; padding: 2rem; text-align: center; }
      h1 { font-size: 1.25rem; font-weight: 600; margin: 0 0 0.5rem; }
      p { font-size: 0.875rem; color: #a9afc7; margin: 0 0 1.5rem; }
      a { color: #8fd0ff; }
    </style>
  </head>
  <body>
    <main>
      <h1>This page didn't load</h1>
      <p>Something went wrong on our end. You can try refreshing or head back home.</p>
      <a href="/">Go home</a>
    </main>
  </body>
</html>`;
}
