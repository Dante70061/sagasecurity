// @lovable.dev/vite-tanstack-config already includes the following — do NOT add them manually
// or the app will break with duplicate plugins:
//   - TanStack devtools (dev-only, first), tanstackStart, viteReact, tailwindcss, tsConfigPaths,
//     nitro (build-only using cloudflare as a default target), VITE_* env injection, @ path alias,
//     React/TanStack dedupe, error logger plugins, and sandbox detection (port/host/strictPort).
// You can pass additional config via defineConfig({ vite: { ... }, etc... }) if needed.
import fs from "node:fs";
import path from "node:path";
import { defineConfig } from "@lovable.dev/vite-tanstack-config";
import type { Plugin } from "vite";

// Vite prebundles Streamdown's lazy highlighter under a hashed name. A later
// optimize pass deletes that file, and Safari reports the 404 as
// "Importing a module script failed", which takes down the page.
function streamdownHighlighterFallback(): Plugin {
  return {
    name: "streamdown-highlighter-fallback",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const pathname = (req.url ?? "").split("?")[0] ?? "";
        if (!pathname.includes("/.vite/deps/highlighted-body-KQOG7T2V-")) return next();
        const depsDir = path.resolve("node_modules/.vite/deps");
        const requested = path.join(depsDir, path.basename(pathname));
        if (fs.existsSync(requested)) return next();
        let current: string | undefined;
        try {
          current = fs.readdirSync(depsDir).find((name) => name.startsWith("highlighted-body-KQOG7T2V-") && name.endsWith(".js"));
        } catch {
          return next();
        }
        if (!current) return next();
        res.statusCode = 200;
        res.setHeader("Content-Type", "text/javascript");
        res.setHeader("Cache-Control", "no-cache");
        fs.createReadStream(path.join(depsDir, current)).pipe(res);
      });
    },
  };
}

export default defineConfig({
  plugins: [streamdownHighlighterFallback()],
  tanstackStart: {
    // Redirect TanStack Start's bundled server entry to src/server.ts (our SSR error wrapper).
    // nitro/vite builds from this
    server: { entry: "server" },
  },
});
