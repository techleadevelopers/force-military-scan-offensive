import express, { type Express } from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// __dirname shim para ESM (tsx)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function serveStatic(app: Express) {
  const distPath = path.resolve(__dirname, "..", "..", "dist", "public");
  if (!fs.existsSync(distPath)) {
    console.warn(
      `[static] Skipping static middleware because build dir is missing: ${distPath}. ` +
      "Run `npm run build` (or ensure dist/ is copied into the image) to enable static assets.",
    );
    return;
  }

  app.use(express.static(distPath));

  // fall through to index.html if the file doesn't exist
  app.use("/{*path}", (_req, res) => {
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
