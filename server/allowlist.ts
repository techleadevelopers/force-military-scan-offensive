import fs from "fs";
import path from "path";

const BACKEND_ROOT = path.join(process.cwd(), "backend");
export const ALLOWLIST_PATH = path.join(BACKEND_ROOT, "scanner", "allowlist.json");

const DEMO_PATTERNS = [/demo/i, /example/i, /test/i];

function failAllowlist(reason: string, err?: unknown): never {
  const details = err instanceof Error ? err.message : "";
  console.error(`🚨 CRITICAL: ${reason}${details ? ` (${details})` : ""}`);
  process.exit(1);
}

export function loadAllowlistStrict(): { allowed_targets: string[] } {
  try {
    const raw = fs.readFileSync(ALLOWLIST_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    const allowed = Array.isArray(parsed.allowed_targets)
      ? parsed.allowed_targets.map((d: any) => String(d))
      : [];

    if (allowed.length === 0) failAllowlist("Allowlist empty or invalid structure");

    const hasDemoDomain = allowed.some((d) => DEMO_PATTERNS.some((p) => p.test(d)));
    if (hasDemoDomain) failAllowlist("Allowlist contains demo/test/example domains");

    return { allowed_targets: allowed };
  } catch (err) {
    failAllowlist("Allowlist not found or unreadable", err);
  }
}

export function writeAllowlistStrict(data: { allowed_targets: string[] }): void {
  if (!data?.allowed_targets || !Array.isArray(data.allowed_targets)) {
    throw new Error("allowlist payload must include allowed_targets array");
  }
  const hasDemoDomain = data.allowed_targets.some((d) =>
    DEMO_PATTERNS.some((p) => p.test(String(d)))
  );
  if (hasDemoDomain) {
    throw new Error("attempted to write demo/test/example domains into allowlist");
  }
  fs.writeFileSync(ALLOWLIST_PATH, JSON.stringify({ allowed_targets: data.allowed_targets }, null, 2));
}

export function ensureAllowlistClean(): void {
  loadAllowlistStrict();
}
