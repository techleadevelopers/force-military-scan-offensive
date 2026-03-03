import type { Express, Request, Response } from "express";
import { type Server } from "http";
import { Server as SocketServer } from "socket.io";
import { spawn, type ChildProcess } from "child_process";
import { log } from "./index";
import { storage } from "./storage";
import { relayIngest } from "./credentialRelay";
import { getUncachableStripeClient } from "./stripeClient";
import { randomUUID } from "crypto";
import * as readline from "readline";
import * as fs from "fs";
import * as path from "path";
import { generateEnterprisePdf, type EnterpriseReportPayload } from "./report";
import { evaluateMockPatterns } from "./mockValidator";
import { loadAllowlistStrict, writeAllowlistStrict } from "./allowlist";

const BACKEND_ROOT = path.join(process.cwd(), "backend");
const PYTHON_BIN = process.env.PYTHON_BIN || process.env.PYTHON || "python";
loadAllowlistStrict(); // fail fast if allowlist is invalid or polluted

function addTargetToAllowlist(target: string): { hostname: string; added: boolean } | null {
  const fullUrl = target.includes("://") ? target : `https://${target}`;
  let parsedUrl: URL | null = null;
  try {
    parsedUrl = new URL(fullUrl);
  } catch {
    return null;
  }

  if (!parsedUrl || (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:")) {
    return null;
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  if (!hostname || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(hostname)) {
    return null;
  }

  const allowlist = loadAllowlistStrict();

  const alreadyPresent = allowlist.allowed_targets.some((entry: string) => {
    const regex = new RegExp(
      "^" + entry.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$",
      "i"
    );
    return regex.test(hostname);
  });

  if (!alreadyPresent) {
    const updated = {
      allowed_targets: [...allowlist.allowed_targets, hostname, `*.${hostname}`],
    };
    writeAllowlistStrict(updated);
    return { hostname, added: true };
  }

  return { hostname, added: false };
}

const BLOCKED_TARGETS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\.0\.0\.0$/,
  /^::1$/,
  /^169\.254\./,
  /\.internal$/i,
  /\.local$/i,
];

function isBlockedTarget(hostname: string): boolean {
  return BLOCKED_TARGETS.some((pattern) => pattern.test(hostname));
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  const io = new SocketServer(httpServer, {
    cors: { origin: "*" },
    transports: ["websocket", "polling"],
    pingTimeout: 30000,
    pingInterval: 10000,
  });
  // expose io for other routers (e.g., admin) via req.app.get("io")
  app.set("io", io);

  function getSessionUserId(req: Request): string | null {
    return (req.session as any)?.userId || null;
  }

  app.get("/api/scans", async (req: Request, res: Response) => {
    const userId = getSessionUserId(req);
    if (!userId) return res.status(401).json({ error: "Not authenticated" });
    try {
      const userScans = await storage.getScansByUser(userId);
      const enriched = userScans.map((s) => {
        const { mockProbability, suspicious } = evaluateMockPatterns(s);
        return { ...s, mockProbability, suspicious };
      });
      return res.json(enriched);
    } catch (err) {
      return res.status(500).json({ error: "Failed to fetch scans" });
    }
  });

  app.get("/api/scans/:id", async (req: Request, res: Response) => {
    const userId = getSessionUserId(req);
    if (!userId) return res.status(401).json({ error: "Not authenticated" });
    try {
      const scan = await storage.getScan(req.params.id);
      if (!scan || scan.userId !== userId) return res.status(404).json({ error: "Scan not found" });
      const { mockProbability, suspicious, valid } = evaluateMockPatterns(scan);
      return res.json({ ...scan, mockProbability, suspicious, valid });
    } catch (err) {
      return res.status(500).json({ error: "Failed to fetch scan" });
    }
  });

  app.post("/api/keys/generate", async (req: Request, res: Response) => {
    const userId = getSessionUserId(req);
    if (!userId) return res.status(401).json({ error: "Not authenticated" });
    try {
      const apiKey = `mse_${randomUUID().replace(/-/g, "")}`;
      await storage.updateUser(userId, { apiKey });
      return res.json({ apiKey });
    } catch (err) {
      return res.status(500).json({ error: "Failed to generate API key" });
    }
  });

  app.get("/api/keys", async (req: Request, res: Response) => {
    const userId = getSessionUserId(req);
    if (!userId) return res.status(401).json({ error: "Not authenticated" });
    try {
      const user = await storage.getUser(userId);
      return res.json({ apiKey: user?.apiKey || null });
    } catch (err) {
      return res.status(500).json({ error: "Failed to fetch API key" });
    }
  });

  app.post("/api/v1/scan", async (req: Request, res: Response) => {
    const apiKey = req.headers["x-api-key"] as string;
    if (!apiKey) return res.status(401).json({ error: "API key required" });
    try {
      const { db } = await import("./db");
      const { users: usersTable } = await import("../shared/schema");
      const { eq } = await import("drizzle-orm");
      const [user] = await db.select().from(usersTable).where(eq(usersTable.apiKey, apiKey));
      if (!user) return res.status(401).json({ error: "Invalid API key" });

      const target = req.body?.target;
      if (!target) return res.status(400).json({ error: "Target URL required" });

      const scan = await storage.createScan({
        userId: user.id,
        target,
        consentIp: req.ip || "api",
        consentAt: new Date(),
      });

      return res.status(201).json({ scanId: scan.id, status: "queued", target });
    } catch (err) {
      return res.status(500).json({ error: "Failed to create scan" });
    }
  });

  app.get("/api/v1/scan/:id", async (req: Request, res: Response) => {
    const apiKey = req.headers["x-api-key"] as string;
    if (!apiKey) return res.status(401).json({ error: "API key required" });
    try {
      const { db } = await import("./db");
      const { users: usersTable } = await import("../shared/schema");
      const { eq } = await import("drizzle-orm");
      const [user] = await db.select().from(usersTable).where(eq(usersTable.apiKey, apiKey));
      if (!user) return res.status(401).json({ error: "Invalid API key" });

      const scan = await storage.getScan(req.params.id);
      if (!scan || scan.userId !== user.id) return res.status(404).json({ error: "Scan not found" });
      const { mockProbability, suspicious, valid } = evaluateMockPatterns(scan);
      return res.json({ ...scan, mockProbability, suspicious, valid });
    } catch (err) {
      return res.status(500).json({ error: "Failed to fetch scan" });
    }
  });

  // Enterprise PDF report generator (session auth)
  app.post("/api/report/pdf", async (req: Request, res: Response) => {
    const userId = getSessionUserId(req);
    if (!userId) return res.status(401).json({ error: "Not authenticated" });

    const report = req.body?.report as EnterpriseReportPayload | undefined;
    if (!report || !report.metadata || !report.panorama) {
      return res.status(400).json({ error: "Invalid report payload" });
    }

    try {
      const pdfBuffer = await generateEnterprisePdf(report);
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", "attachment; filename=\"forcescan-enterprise.pdf\"");
      return res.status(200).send(pdfBuffer);
    } catch (err: any) {
      log(`PDF generation error: ${err?.message}`, "report");
      return res.status(500).json({ error: "Failed to generate PDF" });
    }
  });

  app.post("/api/checkout/create-session", async (req: Request, res: Response) => {
    const userId = getSessionUserId(req);
    if (!userId) return res.status(401).json({ error: "Not authenticated" });

    try {
      const stripe = await getUncachableStripeClient();
      const user = await storage.getUser(userId);
      if (!user) return res.status(401).json({ error: "User not found" });

      const baseUrl = `${req.protocol}://${req.get("host")}`;

      const session = await stripe.checkout.sessions.create({
        customer_email: user.email,
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: "MSE Single Scan Report",
                description: "Full vulnerability report with exposed secrets, PoC payloads, and remediation guidance",
              },
              unit_amount: 500,
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        success_url: `${baseUrl}/dashboard?payment=success`,
        cancel_url: `${baseUrl}/dashboard?payment=cancelled`,
        metadata: {
          userId: user.id,
          type: "single_scan",
        },
      });

      return res.json({ url: session.url });
    } catch (err: any) {
      console.error("Checkout error:", err);
      return res.status(500).json({ error: "Failed to create checkout session" });
    }
  });

  app.get("/api/allowlist", (_req, res) => {
    try {
      const data = loadAllowlistStrict();
      return res.json({ count: data.allowed_targets.length });
    } catch (e) {
      return res.status(500).json({ error: "Failed to read allowlist" });
    }
  });

  app.post("/api/allowlist", (_req, res) => {
    return res.status(403).json({ error: "Direct allowlist modification is disabled" });
  });

  const scanCooldowns = new Map<string, number>();
  const MAX_CONCURRENT_SCANS = 3;
  let activeScanCount = 0;

  io.on("connection", (socket) => {
    log(`Client connected: ${socket.id}`, "socket.io");

    let activeProcess: ChildProcess | null = null;

    socket.on("abort_scan", () => {
      if (activeProcess) {
        log("Aborting scan — killing Python process", "scanner");
        activeProcess.kill("SIGTERM");
        activeProcess = null;
        socket.emit("log_stream", {
          message: "Scan aborted by operator",
          level: "warn",
          phase: "",
        });
      }
    });

    socket.on("start_scan", (data: { target: string }) => {
      if (activeProcess) {
        activeProcess.kill("SIGTERM");
        activeProcess = null;
        activeScanCount = Math.max(0, activeScanCount - 1);
      }

      const target = (data.target || "").trim();
      if (!target || target.length > 2048) {
        socket.emit("log_stream", {
          message: "Invalid target URL",
          level: "error",
          phase: "",
        });
        return;
      }

      const now = Date.now();
      const lastScan = scanCooldowns.get(socket.id) || 0;
      if (now - lastScan < 10000) {
        socket.emit("log_stream", {
          message: "Rate limit: wait 10 seconds between scans",
          level: "warn",
          phase: "",
        });
        return;
      }
      scanCooldowns.set(socket.id, now);

      if (activeScanCount >= MAX_CONCURRENT_SCANS) {
        socket.emit("log_stream", {
          message: "Server busy — maximum concurrent scans reached. Try again shortly.",
          level: "warn",
          phase: "",
        });
        return;
      }

      const fullUrl = target.includes("://") ? target : `https://${target}`;
      let parsedHost: string;
      try {
        parsedHost = new URL(fullUrl).hostname.toLowerCase();
      } catch {
        socket.emit("log_stream", {
          message: "Invalid target URL format",
          level: "error",
          phase: "",
        });
        return;
      }

      if (isBlockedTarget(parsedHost)) {
        log(`SSRF blocked: ${parsedHost}`, "security");
        socket.emit("log_stream", {
          message: "Target blocked — internal/private addresses are not allowed",
          level: "error",
          phase: "",
        });
        return;
      }

      log(`Starting Python assessment for: ${target}`, "scanner");

      try {
        const result = addTargetToAllowlist(target);
        if (result && result.added) {
          log(`Added '${result.hostname}' and '*.${result.hostname}' to allowlist`, "scanner");
          socket.emit("log_stream", {
            message: `Target '${result.hostname}' authorized and added to allowlist`,
            level: "success",
            phase: "",
          });
        }
      } catch (e: any) {
        log(`Allowlist auto-add error: ${e.message}`, "scanner");
      }

      activeScanCount++;

      const scanAccumulator: {
        findings: any[];
        assets: any[];
        report: any | null;
        scanIdPromise: Promise<string | null>;
        severityCounts: { critical: number; high: number; medium: number; low: number; info: number };
      } = {
        findings: [],
        assets: [],
        report: null,
        scanIdPromise: Promise.resolve(null),
        severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      };

      const sessionUserId = (socket.request as any)?.session?.userId || null;

      scanAccumulator.scanIdPromise = (async () => {
        try {
          const scan = await storage.createScan({
            userId: sessionUserId,
            target,
            status: "running",
          });
          log(`[LIFECYCLE] Scan record created: ${scan.id} for target ${target}`, "scanner");
          return scan.id;
        } catch (dbErr: any) {
          log(`[LIFECYCLE] Failed to create scan record: ${dbErr?.message}`, "scanner");
          return null;
        }
      })();

      socket.emit("log_stream", {
        message: `Launching assessment engine for: ${target}`,
        level: "info",
        phase: "",
      });

      const proc = spawn(PYTHON_BIN, ["-m", "scanner.orchestrator", target], {
        cwd: BACKEND_ROOT,
        env: { ...process.env, PYTHONUNBUFFERED: "1" },
        stdio: ["pipe", "pipe", "pipe"],
      });

      activeProcess = proc;

      const rl = readline.createInterface({ input: proc.stdout! });

      rl.on("line", (line: string) => {
        try {
          const event = JSON.parse(line);
          const eventType = event.event;
          const eventData = event.data;

          socket.emit(eventType, eventData);

          if (eventType === "finding_detected") {
            scanAccumulator.findings.push(eventData);
            const sev = (eventData.severity || "info").toLowerCase();
            if (sev in scanAccumulator.severityCounts) {
              (scanAccumulator.severityCounts as any)[sev]++;
            }
          }

          if (eventType === "asset_detected") {
            scanAccumulator.assets.push(eventData);
          }

          if (eventType === "log_stream") {
            const phase = eventData.phase ? `[${eventData.phase}]` : "";
            log(`${phase} ${eventData.message}`, "scanner");
          }

          if (eventType === "report_generated") {
            scanAccumulator.report = eventData;
          }

          if (eventType === "finding_detected" || eventType === "asset_detected") {
            try {
              const desc = eventData.description || eventData.path || "";
              const title = eventData.title || eventData.label || "";
              const evidence = eventData.evidence || "";
              const rawResp = eventData.raw_response || eventData.response_snippet || "";
              const rawPayload = eventData.attack_payload || eventData.payload || "";
              const relayText = `${desc} ${evidence} ${rawResp} ${rawPayload}`;
              const SECRET_RELAY_REGEX = /(?:AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{24,}|ghp_[A-Za-z0-9]{36}|xoxb-[A-Za-z0-9-]+|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+|\b[A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIAL)\s*[=:]\s*["']?([^\s"'\n;#]{4,200})["']?)/gi;
              const matches = [...relayText.matchAll(SECRET_RELAY_REGEX)];
              if (matches.length > 0) {
                const relayEntries = matches.map((m: any) => ({
                  key: title.substring(0, 80) || "SCANNER_FIND",
                  value: m[1] || m[0],
                  type: /password/i.test(m[0]) ? "PASSWORD" : /token|jwt|eyJ/i.test(m[0]) ? "TOKEN" : "SECRET",
                  source: "scanner_auto_relay",
                  target: target || "",
                  capturedAt: new Date().toISOString(),
                }));
                relayIngest(relayEntries);
                log(`[DATABRIDGE] Auto-relayed ${relayEntries.length} credential(s) from scanner finding`, "scanner");
              }
            } catch (relayErr: any) {
              log(`[DATABRIDGE] Relay ingestion error: ${relayErr?.message || relayErr}`, "scanner");
            }
          }
        } catch {
          log(`Python output: ${line}`, "scanner");
        }
      });

      proc.stderr?.on("data", (data: Buffer) => {
        const msg = data.toString().trim();
        if (msg) {
          log(`Python stderr: ${msg}`, "scanner");
        }
      });

      proc.on("close", (code: number | null) => {
        log(`Python process exited with code ${code}`, "scanner");
        activeScanCount = Math.max(0, activeScanCount - 1);
        if (activeProcess === proc) {
          activeProcess = null;
        }

        const totalFindings = scanAccumulator.findings.length;
        const finalStatus = (code === 0 || code === null) ? "completed" : "failed";

        (async () => {
          try {
            const scanId = await scanAccumulator.scanIdPromise;
            if (scanId) {
              const cappedFindings = scanAccumulator.findings.slice(-500);
              const cappedAssets = scanAccumulator.assets.slice(-200);
              await storage.updateScan(scanId, {
                status: finalStatus,
                findingsCount: totalFindings,
                criticalCount: scanAccumulator.severityCounts.critical,
                highCount: scanAccumulator.severityCounts.high,
                mediumCount: scanAccumulator.severityCounts.medium,
                lowCount: scanAccumulator.severityCounts.low,
                infoCount: scanAccumulator.severityCounts.info,
                findings: cappedFindings,
                exposedAssets: cappedAssets,
                telemetry: { report: scanAccumulator.report },
                completedAt: new Date(),
              });
              log(`[LIFECYCLE] Scan ${scanId} persisted: ${finalStatus}, ${totalFindings} findings (C:${scanAccumulator.severityCounts.critical} H:${scanAccumulator.severityCounts.high} M:${scanAccumulator.severityCounts.medium} L:${scanAccumulator.severityCounts.low})`, "scanner");
            } else {
              log(`[LIFECYCLE] Scan persistence skipped — no scan ID available`, "scanner");
            }
          } catch (dbErr: any) {
            log(`[LIFECYCLE] Failed to persist scan results: ${dbErr?.message}`, "scanner");
          }
        })();

        if (code !== 0 && code !== null) {
          socket.emit("log_stream", {
            message: `Assessment engine exited with code ${code}`,
            level: "error",
            phase: "",
          });
          socket.emit("completed", {
            error: `Assessment engine exited unexpectedly (code ${code})`,
          });
        }
      });

      proc.on("error", (err: Error) => {
        log(`Python process error: ${err.message}`, "scanner");
        socket.emit("log_stream", {
          message: `Engine error: ${err.message}`,
          level: "error",
          phase: "",
        });
        socket.emit("completed", {
          error: `Engine error: ${err.message}`,
        });
        if (activeProcess === proc) {
          activeProcess = null;
        }
      });
    });

    socket.on("abort_scan", () => {
      log(`Client requested scan abort`, "scanner");
      if (activeProcess) {
        activeProcess.kill("SIGTERM");
        activeProcess = null;
        activeScanCount = Math.max(0, activeScanCount - 1);
      }
    });

    let activeSniperProcess: ChildProcess | null = null;

    socket.on("start_sniper_scan", (data: { targets: string }) => {
      if (activeSniperProcess) {
        activeSniperProcess.kill("SIGTERM");
        activeSniperProcess = null;
      }

      const targets = (data.targets || "").trim();
      if (!targets || targets.length > 50000) {
        socket.emit("sniper_log", { message: "Invalid targets input", level: "error" });
        return;
      }

      const now = Date.now();
      const lastScan = scanCooldowns.get(`sniper_${socket.id}`) || 0;
      if (now - lastScan < 5000) {
        socket.emit("sniper_log", { message: "Rate limit: wait 5 seconds between scans", level: "warn" });
        return;
      }
      scanCooldowns.set(`sniper_${socket.id}`, now);

      const urlList = targets.split(",").map((u: string) => u.trim()).filter((u: string) => u.length > 0);
      if (urlList.length > 100) {
        socket.emit("sniper_log", { message: "Maximum 100 targets per scan", level: "error" });
        return;
      }
      for (const url of urlList) {
        const fullUrl = url.includes("://") ? url : `https://${url}`;
        try {
          const parsedHost = new URL(fullUrl).hostname.toLowerCase();
          if (isBlockedTarget(parsedHost)) {
            socket.emit("sniper_log", { message: `Blocked target: ${parsedHost}`, level: "error" });
            return;
          }
        } catch {
          socket.emit("sniper_log", { message: `Invalid URL: ${url}`, level: "error" });
          return;
        }
      }

      log(`[SNIPER] Starting sniper scan for ${urlList.length} target(s)`, "scanner");

      const proc = spawn(PYTHON_BIN, ["-m", "scanner.sniper_scan", targets], {
        cwd: BACKEND_ROOT,
        env: { ...process.env, PYTHONUNBUFFERED: "1" },
        stdio: ["pipe", "pipe", "pipe"],
      });

      activeSniperProcess = proc;

      const sniperFindings: any[] = [];
      const sniperAssets: any[] = [];
      let sniperReport: any = null;
      const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

      const rl = readline.createInterface({ input: proc.stdout! });
      rl.on("line", (line: string) => {
        try {
          const event = JSON.parse(line);
          const eventType = event.event;
          const eventData = event.data;

          socket.emit(eventType, eventData);

          if (eventType === "finding_detected") {
            sniperFindings.push(eventData);
            const sev = (eventData.severity || "info").toLowerCase();
            if (sev in severityCounts) {
              (severityCounts as any)[sev]++;
            }
          }

          if (eventType === "asset_detected") {
            sniperAssets.push(eventData);
          }

          if (eventType === "report_generated") {
            sniperReport = eventData;
          }

          if (eventType === "log_stream") {
            const phase = eventData.phase ? `[${eventData.phase}]` : "";
            log(`[SNIPER] ${phase} ${eventData.message}`, "scanner");
          }

          if (eventType === "finding_detected" || eventType === "asset_detected") {
            try {
              const desc = eventData.description || eventData.path || "";
              const title = eventData.title || eventData.label || "";
              const evidence = eventData.evidence || "";
              const relayText = `${desc} ${evidence}`;
              const SECRET_RELAY_REGEX = /(?:AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{24,}|ghp_[A-Za-z0-9]{36}|xoxb-[A-Za-z0-9-]+|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+)/gi;
              const matches = [...relayText.matchAll(SECRET_RELAY_REGEX)];
              if (matches.length > 0) {
                const relayEntries = matches.map((m: any) => ({
                  key: title.substring(0, 80) || "SNIPER_FIND",
                  value: m[0],
                  type: /token|jwt|eyJ/i.test(m[0]) ? "TOKEN" : "SECRET",
                  source: "sniper_auto_relay",
                  target: targets.split(",")[0] || "",
                  capturedAt: new Date().toISOString(),
                }));
                relayIngest(relayEntries);
                log(`[SNIPER-DATABRIDGE] Auto-relayed ${relayEntries.length} credential(s)`, "scanner");
              }
            } catch {}
          }
        } catch {
          log(`[SNIPER] Python output: ${line}`, "scanner");
        }
      });

      proc.stderr?.on("data", (data: Buffer) => {
        const msg = data.toString().trim();
        if (msg) log(`[SNIPER] stderr: ${msg}`, "scanner");
      });

      proc.on("close", (code: number | null) => {
        log(`[SNIPER] Process exited with code ${code}`, "scanner");
        if (activeSniperProcess === proc) activeSniperProcess = null;

        (async () => {
          try {
            const sessionUserId = (socket.request as any)?.session?.userId || null;
            if (sessionUserId) {
              const scan = await storage.createScan({
                userId: sessionUserId,
                target: targets.split(",")[0] || targets,
                status: code === 0 || code === null ? "completed" : "failed",
              });
              await storage.updateScan(scan.id, {
                status: code === 0 || code === null ? "completed" : "failed",
                findingsCount: sniperFindings.length,
                criticalCount: severityCounts.critical,
                highCount: severityCounts.high,
                mediumCount: severityCounts.medium,
                lowCount: severityCounts.low,
                infoCount: severityCounts.info,
                findings: sniperFindings.slice(-500),
                exposedAssets: sniperAssets.slice(-200),
                telemetry: { report: sniperReport },
                completedAt: new Date(),
              });
              log(`[SNIPER] Scan persisted: ${scan.id}`, "scanner");
            }
          } catch (dbErr: any) {
            log(`[SNIPER] Persist error: ${dbErr?.message}`, "scanner");
          }
        })();

        if (code !== 0 && code !== null) {
          socket.emit("completed", { error: `Sniper engine exited with code ${code}` });
        }
      });

      proc.on("error", (err: Error) => {
        log(`[SNIPER] Process error: ${err.message}`, "scanner");
        socket.emit("completed", { error: `Sniper engine error: ${err.message}` });
        if (activeSniperProcess === proc) activeSniperProcess = null;
      });
    });

    socket.on("abort_sniper_scan", () => {
      if (activeSniperProcess) {
        log("[SNIPER] Scan aborted by operator", "scanner");
        activeSniperProcess.kill("SIGTERM");
        activeSniperProcess = null;
        socket.emit("log_stream", { message: "Sniper scan aborted", level: "warn", phase: "" });
      }
    });

    let activeCollectorProcess: ReturnType<typeof spawn> | null = null;

    socket.on("start_auto_collect", (data: { config: string }) => {
      if (activeCollectorProcess) {
        activeCollectorProcess.kill("SIGTERM");
        activeCollectorProcess = null;
      }

      let config: any;
      try {
        config = JSON.parse(data.config || "{}");
      } catch {
        socket.emit("collector_log", { message: "Invalid collector config JSON", level: "error" });
        return;
      }

      const now = Date.now();
      const lastCollect = scanCooldowns.get(`collector_${socket.id}`) || 0;
      if (now - lastCollect < 10000) {
        socket.emit("collector_log", { message: "Rate limit: wait 10 seconds between collections", level: "warn" });
        return;
      }
      scanCooldowns.set(`collector_${socket.id}`, now);

      log(`[AUTO-COLLECTOR] Starting target collection`, "scanner");

      const configStr = JSON.stringify(config);
      const proc = spawn(PYTHON_BIN, ["-m", "scanner.auto_collector", configStr], {
        cwd: BACKEND_ROOT,
        env: { ...process.env, PYTHONUNBUFFERED: "1" },
        stdio: ["pipe", "pipe", "pipe"],
      });

      activeCollectorProcess = proc;

      const rl = readline.createInterface({ input: proc.stdout! });
      rl.on("line", (line: string) => {
        try {
          const event = JSON.parse(line);
          const eventType = event.event;
          const eventData = event.data;
          socket.emit(eventType, eventData);

          if (eventType === "collector_log") {
            log(`[AUTO-COLLECTOR] ${eventData.message}`, "scanner");
          }
        } catch {
          log(`[AUTO-COLLECTOR] Python output: ${line}`, "scanner");
        }
      });

      proc.stderr?.on("data", (data: Buffer) => {
        const msg = data.toString().trim();
        if (msg) log(`[AUTO-COLLECTOR] stderr: ${msg}`, "scanner");
      });

      proc.on("close", (code: number | null) => {
        log(`[AUTO-COLLECTOR] Process exited with code ${code}`, "scanner");
        if (activeCollectorProcess === proc) activeCollectorProcess = null;
        if (code !== 0 && code !== null) {
          socket.emit("collector_log", { message: `Collector exited with code ${code}`, level: "error" });
        }
      });

      proc.on("error", (err: Error) => {
        log(`[AUTO-COLLECTOR] Process error: ${err.message}`, "scanner");
        socket.emit("collector_log", { message: `Collector error: ${err.message}`, level: "error" });
        if (activeCollectorProcess === proc) activeCollectorProcess = null;
      });
    });

    socket.on("abort_auto_collect", () => {
      if (activeCollectorProcess) {
        log("[AUTO-COLLECTOR] Collection aborted by operator", "scanner");
        activeCollectorProcess.kill("SIGTERM");
        activeCollectorProcess = null;
        socket.emit("collector_log", { message: "Collection aborted", level: "warn" });
      }
    });

    socket.on("disconnect", () => {
      log(`Client disconnected: ${socket.id}`, "socket.io");
      scanCooldowns.delete(socket.id);
      scanCooldowns.delete(`sniper_${socket.id}`);
      scanCooldowns.delete(`collector_${socket.id}`);
      if (activeSniperProcess) {
        activeSniperProcess.kill("SIGTERM");
        activeSniperProcess = null;
      }
      if (activeCollectorProcess) {
        activeCollectorProcess.kill("SIGTERM");
        activeCollectorProcess = null;
      }
    });
  });

  // ============================================
  // WebSocket para logs ao vivo do Abuse Engine
  // ============================================
  const abuseSubscriptions = new Map<string, Set<any>>();

  io.on("connection", (abuseSocket) => {
    abuseSocket.on("abuse:subscribe", (data: { target: string }) => {
      const target = data.target;
      if (!target) return;

      if (!abuseSubscriptions.has(target)) {
        abuseSubscriptions.set(target, new Set());
      }
      abuseSubscriptions.get(target)?.add(abuseSocket);

      log(`[ABUSE-LIVE] Client subscribed to ${target}`, "socket.io");

      abuseSocket.on("disconnect", () => {
        abuseSubscriptions.get(target)?.delete(abuseSocket);
        if (abuseSubscriptions.get(target)?.size === 0) {
          abuseSubscriptions.delete(target);
        }
      });
    });
  });

  function emitAbuseLog(target: string, message: string, level: string = "info") {
    const subscribers = abuseSubscriptions.get(target);
    if (subscribers) {
      const payload = {
        message,
        level,
        timestamp: new Date().toISOString()
      };
      subscribers.forEach((s: any) => {
        s.emit("abuse:log", payload);
      });
    }
  }

  // ============================================
  // ENDPOINTS DE ABUSO — handled by adminRouter in admin.ts (real implementations)
  // ============================================

  return httpServer;
}
