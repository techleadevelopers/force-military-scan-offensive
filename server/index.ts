import express, { type Request, Response, NextFunction } from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { createServer } from "http";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { authRouter } from "./auth";
import { adminRouter } from "./admin";
import { pool } from "./db";
import { storage } from "./storage";
// Stripe temporarily disabled for local/dev runs

const app = express();
const httpServer = createServer(app);

app.set("trust proxy", 1);
// CORS para o front (necessário para credenciais + socket)
const FRONTEND_ORIGINS =
  (process.env.FRONTEND_ORIGINS ||
    process.env.FRONTEND_ORIGIN ||
    process.env.VITE_FRONTEND_ORIGIN ||
    "https://www.forcescan.site,https://military-scan-offensive.vercel.app,http://localhost:8000")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin as string | undefined;
  if (origin && FRONTEND_ORIGINS.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
  }
  res.header("Access-Control-Allow-Credentials", "true");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, try again later" },
});

app.use("/api/", apiLimiter);

app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);

app.use(express.urlencoded({ extended: false, limit: "1mb" }));

// Fallback para JSON malformado (ex.: {target:https://foo} vindo do frontend antigo)
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err?.type === "entity.parse.failed" && req.rawBody) {
    const raw = req.rawBody.toString("utf-8").trim();
    try {
      // Tenta normalizar chaves sem aspas e URLs sem aspas
      let fixed = raw.replace(/([{,]\s*)([A-Za-z0-9_]+)\s*:/g, '$1"$2":');
      fixed = fixed.replace(/https?:\/\/[^"'\s}]+/g, (m) => `"${m}"`);
      req.body = JSON.parse(fixed);
      return next();
    } catch {
      return res.status(400).json({
        error: "Invalid JSON payload",
        hint: "Envie JSON válido, ex: {\"target\": \"https://exemplo.com\"}",
        received: raw.slice(0, 200),
      });
    }
  }
  if (err) return res.status(400).json({ error: err.message || "Bad Request" });
  next();
});

const PgStore = connectPgSimple(session);
app.use(
  session({
    store: new PgStore({ pool: pool as any, createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || "mse-dev-secret-change-in-prod",
    resave: false,
    saveUninitialized: false,
    name: "mse.sid",
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: false,
      sameSite: "lax",
    },
  })
);

// Temporary autologin as admin to bypass UI login during tests (always on)
app.use(async (req, _res, next) => {
  const session = req.session as any;
  if (!session?.userId) {
    const email = "admin@mse.dev";
    let user = await storage.getUserByEmail(email);
    if (!user) {
      const bcrypt = await import("bcryptjs");
      const hash = await bcrypt.hash("dev-admin", 10);
      user = await storage.createUser({ email, password: hash, role: "admin" });
    }
    await storage.updateUser(user.id, { role: "admin", plan: "pro" });
    session.userId = user.id;
  }
  next();
});

app.use("/api/auth", authRouter);
app.use(adminRouter);

export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  console.log(`${formattedTime} [${source}] ${message}`);
}

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  await registerRoutes(httpServer, app);

  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    const path = _req?.originalUrl || _req?.url || "";
    console.error(`[ERROR] ${_req?.method || ""} ${path} ::`, err);

    if (res.headersSent) {
      return next(err);
    }

    return res.status(status).json({ message });
  });

  const forceStatic = process.env.FORCE_STATIC === "1";
  if (forceStatic || process.env.NODE_ENV === "production") {
    serveStatic(app);
  } else {
    const { setupVite } = await import("./vite");
    await setupVite(httpServer, app);
  }

  const port = parseInt(process.env.PORT || "5000", 10);
  httpServer.listen(
    {
      port,
      host: "0.0.0.0",
      reusePort: true,
    },
    () => {
      log(`serving on port ${port}`);
    },
  );
})();
