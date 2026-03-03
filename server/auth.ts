import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import { storage } from "./storage";
import { insertUserSchema } from "../shared/schema";
import { z } from "zod";

const registerSchema = insertUserSchema.extend({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

export const authRouter = Router();

authRouter.post("/register", async (req: Request, res: Response) => {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid input", details: parsed.error.flatten() });
    }

    const existing = await storage.getUserByEmail(parsed.data.email);
    if (existing) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(parsed.data.password, 12);
    const user = await storage.createUser({
      email: parsed.data.email,
      password: hashedPassword,
    });

    (req.session as any).userId = user.id;

    return res.status(201).json({
      id: user.id,
      email: user.email,
      plan: user.plan,
      createdAt: user.createdAt,
    });
  } catch (err: any) {
    console.error("Register error:", err);
    return res.status(500).json({ error: "Registration failed" });
  }
});

authRouter.post("/login", async (req: Request, res: Response) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const user = await storage.getUserByEmail(parsed.data.email);
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const valid = await bcrypt.compare(parsed.data.password, user.password);
    if (!valid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    (req.session as any).userId = user.id;

    return res.json({
      id: user.id,
      email: user.email,
      plan: user.plan,
      createdAt: user.createdAt,
    });
  } catch (err: any) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Login failed" });
  }
});

authRouter.post("/logout", (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Logout failed" });
    }
    res.clearCookie("mse.sid");
    return res.json({ success: true });
  });
});

authRouter.get("/me", async (req: Request, res: Response) => {
  const userId = (req.session as any)?.userId;
  if (!userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const user = await storage.getUser(userId);
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    return res.json({
      id: user.id,
      email: user.email,
      plan: user.plan,
      scansThisMonth: user.scansThisMonth,
      apiKey: user.apiKey,
      createdAt: user.createdAt,
    });
  } catch (err: any) {
    console.error("Auth me error:", err);
    return res.status(500).json({ error: "Failed to fetch user" });
  }
});
