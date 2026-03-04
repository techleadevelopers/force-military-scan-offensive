import { eq, desc, sql, count, and } from "drizzle-orm";
import { db } from "./db";
import {
  users, scans, subscriptions, auditLogs,
  scanResults, paymentIntents,
  type User, type InsertUser, type Scan, type InsertScan,
  type Subscription, type InsertSubscription,
  type AuditLog, type InsertAuditLog,
  type ScanResult, type InsertScanResult,
  type PaymentIntent, type InsertPaymentIntent
} from "../shared/schema";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: string, data: Partial<User>): Promise<User | undefined>;

  createScan(scan: InsertScan): Promise<Scan>;
  getScan(id: string): Promise<Scan | undefined>;
  getScansByUser(userId: string): Promise<Scan[]>;
  updateScan(id: string, data: Partial<Scan>): Promise<Scan | undefined>;

  createSubscription(sub: InsertSubscription): Promise<Subscription>;
  getSubscription(userId: string): Promise<Subscription | undefined>;
  updateSubscription(id: string, data: Partial<Subscription>): Promise<Subscription | undefined>;

  createScanResult(result: InsertScanResult): Promise<ScanResult>;
  getScanResults(scanId: string): Promise<ScanResult[]>;

  createAuditLog(log: InsertAuditLog): Promise<AuditLog>;
  getAuditLogs(userId: string): Promise<AuditLog[]>;

  getAllUsers(): Promise<User[]>;
  getAllScans(limit?: number): Promise<Scan[]>;
  getAllAuditLogs(limit?: number): Promise<AuditLog[]>;
  getAdminStats(): Promise<{ totalUsers: number; totalScans: number; activeSubscriptions: number; totalFindings: number; criticalFindings: number; highFindings: number }>;

  createPaymentIntent(data: InsertPaymentIntent): Promise<PaymentIntent>;
  updatePaymentIntent(id: string, data: Partial<PaymentIntent>): Promise<PaymentIntent | undefined>;
  getPaymentIntentById(id: string): Promise<PaymentIntent | undefined>;
  getPaymentIntentByReference(referenceId: string): Promise<PaymentIntent | undefined>;
  getConfirmedPaymentForScan(userId: string, scanId: string): Promise<PaymentIntent | undefined>;
  getRecentConfirmedPayment(userId: string, hours: number): Promise<PaymentIntent | undefined>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }

  async createUser(data: InsertUser): Promise<User> {
    const [user] = await db.insert(users).values(data).returning();
    return user;
  }

  async updateUser(id: string, data: Partial<User>): Promise<User | undefined> {
    const [user] = await db.update(users).set(data).where(eq(users.id, id)).returning();
    return user;
  }

  async createScan(data: InsertScan): Promise<Scan> {
    const [scan] = await db.insert(scans).values(data).returning();
    return scan;
  }

  async getScan(id: string): Promise<Scan | undefined> {
    const [scan] = await db.select().from(scans).where(eq(scans.id, id));
    return scan;
  }

  async getScansByUser(userId: string): Promise<Scan[]> {
    return db.select().from(scans).where(eq(scans.userId, userId));
  }

  async updateScan(id: string, data: Partial<Scan>): Promise<Scan | undefined> {
    const [scan] = await db.update(scans).set(data).where(eq(scans.id, id)).returning();
    return scan;
  }

  async createSubscription(data: InsertSubscription): Promise<Subscription> {
    const [sub] = await db.insert(subscriptions).values(data).returning();
    return sub;
  }

  async getSubscription(userId: string): Promise<Subscription | undefined> {
    const [sub] = await db.select().from(subscriptions).where(eq(subscriptions.userId, userId));
    return sub;
  }

  async updateSubscription(id: string, data: Partial<Subscription>): Promise<Subscription | undefined> {
    const [sub] = await db.update(subscriptions).set(data).where(eq(subscriptions.id, id)).returning();
    return sub;
  }

  async createScanResult(data: InsertScanResult): Promise<ScanResult> {
    const [res] = await db.insert(scanResults).values(data).returning();
    return res;
  }

  async getScanResults(scanId: string): Promise<ScanResult[]> {
    return db.select().from(scanResults).where(eq(scanResults.scanId, scanId));
  }

  async createAuditLog(data: InsertAuditLog): Promise<AuditLog> {
    const [log] = await db.insert(auditLogs).values(data).returning();
    return log;
  }

  async getAuditLogs(userId: string): Promise<AuditLog[]> {
    return db.select().from(auditLogs).where(eq(auditLogs.userId, userId));
  }

  async getAllUsers(): Promise<User[]> {
    return db.select().from(users).orderBy(desc(users.createdAt));
  }

  async getAllScans(limit = 100): Promise<Scan[]> {
    return db.select().from(scans).orderBy(desc(scans.createdAt)).limit(limit);
  }

  async getAllAuditLogs(limit = 200): Promise<AuditLog[]> {
    return db.select().from(auditLogs).orderBy(desc(auditLogs.createdAt)).limit(limit);
  }

  async createPaymentIntent(data: InsertPaymentIntent): Promise<PaymentIntent> {
    const [pi] = await db.insert(paymentIntents).values(data).returning();
    return pi;
  }

  async updatePaymentIntent(id: string, data: Partial<PaymentIntent>): Promise<PaymentIntent | undefined> {
    const [pi] = await db.update(paymentIntents).set(data).where(eq(paymentIntents.id, id)).returning();
    return pi;
  }

  async getPaymentIntentById(id: string): Promise<PaymentIntent | undefined> {
    const [pi] = await db.select().from(paymentIntents).where(eq(paymentIntents.id, id));
    return pi;
  }

  async getPaymentIntentByReference(referenceId: string): Promise<PaymentIntent | undefined> {
    const [pi] = await db.select().from(paymentIntents).where(eq(paymentIntents.referenceId, referenceId));
    return pi;
  }

  async getConfirmedPaymentForScan(userId: string, scanId: string): Promise<PaymentIntent | undefined> {
    const [pi] = await db
      .select()
      .from(paymentIntents)
      .where(
        and(
          eq(paymentIntents.userId, userId),
          eq(paymentIntents.scanId, scanId),
          eq(paymentIntents.status, "CONFIRMED")
        )
      );
    return pi;
  }

  async getRecentConfirmedPayment(userId: string, hours: number): Promise<PaymentIntent | undefined> {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);
    const [pi] = await db
      .select()
      .from(paymentIntents)
      .where(
        and(
          eq(paymentIntents.userId, userId),
          eq(paymentIntents.status, "CONFIRMED"),
          sql`${paymentIntents.paidAt} >= ${since}`
        )
      )
      .orderBy(desc(paymentIntents.paidAt ?? paymentIntents.updatedAt ?? paymentIntents.createdAt))
      .limit(1);
    return pi;
  }

  async getScansByTarget(target: string, limit = 5): Promise<Scan[]> {
    return db.select().from(scans).where(eq(scans.target, target)).orderBy(desc(scans.createdAt)).limit(limit);
  }

  async getAdminStats(): Promise<{ totalUsers: number; totalScans: number; activeSubscriptions: number; totalFindings: number; criticalFindings: number; highFindings: number }> {
    const [userCount] = await db.select({ value: count() }).from(users);
    const [scanCount] = await db.select({ value: count() }).from(scans);
    const [subCount] = await db.select({ value: count() }).from(subscriptions).where(eq(subscriptions.status, "active"));
    const [findings] = await db.select({
      total: sql<number>`COALESCE(SUM(findings_count), 0)`,
      critical: sql<number>`COALESCE(SUM(critical_count), 0)`,
      high: sql<number>`COALESCE(SUM(high_count), 0)`,
    }).from(scans);
    return {
      totalUsers: userCount.value,
      totalScans: scanCount.value,
      activeSubscriptions: subCount.value,
      totalFindings: Number(findings.total),
      criticalFindings: Number(findings.critical),
      highFindings: Number(findings.high),
    };
  }
}

export const storage = new DatabaseStorage();
