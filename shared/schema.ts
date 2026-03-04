import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, boolean, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  firstName: text("first_name").notNull().default(""),
  taxId: text("tax_id").notNull().default(""),
  birthDate: text("birth_date").notNull().default(""),
  role: text("role").notNull().default("user"),
  plan: text("plan").notNull().default("free"),
  scansThisMonth: integer("scans_this_month").notNull().default(0),
  scansResetAt: timestamp("scans_reset_at").defaultNow(),
  apiKey: text("api_key"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const scans = pgTable("scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").references(() => users.id),
  target: text("target").notNull(),
  status: text("status").notNull().default("running"),
  findingsCount: integer("findings_count").notNull().default(0),
  criticalCount: integer("critical_count").notNull().default(0),
  highCount: integer("high_count").notNull().default(0),
  mediumCount: integer("medium_count").notNull().default(0),
  lowCount: integer("low_count").notNull().default(0),
  infoCount: integer("info_count").notNull().default(0),
  findings: jsonb("findings").default([]),
  exposedAssets: jsonb("exposed_assets").default([]),
  telemetry: jsonb("telemetry").default({}),
  phases: jsonb("phases").default({}),
  consentIp: text("consent_ip"),
  consentAt: timestamp("consent_at"),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const subscriptions = pgTable("subscriptions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").references(() => users.id).notNull(),
  plan: text("plan").notNull().default("free"),
  status: text("status").notNull().default("inactive"),
  stripeCustomerId: text("stripe_customer_id"),
  stripeSubscriptionId: text("stripe_subscription_id"),
  enabled: boolean("enabled").notNull().default(false),
  createdAt: timestamp("created_at").defaultNow(),
  expiresAt: timestamp("expires_at"),
});

export const scanResults = pgTable("scan_results", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").references(() => scans.id).notNull(),
  motor11v2Report: jsonb("motor11v2_report").notNull().default({}),
  createdAt: timestamp("created_at").defaultNow(),
});

export const auditLogs = pgTable("audit_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").references(() => users.id),
  action: text("action").notNull(),
  target: text("target"),
  ip: text("ip"),
  details: jsonb("details"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const paymentIntents = pgTable("payment_intents", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").references(() => users.id).notNull(),
  scanId: varchar("scan_id").references(() => scans.id),
  amountCents: integer("amount_cents").notNull(),
  currency: text("currency").notNull().default("BRL"),
  status: text("status").notNull().default("PENDING"),
  gateway: text("gateway").notNull().default("PAGBANK_PIX"),
  externalOrderId: text("external_order_id"),
  externalChargeId: text("external_charge_id"),
  referenceId: text("reference_id"),
  qrCodeText: text("qr_code_text"),
  qrCodeUrl: text("qr_code_url"),
  expiresAt: timestamp("expires_at"),
  idempotencyKey: text("idempotency_key"),
  paidAt: timestamp("paid_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  email: true,
  password: true,
  firstName: true,
});

export const insertScanSchema = createInsertSchema(scans).pick({
  userId: true,
  target: true,
  consentIp: true,
  consentAt: true,
});

export const insertSubscriptionSchema = createInsertSchema(subscriptions).pick({
  userId: true,
  plan: true,
});

export const insertScanResultSchema = createInsertSchema(scanResults).pick({
  scanId: true,
  motor11v2Report: true,
});

export const insertAuditLogSchema = createInsertSchema(auditLogs).pick({
  userId: true,
  action: true,
  target: true,
  ip: true,
  details: true,
});

export const insertPaymentIntentSchema = createInsertSchema(paymentIntents).pick({
  userId: true,
  scanId: true,
  amountCents: true,
  currency: true,
  status: true,
  gateway: true,
  externalOrderId: true,
  externalChargeId: true,
  referenceId: true,
  qrCodeText: true,
  qrCodeUrl: true,
  expiresAt: true,
  idempotencyKey: true,
  paidAt: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scans.$inferSelect;
export type InsertSubscription = z.infer<typeof insertSubscriptionSchema>;
export type Subscription = typeof subscriptions.$inferSelect;
export type InsertScanResult = z.infer<typeof insertScanResultSchema>;
export type ScanResult = typeof scanResults.$inferSelect;
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;
export type InsertPaymentIntent = z.infer<typeof insertPaymentIntentSchema>;
export type PaymentIntent = typeof paymentIntents.$inferSelect;
