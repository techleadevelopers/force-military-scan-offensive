import { randomUUID } from "crypto";
import { db } from "../db";
import { eq } from "drizzle-orm";
import { paymentIntents } from "../../shared/schema";
import { storage } from "../storage";
import { intentLocker } from "./payment-intent-locker";
import { applyTransition } from "./payment.state-machine";

type PixOrderResponse = {
  paymentIntentId: string;
  status: string;
  qrCodeText: string;
  qrCodeImageUrl: string;
  expiresAt: string;
  chargeId: string;
  orderId: string;
};

type PagBankLink = { rel?: string; href?: string };
type PagBankQr = { id: string; text?: string; expiration_date?: string; links?: PagBankLink[] };
type PagBankOrderResponse = { id: string; qr_codes?: PagBankQr[] };
type PagBankOrderCardResponse = { id: string; charges?: Array<{ reference_id?: string; status?: string; payment_response?: { code?: string; message?: string } }> };

const GATEWAY = "PAGBANK_PIX";

export class PagBankService {
  constructor(
    private readonly apiToken: string,
    private readonly baseUrl: string,
    private readonly webhookBase: string
  ) {}

  async createPixOrder(params: {
    userId: string;
    scanId?: string | null;
    amountCents: number;
    description?: string;
    taxId?: string;
  }): Promise<PixOrderResponse> {
    const { userId, scanId, amountCents, description, taxId } = params;
    const referenceId = scanId ? `scan-${scanId}` : `user-${userId}-${Date.now()}`;
    const idempotencyKey = `pix-${referenceId}-${Date.now()}`;

    const claim = await intentLocker.claimPaymentIntent(
      referenceId,
      amountCents,
      scanId || null,
      idempotencyKey,
      userId
    );

    // se já existir, apenas devolve dados (para não gerar múltiplos QRs)
    if (!claim.shouldCreate) {
      const ready = await intentLocker.waitForIntentReady(claim.intent.id);
      return this.mapIntentToResponse(ready);
    }

    const expiresAtReq = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 min

    const taxIdVal = (taxId || "").replace(/\D/g, "") || "00000000000";
    const webhookBase =
      process.env.PAGBANK_WEBHOOK_URL ||
      this.webhookBase ||
      process.env.VITE_API_BASE_URL ||
      process.env.API_BASE_URL ||
      process.env.VERCEL_URL ||
      "";
    const webhookUrl =
      webhookBase && /^https?:\/\//i.test(webhookBase)
        ? `${webhookBase.replace(/\/$/, "")}/api/payments/webhook/pix`
        : null;

    const payload = {
      reference_id: referenceId,
      customer: {
        name: "Forcescan User",
        email: "anon@forcescan.site",
        tax_id: taxIdVal,
      },
      items: [{ name: description || "Forcescan Report", quantity: 1, unit_amount: amountCents }],
      qr_codes: [
        {
          amount: { value: amountCents },
          expiration_date: expiresAtReq,
          instructions: description || "Pagamento PIX Forcescan",
        },
      ],
      ...(webhookUrl ? { notification_urls: [webhookUrl] } : {}),
    };

    const url = `${this.baseUrl}/orders`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiToken}`,
        "Content-Type": "application/json",
        "idempotency-key": idempotencyKey,
      } as any,
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`PagBank order failed: ${res.status} ${errBody}`);
    }
    const data = (await res.json()) as PagBankOrderResponse;
    const qr = data.qr_codes?.[0];
    if (!qr) throw new Error("PagBank order missing qr_codes[0]");

    const qrCodeImageUrl =
      Array.isArray(qr.links) ? qr.links.find((l) => l.rel === "QRCODE.PNG")?.href || "" : "";

    const expiresAt =
      qr.expiration_date && qr.expiration_date.length > 0
        ? new Date(qr.expiration_date)
        : new Date(expiresAtReq);

    await storage.updatePaymentIntent(claim.intent.id, {
      userId,
      scanId: scanId || undefined,
      gateway: GATEWAY,
      status: "PENDING",
      amountCents,
      currency: "BRL",
      referenceId,
      externalOrderId: data.id,
      externalChargeId: qr.id,
      qrCodeText: qr.text ?? "",
      qrCodeUrl: qrCodeImageUrl,
      expiresAt,
      idempotencyKey,
    });

    const updated = await storage.getPaymentIntentById(claim.intent.id);
    if (!updated) throw new Error("Failed to persist payment intent");
    return this.mapIntentToResponse(updated);
  }

  async createCardSession(): Promise<string> {
    const email = process.env.PAGSEGURO_EMAIL || process.env.PAGBANK_EMAIL;
    const token = process.env.PAGSEGURO_API_TOKEN;
    if (!email || !token) {
      throw new Error("PAGSEGURO_EMAIL/PAGBANK_EMAIL e PAGSEGURO_API_TOKEN são obrigatórios para sessão de cartão");
    }
    const cardBase =
      process.env.PAGSEGURO_CARD_BASE_URL ||
      process.env.PAGSEGURO_V2_BASE_URL ||
      "https://ws.pagseguro.uol.com.br";
    const url = `${cardBase.replace(/\/+$/,"")}/v2/sessions?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;
    const res = await fetch(url, { method: "POST", headers: { "content-length": "0" } as any });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`PagBank session failed: ${res.status} ${body}`);
    }
    const body = await res.text();
    const match = body.match(/<id>([^<]+)<\/id>/);
    if (!match) throw new Error("PagBank session response sem <id>");
    return match[1];
  }

  async getPublicKey(): Promise<string> {
    const url = `${this.baseUrl}/public-keys`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiToken}`,
        "Content-Type": "application/json",
      } as any,
      body: JSON.stringify({ type: "card" }),
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`PagBank public key failed: ${res.status} ${body}`);
    }
    const data = await res.json();
    return (data as any).public_key || (data as any).publicKey || "";
  }

  async createCardOrder(params: {
    userId: string;
    scanId?: string | null;
    amountCents: number;
    description?: string;
    taxId?: string;
    holderName: string;
    birthDate?: string;
    cardToken: string; // encrypted token from PagBank JS
    installments?: number;
  }): Promise<PixOrderResponse> {
    const {
      userId,
      scanId,
      amountCents,
      description,
      taxId,
      holderName,
      birthDate,
      cardToken,
      installments,
    } = params;

    const referenceId = scanId ? `scan-${scanId}` : `user-${userId}-${Date.now()}`;
    const idempotencyKey = `card-${referenceId}-${Date.now()}`;
    const taxIdVal = (taxId || "").replace(/\D/g, "") || "00000000000";

    const webhookBase =
      process.env.PAGBANK_WEBHOOK_URL ||
      this.webhookBase ||
      process.env.VITE_API_BASE_URL ||
      process.env.API_BASE_URL ||
      process.env.VERCEL_URL ||
      "";
    const webhookUrl =
      webhookBase && /^https?:\/\//i.test(webhookBase)
        ? `${webhookBase.replace(/\/$/, "")}/api/payments/webhook/pix`
        : null;

    const payload: any = {
      reference_id: referenceId,
      customer: {
        name: holderName || "Forcescan User",
        email: "anon@forcescan.site",
        tax_id: taxIdVal,
      },
      items: [{ name: description || "Forcescan Report", quantity: 1, unit_amount: amountCents }],
      charges: [
        {
          reference_id: `charge-${referenceId}`,
          description: description || "Card charge Forcescan",
          amount: { value: amountCents, currency: "BRL" },
          payment_method: {
            type: "CREDIT_CARD",
            installments: installments || 1,
            capture: true,
            card: {
              encrypted: cardToken,
              holder: {
                name: holderName || "Forcescan User",
                tax_id: taxIdVal,
                birth_date: birthDate || "",
              },
            },
          },
        },
      ],
      ...(webhookUrl ? { notification_urls: [webhookUrl] } : {}),
    };

    const url = `${this.baseUrl}/orders`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiToken}`,
        "Content-Type": "application/json",
        "idempotency-key": idempotencyKey,
      } as any,
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`PagBank card order failed: ${res.status} ${errBody}`);
    }
    const data = (await res.json()) as PagBankOrderCardResponse;
    const charge = data.charges?.[0];
    const chargeId = charge?.reference_id || charge?.payment_response?.code || "";

    const intent = await storage.createPaymentIntent({
      userId,
      scanId: scanId || undefined,
      amountCents,
      currency: "BRL",
      status: "PENDING",
      gateway: "PAGBANK_CARD",
      referenceId,
      externalOrderId: data.id,
      externalChargeId: chargeId,
      idempotencyKey,
    });

    return {
      paymentIntentId: intent.id,
      status: "PENDING",
      qrCodeText: "",
      qrCodeImageUrl: "",
      expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
      chargeId: chargeId,
      orderId: data.id,
    };
  }

  async finalizeFromWebhook(payload: any): Promise<{ updated: boolean }> {
    const ref =
      payload?.reference_id ||
      payload?.data?.reference_id ||
      payload?.data?.transaction?.reference_id ||
      payload?.transaction?.reference_id;

    const chargeId =
      payload?.charge_id ||
      payload?.chargeId ||
      payload?.data?.charge_id ||
      payload?.data?.chargeId ||
      payload?.data?.transaction?.charge_id;

    if (!ref && !chargeId) return { updated: false };

    const intent =
      (ref && (await storage.getPaymentIntentByReference(ref))) ||
      (chargeId
        ? await db
            .select()
            .from(paymentIntents)
            .where(eq(paymentIntents.externalChargeId, chargeId))
            .limit(1)
            .then((rows) => rows[0])
        : undefined);

    if (!intent) return { updated: false };

    const nextStatus = applyTransition(intent.status as any, "CONFIRMED");
    const saved = await storage.updatePaymentIntent(intent.id, {
      status: nextStatus,
      paidAt: new Date(),
    });
    return { updated: !!saved };
  }

  private mapIntentToResponse(intent: any): PixOrderResponse {
    return {
      paymentIntentId: intent.id,
      status: intent.status,
      qrCodeText: intent.qrCodeText || "",
      qrCodeImageUrl: intent.qrCodeUrl || "",
      expiresAt: (intent.expiresAt || new Date()).toISOString(),
      chargeId: intent.externalChargeId || "",
      orderId: intent.externalOrderId || "",
    };
  }
}
