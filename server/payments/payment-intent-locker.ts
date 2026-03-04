import { storage } from "../storage";
import { paymentIntents } from "../../shared/schema";
import { eq } from "drizzle-orm";
import { db } from "../db";
import { PaymentIntent } from "../../shared/schema";

type ClaimResult = { shouldCreate: boolean; intent: PaymentIntent };

/**
 * Locker simples para evitar criação duplicada de intents no mesmo scan/reference.
 * Usa idempotencyKey + referenceId como chave de disputa.
 */
export class PaymentIntentLocker {
  async claimPaymentIntent(
    referenceId: string,
    amountCents: number,
    scanId: string | null,
    idempotencyKey: string,
    userId: string
  ): Promise<ClaimResult> {
    // tenta achar intent existente pelo referenceId
    const existing = await storage.getPaymentIntentByReference(referenceId);
    if (existing) {
      return { shouldCreate: false, intent: existing };
    }

    // cria com transação leve para evitar race
    const [intent] = await db
      .insert(paymentIntents)
      .values({
        referenceId,
        amountCents,
        currency: "BRL",
        status: "PENDING",
        gateway: "PAGBANK_PIX",
        scanId: scanId || undefined,
        userId,
        idempotencyKey,
      })
      .returning();

    return { shouldCreate: true, intent };
  }

  async waitForIntentReady(intentId: string): Promise<PaymentIntent> {
    // neste backend simples, só retorna o registro; caller pode revalidar status
    const intent = await storage.getPaymentIntentById(intentId);
    if (!intent) throw new Error("Payment intent not found");
    return intent;
  }
}

export const intentLocker = new PaymentIntentLocker();
