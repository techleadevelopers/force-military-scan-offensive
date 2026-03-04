import { storage } from "../storage";
import { normalizePlan } from "../plan/limits";

export async function hasPaidAccess(
  userId: string,
  scanId?: string | null,
  plan?: string | null
): Promise<boolean> {
  const normalized = normalizePlan(plan || "");
  if (normalized === "pro" || normalized === "enterprise") return true;

  // Pagamento específico para o scan
  if (scanId) {
    const confirmed = await storage.getConfirmedPaymentForScan(userId, scanId);
    if (confirmed) return true;
  }

  // Pagamento avulso recente (sem scanId) — admite desbloqueio geral
  const recent = await storage.getRecentConfirmedPayment(userId, 48);
  return !!recent;
}
