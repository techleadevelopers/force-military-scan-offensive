import { storage } from "../storage";
import type { User } from "../../shared/schema";

export type PlanKey = "free" | "pro" | "enterprise";
export type PlanFeature = "scan" | "api_scan" | "sniper" | "collector";

type PlanPolicy = {
  monthlyScans: number;
  allowApi: boolean;
  allowSniper: boolean;
  allowCollector: boolean;
};

const PLAN_POLICIES: Record<PlanKey, PlanPolicy> = {
  free: {
    monthlyScans: 3,
    allowApi: false,
    allowSniper: false,
    allowCollector: false,
  },
  pro: {
    monthlyScans: 50,
    allowApi: true,
    allowSniper: true,
    allowCollector: true,
  },
  enterprise: {
    monthlyScans: 500,
    allowApi: true,
    allowSniper: true,
    allowCollector: true,
  },
};

function startOfCurrentMonth(): Date {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0, 0);
}

export function normalizePlan(plan?: string | null): PlanKey {
  const key = (plan || "").toLowerCase() as PlanKey;
  if (key === "pro" || key === "enterprise") return key;
  return "free";
}

async function refreshCounters(user: User): Promise<User> {
  const currentMonth = startOfCurrentMonth();
  if (!user.scansResetAt || user.scansResetAt < currentMonth) {
    const updated =
      (await storage.updateUser(user.id, {
        scansThisMonth: 0,
        scansResetAt: currentMonth,
      })) || user;
    return updated;
  }
  return user;
}

export async function guardPlan(
  userId: string,
  feature: PlanFeature
): Promise<{ allowed: boolean; user?: User; policy?: PlanPolicy; message?: string; plan: PlanKey }> {
  const user = await storage.getUser(userId);
  if (!user) {
    return { allowed: false, message: "User not found", plan: "free" };
  }

  // Admin users have unrestricted access to all engines and quotas
  if (user.role === "admin") {
    const refreshedAdmin = await refreshCounters(user);
    return {
      allowed: true,
      user: refreshedAdmin,
      policy: PLAN_POLICIES.enterprise,
      plan: "enterprise",
    };
  }

  const normalizedPlan = normalizePlan(user.plan);
  const policy = PLAN_POLICIES[normalizedPlan];
  let refreshedUser = await refreshCounters(user);

  const deny = (message: string) => ({
    allowed: false,
    user: refreshedUser,
    policy,
    message,
    plan: normalizedPlan,
  });

  if (feature === "api_scan" && !policy.allowApi) {
    return deny("API access is not available on your current plan.");
  }
  if (feature === "sniper" && !policy.allowSniper) {
    return deny("Sniper exploitation is limited to Pro or Enterprise plans.");
  }
  if (feature === "collector" && !policy.allowCollector) {
    return deny("Auto-collector is limited to Pro or Enterprise plans.");
  }

  if (feature === "scan" || feature === "api_scan") {
    if (refreshedUser.scansThisMonth >= policy.monthlyScans) {
      return deny(
        `Monthly scan quota reached (${policy.monthlyScans}). Upgrade to continue scanning.`
      );
    }
  }

  return { allowed: true, user: refreshedUser, policy, plan: normalizedPlan };
}

export async function consumeScan(user: User): Promise<User> {
  const refreshed = await refreshCounters(user);
  const newCount = (refreshed.scansThisMonth || 0) + 1;
  return (
    (await storage.updateUser(refreshed.id, {
      scansThisMonth: newCount,
      scansResetAt: startOfCurrentMonth(),
    })) || { ...refreshed, scansThisMonth: newCount, scansResetAt: startOfCurrentMonth() }
  );
}

export function getPlanPolicy(plan: string | null | undefined): PlanPolicy {
  return PLAN_POLICIES[normalizePlan(plan)];
}
