export interface MockIssue {
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
  action?: "REJECT" | "WARN";
}

function normalizeArray<T = any>(value: any, defaultValue: T[] = []): T[] {
  if (Array.isArray(value)) return value as T[];
  if (value === undefined || value === null) return defaultValue;
  return defaultValue;
}

function extractSubdomains(scan: any): string[] {
  // Prefer structured phase data if present
  const fromPhase = normalizeArray(scan?.phases?.surface_mapping?.subdomains);
  if (fromPhase.length > 0) return fromPhase;

  // Fallback: exposedAssets marked as endpoint
  const assets = normalizeArray(scan?.exposedAssets);
  const endpoints = assets
    .filter((a: any) => a?.type === "endpoint" && typeof a?.value === "string")
    .map((a: any) => a.value);
  if (endpoints.length > 0) return endpoints;

  // Fallback: findings mentioning subdomains
  const findings = normalizeArray(scan?.findings);
  const fromFindings = findings
    .filter((f: any) => typeof f?.title === "string" && f.title.toLowerCase().includes("subdomain"))
    .map((f: any) => f?.endpoint || f?.asset || f?.title)
    .filter(Boolean);
  return fromFindings as string[];
}

function isGeneric17Subdomains(subdomains: string[]): boolean {
  if (subdomains.length !== 17) return false;
  const genericNames = [
    "api", "admin", "dev", "staging", "test", "beta",
    "ftp", "vpn", "cdn", "ci", "gitlab", "jira",
    "app", "ws", "socket", "status", "monitor",
  ];
  const names = subdomains.map((s) => (s || "").split(".")[0].toLowerCase());
  return names.every((n) => genericNames.includes(n));
}

function hasUnconfirmedRedisSSRF(findings: any[]): boolean {
  return findings.some((f: any) => {
    const blob = JSON.stringify(f || {}).toLowerCase();
    if (!blob.includes("ssrf") || !blob.includes("redis")) return false;
    const confirmed = Boolean((f as any).confirmed);
    const evidence = (f as any).evidence ? JSON.stringify((f as any).evidence).toLowerCase() : "";
    const hasSignatures = evidence.includes("redis_version") && evidence.includes("connected_clients");
    return !confirmed || !hasSignatures;
  });
}

function countBulkDumps(dumps: any[]): MockIssue | null {
  const tsCount: Record<string, number> = {};
  dumps.forEach((d: any) => {
    const ts = (d?.createdAt || d?.timestamp || "").toString().split(".")[0];
    if (!ts) return;
    tsCount[ts] = (tsCount[ts] || 0) + 1;
  });
  const overloaded = Object.entries(tsCount).find(([, c]) => c > 5);
  if (overloaded) {
    const [ts, count] = overloaded;
    return {
      type: "bulk_dumps",
      severity: "critical",
      message: `${count} dumps gerados no mesmo segundo (${ts}) - IMPOSSÍVEL`,
      action: "REJECT",
    };
  }
  return null;
}

function detectPerfectNumbers(metrics: Record<string, any>): MockIssue[] {
  const perfectNumbers = [100, 99, 98, 70, 50, 25, 10, 5, 4, 3, 2, 1];
  const issues: MockIssue[] = [];
  for (const [key, value] of Object.entries(metrics || {})) {
    if (typeof value === "number" && perfectNumbers.includes(value) && value > 0) {
      issues.push({
        type: "perfect_number",
        severity: "medium",
        message: `Métrica '${key}' tem valor perfeito: ${value}`,
        action: "WARN",
      });
    }
  }
  return issues;
}

function allDumpsZeroCredentials(dumps: any[]): MockIssue | null {
  if (!dumps || dumps.length === 0) return null;
  const zeroCreds = dumps.every((d: any) => (d?.itemCount ?? d?.credentials_count ?? 0) === 0);
  if (!zeroCreds) return null;
  return {
    type: "zero_credentials",
    severity: "high",
    message: `ZERO credenciais em ${dumps.length} dumps - estatisticamente improvável`,
    action: "REJECT",
  };
}

export function evaluateMockPatterns(scan: any, dumps: any[] = []): { mockProbability: number; suspicious: MockIssue[]; valid: boolean } {
  const suspicious: MockIssue[] = [];

  const subdomains = extractSubdomains(scan);
  if (isGeneric17Subdomains(subdomains)) {
    suspicious.push({
      type: "subdomain_pattern",
      severity: "critical",
      message: `17 subdomínios genéricos detectados: ${subdomains.map((s) => (s || "").split(".")[0]).join(", ")}`,
      action: "REJECT",
    });
  }

  const findings = normalizeArray(scan?.findings);
  if (hasUnconfirmedRedisSSRF(findings)) {
    suspicious.push({
      type: "ssrf_redis_false_positive",
      severity: "high",
      message: "SSRF Redis reportado mas NÃO confirmado",
      action: "REJECT",
    });
  }

  const bulk = countBulkDumps(dumps);
  if (bulk) suspicious.push(bulk);

  const perfects = detectPerfectNumbers(scan?.metrics || scan?.telemetry || {});
  suspicious.push(...perfects);

  const zeroCreds = allDumpsZeroCredentials(dumps);
  if (zeroCreds) suspicious.push(zeroCreds);

  const criticalRejects = suspicious.filter((i) => (i.action === "REJECT") && (i.severity === "critical" || i.severity === "high"));
  const valid = criticalRejects.length === 0;
  const mockProbability = Math.min(100, suspicious.length * 20);

  return { mockProbability, suspicious, valid };
}
