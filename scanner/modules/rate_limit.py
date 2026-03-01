import httpx
import asyncio
import time
from .base import BaseModule
from scanner.models import Finding
from scanner.config import USER_AGENT, MAX_REQUESTS_PER_MODULE, REQUEST_DELAY_MS


class RateLimitModule(BaseModule):
    name = "Rate Limit Simulation"
    phase = "simulation"
    description = "Controlled rate limiting detection — tests if the target enforces request rate limits"

    BURST_SIZE = 15
    BURST_DELAY = 0.05

    async def execute(self, job) -> list:
        findings = []
        base_url = job.base_url

        self.log(f"Testing rate limit enforcement on {base_url}")
        self.log(f"Burst size: {self.BURST_SIZE} requests (controlled, non-destructive)")

        try:
            async with httpx.AsyncClient(
                timeout=15,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                self.log("Sending controlled burst of requests...")

                responses = []
                start_time = time.time()
                request_count = 0

                for i in range(self.BURST_SIZE):
                    try:
                        resp = await client.get(base_url)
                        responses.append(resp.status_code)
                        request_count += 1
                        self.telemetry(requestsAnalyzed=request_count)
                        await asyncio.sleep(self.BURST_DELAY)
                    except Exception as e:
                        self.log(f"Request {i + 1} failed: {e}", "debug")
                        responses.append(0)

                elapsed = time.time() - start_time
                self.log(f"Burst completed: {len(responses)} requests in {elapsed:.2f}s")

                rate_limited = [r for r in responses if r == 429]
                errors = [r for r in responses if r >= 500]
                successes = [r for r in responses if 200 <= r < 400]

                self.log(f"Results: {len(successes)} success, {len(rate_limited)} rate-limited, {len(errors)} errors")

                if not rate_limited:
                    self.log("[WARN] No rate limiting detected after burst", "warn")
                    findings.append(
                        Finding(
                            severity="medium",
                            title="No Rate Limiting Detected",
                            description=f"Server accepted all {self.BURST_SIZE} burst requests without returning 429 Too Many Requests.",
                            phase=self.phase,
                            recommendation="Implement rate limiting (e.g., token bucket or sliding window) to prevent brute-force and DoS attacks.",
                            cvss_score=5.3,
                            references=["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
                        )
                    )
                    self.finding("medium", "No Rate Limiting Detected",
                                 f"All {self.BURST_SIZE} requests accepted without throttling", cvss_score=5.3)
                else:
                    first_429 = responses.index(429) + 1
                    self.log(f"[PASS] Rate limiting activated after {first_429} requests", "success")

                retry_after = None
                if rate_limited:
                    resp_check = await client.get(base_url)
                    retry_after = resp_check.headers.get("Retry-After")

                if rate_limited and not retry_after:
                    findings.append(
                        Finding(
                            severity="low",
                            title="Missing Retry-After Header",
                            description="Rate limiting returns 429 but does not include Retry-After header.",
                            phase=self.phase,
                            recommendation="Include Retry-After header in 429 responses to inform clients of wait time.",
                            cvss_score=2.1,
                        )
                    )
                    self.finding("low", "Missing Retry-After Header",
                                 "429 responses lack Retry-After header", cvss_score=2.1)

                self.log("Testing login endpoint rate limiting...")
                common_login_paths = ["/login", "/api/login", "/auth/login", "/api/auth/login", "/signin"]
                for path in common_login_paths:
                    try:
                        resp = await client.post(
                            f"{base_url}{path}",
                            json={"username": "test", "password": "test"},
                            headers={"Content-Type": "application/json"},
                        )
                        request_count += 1
                        self.telemetry(requestsAnalyzed=request_count)
                        if resp.status_code not in (404, 405):
                            self.log(f"Login endpoint found: {path} (HTTP {resp.status_code})")
                            login_responses = []
                            for _ in range(5):
                                r = await client.post(
                                    f"{base_url}{path}",
                                    json={"username": "test", "password": "invalid"},
                                )
                                login_responses.append(r.status_code)
                                request_count += 1
                                await asyncio.sleep(0.1)

                            if 429 not in login_responses:
                                findings.append(
                                    Finding(
                                        severity="high",
                                        title="No Login Rate Limiting",
                                        description=f"Login endpoint {path} does not enforce rate limiting after multiple failed attempts.",
                                        phase=self.phase,
                                        recommendation="Implement account lockout or rate limiting on authentication endpoints.",
                                        cvss_score=7.3,
                                    )
                                )
                                self.finding("high", "No Login Rate Limiting",
                                             f"Endpoint {path} allows unlimited login attempts", cvss_score=7.3)
                            break
                    except Exception:
                        pass

        except Exception as e:
            self.log(f"Rate limit test error: {e}", "error")

        self.log(f"Rate limit simulation complete — {len(findings)} finding(s)")
        return findings
