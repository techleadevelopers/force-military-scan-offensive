import httpx
import asyncio
from .base import BaseModule
from scanner.models import Finding
from scanner.config import USER_AGENT


class CORSAnalyzerModule(BaseModule):
    name = "CORS Policy Analyzer"
    phase = "misconfig"
    description = "Analyze Cross-Origin Resource Sharing policy for misconfigurations"

    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.example.com",
        "null",
    ]

    INTERNAL_ORIGINS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://192.168.1.1",
        "http://10.0.0.1",
    ]

    SENSITIVE_EXPOSED_HEADERS = [
        "authorization",
        "x-api-key",
        "x-csrf-token",
        "x-auth-token",
        "set-cookie",
        "x-forwarded-for",
        "x-real-ip",
        "x-session-id",
        "x-request-id",
    ]

    async def execute(self, job) -> list:
        findings = []
        base_url = job.base_url

        self.log(f"Analyzing CORS policy for {base_url}")

        try:
            async with httpx.AsyncClient(
                timeout=15,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                self.log("Sending preflight requests with test origins...")
                request_count = 0

                resp_base = await client.options(
                    base_url,
                    headers={"Origin": "https://test.example.com", "Access-Control-Request-Method": "GET"},
                )
                request_count += 1
                self.telemetry(requestsAnalyzed=request_count)

                acao = resp_base.headers.get("Access-Control-Allow-Origin", "")
                acac = resp_base.headers.get("Access-Control-Allow-Credentials", "")
                acam = resp_base.headers.get("Access-Control-Allow-Methods", "")
                acah = resp_base.headers.get("Access-Control-Allow-Headers", "")

                if acao:
                    self.log(f"ACAO: {acao}")
                if acac:
                    self.log(f"ACAC: {acac}")
                if acam:
                    self.log(f"ACAM: {acam}")

                if acao == "*":
                    self.log("[WARN] Wildcard CORS policy detected!", "warn")
                    if acac.lower() == "true":
                        findings.append(
                            Finding(
                                severity="critical",
                                title="Wildcard CORS with Credentials",
                                description="CORS allows all origins (Access-Control-Allow-Origin: *) combined with Access-Control-Allow-Credentials: true. This is a critical misconfiguration.",
                                phase=self.phase,
                                recommendation="Never combine wildcard origin with credentials. Implement a strict origin allowlist.",
                                cvss_score=9.1,
                                references=["https://portswigger.net/web-security/cors"],
                            )
                        )
                        self.finding("critical", "Wildcard CORS with Credentials",
                                     "ACAO: * with ACAC: true — critical misconfiguration", cvss_score=9.1)
                    else:
                        findings.append(
                            Finding(
                                severity="medium",
                                title="Wildcard CORS Policy",
                                description="Access-Control-Allow-Origin is set to '*', allowing any origin to read responses.",
                                phase=self.phase,
                                recommendation="Replace wildcard with specific trusted origins.",
                                cvss_score=5.3,
                            )
                        )
                        self.finding("medium", "Wildcard CORS Policy",
                                     "ACAO: * — any origin can read responses", cvss_score=5.3)

                for origin in self.TEST_ORIGINS:
                    await asyncio.sleep(0.2)
                    request_count += 1
                    self.telemetry(requestsAnalyzed=request_count)

                    try:
                        resp = await client.get(
                            base_url,
                            headers={"Origin": origin, "User-Agent": USER_AGENT},
                        )
                        reflected_origin = resp.headers.get("Access-Control-Allow-Origin", "")

                        if reflected_origin == origin:
                            self.log(f"[FAIL] Origin reflected: {origin} → {reflected_origin}", "error")
                            findings.append(
                                Finding(
                                    severity="high",
                                    title="CORS Origin Reflection",
                                    description=f"Server reflects arbitrary origin: {origin}. Attacker-controlled origins are accepted.",
                                    phase=self.phase,
                                    recommendation="Validate Origin header against a strict allowlist. Do not reflect the Origin header blindly.",
                                    cvss_score=7.5,
                                    references=["https://portswigger.net/web-security/cors"],
                                )
                            )
                            self.finding("high", "CORS Origin Reflection",
                                         f"Reflected origin: {origin}", cvss_score=7.5)
                        elif reflected_origin:
                            self.log(f"[OK] Origin {origin} → {reflected_origin}", "info")
                        else:
                            self.log(f"[OK] Origin {origin} — no ACAO returned", "success")
                    except Exception as e:
                        self.log(f"Request failed for origin {origin}: {e}", "debug")

                if not acao:
                    self.log("No CORS headers detected — CORS is not configured (default deny)", "success")

                bypass_findings = await self._test_subdomain_bypass(client, job, request_count)
                findings.extend(bypass_findings[0])
                request_count = bypass_findings[1]

                null_findings = await self._test_null_origin_credentials(client, base_url, request_count)
                findings.extend(null_findings[0])
                request_count = null_findings[1]

                internal_findings = await self._test_internal_origins(client, base_url, request_count)
                findings.extend(internal_findings[0])
                request_count = internal_findings[1]

                exposed_findings = await self._check_exposed_headers(client, base_url, request_count)
                findings.extend(exposed_findings[0])
                request_count = exposed_findings[1]

        except Exception as e:
            self.log(f"CORS analysis error: {e}", "error")

        self.log(f"CORS analysis complete — {len(findings)} finding(s)")
        return findings

    async def _test_subdomain_bypass(self, client, job, request_count):
        findings = []
        hostname = job.hostname

        bypass_origins = [
            f"https://{hostname}.attacker.com",
            f"https://attacker{hostname}",
            f"https://{hostname.replace('.', '-')}.attacker.com",
        ]

        parts = hostname.split(".")
        if len(parts) >= 2:
            domain_no_tld = parts[0]
            bypass_origins.append(f"https://{domain_no_tld}.com.attacker.com")

        self.log(f"Testing {len(bypass_origins)} subdomain/regex bypass origins...")

        for origin in bypass_origins:
            await asyncio.sleep(0.2)
            request_count += 1
            self.telemetry(requestsAnalyzed=request_count)

            try:
                resp = await client.get(
                    job.base_url,
                    headers={"Origin": origin, "User-Agent": USER_AGENT},
                )
                reflected = resp.headers.get("Access-Control-Allow-Origin", "")
                creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if reflected == origin:
                    severity = "critical" if creds == "true" else "high"
                    cvss = 9.1 if creds == "true" else 7.5
                    cred_note = " with credentials" if creds == "true" else ""
                    self.log(f"[FAIL] Subdomain bypass accepted: {origin}{cred_note}", "error")
                    findings.append(
                        Finding(
                            severity=severity,
                            title=f"CORS Subdomain Bypass{cred_note}",
                            description=f"Server accepted bypass origin: {origin}. The CORS whitelist parser may be flawed, allowing attacker-controlled subdomains.",
                            phase=self.phase,
                            recommendation="Use exact string matching for allowed origins. Do not use regex or substring matching for origin validation.",
                            cvss_score=cvss,
                            references=["https://portswigger.net/web-security/cors"],
                        )
                    )
                    self.finding(severity, "CORS Subdomain Bypass",
                                 f"Bypass origin accepted: {origin}{cred_note}", cvss_score=cvss)
                    self.asset("config", origin, f"CORS bypass origin accepted: {origin}", severity)
                else:
                    self.log(f"[OK] Bypass origin {origin} — not reflected", "success")
            except Exception as e:
                self.log(f"Bypass test failed for {origin}: {e}", "debug")

        return findings, request_count

    async def _test_null_origin_credentials(self, client, base_url, request_count):
        findings = []
        self.log("Testing null origin with credentials...")

        await asyncio.sleep(0.2)
        request_count += 1
        self.telemetry(requestsAnalyzed=request_count)

        try:
            resp = await client.get(
                base_url,
                headers={"Origin": "null", "User-Agent": USER_AGENT},
            )
            reflected = resp.headers.get("Access-Control-Allow-Origin", "")
            creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if reflected == "null" and creds == "true":
                self.log("[FAIL] Null origin accepted with credentials!", "error")
                findings.append(
                    Finding(
                        severity="critical",
                        title="CORS Null Origin with Credentials",
                        description="Server allows 'null' origin with Access-Control-Allow-Credentials: true. Sandboxed iframes and data: URIs send 'null' as origin, enabling cross-origin data theft.",
                        phase=self.phase,
                        recommendation="Never allow the 'null' origin, especially with credentials. Remove 'null' from any origin allowlists.",
                        cvss_score=9.1,
                        references=[
                            "https://portswigger.net/web-security/cors",
                            "https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties",
                        ],
                    )
                )
                self.finding("critical", "CORS Null Origin with Credentials",
                             "null origin accepted with ACAC: true — exploitable via sandboxed iframe", cvss_score=9.1)
                self.asset("config", "null-origin-cors", "Null origin with credentials allowed", "critical")
            else:
                self.log("[OK] Null origin + credentials combo not exploitable", "success")
        except Exception as e:
            self.log(f"Null origin test failed: {e}", "debug")

        return findings, request_count

    async def _test_internal_origins(self, client, base_url, request_count):
        findings = []
        self.log(f"Testing {len(self.INTERNAL_ORIGINS)} internal/private IP origins...")

        for origin in self.INTERNAL_ORIGINS:
            await asyncio.sleep(0.2)
            request_count += 1
            self.telemetry(requestsAnalyzed=request_count)

            try:
                resp = await client.get(
                    base_url,
                    headers={"Origin": origin, "User-Agent": USER_AGENT},
                )
                reflected = resp.headers.get("Access-Control-Allow-Origin", "")
                creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if reflected == origin:
                    cred_note = " with credentials" if creds == "true" else ""
                    self.log(f"[FAIL] Internal origin accepted: {origin}{cred_note}", "error")
                    findings.append(
                        Finding(
                            severity="high",
                            title="CORS Allows Internal Origin",
                            description=f"Server accepts internal/private origin: {origin}{cred_note}. This may allow SSRF-like attacks from compromised internal hosts.",
                            phase=self.phase,
                            recommendation="Do not whitelist internal or private IP addresses in CORS policies for public-facing applications.",
                            cvss_score=7.5,
                            references=["https://portswigger.net/web-security/cors"],
                        )
                    )
                    self.finding("high", "CORS Allows Internal Origin",
                                 f"Internal origin accepted: {origin}{cred_note}", cvss_score=7.5)
                    self.asset("config", origin, f"CORS internal origin whitelisted: {origin}", "high")
                else:
                    self.log(f"[OK] Internal origin {origin} — not reflected", "success")
            except Exception as e:
                self.log(f"Internal origin test failed for {origin}: {e}", "debug")

        return findings, request_count

    async def _check_exposed_headers(self, client, base_url, request_count):
        findings = []
        self.log("Checking Access-Control-Expose-Headers for sensitive header leaks...")

        await asyncio.sleep(0.2)
        request_count += 1
        self.telemetry(requestsAnalyzed=request_count)

        try:
            resp = await client.options(
                base_url,
                headers={
                    "Origin": "https://test.example.com",
                    "Access-Control-Request-Method": "GET",
                    "User-Agent": USER_AGENT,
                },
            )
            expose_headers = resp.headers.get("Access-Control-Expose-Headers", "")

            if not expose_headers:
                resp_get = await client.get(
                    base_url,
                    headers={"Origin": "https://test.example.com", "User-Agent": USER_AGENT},
                )
                expose_headers = resp_get.headers.get("Access-Control-Expose-Headers", "")
                request_count += 1
                self.telemetry(requestsAnalyzed=request_count)

            if expose_headers:
                exposed_list = [h.strip().lower() for h in expose_headers.split(",")]
                sensitive_found = [
                    h for h in exposed_list
                    if h in self.SENSITIVE_EXPOSED_HEADERS
                ]

                if expose_headers.strip() == "*":
                    self.log("[WARN] All headers exposed via CORS (wildcard)", "warn")
                    findings.append(
                        Finding(
                            severity="medium",
                            title="CORS Exposes All Headers (Wildcard)",
                            description="Access-Control-Expose-Headers is set to '*', exposing all response headers to cross-origin requests. This may leak sensitive information.",
                            phase=self.phase,
                            recommendation="Restrict Access-Control-Expose-Headers to only necessary, non-sensitive headers.",
                            cvss_score=5.3,
                        )
                    )
                    self.finding("medium", "CORS Exposes All Headers (Wildcard)",
                                 "Access-Control-Expose-Headers: * — all headers visible cross-origin", cvss_score=5.3)
                    self.asset("config", "cors-expose-wildcard", "CORS exposes all headers via wildcard", "medium")
                elif sensitive_found:
                    headers_str = ", ".join(sensitive_found)
                    self.log(f"[WARN] Sensitive headers exposed via CORS: {headers_str}", "warn")
                    findings.append(
                        Finding(
                            severity="medium",
                            title="CORS Exposes Sensitive Headers",
                            description=f"Access-Control-Expose-Headers includes sensitive headers: {headers_str}. These headers can be read by cross-origin JavaScript.",
                            phase=self.phase,
                            recommendation="Remove sensitive headers from Access-Control-Expose-Headers. Only expose headers that cross-origin scripts legitimately need.",
                            cvss_score=5.3,
                            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers"],
                        )
                    )
                    self.finding("medium", "CORS Exposes Sensitive Headers",
                                 f"Sensitive headers exposed: {headers_str}", cvss_score=5.3)
                    self.asset("config", "cors-expose-sensitive", f"CORS exposes: {headers_str}", "medium")
                else:
                    self.log(f"[OK] Exposed headers are non-sensitive: {expose_headers}", "success")
            else:
                self.log("[OK] No Access-Control-Expose-Headers header found", "success")
        except Exception as e:
            self.log(f"Exposed headers check failed: {e}", "debug")

        return findings, request_count
