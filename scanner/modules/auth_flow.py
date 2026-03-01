import httpx
import asyncio
from .base import BaseModule
from scanner.models import Finding
from scanner.config import USER_AGENT


class AuthFlowModule(BaseModule):
    name = "Auth Flow Validation"
    phase = "simulation"
    description = "Validate authentication mechanisms, session management, and access controls"

    COMMON_ENDPOINTS = [
        ("/login", "GET"),
        ("/api/login", "POST"),
        ("/auth/login", "POST"),
        ("/register", "GET"),
        ("/api/register", "POST"),
        ("/api/user", "GET"),
        ("/api/me", "GET"),
        ("/api/profile", "GET"),
        ("/admin", "GET"),
        ("/api/admin", "GET"),
        ("/dashboard", "GET"),
        ("/api/users", "GET"),
        ("/.env", "GET"),
        ("/wp-admin", "GET"),
        ("/phpmyadmin", "GET"),
        ("/api/config", "GET"),
    ]

    async def execute(self, job) -> list:
        findings = []
        base_url = job.base_url

        self.log(f"Validating authentication flows on {base_url}")

        try:
            async with httpx.AsyncClient(
                timeout=15,
                verify=False,
                follow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                request_count = 0
                self.log("Probing common authentication and admin endpoints...")

                accessible_endpoints = []
                for path, method in self.COMMON_ENDPOINTS:
                    try:
                        if method == "GET":
                            resp = await client.get(f"{base_url}{path}")
                        else:
                            resp = await client.post(
                                f"{base_url}{path}",
                                json={"username": "test", "password": "test"},
                            )
                        request_count += 1
                        self.telemetry(requestsAnalyzed=request_count)

                        if resp.status_code < 400:
                            accessible_endpoints.append((path, resp.status_code))
                            self.log(f"  [{resp.status_code}] {method} {path} — accessible", "warn")
                        elif resp.status_code == 401:
                            self.log(f"  [401] {method} {path} — protected", "success")
                        elif resp.status_code == 403:
                            self.log(f"  [403] {method} {path} — forbidden", "success")
                        else:
                            self.log(f"  [{resp.status_code}] {method} {path}", "debug")

                        await asyncio.sleep(0.15)
                    except Exception:
                        pass

                sensitive_accessible = [
                    (p, c) for p, c in accessible_endpoints
                    if any(s in p for s in ["/admin", "/api/users", "/.env", "/config", "/phpmyadmin", "/wp-admin"])
                ]
                if sensitive_accessible:
                    paths = ", ".join(f"{p} ({c})" for p, c in sensitive_accessible)
                    findings.append(
                        Finding(
                            severity="critical",
                            title="Sensitive Endpoints Accessible Without Auth",
                            description=f"The following sensitive endpoints are accessible without authentication: {paths}",
                            phase=self.phase,
                            recommendation="Implement authentication and authorization checks on all sensitive endpoints.",
                            cvss_score=9.1,
                            references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                        )
                    )
                    self.finding("critical", "Sensitive Endpoints Exposed",
                                 f"Accessible: {paths[:100]}", cvss_score=9.1)

                self.log("Testing session security...")
                for path, method in [("/login", "GET"), ("/api/login", "POST")]:
                    try:
                        if method == "POST":
                            resp = await client.post(
                                f"{base_url}{path}",
                                json={"username": "test", "password": "test"},
                            )
                        else:
                            resp = await client.get(f"{base_url}{path}")
                        request_count += 1
                        self.telemetry(requestsAnalyzed=request_count)

                        set_cookie = resp.headers.get("set-cookie", "")
                        if set_cookie:
                            self.log(f"Session cookie detected on {path}")
                            cookie_lower = set_cookie.lower()
                            issues = []
                            if "httponly" not in cookie_lower:
                                issues.append("Missing HttpOnly")
                            if "secure" not in cookie_lower:
                                issues.append("Missing Secure")
                            if "samesite" not in cookie_lower:
                                issues.append("Missing SameSite")

                            if issues:
                                desc = f"Session cookie on {path}: {'; '.join(issues)}"
                                findings.append(
                                    Finding(
                                        severity="medium",
                                        title="Insecure Session Cookie",
                                        description=desc,
                                        phase=self.phase,
                                        recommendation="Configure session cookies with HttpOnly, Secure, and SameSite=Strict flags.",
                                        cvss_score=5.4,
                                    )
                                )
                                self.finding("medium", "Insecure Session Cookie", desc[:100], cvss_score=5.4)
                    except Exception:
                        pass

                self.log("Checking for default credentials indicators...")
                for path in ["/api/health", "/api/status", "/health", "/status"]:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        request_count += 1
                        if resp.status_code == 200:
                            body = resp.text.lower()
                            if any(kw in body for kw in ["debug", "stack", "traceback", "exception"]):
                                findings.append(
                                    Finding(
                                        severity="medium",
                                        title="Debug Information Exposed",
                                        description=f"Debug/error information exposed on {path}",
                                        phase=self.phase,
                                        recommendation="Disable debug mode in production. Do not expose stack traces or internal error details.",
                                        cvss_score=5.3,
                                    )
                                )
                                self.finding("medium", "Debug Info Exposed", f"Endpoint: {path}", cvss_score=5.3)
                    except Exception:
                        pass

                self.telemetry(requestsAnalyzed=request_count)

        except Exception as e:
            self.log(f"Auth flow validation error: {e}", "error")

        self.log(f"Auth flow validation complete — {len(findings)} finding(s)")
        return findings
