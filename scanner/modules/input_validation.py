import httpx
import asyncio
import re
from .base import BaseModule
from scanner.models import Finding
from scanner.config import USER_AGENT


class InputValidationModule(BaseModule):
    name = "Input Validation Stress Test"
    phase = "simulation"
    description = "Non-destructive input validation testing — checks how the application handles malformed input"

    SAFE_PAYLOADS = [
        {"name": "XSS Probe (reflected)", "payload": "<script>alert(1)</script>", "detect": "<script>alert(1)</script>"},
        {"name": "XSS Probe (event)", "payload": '"><img src=x onerror=alert(1)>', "detect": 'onerror=alert(1)'},
        {"name": "SQL Injection Probe", "payload": "' OR '1'='1", "detect": "error|exception|syntax|mysql|postgresql|sqlite|odbc"},
        {"name": "Path Traversal Probe", "payload": "../../etc/passwd", "detect": "root:"},
        {"name": "SSTI Probe", "payload": "{{7*7}}", "detect": "49"},
        {"name": "Command Injection Probe", "payload": ";echo test123;", "detect": "test123"},
        {"name": "LDAP Injection Probe", "payload": "*)(&", "detect": "ldap|directory"},
        {"name": "Long Input", "payload": "A" * 10000, "detect": ""},
        {"name": "Unicode Probe", "payload": "\u0000\uffff\ud800", "detect": ""},
        {"name": "Special Characters", "payload": "!@#$%^&*(){}[]|\\;:'\"<>?,./`~", "detect": ""},
        {"name": "NoSQL Injection Probe", "payload": '{"$gt":""}', "detect": "error|exception|mongo"},
        {"name": "JSON Prototype Pollution", "payload": '{"__proto__":{"admin":true}}', "detect": ""},
    ]

    SSRF_PAYLOADS = [
        {"name": "AWS Metadata", "url": "http://169.254.169.254/latest/meta-data/", "detect": "ami-id|instance-id|hostname|iam"},
        {"name": "Localhost Redis", "url": "http://127.0.0.1:6379", "detect": "redis|REDIS|ERR"},
        {"name": "IPv6 Loopback", "url": "http://[::1]", "detect": ""},
        {"name": "Hex Loopback", "url": "http://0x7f000001", "detect": ""},
    ]

    OPEN_REDIRECT_PARAMS = [
        {"param": "redirect", "value": "https://evil.com"},
        {"param": "url", "value": "//evil.com"},
        {"param": "next", "value": "https://evil.com"},
    ]

    IDOR_PATHS = [
        "/api/users/1",
        "/api/users/2",
        "/api/orders/1",
    ]

    VERB_TAMPERING_METHODS = ["PUT", "DELETE", "PATCH"]

    XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<foo>&xxe;</foo>"""

    async def execute(self, job) -> list:
        findings = []
        base_url = job.base_url

        self.log(f"Running non-destructive input validation tests on {base_url}")
        self.log("Note: These tests use benign probe payloads only")

        try:
            async with httpx.AsyncClient(
                timeout=15,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                request_count = 0

                self.log("Testing URL parameter handling...")
                for test in self.SAFE_PAYLOADS:
                    try:
                        resp = await client.get(
                            f"{base_url}/search",
                            params={"q": test["payload"]},
                        )
                        request_count += 1
                        self.telemetry(requestsAnalyzed=request_count)

                        body = resp.text

                        if test["detect"] and test["detect"] in body:
                            severity = "high" if "xss" in test["name"].lower() or "sql" in test["name"].lower() else "medium"
                            findings.append(
                                Finding(
                                    severity=severity,
                                    title=f"Potential {test['name']} Vulnerability",
                                    description=f"Input probe was reflected/triggered in response. Payload: {test['payload'][:50]}",
                                    phase=self.phase,
                                    recommendation="Implement proper input validation and output encoding. Use parameterized queries for database operations.",
                                    cvss_score=7.5 if severity == "high" else 5.3,
                                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                                )
                            )
                            self.finding(severity, f"Potential {test['name']}",
                                         f"Probe reflected in response", cvss_score=7.5 if severity == "high" else 5.3)
                            self.log(f"  [FAIL] {test['name']} — probe detected in response!", "error")
                        elif test["detect"] and re.search(test["detect"], body, re.IGNORECASE):
                            self.log(f"  [WARN] {test['name']} — pattern match detected", "warn")
                            findings.append(
                                Finding(
                                    severity="medium",
                                    title=f"Suspicious Response: {test['name']}",
                                    description=f"Response contains patterns matching {test['name']} indicators",
                                    phase=self.phase,
                                    recommendation="Review input handling and error responses for information leakage.",
                                    cvss_score=5.3,
                                )
                            )
                            self.finding("medium", f"Suspicious: {test['name']}",
                                         "Pattern match in response", cvss_score=5.3)
                        else:
                            self.log(f"  [PASS] {test['name']} — properly handled", "success")

                        if resp.status_code >= 500:
                            findings.append(
                                Finding(
                                    severity="medium",
                                    title=f"Server Error on Input: {test['name']}",
                                    description=f"Server returned {resp.status_code} for input probe: {test['payload'][:30]}",
                                    phase=self.phase,
                                    recommendation="Implement proper error handling. Never return 500 errors for malformed input.",
                                    cvss_score=5.3,
                                )
                            )
                            self.finding("medium", f"Server Error: {test['name']}",
                                         f"HTTP {resp.status_code} on malformed input", cvss_score=5.3)

                        await asyncio.sleep(0.15)
                    except Exception:
                        pass

                self.log("Testing response error handling...")
                error_paths = [
                    "/nonexistent-path-12345",
                    "/api/v99/invalid",
                    "/%00%0a%0d",
                ]
                for path in error_paths:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        request_count += 1
                        self.telemetry(requestsAnalyzed=request_count)
                        body = resp.text.lower()

                        if any(kw in body for kw in ["stack trace", "traceback", "at com.", "at org.", "file \"", "line ", "exception in"]):
                            findings.append(
                                Finding(
                                    severity="medium",
                                    title="Verbose Error Messages",
                                    description=f"Error page at {path} reveals internal application details (stack traces, file paths)",
                                    phase=self.phase,
                                    recommendation="Configure custom error pages that do not reveal internal implementation details.",
                                    cvss_score=5.3,
                                )
                            )
                            self.finding("medium", "Verbose Error Messages",
                                         f"Stack trace exposed on {path}", cvss_score=5.3)
                            self.log(f"  [WARN] Verbose error on {path}", "warn")
                        else:
                            self.log(f"  [PASS] Error page on {path} — no leakage", "success")
                    except Exception:
                        pass

                ssrf_findings = await self._test_ssrf(client, base_url)
                findings.extend(ssrf_findings)

                xxe_findings = await self._test_xxe(client, base_url)
                findings.extend(xxe_findings)

                idor_findings = await self._test_idor(client, base_url)
                findings.extend(idor_findings)

                redirect_findings = await self._test_open_redirect(client, base_url)
                findings.extend(redirect_findings)

                verb_findings = await self._test_verb_tampering(client, base_url)
                findings.extend(verb_findings)

        except Exception as e:
            self.log(f"Input validation test error: {e}", "error")

        self.log(f"Input validation tests complete — {len(findings)} finding(s)")
        return findings

    async def _test_ssrf(self, client, base_url) -> list:
        findings = []
        self.log("Testing for SSRF vulnerabilities...")
        for test in self.SSRF_PAYLOADS:
            try:
                for param_name in ["url", "target", "dest", "redirect", "uri", "path", "page", "feed", "host"]:
                    resp = await client.get(
                        base_url,
                        params={param_name: test["url"]},
                    )
                    body = resp.text

                    if test["detect"] and re.search(test["detect"], body, re.IGNORECASE):
                        findings.append(
                            Finding(
                                severity="critical",
                                title=f"Potential SSRF: {test['name']}",
                                description=f"Server responded with internal data when URL parameter '{param_name}' was set to {test['url']}",
                                phase=self.phase,
                                recommendation="Implement server-side URL validation. Block requests to internal/private IP ranges and metadata endpoints.",
                                cvss_score=9.1,
                                references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                            )
                        )
                        self.finding("critical", f"Potential SSRF: {test['name']}",
                                     f"Internal data detected via param '{param_name}'", cvss_score=9.1)
                        self.asset("vulnerability", f"?{param_name}={test['url']}", f"SSRF vector: {test['name']}", "critical", "ssrf")
                        self.log(f"  [FAIL] SSRF {test['name']} via '{param_name}' — internal data leaked!", "error")
                        break
                    await asyncio.sleep(0.1)
                else:
                    self.log(f"  [PASS] SSRF {test['name']} — no internal data leaked", "success")
            except Exception:
                pass
        return findings

    async def _test_xxe(self, client, base_url) -> list:
        findings = []
        self.log("Testing for XXE vulnerabilities...")
        try:
            xxe_endpoints = [
                base_url,
                f"{base_url}/api",
                f"{base_url}/upload",
                f"{base_url}/xml",
                f"{base_url}/soap",
            ]
            for endpoint in xxe_endpoints:
                try:
                    resp = await client.post(
                        endpoint,
                        content=self.XXE_PAYLOAD,
                        headers={"Content-Type": "application/xml"},
                    )
                    body = resp.text

                    if resp.status_code < 500 and any(indicator in body.lower() for indicator in ["root:", "localhost", "etc/passwd", "hostname"]):
                        findings.append(
                            Finding(
                                severity="critical",
                                title="Potential XXE Injection",
                                description=f"XML External Entity processing detected at {endpoint}. The server appears to process DTD declarations.",
                                phase=self.phase,
                                recommendation="Disable DTD processing in XML parsers. Use JSON instead of XML where possible.",
                                cvss_score=9.1,
                                references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                            )
                        )
                        self.finding("critical", "Potential XXE Injection",
                                     f"XML entity processing detected at {endpoint}", cvss_score=9.1)
                        self.asset("vulnerability", endpoint, "XXE injection vector", "critical", "xxe")
                        self.log(f"  [FAIL] XXE detected at {endpoint}!", "error")
                    else:
                        self.log(f"  [PASS] XXE test on {endpoint} — safe", "success")
                    await asyncio.sleep(0.15)
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    async def _test_idor(self, client, base_url) -> list:
        findings = []
        self.log("Testing for IDOR vulnerabilities...")
        for path in self.IDOR_PATHS:
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code == 200:
                    body = resp.text
                    if len(body) > 10 and "not found" not in body.lower() and "unauthorized" not in body.lower():
                        findings.append(
                            Finding(
                                severity="high",
                                title=f"Potential IDOR: {path}",
                                description=f"Sequential ID endpoint {path} returned 200 OK with content, potentially exposing data without authentication.",
                                phase=self.phase,
                                recommendation="Implement proper authorization checks. Use UUIDs instead of sequential IDs. Verify user ownership before returning data.",
                                cvss_score=7.5,
                                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"],
                            )
                        )
                        self.finding("high", f"Potential IDOR: {path}",
                                     f"Sequential ID endpoint accessible without auth", cvss_score=7.5)
                        self.asset("endpoint", path, f"IDOR candidate: {path}", "high", "idor")
                        self.log(f"  [WARN] IDOR candidate at {path} — 200 OK with content", "warn")
                    else:
                        self.log(f"  [PASS] {path} — response not indicative of IDOR", "success")
                else:
                    self.log(f"  [PASS] {path} — HTTP {resp.status_code}", "success")
                await asyncio.sleep(0.1)
            except Exception:
                pass
        return findings

    async def _test_open_redirect(self, client, base_url) -> list:
        findings = []
        self.log("Testing for open redirect vulnerabilities...")
        for test in self.OPEN_REDIRECT_PARAMS:
            try:
                resp = await client.get(
                    base_url,
                    params={test["param"]: test["value"]},
                    follow_redirects=False,
                )
                location = resp.headers.get("location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and ("evil.com" in location):
                    findings.append(
                        Finding(
                            severity="medium",
                            title="Open Redirect Detected",
                            description=f"Parameter '{test['param']}' with value '{test['value']}' causes redirect to external domain. Location: {location}",
                            phase=self.phase,
                            recommendation="Validate redirect URLs against a whitelist. Do not allow user-controlled redirect targets to external domains.",
                            cvss_score=6.1,
                            references=["https://cwe.mitre.org/data/definitions/601.html"],
                        )
                    )
                    self.finding("medium", "Open Redirect Detected",
                                 f"Redirect via '{test['param']}' to external domain", cvss_score=6.1)
                    self.asset("vulnerability", f"?{test['param']}={test['value']}", f"Open redirect: {test['param']}", "medium", "redirect")
                    self.log(f"  [FAIL] Open redirect via '{test['param']}' → {location}", "error")
                else:
                    self.log(f"  [PASS] No open redirect via '{test['param']}'", "success")
                await asyncio.sleep(0.1)
            except Exception:
                pass
        return findings

    async def _test_verb_tampering(self, client, base_url) -> list:
        findings = []
        self.log("Testing HTTP verb tampering...")
        for method in self.VERB_TAMPERING_METHODS:
            try:
                resp = await client.request(method, base_url)
                if resp.status_code == 200:
                    findings.append(
                        Finding(
                            severity="medium",
                            title=f"HTTP {method} Method Accepted",
                            description=f"The server accepted an HTTP {method} request on the base URL and returned 200 OK. This may indicate improper method restriction.",
                            phase=self.phase,
                            recommendation="Restrict HTTP methods to only those required. Return 405 Method Not Allowed for unsupported methods.",
                            cvss_score=5.3,
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"],
                        )
                    )
                    self.finding("medium", f"HTTP {method} Method Accepted",
                                 f"{method} returned 200 OK on base URL", cvss_score=5.3)
                    self.asset("config", base_url, f"Verb tampering: {method} allowed", "medium", "verb-tampering")
                    self.log(f"  [WARN] HTTP {method} accepted (200 OK)", "warn")
                else:
                    self.log(f"  [PASS] HTTP {method} — {resp.status_code}", "success")
                await asyncio.sleep(0.1)
            except Exception:
                pass
        return findings
