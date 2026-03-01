import re
import httpx
import asyncio
from .base import BaseModule
from scanner.models import Finding
from scanner.config import USER_AGENT


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "title": "Missing HSTS Header",
        "description": "Strict-Transport-Security header is not set. Users may connect over insecure HTTP.",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
        "cvss_score": 6.1,
    },
    "Content-Security-Policy": {
        "severity": "high",
        "title": "Missing Content-Security-Policy",
        "description": "CSP header is not configured. Application is vulnerable to XSS and data injection attacks.",
        "recommendation": "Implement a strict Content-Security-Policy. Start with 'default-src self' and expand as needed.",
        "cvss_score": 6.5,
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "title": "Missing X-Content-Type-Options",
        "description": "Browser may MIME-sniff responses, potentially executing malicious content.",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header.",
        "cvss_score": 4.3,
    },
    "X-Frame-Options": {
        "severity": "medium",
        "title": "Missing X-Frame-Options",
        "description": "Application may be vulnerable to clickjacking attacks via iframes.",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header. Alternatively, use CSP frame-ancestors.",
        "cvss_score": 4.7,
    },
    "X-XSS-Protection": {
        "severity": "low",
        "title": "Missing X-XSS-Protection",
        "description": "Legacy XSS protection header not set (still useful for older browsers).",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' header.",
        "cvss_score": 2.1,
    },
    "Referrer-Policy": {
        "severity": "low",
        "title": "Missing Referrer-Policy",
        "description": "Browser may leak referrer information to third-party sites.",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
        "cvss_score": 3.1,
    },
    "Permissions-Policy": {
        "severity": "low",
        "title": "Missing Permissions-Policy",
        "description": "Browser features (camera, microphone, geolocation) are not restricted.",
        "recommendation": "Add Permissions-Policy header to limit browser feature access.",
        "cvss_score": 2.5,
    },
}

DANGEROUS_HEADERS = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

CROSS_ORIGIN_HEADERS = {
    "Cross-Origin-Embedder-Policy": {
        "severity": "low",
        "title": "Missing Cross-Origin-Embedder-Policy",
        "description": "Cross-Origin-Embedder-Policy (COEP) header is not set. This header helps prevent cross-origin resource loading without explicit permission.",
        "recommendation": "Add 'Cross-Origin-Embedder-Policy: require-corp' header.",
        "cvss_score": 3.0,
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "title": "Missing Cross-Origin-Opener-Policy",
        "description": "Cross-Origin-Opener-Policy (COOP) header is not set. Without it, cross-origin windows may access this window's context.",
        "recommendation": "Add 'Cross-Origin-Opener-Policy: same-origin' header.",
        "cvss_score": 3.0,
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "low",
        "title": "Missing Cross-Origin-Resource-Policy",
        "description": "Cross-Origin-Resource-Policy (CORP) header is not set. Resources may be loaded by cross-origin documents.",
        "recommendation": "Add 'Cross-Origin-Resource-Policy: same-origin' or 'same-site' header.",
        "cvss_score": 3.0,
    },
}

CSP_DANGEROUS_DIRECTIVES = {
    "unsafe-inline": {
        "severity": "high",
        "title": "Weak CSP: unsafe-inline Detected",
        "description": "Content-Security-Policy contains 'unsafe-inline', which allows inline scripts and styles, defeating the purpose of CSP against XSS attacks.",
        "recommendation": "Remove 'unsafe-inline' from CSP and use nonces or hashes for inline scripts.",
        "cvss_score": 6.5,
    },
    "unsafe-eval": {
        "severity": "high",
        "title": "Weak CSP: unsafe-eval Detected",
        "description": "Content-Security-Policy contains 'unsafe-eval', which allows use of eval() and similar dynamic code execution, increasing XSS risk.",
        "recommendation": "Remove 'unsafe-eval' from CSP and refactor code to avoid eval().",
        "cvss_score": 6.5,
    },
}

SERVER_VERSION_PATTERN = re.compile(
    r"(Apache|nginx|Microsoft-IIS|LiteSpeed|Caddy|OpenResty|Tomcat|Jetty|Envoy|Gunicorn|Werkzeug|Express)"
    r"[/\s](\d+[\.\d]*)",
    re.IGNORECASE,
)


class HeadersAnalyzerModule(BaseModule):
    name = "HTTP Security Headers Analyzer"
    phase = "misconfig"
    description = "Analyze HTTP response headers for security misconfigurations"

    async def execute(self, job) -> list:
        findings = []
        base_url = job.base_url

        self.log(f"Fetching HTTP headers from {base_url}")

        try:
            async with httpx.AsyncClient(
                timeout=15,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                resp = await client.get(base_url)
                headers = resp.headers

                self.log(f"HTTP {resp.status_code} — {len(headers)} headers received", "success")
                self.telemetry(requestsAnalyzed=1)

                self.log("Checking security headers...")
                present = []
                missing = []
                for header_name, config in SECURITY_HEADERS.items():
                    value = headers.get(header_name)
                    if value:
                        present.append(header_name)
                        self.log(f"  [PASS] {header_name}: {value[:80]}", "success")
                    else:
                        missing.append(header_name)
                        self.log(f"  [FAIL] {header_name}: NOT SET", "warn")
                        findings.append(
                            Finding(
                                severity=config["severity"],
                                title=config["title"],
                                description=config["description"],
                                phase=self.phase,
                                recommendation=config["recommendation"],
                                cvss_score=config["cvss_score"],
                            )
                        )
                        self.finding(
                            config["severity"],
                            config["title"],
                            config["description"][:100],
                            cvss_score=config["cvss_score"],
                        )

                score = (len(present) / len(SECURITY_HEADERS)) * 100
                self.log(f"Security headers score: {score:.0f}% ({len(present)}/{len(SECURITY_HEADERS)})")

                self.log("Checking for information leakage headers...")
                for h in DANGEROUS_HEADERS:
                    val = headers.get(h)
                    if val:
                        self.log(f"  [WARN] {h}: {val}", "warn")
                        findings.append(
                            Finding(
                                severity="low",
                                title=f"Information Leakage: {h}",
                                description=f"Header {h} reveals: {val}",
                                phase=self.phase,
                                recommendation=f"Remove the {h} header from HTTP responses.",
                                cvss_score=3.1,
                            )
                        )
                        self.finding("low", f"Info Leak: {h}", f"{h}: {val}", cvss_score=3.1)

                cookie_header = headers.get("set-cookie", "")
                if cookie_header:
                    self.log("Analyzing cookie security...")
                    cookie_lower = cookie_header.lower()
                    issues = []
                    if "secure" not in cookie_lower:
                        issues.append("Missing Secure flag")
                    if "httponly" not in cookie_lower:
                        issues.append("Missing HttpOnly flag")
                    if "samesite" not in cookie_lower:
                        issues.append("Missing SameSite attribute")

                    if issues:
                        desc = f"Cookie security issues: {'; '.join(issues)}"
                        findings.append(
                            Finding(
                                severity="medium",
                                title="Insecure Cookie Configuration",
                                description=desc,
                                phase=self.phase,
                                recommendation="Set Secure, HttpOnly, and SameSite=Strict attributes on all cookies.",
                                cvss_score=5.4,
                            )
                        )
                        self.finding("medium", "Insecure Cookie Configuration", desc[:100], cvss_score=5.4)
                        self.log(f"  [WARN] {desc}", "warn")
                    else:
                        self.log("  [PASS] Cookie security attributes present", "success")

                findings.extend(self._analyze_csp_deep(headers))
                findings.extend(self._analyze_hsts_deep(headers))
                findings.extend(self._check_server_version(headers))
                findings.extend(self._check_cross_origin_policies(headers))
                findings.extend(self._check_cookie_prefixes(headers))

        except httpx.ConnectError as e:
            self.log(f"Connection failed: {e}", "error")
        except Exception as e:
            self.log(f"Header analysis error: {e}", "error")

        self.log(f"Header analysis complete — {len(findings)} finding(s)")
        return findings

    def _analyze_csp_deep(self, headers) -> list:
        findings = []
        csp = headers.get("Content-Security-Policy")
        if not csp:
            return findings

        self.log("Deep CSP analysis...")

        for keyword, config in CSP_DANGEROUS_DIRECTIVES.items():
            if keyword in csp:
                self.log(f"  [WARN] CSP contains '{keyword}'", "warn")
                findings.append(
                    Finding(
                        severity=config["severity"],
                        title=config["title"],
                        description=config["description"],
                        phase=self.phase,
                        recommendation=config["recommendation"],
                        cvss_score=config["cvss_score"],
                    )
                )
                self.finding(config["severity"], config["title"], config["description"][:100], cvss_score=config["cvss_score"])
                self.asset("config", "CSP", f"CSP directive: {keyword}", config["severity"], category="csp")

        directives = csp.split(";")
        for directive in directives:
            directive = directive.strip()
            if not directive:
                continue

            parts = directive.split()
            if len(parts) < 2:
                continue

            directive_name = parts[0]
            sources = parts[1:]

            for src in sources:
                if src.strip() == "*":
                    title = f"Weak CSP: Wildcard Source in {directive_name}"
                    desc = f"CSP directive '{directive_name}' uses wildcard source '*', allowing resources from any origin."
                    self.log(f"  [WARN] Wildcard '*' in {directive_name}", "warn")
                    findings.append(
                        Finding(
                            severity="high",
                            title=title,
                            description=desc,
                            phase=self.phase,
                            recommendation=f"Replace wildcard in '{directive_name}' with specific trusted domains.",
                            cvss_score=6.0,
                        )
                    )
                    self.finding("high", title, desc[:100], cvss_score=6.0)
                    self.asset("config", "CSP", f"Wildcard in {directive_name}", "high", category="csp")

                if src.strip().startswith("data:"):
                    title = f"Weak CSP: data: URI in {directive_name}"
                    desc = f"CSP directive '{directive_name}' allows 'data:' URIs, which can be used to inject executable content."
                    self.log(f"  [WARN] data: URI in {directive_name}", "warn")
                    findings.append(
                        Finding(
                            severity="medium",
                            title=title,
                            description=desc,
                            phase=self.phase,
                            recommendation=f"Remove 'data:' from '{directive_name}' unless absolutely required.",
                            cvss_score=5.0,
                        )
                    )
                    self.finding("medium", title, desc[:100], cvss_score=5.0)
                    self.asset("config", "CSP", f"data: URI in {directive_name}", "medium", category="csp")

            non_self_sources = [s for s in sources if s not in ("'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'report-sample'") and not s.startswith("'nonce-") and not s.startswith("'sha")]
            domain_sources = [s for s in non_self_sources if s not in ("data:", "blob:", "mediastream:", "filesystem:", "*")]
            if len(domain_sources) > 5:
                title = f"Weak CSP: Overly Broad Whitelist in {directive_name}"
                desc = f"CSP directive '{directive_name}' whitelists {len(domain_sources)} domains, increasing the attack surface."
                self.log(f"  [WARN] {len(domain_sources)} domains whitelisted in {directive_name}", "warn")
                findings.append(
                    Finding(
                        severity="medium",
                        title=title,
                        description=desc,
                        phase=self.phase,
                        recommendation=f"Reduce the number of whitelisted domains in '{directive_name}'. Consider using nonces or hashes.",
                        cvss_score=4.5,
                    )
                )
                self.finding("medium", title, desc[:100], cvss_score=4.5)
                self.asset("config", "CSP", f"Broad whitelist in {directive_name}: {len(domain_sources)} domains", "medium", category="csp")

        if findings:
            self.log(f"  CSP deep analysis found {len(findings)} issue(s)", "warn")
        else:
            self.log("  [PASS] CSP appears well configured", "success")

        return findings

    def _analyze_hsts_deep(self, headers) -> list:
        findings = []
        hsts = headers.get("Strict-Transport-Security")
        if not hsts:
            return findings

        self.log("Deep HSTS analysis...")

        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            min_recommended = 15768000
            if max_age < min_recommended:
                title = "HSTS Max-Age Below Recommended Minimum"
                desc = f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). Recommended minimum is {min_recommended} seconds (6 months)."
                self.log(f"  [WARN] max-age={max_age} < {min_recommended}", "warn")
                findings.append(
                    Finding(
                        severity="medium",
                        title=title,
                        description=desc,
                        phase=self.phase,
                        recommendation=f"Increase HSTS max-age to at least {min_recommended} seconds (6 months), ideally 31536000 (1 year).",
                        cvss_score=4.0,
                    )
                )
                self.finding("medium", title, desc[:100], cvss_score=4.0)
                self.asset("config", "HSTS", f"max-age={max_age}", "medium", category="hsts")
            else:
                self.log(f"  [PASS] max-age={max_age} (adequate)", "success")
        else:
            title = "HSTS Missing max-age Directive"
            desc = "HSTS header is present but missing the required max-age directive."
            self.log("  [WARN] max-age directive missing", "warn")
            findings.append(
                Finding(
                    severity="medium",
                    title=title,
                    description=desc,
                    phase=self.phase,
                    recommendation="Add max-age directive to HSTS header.",
                    cvss_score=4.0,
                )
            )
            self.finding("medium", title, desc[:100], cvss_score=4.0)

        hsts_lower = hsts.lower()

        if "includesubdomains" not in hsts_lower:
            title = "HSTS Missing includeSubDomains"
            desc = "HSTS header does not include 'includeSubDomains'. Subdomains may still be accessed over insecure HTTP."
            self.log("  [WARN] includeSubDomains not set", "warn")
            findings.append(
                Finding(
                    severity="low",
                    title=title,
                    description=desc,
                    phase=self.phase,
                    recommendation="Add 'includeSubDomains' to HSTS header to protect all subdomains.",
                    cvss_score=3.0,
                )
            )
            self.finding("low", title, desc[:100], cvss_score=3.0)
            self.asset("config", "HSTS", "Missing includeSubDomains", "low", category="hsts")
        else:
            self.log("  [PASS] includeSubDomains present", "success")

        if "preload" not in hsts_lower:
            title = "HSTS Missing preload Directive"
            desc = "HSTS header does not include 'preload'. The domain is not eligible for browser HSTS preload lists."
            self.log("  [INFO] preload not set", "info")
            findings.append(
                Finding(
                    severity="info",
                    title=title,
                    description=desc,
                    phase=self.phase,
                    recommendation="Add 'preload' to HSTS header and submit to hstspreload.org for inclusion in browser preload lists.",
                    cvss_score=1.0,
                )
            )
            self.finding("info", title, desc[:100], cvss_score=1.0)
        else:
            self.log("  [PASS] preload present", "success")

        return findings

    def _check_server_version(self, headers) -> list:
        findings = []
        server = headers.get("Server", "")
        if not server:
            return findings

        self.log("Checking Server header for version disclosure...")

        match = SERVER_VERSION_PATTERN.search(server)
        if match:
            software = match.group(1)
            version = match.group(2)
            title = f"Server Version Disclosure: {software}/{version}"
            desc = f"The Server header reveals '{server}', disclosing the web server software and version. This information aids attackers in targeting known vulnerabilities."
            self.log(f"  [WARN] Server version disclosed: {software}/{version}", "warn")
            findings.append(
                Finding(
                    severity="medium",
                    title=title,
                    description=desc,
                    phase=self.phase,
                    recommendation="Remove or obfuscate the Server header to prevent version disclosure. Configure the server to return a generic value.",
                    cvss_score=5.3,
                )
            )
            self.finding("medium", title, desc[:100], cvss_score=5.3)
            self.asset("config", "Server", f"Version: {software}/{version}", "medium", category="server-info")
        else:
            self.log(f"  [PASS] Server header present but no version detected: {server[:60]}", "success")

        return findings

    def _check_cross_origin_policies(self, headers) -> list:
        findings = []
        self.log("Checking Cross-Origin policy headers...")

        for header_name, config in CROSS_ORIGIN_HEADERS.items():
            value = headers.get(header_name)
            if value:
                self.log(f"  [PASS] {header_name}: {value[:80]}", "success")
            else:
                self.log(f"  [FAIL] {header_name}: NOT SET", "warn")
                findings.append(
                    Finding(
                        severity=config["severity"],
                        title=config["title"],
                        description=config["description"],
                        phase=self.phase,
                        recommendation=config["recommendation"],
                        cvss_score=config["cvss_score"],
                    )
                )
                self.finding(config["severity"], config["title"], config["description"][:100], cvss_score=config["cvss_score"])
                self.asset("config", header_name, f"Missing {header_name}", config["severity"], category="cross-origin")

        return findings

    def _check_cookie_prefixes(self, headers) -> list:
        findings = []
        all_cookies = headers.get_list("set-cookie") if hasattr(headers, "get_list") else []
        if not all_cookies:
            raw = headers.get("set-cookie", "")
            if raw:
                all_cookies = [raw]

        if not all_cookies:
            return findings

        self.log("Checking cookie prefixes...")

        for cookie_str in all_cookies:
            cookie_lower = cookie_str.lower()
            name_part = cookie_str.split("=", 1)[0].strip()

            is_secure = "secure" in cookie_lower
            has_path_root = "path=/" in cookie_lower.replace(" ", "")
            has_domain = "domain=" in cookie_lower

            if is_secure and has_path_root and not has_domain:
                if not name_part.startswith("__Host-"):
                    title = f"Cookie Missing __Host- Prefix: {name_part}"
                    desc = f"Cookie '{name_part}' has Secure flag, Path=/, and no Domain attribute — it should use the '__Host-' prefix for stronger security binding."
                    self.log(f"  [WARN] Cookie '{name_part}' should use __Host- prefix", "warn")
                    findings.append(
                        Finding(
                            severity="low",
                            title=title,
                            description=desc,
                            phase=self.phase,
                            recommendation=f"Rename cookie '{name_part}' to '__Host-{name_part}' to enforce origin-bound cookie behavior.",
                            cvss_score=2.5,
                        )
                    )
                    self.finding("low", title, desc[:100], cvss_score=2.5)
                    self.asset("config", "Cookie", f"Missing __Host- prefix: {name_part}", "low", category="cookie")
            elif is_secure:
                if not name_part.startswith("__Secure-") and not name_part.startswith("__Host-"):
                    title = f"Cookie Missing __Secure- Prefix: {name_part}"
                    desc = f"Cookie '{name_part}' has the Secure flag but does not use the '__Secure-' prefix, missing an opportunity for additional security."
                    self.log(f"  [INFO] Cookie '{name_part}' could use __Secure- prefix", "info")
                    findings.append(
                        Finding(
                            severity="info",
                            title=title,
                            description=desc,
                            phase=self.phase,
                            recommendation=f"Consider renaming cookie '{name_part}' to '__Secure-{name_part}' to ensure it's only sent over HTTPS.",
                            cvss_score=1.0,
                        )
                    )
                    self.finding("info", title, desc[:100], cvss_score=1.0)
                    self.asset("config", "Cookie", f"Missing __Secure- prefix: {name_part}", "info", category="cookie")

        return findings
