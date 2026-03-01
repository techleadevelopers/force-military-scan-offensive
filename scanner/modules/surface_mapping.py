import socket
import ssl
import asyncio
from urllib.parse import urlparse
from .base import BaseModule
from scanner.models import Finding


class SurfaceMappingModule(BaseModule):
    name = "Surface Mapping"
    phase = "surface"
    description = "Attack surface enumeration: DNS resolution, port scanning, technology fingerprinting"

    COMMON_PORTS = [
        21, 22, 25, 53, 80, 110, 143, 443, 993, 995,
        3306, 3389, 5432, 6379, 8080, 8443, 8888, 9090,
        27017, 11211, 9200, 5601, 2379, 4443, 15672, 9042,
    ]

    COMMON_SUBDOMAINS = [
        "api", "admin", "dev", "staging", "test", "beta", "mail", "ftp",
        "vpn", "cdn", "ci", "jenkins", "gitlab", "jira", "dashboard",
        "internal", "portal", "db", "backup", "m", "mobile", "app",
        "ws", "socket", "status", "monitor", "grafana", "kibana",
        "docs", "wiki",
    ]

    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD"]

    async def execute(self, job) -> list:
        findings = []
        hostname = job.hostname
        base_url = job.base_url

        self.log(f"Target: {base_url}")
        self.log(f"Resolving DNS for {hostname}...")

        try:
            addrs = socket.getaddrinfo(hostname, None)
            unique_ips = list(set(addr[4][0] for addr in addrs))
            self.log(f"DNS resolved: {', '.join(unique_ips)}", "success")

            for ip in unique_ips:
                try:
                    reverse = socket.gethostbyaddr(ip)
                    self.log(f"Reverse DNS for {ip}: {reverse[0]}")
                except socket.herror:
                    self.log(f"No reverse DNS for {ip}", "debug")
        except socket.gaierror as e:
            self.log(f"DNS resolution failed: {e}", "error")
            findings.append(
                Finding(
                    severity="info",
                    title="DNS Resolution Failed",
                    description=f"Could not resolve {hostname}: {e}",
                    phase=self.phase,
                    recommendation="Verify the target hostname is correct and DNS is properly configured.",
                )
            )
            return findings

        subdomain_findings = await self._enumerate_subdomains(hostname)
        findings.extend(subdomain_findings)

        self.log("Scanning common service ports...")
        self.telemetry(activeModules=1)
        open_ports = []
        scanned = 0
        for port in self.COMMON_PORTS:
            scanned += 1
            self.telemetry(requestsAnalyzed=scanned)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    service = self._identify_service(port)
                    open_ports.append((port, service))
                    self.log(f"  Port {port}/{service} — OPEN", "warn")
                await asyncio.sleep(0.1)
            except Exception:
                pass

        if open_ports:
            port_list = ", ".join(f"{p}/{s}" for p, s in open_ports)
            self.log(f"Open ports found: {port_list}", "success")

            risky_ports = [p for p, s in open_ports if p in (21, 22, 3306, 5432, 6379, 3389, 27017, 11211, 9200, 2379, 9042)]
            if risky_ports:
                findings.append(
                    Finding(
                        severity="medium",
                        title="Sensitive Services Exposed",
                        description=f"Potentially sensitive ports open: {', '.join(str(p) for p in risky_ports)}",
                        phase=self.phase,
                        recommendation="Restrict access to sensitive service ports using firewall rules. Only expose necessary services.",
                        cvss_score=5.3,
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    ),
                )
                self.finding(
                    "medium",
                    "Sensitive Services Exposed",
                    f"Ports: {', '.join(str(p) for p in risky_ports)}",
                    cvss_score=5.3,
                )
        else:
            self.log("No common ports detected as open (may be filtered)", "info")

        self.log("Attempting server fingerprinting via HTTP...")
        try:
            import httpx
            async with httpx.AsyncClient(
                timeout=10, verify=False, follow_redirects=True,
                headers={"User-Agent": "OSLO-SecurityAssessment/2.0"}
            ) as client:
                resp = await client.get(base_url)
                server = resp.headers.get("server", "")
                powered_by = resp.headers.get("x-powered-by", "")

                if server:
                    self.log(f"Server header: {server}")
                    findings.append(
                        Finding(
                            severity="low",
                            title="Server Version Disclosed",
                            description=f"Server header reveals: {server}",
                            phase=self.phase,
                            recommendation="Remove or genericize the Server header to prevent technology fingerprinting.",
                            cvss_score=3.1,
                        ),
                    )
                    self.finding("low", "Server Version Disclosed", f"Server: {server}", cvss_score=3.1)

                if powered_by:
                    self.log(f"X-Powered-By: {powered_by}")
                    findings.append(
                        Finding(
                            severity="low",
                            title="Technology Stack Disclosed",
                            description=f"X-Powered-By header reveals: {powered_by}",
                            phase=self.phase,
                            recommendation="Remove X-Powered-By header to limit information leakage.",
                            cvss_score=3.1,
                        ),
                    )
                    self.finding("low", "Technology Stack Disclosed", f"X-Powered-By: {powered_by}", cvss_score=3.1)

                self.telemetry(requestsAnalyzed=scanned + 1)
        except Exception as e:
            self.log(f"HTTP fingerprinting failed: {e}", "warn")

        method_findings = await self._discover_http_methods(base_url, scanned)
        findings.extend(method_findings)

        robots_findings = await self._fetch_robots_sitemap(base_url)
        findings.extend(robots_findings)

        self.log(f"Surface mapping complete — {len(findings)} finding(s)")
        return findings

    async def _enumerate_subdomains(self, hostname: str) -> list:
        findings = []
        self.log("Starting subdomain enumeration...")

        parts = hostname.split(".")
        if len(parts) < 2:
            self.log("Hostname too short for subdomain enumeration", "debug")
            return findings

        base_domain = ".".join(parts[-2:]) if len(parts) <= 2 else ".".join(parts[-2:])
        if len(parts) > 2:
            base_domain = ".".join(parts[-(min(len(parts), 2)):])

        discovered = []
        for sub in self.COMMON_SUBDOMAINS:
            subdomain = f"{sub}.{base_domain}"
            if subdomain == hostname:
                continue
            try:
                socket.getaddrinfo(subdomain, None)
                discovered.append(subdomain)
                self.log(f"  Subdomain discovered: {subdomain}", "success")

                severity = "info"
                sensitive_subs = ["admin", "dev", "staging", "test", "internal", "backup", "db", "jenkins", "gitlab", "jira", "grafana", "kibana", "ci"]
                if sub in sensitive_subs:
                    severity = "medium"

                findings.append(
                    Finding(
                        severity=severity,
                        title=f"Subdomain Discovered: {subdomain}",
                        description=f"The subdomain {subdomain} resolves to an IP address and may expose additional attack surface.",
                        phase=self.phase,
                        recommendation="Review discovered subdomains for unnecessary exposure. Ensure sensitive environments (staging, admin, internal) are not publicly accessible.",
                        cvss_score=3.1 if severity == "info" else 5.3,
                    )
                )
                self.finding(
                    severity,
                    f"Subdomain Discovered: {subdomain}",
                    f"Subdomain {subdomain} is resolvable via DNS.",
                    cvss_score=3.1 if severity == "info" else 5.3,
                )
                self.asset("endpoint", subdomain, f"Subdomain: {subdomain}", severity)

            except socket.gaierror:
                pass
            except Exception:
                pass

        if discovered:
            self.log(f"Subdomain enumeration complete — {len(discovered)} subdomain(s) found", "success")
        else:
            self.log("No additional subdomains discovered", "info")

        return findings

    async def _discover_http_methods(self, base_url: str, scanned: int) -> list:
        findings = []
        self.log("Testing HTTP methods on target...")

        try:
            import httpx
            async with httpx.AsyncClient(
                timeout=10, verify=False, follow_redirects=False,
                headers={"User-Agent": "OSLO-SecurityAssessment/2.0"}
            ) as client:
                allowed_methods = []
                for method in self.HTTP_METHODS:
                    try:
                        resp = await client.request(method, base_url)
                        if resp.status_code < 405:
                            allowed_methods.append(method)

                            if method == "TRACE" and resp.status_code == 200:
                                findings.append(
                                    Finding(
                                        severity="high",
                                        title="HTTP TRACE Enabled — Cross-Site Tracing (XST)",
                                        description="The server responds to HTTP TRACE requests. This can be exploited for Cross-Site Tracing (XST) attacks to steal credentials or session tokens.",
                                        phase=self.phase,
                                        recommendation="Disable the TRACE HTTP method on the web server. In Apache, use 'TraceEnable Off'. In Nginx, TRACE is disabled by default.",
                                        cvss_score=5.9,
                                        references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                                    )
                                )
                                self.finding(
                                    "high",
                                    "HTTP TRACE Enabled — Cross-Site Tracing (XST)",
                                    "TRACE method returns 200, enabling potential XST attacks.",
                                    cvss_score=5.9,
                                )
                                self.asset("config", base_url, "TRACE method enabled", "high")

                        await asyncio.sleep(0.1)
                    except Exception:
                        pass

                if allowed_methods:
                    self.log(f"Allowed HTTP methods: {', '.join(allowed_methods)}", "info")
                    self.asset("config", base_url, f"HTTP Methods: {', '.join(allowed_methods)}", "info")

        except Exception as e:
            self.log(f"HTTP method discovery failed: {e}", "warn")

        return findings

    async def _fetch_robots_sitemap(self, base_url: str) -> list:
        findings = []
        self.log("Fetching robots.txt and sitemap.xml...")

        try:
            import httpx
            async with httpx.AsyncClient(
                timeout=10, verify=False, follow_redirects=True,
                headers={"User-Agent": "OSLO-SecurityAssessment/2.0"}
            ) as client:
                try:
                    resp = await client.get(f"{base_url}/robots.txt")
                    if resp.status_code == 200 and len(resp.text.strip()) > 0:
                        self.log("robots.txt found, parsing...", "success")
                        sensitive_paths = []
                        all_paths = []

                        sensitive_keywords = [
                            "admin", "login", "dashboard", "config", "backup",
                            "secret", "private", "internal", "api", "debug",
                            "test", "staging", "dev", "wp-admin", "phpmyadmin",
                            "cpanel", ".env", ".git", "database", "db",
                        ]

                        for line in resp.text.splitlines():
                            line = line.strip()
                            if line.lower().startswith("disallow:"):
                                path = line.split(":", 1)[1].strip()
                                if path and path != "/":
                                    all_paths.append(path)
                                    for kw in sensitive_keywords:
                                        if kw in path.lower():
                                            sensitive_paths.append(path)
                                            break
                            elif line.lower().startswith("sitemap:"):
                                sitemap_url = line.split(":", 1)[1].strip()
                                if sitemap_url:
                                    self.asset("endpoint", sitemap_url, f"Sitemap: {sitemap_url}", "info")

                        if all_paths:
                            for path in all_paths:
                                self.asset("config", path, f"robots.txt path: {path}", "low")

                        if sensitive_paths:
                            findings.append(
                                Finding(
                                    severity="low",
                                    title="Sensitive Paths in robots.txt",
                                    description=f"robots.txt disallows potentially sensitive paths: {', '.join(sensitive_paths[:10])}",
                                    phase=self.phase,
                                    recommendation="Review disallowed paths in robots.txt. Sensitive paths listed here may attract attacker attention. Ensure proper access controls are in place.",
                                    cvss_score=3.1,
                                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"],
                                )
                            )
                            self.finding(
                                "low",
                                "Sensitive Paths in robots.txt",
                                f"Sensitive disallowed paths: {', '.join(sensitive_paths[:10])}",
                                cvss_score=3.1,
                            )
                        elif all_paths:
                            self.log(f"robots.txt has {len(all_paths)} disallowed path(s), none flagged as sensitive", "info")
                    else:
                        self.log("No robots.txt found or empty", "info")
                except Exception as e:
                    self.log(f"Failed to fetch robots.txt: {e}", "debug")

                try:
                    resp = await client.get(f"{base_url}/sitemap.xml")
                    if resp.status_code == 200 and "xml" in resp.headers.get("content-type", "").lower():
                        self.log("sitemap.xml found, parsing...", "success")
                        import re
                        urls = re.findall(r"<loc>(.*?)</loc>", resp.text)
                        for url in urls[:50]:
                            self.asset("endpoint", url, f"Sitemap entry: {url}", "info")
                        if urls:
                            self.log(f"Found {len(urls)} URL(s) in sitemap.xml", "info")
                    else:
                        self.log("No sitemap.xml found", "info")
                except Exception as e:
                    self.log(f"Failed to fetch sitemap.xml: {e}", "debug")

        except Exception as e:
            self.log(f"robots.txt/sitemap.xml fetch failed: {e}", "warn")

        return findings

    def _identify_service(self, port: int) -> str:
        services = {
            21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http",
            110: "pop3", 143: "imap", 443: "https", 993: "imaps",
            995: "pop3s", 3306: "mysql", 3389: "rdp", 5432: "postgres",
            6379: "redis", 8080: "http-alt", 8443: "https-alt",
            8888: "http-alt2", 9090: "http-alt3",
            27017: "mongodb", 11211: "memcached", 9200: "elasticsearch",
            5601: "kibana", 2379: "etcd", 4443: "https-alt4",
            15672: "rabbitmq-mgmt", 9042: "cassandra",
        }
        return services.get(port, "unknown")
