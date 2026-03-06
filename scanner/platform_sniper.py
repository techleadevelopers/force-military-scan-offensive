import asyncio
import httpx
import json
import re
import socket
import sys
import time
from typing import List, Dict, Any, Optional
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

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

PLATFORM_SIGNATURES = {
    "wordpress": {
        "patterns": [r"/wp-content/", r"/wp-includes/", r"/wp-admin/", r"wp-json", r"wordpress"],
        "files": ["/wp-login.php", "/xmlrpc.php", "/wp-config.php.bak", "/wp-config.php~", "/.wp-config.php.swp"],
        "vulns": ["xmlrpc_bruteforce", "user_enumeration", "config_backup", "debug_log"],
    },
    "shopify": {
        "patterns": [r"cdn\.shopify\.com", r"Shopify\.theme", r"shopify-section", r"myshopify\.com"],
        "files": ["/admin", "/cart.json", "/products.json", "/collections.json"],
        "vulns": ["cart_manipulation", "api_exposure", "admin_detection"],
    },
    "woocommerce": {
        "patterns": [r"woocommerce", r"wc-ajax", r"/wp-content/plugins/woocommerce/", r"wc_cart_hash"],
        "files": ["/wp-json/wc/v3/products", "/wp-json/wc/v3/orders", "/?wc-ajax=get_refreshed_fragments"],
        "vulns": ["rest_api_exposure", "cart_manipulation", "order_enumeration"],
    },
    "nextjs": {
        "patterns": [r"/_next/static/", r"__NEXT_DATA__", r"_next/image", r"nextjs"],
        "files": ["/_next/data/", "/api/", "/.next/BUILD_ID"],
        "vulns": ["source_map_exposure", "api_route_exposure", "build_id_leak"],
    },
    "react_spa": {
        "patterns": [r"/static/js/", r"react-dom", r"reactRoot", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"createRoot"],
        "files": ["/static/js/main.chunk.js", "/manifest.json", "/asset-manifest.json"],
        "vulns": ["source_map_exposure", "js_secrets", "env_in_bundle"],
    },
    "angular": {
        "patterns": [r"ng-version", r"ng-app", r"angular", r"/main\.[a-f0-9]+\.js"],
        "files": ["/ngsw.json", "/assets/", "/3rdpartylicenses.txt"],
        "vulns": ["source_map_exposure", "template_injection"],
    },
    "vue": {
        "patterns": [r"__vue__", r"vue-router", r"/js/app\.[a-f0-9]+\.js", r"vuex"],
        "files": ["/js/app.js", "/manifest.json"],
        "vulns": ["source_map_exposure", "js_secrets"],
    },
    "laravel": {
        "patterns": [r"laravel_session", r"XSRF-TOKEN", r"laravel"],
        "files": ["/.env", "/storage/logs/laravel.log", "/telescope", "/horizon"],
        "vulns": ["env_exposure", "debug_mode", "telescope_exposed", "log_exposure"],
    },
    "django": {
        "patterns": [r"csrfmiddlewaretoken", r"django", r"__debug__"],
        "files": ["/admin/", "/__debug__/", "/api/schema/"],
        "vulns": ["admin_exposed", "debug_toolbar", "api_schema_leak"],
    },
    "express": {
        "patterns": [r"X-Powered-By.*Express", r"connect\.sid"],
        "files": ["/api/", "/.env", "/swagger", "/api-docs"],
        "vulns": ["header_leak", "env_exposure", "swagger_exposed"],
    },
    "anota_ai": {
        "patterns": [r"index-DFFyR32_\.js", r"anota", r"anotaai", r"cardapio"],
        "files": ["/api/v1/", "/cardapio"],
        "vulns": ["google_maps_key", "js_secrets", "api_exposure"],
    },
}

API_KEY_PATTERNS = {
    "google_maps": re.compile(r"AIzaSy[0-9A-Za-z_-]{33}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Za-z]{16}"),
    "stripe_publishable": re.compile(r"pk_(test|live)_[0-9A-Za-z]{24,}"),
    "stripe_secret": re.compile(r"sk_(test|live)_[0-9A-Za-z]{24,}"),
    "github_token": re.compile(r"ghp_[0-9A-Za-z]{36}"),
    "gitlab_token": re.compile(r"glpat-[0-9A-Za-z_-]{20,}"),
    "firebase": re.compile(r"AIzaSy[0-9A-Za-z_-]{33}"),
    "slack_token": re.compile(r"xox[bporas]-[0-9A-Za-z-]{10,}"),
    "jwt_secret": re.compile(r"""(?:jwt[_-]?secret|JWT_SECRET|jwt_key)\s*[=:]\s*['"]([^'"]{8,})['"]""", re.I),
    "mongodb_uri": re.compile(r"mongodb(?:\+srv)?://[^\s'\"<>]{10,}"),
    "postgres_uri": re.compile(r"postgres(?:ql)?://[^\s'\"<>]{10,}"),
    "redis_url": re.compile(r"redis://[^\s'\"<>]{5,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "sendgrid_key": re.compile(r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"),
    "twilio_sid": re.compile(r"AC[0-9a-f]{32}"),
    "mailgun_key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "heroku_api": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
}

COOKIE_SECURITY_FLAGS = ["httponly", "secure", "samesite"]

DANGEROUS_HEADERS = {
    "x-powered-by": "Server technology leaked",
    "server": "Server version leaked",
    "x-aspnet-version": "ASP.NET version leaked",
    "x-aspnetmvc-version": "ASP.NET MVC version leaked",
}


def emit(event_type: str, data: dict):
    payload = {"type": event_type, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), **data}
    print(json.dumps(payload), flush=True)


def emit_log(message: str, level: str = "info"):
    emit("PLATFORM_SNIPER_LOG", {"message": message, "level": level})


def is_blocked(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        if any(p.search(host) for p in BLOCKED_HOSTS):
            return True
        try:
            resolved = socket.getaddrinfo(host, None)
            for _, _, _, _, addr in resolved:
                ip = addr[0]
                if any(p.search(ip) for p in BLOCKED_HOSTS):
                    return True
        except socket.gaierror:
            pass
        return False
    except Exception:
        return True


class PlatformSniper:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.parsed = urlparse(self.target)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.tech_stack: Dict[str, Any] = {
            "platforms": [],
            "frameworks": [],
            "server": None,
            "waf": None,
            "cdn": None,
            "js_files": [],
            "cookies": [],
            "headers": {},
        }
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.api_keys_found: List[Dict[str, str]] = []
        self.findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    async def run(self):
        emit_log(f"Platform Sniper initialized  Target: {self.target}")
        emit("PLATFORM_SNIPER_START", {"target": self.target})

        async with httpx.AsyncClient(
            timeout=15,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": USER_AGENTS[0], "Accept": "text/html,application/xhtml+xml,*/*"},
        ) as client:
            self.client = client

            html, headers, cookies = await self._fetch_target()
            if html is None:
                emit("PLATFORM_SNIPER_ERROR", {"error": "Failed to fetch target"})
                return

            await self._analyze_headers(headers)
            await self._analyze_cookies(cookies)
            await self._fingerprint_platform(html)
            await self._scan_js_files(html)
            await self._scan_inline_secrets(html)
            await self._probe_sensitive_files()
            await self._check_cors()
            await self._check_source_maps(html)
            await self._check_open_redirect()

        self._generate_report()

    async def _safe_get(self, url: str, **kwargs):
        max_redirects = 5
        current_url = url
        for _ in range(max_redirects):
            resp = await self.client.get(current_url, **kwargs)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if not location:
                    return resp
                next_url = urljoin(current_url, location)
                if is_blocked(next_url):
                    emit_log(f"Redirect to blocked host blocked: {next_url}", "warn")
                    return resp
                current_url = next_url
                continue
            return resp
        return resp

    async def _fetch_target(self):
        emit_log(f"Fetching target: {self.target}")
        try:
            resp = await self._safe_get(self.target)
            emit_log(f"Response: {resp.status_code} | Size: {len(resp.text)} bytes | Server: {resp.headers.get('server', 'hidden')}")
            return resp.text, dict(resp.headers), resp.cookies
        except Exception as e:
            emit_log(f"Failed to fetch target: {e}", "error")
            return None, None, None

    async def _analyze_headers(self, headers: dict):
        emit_log("Analyzing response headers...")

        for header_name, warning in DANGEROUS_HEADERS.items():
            val = headers.get(header_name)
            if val:
                self.tech_stack["headers"][header_name] = val
                self._add_vuln(
                    "Header Information Disclosure",
                    f"{header_name}: {val}  {warning}",
                    "low",
                    evidence=f"{header_name}: {val}",
                )

        server = headers.get("server", "")
        if server:
            self.tech_stack["server"] = server
            emit_log(f"Server: {server}")

        if "cf-ray" in headers or "cf-cache-status" in headers:
            self.tech_stack["cdn"] = "Cloudflare"
            self.tech_stack["waf"] = "Cloudflare"
            emit_log("CDN/WAF: Cloudflare detected", "warn")
        elif "x-amz-cf-id" in headers:
            self.tech_stack["cdn"] = "AWS CloudFront"
            emit_log("CDN: AWS CloudFront detected")
        elif "x-vercel-id" in headers:
            self.tech_stack["cdn"] = "Vercel"
            emit_log("CDN: Vercel detected")
        elif "x-cache" in headers and "fastly" in headers.get("via", "").lower():
            self.tech_stack["cdn"] = "Fastly"
            emit_log("CDN: Fastly detected")

        csp = headers.get("content-security-policy", "")
        if not csp:
            self._add_vuln(
                "Missing Content-Security-Policy",
                "No CSP header detected  XSS attacks have higher impact",
                "medium",
            )

        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            self._add_vuln(
                "Missing HSTS Header",
                "Strict-Transport-Security not set  SSL stripping possible",
                "low",
            )

    async def _analyze_cookies(self, cookies):
        emit_log("Analyzing cookies...")
        for name in cookies:
            cookie_str = str(cookies.jar)
            has_httponly = "httponly" in cookie_str.lower()
            has_secure = "secure" in cookie_str.lower()
            has_samesite = "samesite" in cookie_str.lower()

            self.tech_stack["cookies"].append({"name": name, "httponly": has_httponly, "secure": has_secure, "samesite": has_samesite})

            issues = []
            if not has_httponly:
                issues.append("missing HttpOnly")
            if not has_secure and self.parsed.scheme == "https":
                issues.append("missing Secure")
            if not has_samesite:
                issues.append("missing SameSite")

            if issues:
                self._add_vuln(
                    "Insecure Cookie Configuration",
                    f"Cookie '{name}': {', '.join(issues)}",
                    "medium" if "HttpOnly" in str(issues) else "low",
                    evidence=f"Cookie: {name}  {', '.join(issues)}",
                )

    async def _fingerprint_platform(self, html: str):
        emit_log("Fingerprinting platform and technology stack...")

        for platform_name, sig in PLATFORM_SIGNATURES.items():
            matched = False
            for pattern in sig["patterns"]:
                if re.search(pattern, html, re.I):
                    matched = True
                    break

            if matched:
                self.tech_stack["platforms"].append(platform_name)
                emit_log(f"Platform detected: {platform_name.upper()}", "warn")

                for vuln_type in sig["vulns"]:
                    await self._probe_platform_vuln(platform_name, vuln_type)

        if not self.tech_stack["platforms"]:
            emit_log("No known platform signature detected  generic scan mode")

    async def _probe_platform_vuln(self, platform: str, vuln_type: str):
        sig = PLATFORM_SIGNATURES.get(platform, {})

        if vuln_type == "xmlrpc_bruteforce":
            url = urljoin(self.base_url, "/xmlrpc.php")
            try:
                resp = await self.client.post(
                    url,
                    content='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                    headers={"Content-Type": "text/xml"},
                )
                if resp.status_code == 200 and "methodResponse" in resp.text:
                    self._add_vuln(
                        "WordPress XML-RPC Enabled",
                        f"XML-RPC at {url} accepts method calls  bruteforce/DDoS amplification possible",
                        "high",
                        evidence=f"HTTP {resp.status_code}  system.listMethods returned valid response",
                    )
            except Exception:
                pass

        elif vuln_type == "user_enumeration":
            url = urljoin(self.base_url, "/wp-json/wp/v2/users")
            try:
                resp = await self.client.get(url)
                if resp.status_code == 200:
                    try:
                        users = resp.json()
                        if isinstance(users, list) and len(users) > 0:
                            names = [u.get("slug", "?") for u in users[:5]]
                            self._add_vuln(
                                "WordPress User Enumeration",
                                f"WP REST API exposes user list: {', '.join(names)}",
                                "medium",
                                evidence=f"GET {url} â†’ {len(users)} users found",
                            )
                    except Exception:
                        pass
            except Exception:
                pass

        elif vuln_type == "config_backup":
            for path in ["/wp-config.php.bak", "/wp-config.php~", "/.wp-config.php.swp", "/wp-config.old"]:
                url = urljoin(self.base_url, path)
                try:
                    resp = await self.client.get(url)
                    if resp.status_code == 200 and ("DB_NAME" in resp.text or "DB_PASSWORD" in resp.text):
                        self._add_vuln(
                            "WordPress Config Backup Exposed",
                            f"Config backup at {path}  database credentials exposed",
                            "critical",
                            evidence=f"GET {url} â†’ contains DB_NAME/DB_PASSWORD",
                        )
                        break
                except Exception:
                    pass

        elif vuln_type == "debug_log":
            url = urljoin(self.base_url, "/wp-content/debug.log")
            try:
                resp = await self.client.get(url)
                if resp.status_code == 200 and ("PHP" in resp.text or "Error" in resp.text):
                    self._add_vuln(
                        "WordPress Debug Log Exposed",
                        f"Debug log accessible at /wp-content/debug.log ({len(resp.text)} bytes)",
                        "high",
                        evidence=f"GET {url} â†’ {resp.status_code}",
                    )
            except Exception:
                pass

        elif vuln_type == "env_exposure":
            url = urljoin(self.base_url, "/.env")
            try:
                resp = await self.client.get(url)
                if resp.status_code == 200 and ("=" in resp.text) and ("APP_" in resp.text or "DB_" in resp.text or "SECRET" in resp.text.upper()):
                    self._add_vuln(
                        "Environment File Exposed (.env)",
                        f".env file accessible  contains application secrets",
                        "critical",
                        evidence=f"GET {url} â†’ {resp.status_code} ({len(resp.text)} bytes)",
                    )
            except Exception:
                pass

        elif vuln_type == "debug_mode":
            try:
                resp = await self.client.get(self.base_url + "/nonexistent-page-test-404")
                if "Traceback" in resp.text or "DEBUG" in resp.text or "INSTALLED_APPS" in resp.text:
                    self._add_vuln(
                        "Debug Mode Active in Production",
                        "Application returns stack traces/debug info on error pages",
                        "high",
                        evidence="404 page contains debug information",
                    )
            except Exception:
                pass

        elif vuln_type == "telescope_exposed":
            url = urljoin(self.base_url, "/telescope")
            try:
                resp = await self.client.get(url)
                if resp.status_code == 200 and ("telescope" in resp.text.lower() or "Laravel" in resp.text):
                    self._add_vuln(
                        "Laravel Telescope Exposed",
                        "Telescope debug panel accessible without authentication",
                        "critical",
                        evidence=f"GET {url} â†’ {resp.status_code}",
                    )
            except Exception:
                pass

        elif vuln_type == "log_exposure":
            url = urljoin(self.base_url, "/storage/logs/laravel.log")
            try:
                resp = await self.client.get(url)
                if resp.status_code == 200 and ("stack trace" in resp.text.lower() or "Exception" in resp.text):
                    self._add_vuln(
                        "Laravel Log File Exposed",
                        f"Application log accessible  {len(resp.text)} bytes of debug data",
                        "high",
                        evidence=f"GET {url} â†’ {resp.status_code}",
                    )
            except Exception:
                pass

        elif vuln_type == "swagger_exposed":
            for path in ["/swagger", "/api-docs", "/swagger-ui", "/swagger.json", "/openapi.json"]:
                url = urljoin(self.base_url, path)
                try:
                    resp = await self.client.get(url)
                    if resp.status_code == 200 and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower() or "paths" in resp.text):
                        self._add_vuln(
                            "API Documentation Exposed",
                            f"Swagger/OpenAPI docs accessible at {path}",
                            "medium",
                            evidence=f"GET {url} â†’ {resp.status_code}",
                        )
                        break
                except Exception:
                    pass

        elif vuln_type == "cart_manipulation":
            for path in ["/cart.json", "/?wc-ajax=get_refreshed_fragments"]:
                url = urljoin(self.base_url, path)
                try:
                    resp = await self.client.get(url)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data:
                                self._add_vuln(
                                    "Cart API Exposed",
                                    f"Cart data accessible without authentication at {path}",
                                    "medium",
                                    evidence=f"GET {url} â†’ JSON response ({len(resp.text)} bytes)",
                                )
                        except Exception:
                            pass
                except Exception:
                    pass

        elif vuln_type == "rest_api_exposure":
            for path in ["/wp-json/wc/v3/products", "/wp-json/wc/v3/orders"]:
                url = urljoin(self.base_url, path)
                try:
                    resp = await self.client.get(url)
                    if resp.status_code == 200:
                        self._add_vuln(
                            "WooCommerce REST API Exposed",
                            f"WooCommerce API endpoint accessible: {path}",
                            "high",
                            evidence=f"GET {url} â†’ {resp.status_code}",
                        )
                except Exception:
                    pass

        elif vuln_type == "source_map_exposure":
            for js_file in self.tech_stack.get("js_files", [])[:10]:
                map_url = urljoin(self.base_url, js_file + ".map")
                try:
                    resp = await self.client.head(map_url)
                    if resp.status_code == 200:
                        self._add_vuln(
                            f"Source Map Exposed ({platform})",
                            f"Source map accessible: {js_file}.map  full source code readable",
                            "high",
                            evidence=f"HEAD {map_url} â†’ {resp.status_code}",
                        )
                        emit_log(f"SOURCE MAP: {js_file}.map accessible on {platform}", "error")
                        break
                except Exception:
                    pass

        elif vuln_type == "google_maps_key":
            for key_entry in self.api_keys_found:
                if key_entry.get("type") == "google_maps":
                    test_url = f"https://maps.googleapis.com/maps/api/geocode/json?latlng=0,0&key={key_entry['value']}"
                    try:
                        resp = await self.client.get(test_url)
                        if resp.status_code == 200 and "error_message" not in resp.text:
                            self._add_vuln(
                                f"Google Maps API Key Active ({platform})",
                                f"Exposed Google Maps key is active and billable",
                                "high",
                                evidence=f"Key {key_entry['value'][:20]}... responds to geocode API",
                            )
                    except Exception:
                        pass

        elif vuln_type == "js_secrets":
            pass

        elif vuln_type == "api_exposure":
            for path in sig.get("files", []):
                url = urljoin(self.base_url, path)
                try:
                    resp = await self.client.get(url)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        self._add_vuln(
                            "API Endpoint Exposed",
                            f"Accessible API endpoint: {path} ({len(resp.text)} bytes)",
                            "medium",
                            evidence=f"GET {url} â†’ {resp.status_code}",
                        )
                except Exception:
                    pass

        elif vuln_type in ("admin_exposed", "admin_detection"):
            url = urljoin(self.base_url, "/admin")
            try:
                resp = await self.client.get(url)
                if resp.status_code == 200 and ("login" in resp.text.lower() or "password" in resp.text.lower()):
                    self._add_vuln(
                        "Admin Panel Accessible",
                        f"Admin login page at /admin  brute-force target",
                        "medium",
                        evidence=f"GET {url} â†’ {resp.status_code}",
                    )
            except Exception:
                pass

    async def _scan_js_files(self, html: str):
        emit_log("Scanning JavaScript files for secrets...")
        js_urls = re.findall(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html, re.I)

        scanned = 0
        for js_path in js_urls[:20]:
            js_url = urljoin(self.base_url, js_path)
            if is_blocked(js_url):
                continue

            try:
                resp = await self.client.get(js_url)
                if resp.status_code != 200:
                    continue

                self.tech_stack["js_files"].append(js_path)
                js_content = resp.text
                scanned += 1

                for key_name, pattern in API_KEY_PATTERNS.items():
                    matches = pattern.findall(js_content)
                    for match in matches:
                        match_val = match if isinstance(match, str) else match[0] if match else ""
                        if len(match_val) < 8:
                            continue
                        severity = "critical" if key_name in ("aws_access_key", "stripe_secret", "private_key", "mongodb_uri", "postgres_uri") else "high" if key_name in ("github_token", "jwt_secret", "slack_token") else "medium"

                        self.api_keys_found.append({"type": key_name, "value": match_val[:40] + "..." if len(match_val) > 40 else match_val, "source": js_path})
                        self._add_vuln(
                            f"API Key Exposed: {key_name.upper().replace('_', ' ')}",
                            f"{key_name} found in {js_path}",
                            severity,
                            evidence=f"{match_val[:50]}{'...' if len(match_val) > 50 else ''}",
                        )
                        emit_log(f"SECRET FOUND: {key_name} in {js_path}", "error")

            except Exception:
                pass

        emit_log(f"Scanned {scanned} JS files  {len(self.api_keys_found)} secrets found")

    async def _scan_inline_secrets(self, html: str):
        emit_log("Scanning inline scripts and HTML for secrets...")

        for key_name, pattern in API_KEY_PATTERNS.items():
            matches = pattern.findall(html)
            for match in matches:
                match_val = match if isinstance(match, str) else match[0] if match else ""
                if len(match_val) < 8:
                    continue
                already = any(k["value"].startswith(match_val[:20]) for k in self.api_keys_found)
                if already:
                    continue

                severity = "critical" if key_name in ("aws_access_key", "stripe_secret", "private_key", "mongodb_uri") else "high"
                self.api_keys_found.append({"type": key_name, "value": match_val[:40] + "..." if len(match_val) > 40 else match_val, "source": "inline_html"})
                self._add_vuln(
                    f"Inline Secret: {key_name.upper().replace('_', ' ')}",
                    f"{key_name} found in page HTML source",
                    severity,
                    evidence=match_val[:50],
                )

    async def _probe_sensitive_files(self):
        emit_log("Probing for sensitive files and endpoints...")

        sensitive_paths = [
            ("/.env", "Environment variables"),
            ("/.git/config", "Git configuration"),
            ("/.git/HEAD", "Git HEAD reference"),
            ("/robots.txt", "Robots.txt"),
            ("/sitemap.xml", "Sitemap"),
            ("/.htaccess", "Apache config"),
            ("/server-status", "Apache server status"),
            ("/elmah.axd", "ASP.NET error log"),
            ("/web.config", "IIS configuration"),
            ("/phpinfo.php", "PHP info page"),
            ("/info.php", "PHP info page"),
            ("/.DS_Store", "MacOS metadata"),
            ("/crossdomain.xml", "Flash cross-domain policy"),
            ("/clientaccesspolicy.xml", "Silverlight policy"),
            ("/backup.sql", "SQL backup file"),
            ("/dump.sql", "SQL dump file"),
            ("/database.sql", "Database export"),
            ("/db.sql", "Database file"),
        ]

        for path, desc in sensitive_paths:
            url = urljoin(self.base_url, path)
            try:
                resp = await self.client.get(url)
                if resp.status_code == 200 and len(resp.text) > 20:
                    is_real = False
                    if path == "/.env" and ("=" in resp.text and any(k in resp.text.upper() for k in ["APP_", "DB_", "SECRET", "KEY", "PASSWORD"])):
                        is_real = True
                        severity = "critical"
                    elif path.startswith("/.git/") and ("ref:" in resp.text or "[core]" in resp.text):
                        is_real = True
                        severity = "critical"
                    elif path == "/phpinfo.php" and "phpversion" in resp.text.lower():
                        is_real = True
                        severity = "high"
                    elif path in ("/server-status",) and "Apache" in resp.text:
                        is_real = True
                        severity = "high"
                    elif path.endswith(".sql") and ("CREATE TABLE" in resp.text or "INSERT INTO" in resp.text):
                        is_real = True
                        severity = "critical"
                    elif path == "/robots.txt" and ("Disallow" in resp.text or "Allow" in resp.text):
                        is_real = True
                        severity = "info"
                    elif path == "/sitemap.xml" and "urlset" in resp.text:
                        is_real = True
                        severity = "info"

                    if is_real:
                        self._add_vuln(
                            f"Sensitive File Exposed: {path}",
                            f"{desc} accessible at {path} ({len(resp.text)} bytes)",
                            severity,
                            evidence=f"GET {url} â†’ {resp.status_code}",
                        )
                        emit_log(f"SENSITIVE FILE: {path} ({len(resp.text)} bytes)", "error" if severity in ("critical", "high") else "warn")
            except Exception:
                pass

    async def _check_cors(self):
        emit_log("Testing CORS configuration...")
        evil_origins = [
            f"https://{self.parsed.netloc}.evil.com",
            "https://evil.com",
            "null",
        ]

        for origin in evil_origins:
            try:
                resp = await self.client.get(
                    self.target,
                    headers={"Origin": origin},
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == origin or acao == "*":
                    severity = "high" if acac.lower() == "true" else "medium"
                    self._add_vuln(
                        "CORS Misconfiguration",
                        f"Server reflects arbitrary origin: {origin} â†’ ACAO: {acao}, credentials: {acac}",
                        severity,
                        evidence=f"Origin: {origin} â†’ Access-Control-Allow-Origin: {acao}",
                    )
                    emit_log(f"CORS BYPASS: Origin {origin} reflected with credentials={acac}", "error")
                    break
            except Exception:
                pass

    async def _check_source_maps(self, html: str):
        emit_log("Checking for exposed source maps...")
        js_files = re.findall(r'src=["\']([^"\']*\.js)["\']', html, re.I)

        for js_path in js_files[:10]:
            map_url = urljoin(self.base_url, js_path + ".map")
            try:
                resp = await self.client.head(map_url)
                if resp.status_code == 200:
                    self._add_vuln(
                        "Source Map Exposed",
                        f"Source map accessible: {js_path}.map  full source code readable",
                        "high",
                        evidence=f"HEAD {map_url} â†’ {resp.status_code}",
                    )
                    emit_log(f"SOURCE MAP: {js_path}.map accessible", "error")
                    break
            except Exception:
                pass

    async def _check_open_redirect(self):
        emit_log("Testing for open redirect...")
        params = ["url", "redirect", "next", "return", "returnUrl", "redirect_uri", "continue", "dest", "destination", "redir", "target", "return_to", "go"]

        for param in params:
            test_url = f"{self.target}?{param}=https://evil.com"
            try:
                resp = await self.client.get(test_url, follow_redirects=False)
                location = resp.headers.get("location", "")
                if "evil.com" in location:
                    self._add_vuln(
                        "Open Redirect",
                        f"Parameter '{param}' redirects to attacker-controlled URL",
                        "medium",
                        evidence=f"GET {test_url} â†’ Location: {location}",
                    )
                    emit_log(f"OPEN REDIRECT: ?{param}= â†’ {location}", "error")
                    break
            except Exception:
                pass

    def _add_vuln(self, title: str, description: str, severity: str, evidence: str = ""):
        vuln = {
            "title": title,
            "description": description,
            "severity": severity,
            "evidence": evidence,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        self.vulnerabilities.append(vuln)
        self.findings_count[severity] = self.findings_count.get(severity, 0) + 1

        emit("PLATFORM_SNIPER_FINDING", {
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
        })

    def _generate_report(self):
        report = {
            "target": self.target,
            "tech_stack": self.tech_stack,
            "vulnerabilities": self.vulnerabilities,
            "api_keys_found": self.api_keys_found,
            "findings_count": self.findings_count,
            "total_vulnerabilities": len(self.vulnerabilities),
            "scan_duration": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

        emit("PLATFORM_SNIPER_REPORT", report)
        emit_log(
            f"Scan complete  {len(self.vulnerabilities)} vulnerabilities found | "
            f"Critical: {self.findings_count['critical']} | High: {self.findings_count['high']} | "
            f"Medium: {self.findings_count['medium']} | Low: {self.findings_count['low']} | "
            f"Platforms: {', '.join(self.tech_stack['platforms']) or 'none'} | "
            f"Secrets: {len(self.api_keys_found)}",
            "success" if self.findings_count["critical"] == 0 else "error",
        )


async def main():
    if len(sys.argv) < 2:
        print(json.dumps({"type": "error", "message": "Usage: python -m scanner.platform_sniper <target_url>"}), flush=True)
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith("http"):
        target = f"https://{target}"

    if is_blocked(target):
        print(json.dumps({"type": "error", "message": "Target is blocked (private/internal)"}), flush=True)
        sys.exit(1)

    scanner = PlatformSniper(target)
    await scanner.run()


if __name__ == "__main__":
    asyncio.run(main())

