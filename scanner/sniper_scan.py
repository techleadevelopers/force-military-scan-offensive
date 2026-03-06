import asyncio
import httpx
import json
import re
import socket
import sys
import time
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin
from collections import defaultdict


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

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

VULNERABLE_VERSIONS = {
    "wordpress": {
        "4.7": ["CVE-2017-1001000", "REST API privilege escalation"],
        "4.8": ["CVE-2017-17090", "SQL injection"],
        "4.9": ["CVE-2018-6389", "DoS via load-scripts.php"],
        "5.0": ["CVE-2019-9787", "XSS in shortcode"],
        "5.1": ["CVE-2019-8942", "RCE via image upload"],
    },
    "joomla": {
        "3.9": ["CVE-2019-10945", "CSRF"],
        "3.4": ["CVE-2015-8562", "RCE via session"],
    },
    "drupal": {
        "7.": ["CVE-2014-3704", "Drupalgeddon SQL injection"],
        "8.": ["CVE-2018-7600", "Drupalgeddon2 RCE"],
    },
    "laravel": {
        "5.5": ["CVE-2018-15133", "RCE via APP_KEY"],
        "5.6": ["Debug mode information disclosure"],
    },
    "apache": {
        "2.2": ["CVE-2017-9798", "Optionsbleed"],
        "2.4.1": ["CVE-2019-0211", "Local privilege escalation"],
        "2.4.2": ["CVE-2019-0211", "Local privilege escalation"],
        "2.4.3": ["CVE-2019-0211", "Local privilege escalation"],
    },
    "nginx": {
        "1.15": ["CVE-2019-9511", "HTTP/2 DoS"],
        "1.14": ["CVE-2019-9516", "HTTP/2 zero-length header DoS"],
    },
    "php": {
        "5.": ["CVE-2019-11043", "RCE (multiple)"],
        "7.0": ["CVE-2019-11043", "RCE"],
        "7.1": ["CVE-2019-11042", "RCE"],
    },
}

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid", "cloudflare", "cf-cache-status"],
    "AWS WAF": ["x-amz-cf-id", "x-amzn-requestid", "awselb"],
    "Sucuri": ["sucuri", "sucuri/cloudproxy", "x-sucuri-id"],
    "ModSecurity": ["modsecurity", "_mod_security"],
    "F5 BIG-IP": ["big-ip", "f5", "bigipserver"],
    "Akamai": ["akamai", "akamaighost", "x-akamai"],
    "Wordfence": ["wordfence"],
    "Imperva": ["incapsula", "imperva", "x-iinfo"],
    "Fortinet": ["fortigate", "fortiweb"],
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing â€” SSL stripping possible",
    "content-security-policy": "CSP missing â€” XSS attacks have higher impact",
    "x-frame-options": "Clickjacking protection missing",
    "x-content-type-options": "MIME-sniffing protection missing",
    "referrer-policy": "Referrer policy missing",
    "permissions-policy": "Permissions policy missing",
}

API_KEY_PATTERNS = {
    "google_maps": re.compile(r"AIzaSy[0-9A-Za-z_-]{33}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Za-z]{16}"),
    "stripe_publishable": re.compile(r"pk_(test|live)_[0-9A-Za-z]{24,}"),
    "stripe_secret": re.compile(r"sk_(test|live)_[0-9A-Za-z]{24,}"),
    "github_token": re.compile(r"ghp_[0-9A-Za-z]{36}"),
    "firebase": re.compile(r"AIzaSy[0-9A-Za-z_-]{33}"),
    "slack_token": re.compile(r"xox[bporas]-[0-9A-Za-z-]{10,}"),
    "jwt_secret": re.compile(r"""(?:jwt[_-]?secret|JWT_SECRET)\s*[=:]\s*['"]([^'"]{8,})['"]""", re.I),
    "mongodb_uri": re.compile(r"mongodb(?:\+srv)?://[^\s'\"<>]{10,}"),
    "postgres_uri": re.compile(r"postgres(?:ql)?://[^\s'\"<>]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "sendgrid_key": re.compile(r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"),
}

PLATFORM_SIGNATURES = {
    "wordpress": [r"/wp-content/", r"/wp-includes/", r"/wp-admin/", r"wp-json"],
    "shopify": [r"cdn\.shopify\.com", r"Shopify\.theme", r"myshopify\.com"],
    "woocommerce": [r"woocommerce", r"wc-ajax", r"wc_cart_hash"],
    "nextjs": [r"/_next/static/", r"__NEXT_DATA__"],
    "react": [r"/static/js/", r"react-dom", r"createRoot"],
    "angular": [r"ng-version", r"ng-app"],
    "vue": [r"__vue__", r"vue-router"],
    "laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "django": [r"csrfmiddlewaretoken", r"__debug__"],
    "express": [r"X-Powered-By.*Express", r"connect\.sid"],
    "joomla": [r"/media/system/js/", r"joomla"],
    "drupal": [r"/sites/default/files/", r"drupal"],
}

SENSITIVE_PATHS = {
    "wordpress": ["/xmlrpc.php", "/wp-json/wp/v2/users", "/wp-content/debug.log", "/wp-config.php.bak"],
    "laravel": ["/.env", "/storage/logs/laravel.log", "/telescope"],
    "django": ["/__debug__/", "/admin/"],
    "express": ["/.env", "/swagger", "/api-docs"],
    "nextjs": ["/.next/BUILD_ID"],
    "generic": ["/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml", "/.DS_Store", "/server-status", "/phpinfo.php"],
}

DANGEROUS_HEADERS = {
    "x-powered-by": "Server technology leaked",
    "server": "Server version leaked",
    "x-aspnet-version": "ASP.NET version leaked",
    "x-aspnetmvc-version": "ASP.NET MVC version leaked",
}


def emit(event_type: str, data: dict):
    payload = {"event": event_type, "data": data, "timestamp": time.time()}
    print(json.dumps(payload), flush=True)


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


class SniperScanner:
    def __init__(self):
        self.results: List[Dict[str, Any]] = []
        self.total_scanned = 0
        self.total_alive = 0
        self.all_findings: List[Dict[str, Any]] = []

    async def scan_single(self, url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        result = {
            "url": url,
            "alive": False,
            "status_code": 0,
            "title": "",
            "waf": [],
            "missing_headers": [],
            "software": {},
            "platforms": [],
            "vulnerabilities": [],
            "api_keys": [],
            "sensitive_paths": [],
            "cookie_issues": [],
            "cors_issues": [],
            "score": 0,
            "findings": [],
        }

        if is_blocked(url):
            result["error"] = "Blocked host"
            return result

        try:
            resp = await client.get(url, follow_redirects=True)
            final_url = str(resp.url)
            if is_blocked(final_url):
                result["error"] = "Redirect to blocked host"
                return result
            result["alive"] = True
            result["status_code"] = resp.status_code
            html = resp.text
            headers = dict(resp.headers)
            headers_lower = {k.lower(): v for k, v in headers.items()}

            title_match = re.search(r"<title>(.*?)</title>", html, re.I | re.DOTALL)
            result["title"] = title_match.group(1).strip()[:100] if title_match else ""

            result["waf"] = self._detect_waf(headers_lower, html)
            result["missing_headers"] = self._check_security_headers(headers_lower)
            result["software"] = self._detect_software(headers_lower, html)
            result["platforms"] = self._detect_platforms(html, headers_lower)
            result["vulnerabilities"] = self._check_vulnerabilities(result["software"])
            result["api_keys"] = self._scan_secrets(html)

            result["cookie_issues"] = self._check_cookies(resp)
            result["cors_issues"] = await self._check_cors(url, client)
            result["sensitive_paths"] = await self._probe_sensitive_paths(url, result["platforms"], client)

            for header_name, warning in DANGEROUS_HEADERS.items():
                if header_name in headers_lower and headers_lower[header_name]:
                    result["findings"].append({
                        "title": f"Header Information Disclosure: {header_name}",
                        "description": f"{warning}: {headers_lower[header_name]}",
                        "severity": "low",
                        "category": "info_disclosure",
                        "location": url,
                    })

            self._build_findings(result)

            score = 0
            if not result["waf"] or "None" in result["waf"]:
                score += 20
            score += min(len(result["missing_headers"]) * 8, 40)
            if result["vulnerabilities"]:
                score += 25
            if result["api_keys"]:
                score += 15
            if result["sensitive_paths"]:
                score += 10
            if result["cors_issues"]:
                score += 10
            server_ver = result["software"].get("apache", "") or result["software"].get("nginx", "")
            if server_ver and any(old in server_ver for old in ["2.2", "1.10", "1.12", "1.14"]):
                score += 10
            php_ver = result["software"].get("php", "")
            if php_ver and any(old in php_ver for old in ["5.", "7.0", "7.1"]):
                score += 10

            result["score"] = min(score, 100)

        except httpx.TimeoutException:
            result["error"] = "Timeout"
        except httpx.ConnectError:
            result["error"] = "Connection Error"
        except Exception as e:
            result["error"] = str(e)[:200]

        return result

    def _detect_waf(self, headers: dict, html: str) -> List[str]:
        detected = []
        html_lower = html.lower()[:5000]
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                for h_key, h_val in headers.items():
                    if sig_lower in h_key or sig_lower in h_val.lower():
                        detected.append(waf_name)
                        break
                else:
                    if sig_lower in html_lower:
                        detected.append(waf_name)
                if waf_name in detected:
                    break
        return list(set(detected)) if detected else ["None"]

    def _check_security_headers(self, headers: dict) -> List[str]:
        return [h for h in SECURITY_HEADERS if h not in headers]

    def _detect_software(self, headers: dict, html: str) -> dict:
        versions: Dict[str, str] = {}
        html_lower = html.lower()[:20000]

        server = headers.get("server", "")
        if server:
            versions["server"] = server
            apache_match = re.search(r"apache/([\d.]+)", server, re.I)
            if apache_match:
                versions["apache"] = apache_match.group(1)
            nginx_match = re.search(r"nginx/([\d.]+)", server, re.I)
            if nginx_match:
                versions["nginx"] = nginx_match.group(1)

        powered = headers.get("x-powered-by", "")
        if powered:
            versions["powered_by"] = powered
            php_match = re.search(r"php/([\d.]+)", powered, re.I)
            if php_match:
                versions["php"] = php_match.group(1)

        if "/wp-content/" in html_lower or "wp-json" in html_lower:
            versions["cms"] = "WordPress"
            gen_match = re.search(r'<meta[^>]*content="wordpress ([\d.]+)"', html_lower)
            if gen_match:
                versions["wordpress"] = gen_match.group(1)

        if "/media/system/js/" in html_lower or "joomla" in html_lower:
            versions["cms"] = "Joomla"
            joomla_match = re.search(r"joomla!?\s*([\d.]+)", html_lower)
            if joomla_match:
                versions["joomla"] = joomla_match.group(1)

        if "/sites/default/files/" in html_lower or "drupal" in html_lower:
            versions["cms"] = "Drupal"
            drupal_match = re.search(r"drupal\s*([\d.x]+)", html_lower)
            if drupal_match:
                versions["drupal"] = drupal_match.group(1)

        return versions

    def _detect_platforms(self, html: str, headers: dict) -> List[str]:
        detected = []
        html_lower = html.lower()[:20000]
        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        combined = html_lower + " " + headers_str

        for platform, patterns in PLATFORM_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.I):
                    detected.append(platform)
                    break
        return detected

    def _check_vulnerabilities(self, software: dict) -> List[dict]:
        vulns = []
        for sw_key, sw_version in software.items():
            if sw_key in VULNERABLE_VERSIONS:
                for vuln_ver, vuln_info in VULNERABLE_VERSIONS[sw_key].items():
                    if vuln_ver in sw_version:
                        vulns.append({
                            "software": sw_key,
                            "version": sw_version,
                            "cve": vuln_info[0],
                            "description": vuln_info[1] if len(vuln_info) > 1 else "",
                        })
        return vulns

    def _scan_secrets(self, html: str) -> List[dict]:
        found = []
        seen = set()
        for key_name, pattern in API_KEY_PATTERNS.items():
            matches = pattern.findall(html)
            for match in matches:
                match_val = match if isinstance(match, str) else match[0] if match else ""
                if len(match_val) < 8 or match_val in seen:
                    continue
                seen.add(match_val)
                found.append({
                    "type": key_name,
                    "value": match_val[:40] + "..." if len(match_val) > 40 else match_val,
                })
        return found

    def _check_cookies(self, resp: httpx.Response) -> List[dict]:
        issues = []
        for cookie in resp.cookies.jar:
            cookie_str = str(cookie).lower()
            missing = []
            if "httponly" not in cookie_str:
                missing.append("HttpOnly")
            if "secure" not in cookie_str:
                missing.append("Secure")
            if "samesite" not in cookie_str:
                missing.append("SameSite")
            if missing:
                issues.append({"name": cookie.name, "missing": missing})
        return issues

    async def _check_cors(self, url: str, client: httpx.AsyncClient) -> List[dict]:
        issues = []
        try:
            resp = await client.options(url, headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"}, follow_redirects=False)
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == "*":
                issues.append({"type": "wildcard_origin", "value": acao})
            elif "evil.com" in acao:
                issues.append({"type": "origin_reflection", "value": acao})
            acac = resp.headers.get("access-control-allow-credentials", "")
            if acac.lower() == "true" and acao != "":
                issues.append({"type": "credentials_with_origin", "value": f"ACAO={acao}, ACAC=true"})
        except Exception:
            pass
        return issues

    async def _probe_sensitive_paths(self, url: str, platforms: List[str], client: httpx.AsyncClient) -> List[dict]:
        found = []
        paths_to_check = set(SENSITIVE_PATHS.get("generic", []))
        for plat in platforms:
            paths_to_check.update(SENSITIVE_PATHS.get(plat, []))

        base = url.rstrip("/")
        for p in list(paths_to_check)[:15]:
            try:
                resp = await client.get(f"{base}{p}", follow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 20:
                    is_sensitive = False
                    text_lower = resp.text.lower()[:2000]
                    if p == "/.env" and ("=" in resp.text) and ("APP_" in resp.text or "DB_" in resp.text or "SECRET" in resp.text.upper()):
                        is_sensitive = True
                    elif p == "/.git/HEAD" and "ref:" in resp.text:
                        is_sensitive = True
                    elif p == "/xmlrpc.php" and "xml" in text_lower:
                        is_sensitive = True
                    elif p.endswith(".log") and ("error" in text_lower or "exception" in text_lower or "stack" in text_lower):
                        is_sensitive = True
                    elif p in ["/swagger", "/api-docs", "/swagger.json"] and ("swagger" in text_lower or "openapi" in text_lower):
                        is_sensitive = True
                    elif p == "/telescope" and "telescope" in text_lower:
                        is_sensitive = True
                    elif p == "/__debug__/" and "debug" in text_lower:
                        is_sensitive = True
                    elif p == "/phpinfo.php" and "phpinfo" in text_lower:
                        is_sensitive = True
                    elif p == "/server-status" and ("apache" in text_lower or "server" in text_lower):
                        is_sensitive = True
                    elif p == "/wp-json/wp/v2/users":
                        try:
                            users = resp.json()
                            if isinstance(users, list) and len(users) > 0:
                                is_sensitive = True
                        except Exception:
                            pass
                    elif p == "/wp-config.php.bak" and ("DB_NAME" in resp.text or "DB_PASSWORD" in resp.text):
                        is_sensitive = True

                    if is_sensitive:
                        found.append({"path": p, "status": resp.status_code, "size": len(resp.text)})
            except Exception:
                pass
        return found

    def _build_findings(self, result: dict):
        findings = result["findings"]

        for vuln in result["vulnerabilities"]:
            findings.append({
                "title": f"{vuln['software'].upper()} {vuln['version']} â€” {vuln['cve']}",
                "description": vuln["description"],
                "severity": "critical",
                "category": "known_vulnerability",
                "location": result["url"],
            })

        for key in result["api_keys"]:
            sev = "critical" if key["type"] in ("aws_access_key", "stripe_secret", "private_key", "mongodb_uri", "postgres_uri") else "high"
            findings.append({
                "title": f"Exposed: {key['type'].upper().replace('_', ' ')}",
                "description": f"API key/secret found in page source: {key['value'][:30]}...",
                "severity": sev,
                "category": "secret_exposure",
                "location": result["url"],
            })

        if not result["waf"] or "None" in result["waf"]:
            findings.append({
                "title": "No WAF Detected",
                "description": "No Web Application Firewall protecting this target",
                "severity": "medium",
                "category": "missing_protection",
                "location": result["url"],
            })

        for header in result["missing_headers"]:
            findings.append({
                "title": f"Missing: {header}",
                "description": SECURITY_HEADERS.get(header, "Security header not set"),
                "severity": "low",
                "category": "missing_header",
                "location": result["url"],
            })

        for sp in result["sensitive_paths"]:
            severity = "critical" if sp["path"] in ["/.env", "/wp-config.php.bak", "/.git/HEAD"] else "high"
            findings.append({
                "title": f"Sensitive Path Exposed: {sp['path']}",
                "description": f"Accessible at {result['url']}{sp['path']} ({sp['size']} bytes)",
                "severity": severity,
                "category": "sensitive_exposure",
                "location": result["url"],
            })

        for cors in result["cors_issues"]:
            findings.append({
                "title": f"CORS Misconfiguration: {cors['type']}",
                "description": f"CORS issue: {cors['value']}",
                "severity": "high" if cors["type"] == "origin_reflection" else "medium",
                "category": "cors",
                "location": result["url"],
            })

        for cookie in result["cookie_issues"]:
            findings.append({
                "title": f"Insecure Cookie: {cookie['name']}",
                "description": f"Cookie missing: {', '.join(cookie['missing'])}",
                "severity": "medium" if "HttpOnly" in cookie["missing"] else "low",
                "category": "insecure_cookie",
                "location": result["url"],
            })

    async def run(self, urls: List[str], min_score: int = 0):
        emit("phase_update", {"phase": "surface", "status": "running"})
        emit("log_stream", {
            "message": f"SNIPER SCAN initialized â€” {len(urls)} target(s) loaded",
            "level": "info",
            "phase": "surface",
        })

        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"},
        ) as client:
            sem = asyncio.Semaphore(10)

            async def scan_with_sem(url: str):
                async with sem:
                    return await self.scan_single(url, client)

            total = len(urls)
            tasks = [scan_with_sem(u) for u in urls]

            emit("phase_update", {"phase": "exposure", "status": "running"})
            emit("log_stream", {
                "message": f"Starting rapid triage of {total} URL(s)...",
                "level": "info",
                "phase": "exposure",
            })

            for i, coro in enumerate(asyncio.as_completed(tasks), 1):
                result = await coro
                self.total_scanned += 1

                if result.get("alive"):
                    self.total_alive += 1

                    level = "error" if result["score"] >= 70 else "warn" if result["score"] >= 40 else "info"
                    emit("log_stream", {
                        "message": f"[SCORE:{result['score']:3d}] {result['url']} â€” WAF: {','.join(result['waf'])} | Platforms: {','.join(result['platforms'][:3]) or '-'} | Server: {result['software'].get('server', '?')[:30]}",
                        "level": level,
                        "phase": "exposure",
                    })

                    for finding in result.get("findings", []):
                        emit("finding_detected", {
                            "severity": finding["severity"],
                            "title": finding["title"],
                            "description": finding["description"],
                            "category": finding.get("category", ""),
                            "phase": "misconfig",
                            "location": finding.get("location", result["url"]),
                        })
                        self.all_findings.append(finding)

                    if result["api_keys"]:
                        for key in result["api_keys"]:
                            emit("asset_detected", {
                                "type": "key",
                                "label": f"{key['type'].upper()}: {key['value']}",
                                "path": result["url"],
                                "severity": "critical" if key["type"] in ("aws_access_key", "stripe_secret", "private_key") else "high",
                                "phase": "exposure",
                                "category": "secret",
                            })

                    if result["sensitive_paths"]:
                        for sp in result["sensitive_paths"]:
                            emit("asset_detected", {
                                "type": "file",
                                "label": sp["path"],
                                "path": f"{result['url']}{sp['path']}",
                                "severity": "critical" if sp["path"] in ["/.env", "/.git/HEAD"] else "high",
                                "phase": "exposure",
                                "category": "sensitive_file",
                            })

                    if result["score"] >= min_score:
                        self.results.append(result)
                        emit("sniper_target", {
                            "url": result["url"],
                            "score": result["score"],
                            "title": result["title"],
                            "waf": result["waf"],
                            "platforms": result["platforms"],
                            "software": result["software"],
                            "vulnerabilities": result["vulnerabilities"],
                            "api_keys": result["api_keys"],
                            "missing_headers": result["missing_headers"],
                            "sensitive_paths": result["sensitive_paths"],
                            "cors_issues": result["cors_issues"],
                            "cookie_issues": result["cookie_issues"],
                            "findings_count": len(result["findings"]),
                        })

                elif result.get("error"):
                    emit("log_stream", {
                        "message": f"[SKIP] {result['url']} â€” {result.get('error', 'unreachable')}",
                        "level": "debug",
                        "phase": "surface",
                    })

                pct = int(i / total * 100)
                emit("telemetry_update", {
                    "progress": pct,
                    "scanned": self.total_scanned,
                    "alive": self.total_alive,
                    "targets_found": len(self.results),
                    "total_findings": len(self.all_findings),
                    "active_modules": 4 if pct < 90 else 1,
                })

        emit("phase_update", {"phase": "misconfig", "status": "completed"})
        emit("phase_update", {"phase": "report", "status": "running"})

        self.results.sort(key=lambda r: r["score"], reverse=True)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.all_findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        scores = [r["score"] for r in self.results] if self.results else [0]
        report = {
            "summary": {
                "total_urls": len(urls),
                "total_scanned": self.total_scanned,
                "total_alive": self.total_alive,
                "targets_found": len(self.results),
                "total_findings": len(self.all_findings),
                "avg_score": round(sum(scores) / max(len(scores), 1), 1),
                "max_score": max(scores) if scores else 0,
                "severity_counts": severity_counts,
                "risk_level": "CRITICAL" if severity_counts["critical"] > 0 else "HIGH" if severity_counts["high"] > 0 else "MEDIUM" if severity_counts["medium"] > 0 else "LOW",
            },
            "top_targets": [
                {
                    "url": r["url"],
                    "score": r["score"],
                    "title": r["title"],
                    "waf": r["waf"],
                    "platforms": r["platforms"],
                    "software": r["software"],
                    "vulnerabilities": r["vulnerabilities"],
                    "api_keys": r["api_keys"],
                    "sensitive_paths": r["sensitive_paths"],
                    "findings_count": len(r["findings"]),
                }
                for r in self.results[:50]
            ],
        }

        emit("report_generated", report)

        emit("log_stream", {
            "message": f"SCAN COMPLETE â€” {self.total_scanned} scanned | {self.total_alive} alive | {len(self.results)} targets found | {len(self.all_findings)} findings (C:{severity_counts['critical']} H:{severity_counts['high']} M:{severity_counts['medium']} L:{severity_counts['low']})",
            "level": "success",
            "phase": "report",
        })

        emit("phase_update", {"phase": "report", "status": "completed"})
        emit("completed", {"status": "success", "targets_found": len(self.results), "total_findings": len(self.all_findings)})


async def main():
    if len(sys.argv) < 2:
        emit("error", {"message": "Usage: python -m scanner.sniper_scan <url_or_urls_comma_separated> [min_score]"})
        sys.exit(1)

    input_arg = sys.argv[1]
    min_score = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    raw_urls = [u.strip() for u in input_arg.split(",") if u.strip()]

    urls = []
    for u in raw_urls:
        if not u.startswith(("http://", "https://")):
            u = f"https://{u}"
        if not is_blocked(u):
            urls.append(u)

    if not urls:
        emit("error", {"message": "No valid URLs to scan"})
        emit("completed", {"status": "error", "error": "No valid URLs"})
        sys.exit(1)

    scanner = SniperScanner()
    await scanner.run(urls, min_score=min_score)


if __name__ == "__main__":
    asyncio.run(main())

