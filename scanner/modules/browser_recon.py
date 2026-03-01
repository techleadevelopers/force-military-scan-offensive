import asyncio
import json
import re
import time
from urllib.parse import urlparse, urljoin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from scanner.modules.base import BaseModule
from scanner.models import Finding


def create_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-software-rasterizer")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--ignore-certificate-errors")
    options.set_capability("goog:loggingPrefs", {
        "browser": "ALL",
        "performance": "ALL",
    })
    service = Service()
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(30)
    return driver


class BrowserReconModule(BaseModule):
    name = "browser_recon"
    phase = "exposure"
    description = "Selenium-based browser reconnaissance — captures JS files, network traffic, cookies, localStorage, console errors"

    async def execute(self, job) -> list:
        findings = []
        driver = None

        try:
            self.log("Launching headless Chromium browser...")
            driver = await asyncio.get_event_loop().run_in_executor(None, create_driver)
            self.log("Browser launched successfully", "success")

            self.log(f"Navigating to {job.base_url}...")
            await asyncio.get_event_loop().run_in_executor(None, driver.get, job.base_url)
            self.log(f"Page loaded — Title: {driver.title}")
            self.telemetry(requestsAnalyzed=1)

            await asyncio.sleep(3)

            js_files = set()
            api_endpoints = set()
            all_requests = []

            try:
                perf_logs = driver.get_log("performance")
                for entry in perf_logs:
                    try:
                        msg = json.loads(entry["message"])["message"]
                        if msg["method"] == "Network.requestWillBeSent":
                            url = msg["params"]["request"]["url"]
                            all_requests.append(url)
                            if url.endswith(".js") or ".js?" in url or "/js/" in url:
                                js_files.add(url)
                            parsed = urlparse(url)
                            if "/api/" in parsed.path or "/graphql" in parsed.path:
                                api_endpoints.add(url)
                        elif msg["method"] == "Network.responseReceived":
                            resp = msg["params"]["response"]
                            ct = resp.get("headers", {}).get("content-type", "")
                            if "javascript" in ct:
                                js_files.add(resp["url"])
                    except (KeyError, json.JSONDecodeError):
                        pass
            except Exception as e:
                self.log(f"Performance log capture: {str(e)}", "warn")

            script_elements = driver.find_elements(By.TAG_NAME, "script")
            inline_scripts = []
            for script in script_elements:
                src = script.get_attribute("src")
                if src:
                    full_url = urljoin(job.base_url, src)
                    js_files.add(full_url)
                else:
                    content = script.get_attribute("innerHTML")
                    if content and len(content.strip()) > 10:
                        inline_scripts.append(content)

            self.log(f"Discovered {len(js_files)} external JS files, {len(inline_scripts)} inline scripts")
            self.telemetry(requestsAnalyzed=len(all_requests) + 1)

            job._js_files = list(js_files)
            job._inline_scripts = inline_scripts
            job._all_requests = all_requests
            job._api_endpoints = list(api_endpoints)

            cookies = driver.get_cookies()
            self.log(f"Captured {len(cookies)} cookies")

            insecure_cookies = []
            for cookie in cookies:
                issues = []
                if not cookie.get("secure"):
                    issues.append("missing Secure flag")
                if not cookie.get("httpOnly"):
                    issues.append("missing HttpOnly flag")
                if cookie.get("sameSite", "None") == "None":
                    issues.append("SameSite=None")
                if issues:
                    insecure_cookies.append({"name": cookie["name"], "issues": issues})

            if insecure_cookies:
                cookie_details = "; ".join(
                    [f"{c['name']} ({', '.join(c['issues'])})" for c in insecure_cookies[:10]]
                )
                f = Finding(
                    severity="medium" if any("HttpOnly" in str(c["issues"]) for c in insecure_cookies) else "low",
                    title=f"Insecure Cookie Configuration ({len(insecure_cookies)} cookies)",
                    description=f"Cookies with security issues: {cookie_details}",
                    phase=self.phase,
                    recommendation="Set Secure, HttpOnly, and SameSite=Strict flags on all sensitive cookies.",
                    cvss_score=4.5,
                )
                findings.append(f)
                self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)

            local_storage = {}
            session_storage = {}
            try:
                local_storage = driver.execute_script(
                    "var items = {}; for (var i = 0; i < localStorage.length; i++) { "
                    "var key = localStorage.key(i); items[key] = localStorage.getItem(key); } return items;"
                )
                session_storage = driver.execute_script(
                    "var items = {}; for (var i = 0; i < sessionStorage.length; i++) { "
                    "var key = sessionStorage.key(i); items[key] = sessionStorage.getItem(key); } return items;"
                )
            except Exception:
                pass

            sensitive_storage_keys = []
            token_patterns = re.compile(
                r"(token|auth|session|jwt|api[_-]?key|secret|password|credential|access|bearer)",
                re.IGNORECASE,
            )
            all_storage = {**local_storage, **session_storage}
            for key, value in all_storage.items():
                if token_patterns.search(key) or (isinstance(value, str) and token_patterns.search(value)):
                    sensitive_storage_keys.append(key)

            if sensitive_storage_keys:
                storage_desc = ", ".join(sensitive_storage_keys[:15])
                f = Finding(
                    severity="high",
                    title=f"Sensitive Data in Browser Storage ({len(sensitive_storage_keys)} keys)",
                    description=f"Potentially sensitive keys found in localStorage/sessionStorage: {storage_desc}. "
                    "Browser storage is accessible to any JavaScript on the page, including XSS payloads.",
                    phase=self.phase,
                    recommendation="Avoid storing tokens, secrets, or credentials in localStorage/sessionStorage. Use HttpOnly cookies instead.",
                    cvss_score=6.5,
                )
                findings.append(f)
                self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)

            if local_storage or session_storage:
                self.log(
                    f"Browser storage: {len(local_storage)} localStorage items, {len(session_storage)} sessionStorage items"
                )

            try:
                console_logs = driver.get_log("browser")
                errors = [
                    log for log in console_logs if log.get("level") in ("SEVERE", "WARNING")
                ]
                if errors:
                    self.log(f"Browser console: {len(errors)} warnings/errors detected", "warn")
                    for err in errors[:5]:
                        self.log(f"  Console {err.get('level', 'ERR')}: {err.get('message', '')[:200]}", "debug")

                    error_msgs = [e.get("message", "") for e in errors]
                    stack_traces = [m for m in error_msgs if "stack" in m.lower() or "error" in m.lower()]
                    if stack_traces:
                        f = Finding(
                            severity="low",
                            title=f"Console Errors Detected ({len(errors)} issues)",
                            description=f"Browser console shows {len(errors)} warnings/errors. "
                            "This may indicate debugging info leaks or unhandled exceptions. "
                            f"Sample: {stack_traces[0][:300]}",
                            phase=self.phase,
                            recommendation="Suppress verbose error output in production. Use a global error handler.",
                            cvss_score=2.0,
                        )
                        findings.append(f)
                        self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
            except Exception:
                pass

            if api_endpoints:
                self.log(f"Discovered {len(api_endpoints)} API endpoints in network traffic")
                for ep in list(api_endpoints)[:10]:
                    self.log(f"  API: {ep}", "debug")

            page_source = driver.page_source
            meta_tags = driver.find_elements(By.TAG_NAME, "meta")
            meta_info = {}
            for tag in meta_tags:
                name = tag.get_attribute("name") or tag.get_attribute("property")
                content = tag.get_attribute("content")
                if name and content:
                    meta_info[name] = content

            frameworks = []
            fw_checks = {
                "React": ["__REACT_DEVTOOLS_GLOBAL_HOOK__", "_reactRootContainer", "data-reactroot"],
                "Angular": ["ng-version", "ng-app", "__ng_zone__"],
                "Vue.js": ["__VUE__", "data-v-", "__vue_app__"],
                "Next.js": ["__NEXT_DATA__", "_next/"],
                "Nuxt.js": ["__NUXT__", "_nuxt/"],
                "jQuery": ["jQuery", "$.fn.jquery"],
                "Svelte": ["__svelte"],
                "Ember.js": ["ember-application"],
            }

            for fw_name, patterns in fw_checks.items():
                for pattern in patterns:
                    if pattern in page_source:
                        frameworks.append(fw_name)
                        break

            if frameworks:
                self.log(f"Frontend frameworks detected: {', '.join(frameworks)}")
                job._detected_frameworks = frameworks

            source_map_refs = re.findall(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", page_source)
            if source_map_refs:
                f = Finding(
                    severity="medium",
                    title=f"Source Maps Exposed ({len(source_map_refs)} references)",
                    description=f"Source map references found: {', '.join(source_map_refs[:5])}. "
                    "Source maps reveal the original unminified source code of the application.",
                    phase=self.phase,
                    recommendation="Remove source map references in production builds. Configure your bundler to exclude them.",
                    cvss_score=5.0,
                )
                findings.append(f)
                self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)

            self.log(f"Browser recon complete — {len(js_files)} JS files, {len(all_requests)} total requests, {len(findings)} findings")

        except Exception as e:
            self.log(f"Browser recon error: {str(e)}", "error")

        finally:
            if driver:
                try:
                    await asyncio.get_event_loop().run_in_executor(None, driver.quit)
                    self.log("Browser closed")
                except Exception:
                    pass

        return findings
