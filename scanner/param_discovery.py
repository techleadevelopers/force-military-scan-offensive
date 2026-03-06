import json
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set

import requests
from bs4 import BeautifulSoup  # type: ignore


def _safe_split_params(query: str) -> List[str]:
    params = []
    for part in query.split("&"):
        if "=" in part:
            name = part.split("=", 1)[0]
        else:
            name = part
        name = name.strip()
        if name:
            params.append(name)
    return params


@dataclass
class DiscoveryTelemetry:
    sources: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_ms: int = 0


class ParameterDiscoveryEngine:
    """
    Descobre nomes de parâmetros a partir de HTML estático e tráfego de rede.

    - discover_from_html: requests + BeautifulSoup (rápido)
    - discover_from_network: Playwright (opcional) captura requisições reais
    - discover_from_js: heurísticas em variáveis globais (opcional, via Playwright)
    """

    def __init__(
        self,
        url: str,
        session: Optional[requests.Session] = None,
        timeout_seconds: int = 12,
        max_params: int = 12,
    ):
        self.url = url
        self.session = session or requests.Session()
        self.timeout_seconds = timeout_seconds
        self.max_params = max_params
        self.telemetry = DiscoveryTelemetry()
        self._discovered: Set[str] = set()

    # Public API ---------------------------------------------------------
    def discover_all(self, use_network: bool = True) -> List[str]:
        start = time.monotonic()

        html_params = self.discover_from_html()
        self._discovered.update(html_params)

        if use_network:
            net_params = self.discover_from_network()
            self._discovered.update(net_params)

        js_params = self.discover_from_js() if use_network else set()
        self._discovered.update(js_params)

        # fallback heuristics if still empty
        if not self._discovered:
            self._discovered.update({"q", "search", "id", "page", "query"})
            self.telemetry.sources.append("fallback")

        self.telemetry.duration_ms = int((time.monotonic() - start) * 1000)
        return list(self._discovered)[: self.max_params]

    # HTML parsing -------------------------------------------------------
    def discover_from_html(self) -> Set[str]:
        params: Set[str] = set()
        try:
            resp = self.session.get(self.url, timeout=self.timeout_seconds, allow_redirects=True)
        except Exception as exc:
            self.telemetry.errors.append(f"html_fetch:{exc}")
            return params

        try:
            url_obj = urllib.parse.urlparse(resp.url)
            params.update(url_obj.query.split("&")) if url_obj.query else None
            params = {p.split("=")[0] for p in params if p}
        except Exception:
            pass

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception as exc:
            self.telemetry.errors.append(f"html_parse:{exc}")
            return params

        for tag in soup.find_all(["input", "select", "textarea", "button"]):
            name = tag.get("name") or tag.get("id")
            if name:
                params.add(str(name))

        for form in soup.find_all("form"):
            form_action = form.get("action", "")
            if "?" in form_action:
                query = form_action.split("?", 1)[1]
                params.update(_safe_split_params(query))

        for link in soup.find_all("a"):
            href = link.get("href")
            if href and "?" in href:
                query = href.split("?", 1)[1]
                params.update(_safe_split_params(query))

        if params:
            self.telemetry.sources.append("html")
        return params

    # Network / Playwright -----------------------------------------------
    def discover_from_network(self) -> Set[str]:
        """
        Usa Playwright (se instalado) para acionar a página, executar ações leves
        e capturar os parâmetros das requisições feitas pelo browser.
        """
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception:
            self.telemetry.errors.append("playwright_missing")
            return set()

        params: Set[str] = set()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()

                def on_request(request):
                    params.update(self._extract_params_from_request(request))

                context.on("request", on_request)

                page.goto(self.url, wait_until="domcontentloaded", timeout=self.timeout_seconds * 1000)
                for action in ["scroll", "click_first_link", "fill_search", "submit_form"]:
                    self._perform_action(page, action)
                    if len(params) >= self.max_params:
                        break

                browser.close()
                if params:
                    self.telemetry.sources.append("network")
        except Exception as exc:
            self.telemetry.errors.append(f"playwright:{exc}")

        return params

    # JS heuristics ------------------------------------------------------
    def discover_from_js(self) -> Set[str]:
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception:
            return set()

        params: Set[str] = set()
        js_probe = """
        const bag = new Set();
        const pushKeys = (obj) => {
          if (!obj || typeof obj !== 'object') return;
          Object.keys(obj).forEach(k => bag.add(k));
        };
        if (window.ajaxSettings && window.ajaxSettings.data) pushKeys(window.ajaxSettings.data);
        if (window.__INITIAL_STATE__) pushKeys(window.__INITIAL_STATE__);
        if (window._env_) pushKeys(window._env_);
        return Array.from(bag);
        """

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                page.goto(self.url, wait_until="domcontentloaded", timeout=self.timeout_seconds * 1000)
                result = page.evaluate(js_probe)
                if isinstance(result, list):
                    params.update([str(r) for r in result if r])
                    if params:
                        self.telemetry.sources.append("js")
                browser.close()
        except Exception as exc:
            self.telemetry.errors.append(f"js_probe:{exc}")

        return params

    # Helpers ------------------------------------------------------------
    def _perform_action(self, page, action: str):
        try:
            if action == "scroll":
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            elif action == "click_first_link":
                page.click("a", timeout=1500)
            elif action == "fill_search":
                page.fill("input[type='search']", "test", timeout=1500)
            elif action == "submit_form":
                page.press("input[type='text'], textarea", "Enter", timeout=1500)
            self.telemetry.actions.append(action)
        except Exception:
            self.telemetry.errors.append(f"action:{action}")

    def _extract_params_from_request(self, request) -> Set[str]:
        found: Set[str] = set()
        try:
            url_obj = urllib.parse.urlparse(request.url)
            found.update([k for k in urllib.parse.parse_qs(url_obj.query).keys()])
        except Exception:
            pass

        try:
            data = request.post_data or ""
            if data:
                # tenta JSON
                try:
                    parsed = json.loads(data)
                    if isinstance(parsed, dict):
                        found.update(parsed.keys())
                except Exception:
                    found.update(_safe_split_params(data))
        except Exception:
            pass

        return found
