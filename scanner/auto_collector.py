#!/usr/bin/env python3
import json
import re
import os
import sys
import csv
import time
import asyncio
import zipfile
import io
from typing import List, Dict, Any, Optional, Set
from urllib.parse import quote, urlparse
from collections import defaultdict

import httpx


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

VALID_TLDS = {
    "com", "org", "net", "br", "io", "gov", "edu", "info", "store", "online",
    "shop", "app", "dev", "co", "me", "us", "uk", "de", "fr", "es", "it",
    "pt", "nl", "be", "ch", "at", "au", "ca", "jp", "cn", "kr", "in",
    "ru", "pl", "se", "no", "fi", "dk", "cz", "hu", "ro", "bg", "hr",
    "sk", "si", "lt", "lv", "ee", "ie", "nz", "za", "mx", "ar", "cl",
    "pe", "uy", "ec", "ve", "py", "bo", "cr", "gt", "hn", "ni", "sv",
    "pa", "do", "cu", "pr", "tt", "jm", "bz", "gy", "sr", "ai", "ag",
    "bb", "dm", "gd", "kn", "lc", "vc", "bs", "ky", "tc", "vg", "vi",
    "xyz", "tech", "site", "cloud", "digital", "agency", "studio", "design",
    "solutions", "systems", "media", "group", "consulting", "services",
    "pro", "biz", "mobi", "name", "tel", "asia", "cat", "coop", "museum",
    "travel", "aero", "jobs", "mil", "int", "eu", "la", "tv", "cc", "ws",
    "club", "space", "fun", "life", "live", "world", "today", "one",
}


def emit(event_type: str, data: dict):
    payload = {"event": event_type, "data": data, "timestamp": time.time()}
    print(json.dumps(payload), flush=True)


def emit_log(message: str, level: str = "info"):
    emit("collector_log", {"message": message, "level": level})


def is_blocked(host: str) -> bool:
    for pattern in BLOCKED_HOSTS:
        if pattern.search(host):
            return True
    return False


def clean_domain(raw: str) -> Optional[str]:
    raw = raw.strip().lower()
    raw = re.sub(r'^https?://', '', raw)
    raw = re.sub(r'^www\.', '', raw)
    raw = raw.split('/')[0]
    raw = raw.split('?')[0]
    raw = raw.split('#')[0]
    raw = raw.split(':')[0]
    if not raw or '.' not in raw:
        return None
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', raw):
        return None
    if is_blocked(raw):
        return None
    tld = raw.split('.')[-1]
    if tld not in VALID_TLDS and len(tld) > 6:
        return None
    if len(raw) < 4 or len(raw) > 253:
        return None
    return raw


class AutoCollector:
    def __init__(self, timeout: int = 10, max_per_source: int = 500):
        self.timeout = timeout
        self.max_per_source = max_per_source
        self.results: Set[str] = set()
        self.source_stats: Dict[str, int] = defaultdict(int)
        self.client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if not self.client:
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                headers={"User-Agent": USER_AGENT},
                follow_redirects=True,
                verify=False,
            )
        return self.client

    async def close(self):
        if self.client:
            await self.client.aclose()
            self.client = None

    def _add_domain(self, raw: str, source: str) -> bool:
        domain = clean_domain(raw)
        if domain and domain not in self.results:
            self.results.add(domain)
            self.source_stats[source] += 1
            return True
        return False

    async def collect_from_crtsh(self, domains: List[str], wildcard: bool = True):
        emit_log(f"[CRT.SH] Scanning {len(domains)} root domain(s)...", "info")
        client = await self._get_client()
        before = len(self.results)

        for domain in domains:
            try:
                query = f"%25.{domain}" if wildcard else domain
                url = f"https://crt.sh/?q={query}&output=json"
                resp = await client.get(url, timeout=15)

                if resp.status_code == 200:
                    data = resp.json()
                    count = 0
                    for entry in data:
                        name = entry.get("name_value", "")
                        if name:
                            for line in name.split("\n"):
                                line = line.strip().lstrip("*.")
                                if self._add_domain(line, "crt.sh"):
                                    count += 1
                                    if count >= self.max_per_source:
                                        break
                        if count >= self.max_per_source:
                            break

                    emit_log(f"  [CRT.SH] {domain} → {count} subdomain(s)", "success")
                else:
                    emit_log(f"  [CRT.SH] {domain} → HTTP {resp.status_code}", "warn")

                await asyncio.sleep(0.5)

            except Exception as e:
                emit_log(f"  [CRT.SH] {domain} error: {str(e)[:80]}", "warn")

        added = len(self.results) - before
        emit_log(f"[CRT.SH] Complete — {added} unique domain(s) added", "success")

    async def collect_from_urlscan(self, queries: List[str]):
        emit_log(f"[URLSCAN] Querying {len(queries)} search(es)...", "info")
        client = await self._get_client()
        before = len(self.results)

        for query in queries:
            try:
                url = f"https://urlscan.io/api/v1/search/?q={quote(query)}&size=100"
                resp = await client.get(url, timeout=15)

                if resp.status_code == 200:
                    data = resp.json()
                    count = 0
                    for result in data.get("results", []):
                        page = result.get("page", {})
                        domain = page.get("domain", "")
                        if domain and self._add_domain(domain, "urlscan"):
                            count += 1
                            if count >= self.max_per_source:
                                break
                    emit_log(f"  [URLSCAN] '{query}' → {count} domain(s)", "success")
                else:
                    emit_log(f"  [URLSCAN] '{query}' → HTTP {resp.status_code}", "warn")

                await asyncio.sleep(2)

            except Exception as e:
                emit_log(f"  [URLSCAN] error: {str(e)[:80]}", "warn")

        added = len(self.results) - before
        emit_log(f"[URLSCAN] Complete — {added} unique domain(s) added", "success")

    async def collect_from_commoncrawl(self, search_domain: Optional[str] = None, limit: int = 500):
        emit_log(f"[COMMONCRAWL] Fetching index (limit={limit})...", "info")
        client = await self._get_client()
        before = len(self.results)

        try:
            cc_index_url = "https://index.commoncrawl.org/collinfo.json"
            resp = await client.get(cc_index_url, timeout=15)
            if resp.status_code != 200:
                emit_log("[COMMONCRAWL] Failed to fetch index list", "warn")
                return

            indexes = resp.json()
            if not indexes:
                emit_log("[COMMONCRAWL] Empty index list", "warn")
                return

            latest_id = indexes[0]["id"]
            search_url = f"https://index.commoncrawl.org/{latest_id}-index"
            params = {"output": "json", "limit": str(min(limit, 1000))}
            if search_domain:
                params["url"] = f"*.{search_domain}"

            resp = await client.get(search_url, params=params, timeout=30)
            count = 0
            for line in resp.text.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    raw_url = data.get("url", "")
                    if raw_url and self._add_domain(raw_url, "commoncrawl"):
                        count += 1
                        if count >= limit:
                            break
                except Exception:
                    pass

            emit_log(f"[COMMONCRAWL] {count} domain(s) collected", "success")

        except Exception as e:
            emit_log(f"[COMMONCRAWL] error: {str(e)[:100]}", "warn")

        added = len(self.results) - before
        emit_log(f"[COMMONCRAWL] Complete — {added} unique domain(s) added", "success")

    async def collect_from_shodan(self, queries: List[str], api_key: Optional[str] = None):
        if not api_key:
            emit_log("[SHODAN] No API key provided — skipping", "warn")
            return

        emit_log(f"[SHODAN] Querying {len(queries)} search(es)...", "info")
        client = await self._get_client()
        before = len(self.results)

        for query in queries:
            try:
                url = f"https://api.shodan.io/shodan/host/search"
                params = {"key": api_key, "query": query, "limit": "100"}
                resp = await client.get(url, params=params, timeout=20)

                if resp.status_code == 200:
                    data = resp.json()
                    count = 0
                    for match in data.get("matches", []):
                        for hostname in match.get("hostnames", []):
                            if hostname and self._add_domain(hostname, "shodan"):
                                count += 1
                    emit_log(f"  [SHODAN] '{query}' → {count} host(s)", "success")
                elif resp.status_code == 401:
                    emit_log("[SHODAN] Invalid API key", "error")
                    return
                else:
                    emit_log(f"  [SHODAN] '{query}' → HTTP {resp.status_code}", "warn")

                await asyncio.sleep(1)

            except Exception as e:
                emit_log(f"  [SHODAN] error: {str(e)[:80]}", "warn")

        added = len(self.results) - before
        emit_log(f"[SHODAN] Complete — {added} unique domain(s) added", "success")

    async def collect_from_public_lists(self, limit: int = 1000):
        emit_log(f"[PUBLIC LISTS] Downloading top domain lists (limit={limit})...", "info")
        client = await self._get_client()
        before = len(self.results)

        lists = [
            ("tranco", "https://tranco-list.eu/download/LATEST/top-1m.csv"),
        ]

        for name, url in lists:
            try:
                resp = await client.get(url, timeout=30)
                if resp.status_code != 200:
                    emit_log(f"  [{name.upper()}] HTTP {resp.status_code}", "warn")
                    continue

                count = 0
                for i, line in enumerate(resp.text.strip().split("\n")):
                    if i >= limit:
                        break
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        domain = parts[1].strip()
                        if self._add_domain(domain, name):
                            count += 1

                emit_log(f"  [{name.upper()}] {count} domain(s)", "success")

            except Exception as e:
                emit_log(f"  [{name.upper()}] error: {str(e)[:80]}", "warn")

        added = len(self.results) - before
        emit_log(f"[PUBLIC LISTS] Complete — {added} unique domain(s) added", "success")

    async def collect_from_google_dorking(self, dorks: List[str]):
        emit_log(f"[GOOGLE DORKS] Processing {len(dorks)} dork(s) via passive extraction...", "info")
        client = await self._get_client()
        before = len(self.results)

        for dork in dorks:
            try:
                url = f"https://www.google.com/search?q={quote(dork)}&num=20"
                resp = await client.get(url, timeout=10)

                if resp.status_code == 200:
                    urls_found = re.findall(r'https?://[^\s"<>]+', resp.text)
                    count = 0
                    for raw_url in urls_found:
                        parsed = urlparse(raw_url)
                        host = parsed.hostname or ""
                        if "google" in host or "gstatic" in host or "googleapis" in host:
                            continue
                        if self._add_domain(host, "google_dork"):
                            count += 1
                    if count > 0:
                        emit_log(f"  [DORK] '{dork[:40]}...' → {count} domain(s)", "success")
                elif resp.status_code == 429:
                    emit_log("[GOOGLE DORKS] Rate limited by Google — stopping dorks", "warn")
                    break
                else:
                    emit_log(f"  [DORK] HTTP {resp.status_code}", "warn")

                await asyncio.sleep(3)

            except Exception as e:
                emit_log(f"  [DORK] error: {str(e)[:80]}", "warn")

        added = len(self.results) - before
        emit_log(f"[GOOGLE DORKS] Complete — {added} unique domain(s) added", "success")

    async def run(self, config: Dict[str, Any]):
        emit_log("AUTO COLLECTOR — Starting automatic target collection", "info")
        emit("collector_phase", {"phase": "collecting", "status": "running"})
        start_time = time.time()

        if config.get("crtsh_domains"):
            await self.collect_from_crtsh(
                config["crtsh_domains"],
                wildcard=config.get("crtsh_wildcard", True),
            )
            emit("collector_progress", {"collected": len(self.results), "sources": dict(self.source_stats)})

        if config.get("urlscan_queries"):
            await self.collect_from_urlscan(config["urlscan_queries"])
            emit("collector_progress", {"collected": len(self.results), "sources": dict(self.source_stats)})

        if config.get("commoncrawl", False):
            await self.collect_from_commoncrawl(
                search_domain=config.get("commoncrawl_domain"),
                limit=config.get("commoncrawl_limit", 500),
            )
            emit("collector_progress", {"collected": len(self.results), "sources": dict(self.source_stats)})

        if config.get("shodan_queries") and config.get("shodan_api_key"):
            await self.collect_from_shodan(
                config["shodan_queries"],
                api_key=config["shodan_api_key"],
            )
            emit("collector_progress", {"collected": len(self.results), "sources": dict(self.source_stats)})

        if config.get("public_lists", False):
            await self.collect_from_public_lists(
                limit=config.get("public_lists_limit", 1000),
            )
            emit("collector_progress", {"collected": len(self.results), "sources": dict(self.source_stats)})

        if config.get("google_dorks"):
            await self.collect_from_google_dorking(config["google_dorks"])
            emit("collector_progress", {"collected": len(self.results), "sources": dict(self.source_stats)})

        elapsed = time.time() - start_time

        sorted_domains = sorted(self.results)

        emit("collector_phase", {"phase": "complete", "status": "completed"})
        emit("collector_result", {
            "domains": sorted_domains,
            "total": len(sorted_domains),
            "sources": dict(self.source_stats),
            "elapsed": round(elapsed, 1),
        })

        emit_log(
            f"AUTO COLLECTOR complete — {len(sorted_domains)} unique domain(s) from {len(self.source_stats)} source(s) in {elapsed:.1f}s",
            "success",
        )

        await self.close()


async def main():
    if len(sys.argv) < 2:
        emit("error", {"message": "Usage: python -m scanner.auto_collector <config_json>"})
        sys.exit(1)

    try:
        config = json.loads(sys.argv[1])
    except json.JSONDecodeError:
        emit("error", {"message": "Invalid JSON config"})
        sys.exit(1)

    collector = AutoCollector(
        timeout=config.get("timeout", 10),
        max_per_source=config.get("max_per_source", 500),
    )
    await collector.run(config)


if __name__ == "__main__":
    asyncio.run(main())
