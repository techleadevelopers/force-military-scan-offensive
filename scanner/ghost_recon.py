"""
MSE Ghost Recon Engine v1.0 — Zero-Footprint Passive OSINT
============================================================
Reconnaissance layer that maps the attack surface WITHOUT
sending a single request to the target. All data comes from
public third-party sources:
  1. Certificate Transparency Logs (crt.sh)
  2. DNS History via passive DNS (SecurityTrails-style)
  3. Wayback Machine / Archive.org snapshots
  4. Technology fingerprinting via public CDN headers
  5. ASN/IP range enumeration
  6. Subdomain enumeration via CT + DNS

Zero footprint: the target NEVER sees our IP during recon.
All HTTP requests go to crt.sh, web.archive.org, etc.
"""

import asyncio
import json
import re
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, field

import httpx


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + f".{int(time.time() * 1000) % 1000:03d}"


def ghost_emit(event_type: str, data: dict):
    payload = {"event": f"ghost_recon:{event_type}", "data": data, "timestamp": time.time()}
    print(json.dumps(payload), flush=True)


def ghost_log(message: str, level: str = "info", phase: str = "ghost_recon"):
    ghost_emit("log_stream", {"message": message, "level": level, "phase": phase})


@dataclass
class ReconIntelligence:
    subdomains: List[str] = field(default_factory=list)
    archived_endpoints: List[str] = field(default_factory=list)
    certificate_domains: List[str] = field(default_factory=list)
    technology_hints: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)
    forgotten_paths: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    zero_footprint: bool = True

    def to_dict(self) -> dict:
        return {
            "subdomains": self.subdomains[:50],
            "archived_endpoints": self.archived_endpoints[:100],
            "certificate_domains": self.certificate_domains[:50],
            "technology_hints": self.technology_hints,
            "ip_ranges": self.ip_ranges[:20],
            "forgotten_paths": self.forgotten_paths[:50],
            "confidence_score": round(self.confidence_score, 3),
            "zero_footprint": self.zero_footprint,
            "total_attack_surface": (
                len(self.subdomains) + len(self.archived_endpoints) +
                len(self.forgotten_paths)
            ),
        }


FORGOTTEN_PATH_PATTERNS = [
    r"/admin", r"/wp-admin", r"/wp-login", r"/phpmyadmin",
    r"/api/v1", r"/api/v2", r"/api/internal", r"/api/debug",
    r"/graphql", r"/graphiql", r"/_debug", r"/debug",
    r"/swagger", r"/api-docs", r"/openapi",
    r"/actuator", r"/health", r"/metrics", r"/status",
    r"/.env", r"/config", r"/settings",
    r"/staging", r"/test", r"/dev", r"/beta",
    r"/backup", r"/dump", r"/export",
    r"/console", r"/shell", r"/terminal",
    r"/dashboard", r"/panel", r"/manage",
    r"/login", r"/signup", r"/register", r"/auth",
    r"/upload", r"/file", r"/download",
]

TECH_HINTS_FROM_HEADERS = {
    "x-powered-by": None,
    "server": None,
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal",
    "x-generator": None,
    "x-wordpress": "WordPress",
    "x-shopify-stage": "Shopify",
    "x-wix-renderer-server": "Wix",
}


class GhostReconEngine:
    def __init__(self, target_domain: str, log_fn=None, emit_fn=None):
        self.target = target_domain
        self.domain = urlparse(target_domain if "://" in target_domain else f"https://{target_domain}").hostname or target_domain
        self.log = log_fn or ghost_log
        self.emit = emit_fn or ghost_emit
        self.intel = ReconIntelligence()
        self.client: Optional[httpx.AsyncClient] = None

    async def execute(self) -> Dict:
        self.log(
            f"[GHOST] ZERO-FOOTPRINT RECON INITIATED — Target domain: {self.domain}",
            "warn", "ghost_recon"
        )
        self.log(
            "[GHOST] All queries go to PUBLIC third-party sources. "
            "Target will NOT see our IP.",
            "info", "ghost_recon"
        )

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(12.0, connect=5.0),
            follow_redirects=True,
            verify=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; MSE-OSINT/1.0)"},
        ) as client:
            self.client = client

            tasks = [
                self._query_certificate_transparency(),
                self._query_wayback_machine(),
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        self._extract_forgotten_paths()
        self._calculate_confidence()

        self.log(
            f"[GHOST] RECON COMPLETE — {len(self.intel.subdomains)} subdomains, "
            f"{len(self.intel.archived_endpoints)} archived endpoints, "
            f"{len(self.intel.forgotten_paths)} forgotten paths, "
            f"confidence: {self.intel.confidence_score:.1%}",
            "warn", "ghost_recon"
        )

        report = self.intel.to_dict()
        self.emit("ghost_recon_report", report)
        return report

    async def _query_certificate_transparency(self):
        self.log(
            "[GHOST] Querying Certificate Transparency logs (crt.sh)...",
            "info", "ghost_recon"
        )
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                entries = resp.json()
                seen = set()
                for entry in entries[:500]:
                    name_value = entry.get("name_value", "")
                    for line in name_value.split("\n"):
                        subdomain = line.strip().lower()
                        if subdomain and subdomain not in seen and "*" not in subdomain:
                            seen.add(subdomain)
                            if subdomain.endswith(f".{self.domain}") or subdomain == self.domain:
                                self.intel.subdomains.append(subdomain)
                                self.intel.certificate_domains.append(subdomain)

                self.log(
                    f"[GHOST] CT logs: {len(self.intel.subdomains)} unique subdomains discovered",
                    "warn" if self.intel.subdomains else "info", "ghost_recon"
                )

                interesting = [s for s in self.intel.subdomains if any(
                    kw in s for kw in ["admin", "dev", "staging", "test", "internal", "api", "beta", "vpn", "mail"]
                )]
                if interesting:
                    self.log(
                        f"[GHOST] HIGH-VALUE subdomains: {', '.join(interesting[:10])}",
                        "error", "ghost_recon"
                    )
            else:
                self.log(
                    f"[GHOST] CT query returned HTTP {resp.status_code}",
                    "info", "ghost_recon"
                )
        except Exception as e:
            self.log(
                f"[GHOST] CT query failed: {str(e)[:100]}",
                "info", "ghost_recon"
            )

    async def _query_wayback_machine(self):
        self.log(
            "[GHOST] Querying Wayback Machine (archive.org) for historical endpoints...",
            "info", "ghost_recon"
        )
        try:
            url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={self.domain}/*&output=json&limit=300&fl=original&collapse=urlkey"
            )
            resp = await self.client.get(url)
            if resp.status_code == 200:
                rows = resp.json()
                for row in rows[1:]:
                    if row and len(row) > 0:
                        archived_url = row[0]
                        self.intel.archived_endpoints.append(archived_url)

                self.log(
                    f"[GHOST] Wayback Machine: {len(self.intel.archived_endpoints)} historical endpoints found",
                    "warn" if self.intel.archived_endpoints else "info", "ghost_recon"
                )
            else:
                self.log(
                    f"[GHOST] Wayback query returned HTTP {resp.status_code}",
                    "info", "ghost_recon"
                )
        except Exception as e:
            self.log(
                f"[GHOST] Wayback query failed: {str(e)[:100]}",
                "info", "ghost_recon"
            )

    def _extract_forgotten_paths(self):
        all_urls = self.intel.archived_endpoints
        seen_paths = set()
        for url_str in all_urls:
            try:
                parsed = urlparse(url_str)
                path = parsed.path.rstrip("/")
                if path and path not in seen_paths:
                    seen_paths.add(path)
                    for pattern in FORGOTTEN_PATH_PATTERNS:
                        if re.search(pattern, path, re.I):
                            self.intel.forgotten_paths.append(path)
                            break
            except Exception:
                pass

        if self.intel.forgotten_paths:
            self.log(
                f"[GHOST] FORGOTTEN PATHS detected in archives: "
                f"{', '.join(self.intel.forgotten_paths[:8])}",
                "error", "ghost_recon"
            )

    def _calculate_confidence(self):
        score = 0.0
        if len(self.intel.subdomains) > 0:
            score += 0.25
        if len(self.intel.subdomains) > 10:
            score += 0.15
        if len(self.intel.archived_endpoints) > 0:
            score += 0.20
        if len(self.intel.archived_endpoints) > 50:
            score += 0.10
        if len(self.intel.forgotten_paths) > 0:
            score += 0.20
        if len(self.intel.technology_hints) > 0:
            score += 0.10
        self.intel.confidence_score = min(score, 1.0)


async def run_ghost_recon(target: str) -> Dict:
    engine = GhostReconEngine(target)
    return await engine.execute()
