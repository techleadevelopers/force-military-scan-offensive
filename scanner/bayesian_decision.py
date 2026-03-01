"""
MSE Bayesian Decision Engine
===============================
Uses Bayesian inference for attack decisions instead of fixed thresholds.
P(success | evidence) = P(evidence|success) * P(success) / P(evidence)
Adapts probability based on accumulated evidence during scan.
"""

import math
from typing import List, Dict, Any, Optional


PRIOR_PROBABILITIES = {
    "ssrf": 0.45,
    "ssrf_internal": 0.45,
    "ssrf_metadata": 0.50,
    "sqli": 0.35,
    "nosql_injection": 0.40,
    "xss": 0.55,
    "lfi": 0.30,
    "rce": 0.15,
    "ssti": 0.30,
    "deserialization": 0.25,
    "prototype_pollution": 0.35,
    "jwt_none_algorithm": 0.40,
    "path_traversal": 0.45,
    "idor": 0.50,
    "broken_auth": 0.45,
    "credential_leak": 0.55,
    "api_exposure": 0.60,
    "debug_exposure": 0.35,
    "cors_misconfiguration": 0.50,
    "open_redirect": 0.55,
    "command_injection": 0.20,
    "xxe": 0.25,
    "csrf_bypass": 0.40,
    "mass_assignment": 0.35,
    "introspection": 0.70,
    "admin_bypass": 0.30,
    "waf_bypass": 0.35,
    "race_condition": 0.30,
    "http_smuggling": 0.25,
    "timing_side_channel": 0.35,
}


class BayesianDecisionEngine:

    def __init__(self):
        self.priors = dict(PRIOR_PROBABILITIES)
        self.evidence_history: List[Dict] = []
        self.posterior_cache: Dict[str, float] = {}

    def update_prior(self, attack_vector: str, outcome: bool):
        current = self.priors.get(attack_vector, 0.3)
        if outcome:
            self.priors[attack_vector] = min(current * 1.15, 0.98)
        else:
            self.priors[attack_vector] = max(current * 0.85, 0.05)

        self.evidence_history.append({
            "vector": attack_vector,
            "outcome": outcome,
            "updated_prior": self.priors[attack_vector],
        })

    def calculate_success_probability(self, attack_vector: str, context: Dict) -> Dict:
        prior = self.priors.get(attack_vector, 0.3)

        likelihood = 1.0

        stack_vectors = set(context.get("stack_vectors", []))
        if attack_vector in stack_vectors:
            likelihood *= 1.5

        waf_strength = context.get("waf_strength", "unknown")
        waf_factors = {"weak": 1.3, "medium": 1.0, "strong": 0.5, "none": 1.5, "unknown": 1.0}
        likelihood *= waf_factors.get(waf_strength, 1.0)

        historical = self._historical_success_rate(attack_vector)
        likelihood *= (1.0 + historical)

        correlation_boost = self._correlation_boost(attack_vector, context.get("findings", []))
        likelihood *= correlation_boost

        findings_count = len(context.get("findings", []))
        if findings_count > 20:
            likelihood *= 1.2
        elif findings_count > 10:
            likelihood *= 1.1

        if context.get("auto_dump_triggered"):
            likelihood *= 1.3

        posterior = prior * likelihood
        posterior = min(posterior, 0.99)

        if posterior > 0.6:
            decision = "ATTACK"
        elif posterior > 0.3:
            decision = "DEFER"
        else:
            decision = "SKIP"

        result = {
            "attack_vector": attack_vector,
            "probability": round(posterior, 4),
            "prior": round(prior, 4),
            "likelihood": round(likelihood, 4),
            "decision": decision,
            "factors": {
                "stack_match": attack_vector in stack_vectors,
                "waf_factor": waf_factors.get(waf_strength, 1.0),
                "historical_rate": round(historical, 4),
                "correlation_boost": round(correlation_boost, 4),
                "evidence_count": findings_count,
            },
        }

        self.posterior_cache[attack_vector] = posterior
        return result

    def batch_evaluate(self, vectors: List[str], context: Dict) -> List[Dict]:
        results = []
        for vector in vectors:
            results.append(self.calculate_success_probability(vector, context))
        return sorted(results, key=lambda x: x["probability"], reverse=True)

    def _historical_success_rate(self, attack_vector: str) -> float:
        relevant = [e for e in self.evidence_history if e["vector"] == attack_vector]
        if not relevant:
            return 0.0
        successes = sum(1 for e in relevant if e["outcome"])
        return successes / len(relevant)

    def _correlation_boost(self, attack_vector: str, findings: List[Dict]) -> float:
        boost = 1.0

        correlation_map = {
            "ssrf": ["cloud_credential", "api_endpoint", "url_parameter"],
            "sqli": ["database_url", "db_credential", "error_message"],
            "lfi": ["path_traversal", "file_parameter"],
            "rce": ["deserialization", "ssti", "command_injection"],
            "jwt_none_algorithm": ["jwt_token", "auth_endpoint"],
            "prototype_pollution": ["express", "node_module"],
            "idor": ["session_token", "user_id_parameter"],
        }

        related_hints = correlation_map.get(attack_vector, [])
        if not related_hints:
            return boost

        for finding in findings:
            f_type = ""
            if isinstance(finding, dict):
                f_type = (finding.get("type", "") + " " + finding.get("title", "")).lower()
            elif hasattr(finding, "title"):
                f_type = (getattr(finding, "title", "") or "").lower()

            for hint in related_hints:
                if hint.replace("_", " ") in f_type or hint.replace("_", "") in f_type:
                    boost *= 1.15

        return min(boost, 3.0)

    def generate_report(self) -> Dict:
        attack_decisions = []
        defer_decisions = []
        skip_decisions = []

        for vector, prob in self.posterior_cache.items():
            entry = {"vector": vector, "probability": prob}
            if prob > 0.6:
                attack_decisions.append(entry)
            elif prob > 0.3:
                defer_decisions.append(entry)
            else:
                skip_decisions.append(entry)

        return {
            "total_evaluated": len(self.posterior_cache),
            "attack_vectors": len(attack_decisions),
            "deferred_vectors": len(defer_decisions),
            "skipped_vectors": len(skip_decisions),
            "top_attack_targets": sorted(attack_decisions, key=lambda x: x["probability"], reverse=True)[:5],
            "evidence_updates": len(self.evidence_history),
            "decisions": {
                "attack": [d["vector"] for d in attack_decisions],
                "defer": [d["vector"] for d in defer_decisions],
                "skip": [d["vector"] for d in skip_decisions],
            },
        }
