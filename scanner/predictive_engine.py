"""
MSE Predictive Decision Engine
================================
Predicts where vulnerabilities MUST exist based on patterns,
stack fingerprints, OSINT intelligence, and historical data.
Does not wait to find â€” it PREDICTS before scanning.
"""

import re
from typing import List, Dict, Any, Optional


STACK_VULNERABILITY_PREDICTIONS = {
    "express": [
        {"vuln": "prototype_pollution", "confidence": 0.92, "locations": ["/api", "/graphql", "/__proto__"]},
        {"vuln": "jwt_none_algorithm", "confidence": 0.88, "locations": ["/auth", "/login", "/api/token"]},
        {"vuln": "nosql_injection", "confidence": 0.85, "locations": ["/search", "/query", "/filter"]},
        {"vuln": "ssrf_internal", "confidence": 0.78, "locations": ["/proxy", "/fetch", "/url", "/webhook"]},
        {"vuln": "path_traversal", "confidence": 0.75, "locations": ["/download", "/file", "/static"]},
    ],
    "next": [
        {"vuln": "ssrf_api_routes", "confidence": 0.90, "locations": ["/api/", "/_next/data"]},
        {"vuln": "broken_auth", "confidence": 0.82, "locations": ["/api/auth", "/api/user"]},
        {"vuln": "api_exposure", "confidence": 0.88, "locations": ["/_next/", "/api/"]},
        {"vuln": "path_traversal", "confidence": 0.70, "locations": ["/_next/data", "/api/preview"]},
    ],
    "django": [
        {"vuln": "ssti", "confidence": 0.85, "locations": ["/admin/", "/template/", "/render/"]},
        {"vuln": "orm_injection", "confidence": 0.80, "locations": ["/api/", "/search/", "/filter/"]},
        {"vuln": "csrf_bypass", "confidence": 0.75, "locations": ["/api/", "/ajax/"]},
        {"vuln": "debug_exposure", "confidence": 0.90, "locations": ["/__debug__/", "/debug/"]},
    ],
    "spring": [
        {"vuln": "deserialization", "confidence": 0.88, "locations": ["/actuator", "/api/"]},
        {"vuln": "sqli", "confidence": 0.82, "locations": ["/api/", "/search", "/query"]},
        {"vuln": "ssti", "confidence": 0.78, "locations": ["/error", "/template"]},
        {"vuln": "actuator_exposure", "confidence": 0.92, "locations": ["/actuator/env", "/actuator/health"]},
    ],
    "php": [
        {"vuln": "sqli", "confidence": 0.90, "locations": ["/index.php", "/search.php", "/login.php"]},
        {"vuln": "lfi", "confidence": 0.88, "locations": ["/include.php", "/page.php", "/download.php"]},
        {"vuln": "rce", "confidence": 0.75, "locations": ["/upload.php", "/admin.php"]},
        {"vuln": "deserialization", "confidence": 0.72, "locations": ["/api.php", "/cache/"]},
    ],
    "flask": [
        {"vuln": "ssti", "confidence": 0.92, "locations": ["/render", "/template", "/preview"]},
        {"vuln": "ssrf", "confidence": 0.80, "locations": ["/fetch", "/proxy", "/url"]},
        {"vuln": "debug_exposure", "confidence": 0.88, "locations": ["/console", "/debug"]},
        {"vuln": "path_traversal", "confidence": 0.78, "locations": ["/download", "/file"]},
    ],
    "rails": [
        {"vuln": "deserialization", "confidence": 0.85, "locations": ["/api/", "/sessions"]},
        {"vuln": "mass_assignment", "confidence": 0.90, "locations": ["/users", "/profile", "/settings"]},
        {"vuln": "sqli", "confidence": 0.80, "locations": ["/search", "/filter", "/api/"]},
    ],
    "firebase": [
        {"vuln": "nosql_injection", "confidence": 0.88, "locations": ["/.json", "/api/"]},
        {"vuln": "broken_auth", "confidence": 0.85, "locations": ["/auth/", "/__/auth/"]},
        {"vuln": "rules_bypass", "confidence": 0.82, "locations": ["/.json", "/api/data"]},
    ],
    "graphql": [
        {"vuln": "introspection", "confidence": 0.95, "locations": ["/graphql"]},
        {"vuln": "idor", "confidence": 0.85, "locations": ["/graphql"]},
        {"vuln": "batching_dos", "confidence": 0.80, "locations": ["/graphql"]},
        {"vuln": "injection", "confidence": 0.78, "locations": ["/graphql"]},
    ],
    "aws": [
        {"vuln": "ssrf_metadata", "confidence": 0.92, "locations": ["/proxy", "/fetch", "/url"]},
        {"vuln": "iam_escalation", "confidence": 0.85, "locations": ["/api/", "/lambda/"]},
        {"vuln": "s3_misconfiguration", "confidence": 0.80, "locations": ["/upload", "/assets"]},
    ],
}

WAF_PREDICTION_ADJUSTMENTS = {
    "cloudflare": {"origin_ip_leak": 0.80, "waf_bypass_unicode": 0.65, "rate_limit_bypass": 0.55},
    "akamai": {"cache_poisoning": 0.70, "waf_bypass_encoding": 0.60},
    "aws_waf": {"ssrf_bypass": 0.75, "sqli_unicode": 0.60},
    "imperva": {"smuggling_bypass": 0.65, "encoding_bypass": 0.55},
}

HISTORICAL_ENDPOINT_PREDICTIONS = {
    "/admin": {"vuln": "admin_bypass", "confidence": 0.75, "techniques": ["default_creds", "path_traversal", "verb_tampering"]},
    "/debug": {"vuln": "debug_info_leak", "confidence": 0.90, "techniques": ["direct_access"]},
    "/test": {"vuln": "test_data_exposure", "confidence": 0.85, "techniques": ["direct_access"]},
    "/staging": {"vuln": "staging_leak", "confidence": 0.80, "techniques": ["direct_access"]},
    "/backup": {"vuln": "backup_exposure", "confidence": 0.88, "techniques": ["direct_access", "path_traversal"]},
    "/.env": {"vuln": "env_file_leak", "confidence": 0.92, "techniques": ["direct_access"]},
    "/.git": {"vuln": "git_exposure", "confidence": 0.90, "techniques": ["direct_access"]},
    "/swagger": {"vuln": "api_docs_exposure", "confidence": 0.85, "techniques": ["direct_access"]},
    "/api-docs": {"vuln": "api_docs_exposure", "confidence": 0.85, "techniques": ["direct_access"]},
    "/graphql": {"vuln": "graphql_introspection", "confidence": 0.88, "techniques": ["introspection_query"]},
    "/wp-admin": {"vuln": "wordpress_admin", "confidence": 0.80, "techniques": ["default_creds", "brute_force"]},
    "/phpmyadmin": {"vuln": "phpmyadmin_exposure", "confidence": 0.85, "techniques": ["default_creds"]},
}


class PredictiveDecisionEngine:

    def __init__(self, target_intelligence: Dict):
        self.intel = target_intelligence
        self.predictions: List[Dict] = []

    def predict_attack_surface(self) -> List[Dict]:
        predictions = []

        detected_stacks = self.intel.get("detected_stacks", [])
        for stack in detected_stacks:
            stack_preds = STACK_VULNERABILITY_PREDICTIONS.get(stack, [])
            for pred in stack_preds:
                predictions.append({
                    **pred,
                    "source": f"stack_prediction:{stack}",
                    "chain": self._infer_chain(pred["vuln"]),
                })

        waf = self.intel.get("waf_vendor", "").lower()
        if waf:
            waf_preds = WAF_PREDICTION_ADJUSTMENTS.get(waf, {})
            for vuln, conf in waf_preds.items():
                predictions.append({
                    "vuln": vuln,
                    "confidence": conf,
                    "locations": ["/"],
                    "source": f"waf_prediction:{waf}",
                })

        historical = self.intel.get("historical_endpoints", [])
        for endpoint in historical:
            for pattern, pred_info in HISTORICAL_ENDPOINT_PREDICTIONS.items():
                if pattern in endpoint:
                    predictions.append({
                        **pred_info,
                        "locations": [endpoint],
                        "source": "historical_prediction",
                    })

        osint_leaks = self.intel.get("osint_leaks", [])
        for leak in osint_leaks:
            leak_lower = leak.lower() if isinstance(leak, str) else ""
            if "aws" in leak_lower:
                predictions.append({
                    "vuln": "aws_iam_takeover",
                    "confidence": 0.95,
                    "locations": ["/"],
                    "source": "osint_leak",
                    "chain": ["ssrf_metadata", "iam_assume_role"],
                    "extraction": True,
                })
            elif "api_key" in leak_lower or "secret" in leak_lower:
                predictions.append({
                    "vuln": "credential_reuse",
                    "confidence": 0.85,
                    "locations": ["/api/", "/auth/"],
                    "source": "osint_leak",
                })

        self.predictions = predictions
        return predictions

    def prioritize_by_success_probability(self, predictions: List[Dict]) -> List[Dict]:
        stack_vectors = set()
        for stack in self.intel.get("detected_stacks", []):
            for pred in STACK_VULNERABILITY_PREDICTIONS.get(stack, []):
                stack_vectors.add(pred["vuln"])

        for pred in predictions:
            factors = {
                "stack_match": 0.30 if pred["vuln"] in stack_vectors else 0.0,
                "base_confidence": pred.get("confidence", 0.5) * 0.40,
                "historical_proof": 0.20 if pred.get("source") == "historical_prediction" else 0.0,
                "osint_boost": 0.10 if pred.get("source") == "osint_leak" else 0.0,
            }
            pred["success_probability"] = min(sum(factors.values()), 1.0)
            pred["factors"] = factors

        return sorted(predictions, key=lambda x: x["success_probability"], reverse=True)

    def generate_report(self) -> Dict:
        by_confidence = sorted(self.predictions, key=lambda x: x.get("confidence", 0), reverse=True)
        high_conf = [p for p in by_confidence if p.get("confidence", 0) >= 0.80]
        medium_conf = [p for p in by_confidence if 0.60 <= p.get("confidence", 0) < 0.80]

        return {
            "total_predictions": len(self.predictions),
            "high_confidence": len(high_conf),
            "medium_confidence": len(medium_conf),
            "top_predictions": by_confidence[:10],
            "attack_surface_coverage": len(set(p.get("vuln") for p in self.predictions)),
            "predicted_locations": len(set(
                loc for p in self.predictions for loc in p.get("locations", [])
            )),
        }

    @staticmethod
    def _infer_chain(vuln: str) -> Optional[List[str]]:
        chains = {
            "ssrf_internal": ["ssrf", "metadata_access", "credential_harvest"],
            "ssrf_metadata": ["ssrf", "iam_role", "full_account_takeover"],
            "sqli": ["injection", "data_dump", "credential_harvest"],
            "lfi": ["file_read", "config_leak", "credential_harvest"],
            "ssti": ["template_injection", "rce", "reverse_shell"],
            "deserialization": ["object_injection", "rce", "persistence"],
            "prototype_pollution": ["pollution", "rce", "data_manipulation"],
            "jwt_none_algorithm": ["token_forge", "auth_bypass", "privilege_escalation"],
        }
        return chains.get(vuln)

