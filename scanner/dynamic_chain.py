"""
MSE Dynamic Chain Builder
============================
Builds exploitation chains DYNAMICALLY in real-time based on
what it discovers. Not pre-defined chains  adaptive paths
constructed from live intelligence.
"""

from typing import List, Dict, Any, Optional
from collections import defaultdict


ATTACK_PATH_GRAPH = {
    "ssrf": {
        "leads_to": ["cloud_metadata", "internal_services", "credential_leak", "file_read"],
        "requires": [],
        "base_probability": 0.85,
    },
    "sqli": {
        "leads_to": ["database_dump", "os_command", "file_read", "credential_harvest"],
        "requires": [],
        "base_probability": 0.80,
    },
    "xss": {
        "leads_to": ["session_hijack", "keylogger", "csrf_token_theft", "dom_exfil"],
        "requires": [],
        "base_probability": 0.60,
    },
    "lfi": {
        "leads_to": ["source_code_leak", "config_file_read", "ssh_key_leak", "credential_harvest"],
        "requires": [],
        "base_probability": 0.75,
    },
    "ssti": {
        "leads_to": ["rce", "reverse_shell", "credential_harvest"],
        "requires": [],
        "base_probability": 0.70,
    },
    "cloud_metadata": {
        "leads_to": ["iam_role_assumption", "aws_console_access", "s3_access"],
        "requires": ["ssrf"],
        "base_probability": 0.90,
    },
    "credential_leak": {
        "leads_to": ["admin_access", "db_direct_access", "lateral_movement", "api_abuse"],
        "requires": [],
        "base_probability": 0.85,
    },
    "credential_harvest": {
        "leads_to": ["admin_access", "lateral_movement", "persistence"],
        "requires": [],
        "base_probability": 0.80,
    },
    "database_dump": {
        "leads_to": ["pii_exfiltration", "credential_harvest", "financial_data"],
        "requires": ["sqli"],
        "base_probability": 0.85,
    },
    "admin_access": {
        "leads_to": ["full_control", "user_data_access", "config_modification"],
        "requires": ["credential_leak"],
        "base_probability": 0.75,
    },
    "rce": {
        "leads_to": ["reverse_shell", "persistence", "lateral_movement", "data_exfiltration"],
        "requires": [],
        "base_probability": 0.65,
    },
    "file_read": {
        "leads_to": ["source_code_leak", "config_file_read", "credential_harvest"],
        "requires": [],
        "base_probability": 0.80,
    },
    "iam_role_assumption": {
        "leads_to": ["full_cloud_takeover", "s3_access", "ec2_control"],
        "requires": ["cloud_metadata"],
        "base_probability": 0.85,
    },
    "session_hijack": {
        "leads_to": ["admin_access", "user_impersonation"],
        "requires": ["xss"],
        "base_probability": 0.70,
    },
    "jwt_forge": {
        "leads_to": ["admin_access", "privilege_escalation"],
        "requires": [],
        "base_probability": 0.80,
    },
    "prototype_pollution": {
        "leads_to": ["rce", "auth_bypass", "data_manipulation"],
        "requires": [],
        "base_probability": 0.60,
    },
}


class DynamicChainBuilder:

    def __init__(self, initial_findings: Optional[List[str]] = None):
        self.findings = list(initial_findings or [])
        self.chain: List[Dict] = []
        self.explored: set = set()
        self.available_paths = dict(ATTACK_PATH_GRAPH)

    def add_finding(self, finding_type: str):
        normalized = finding_type.lower().replace(" ", "_").replace("-", "_")
        if normalized not in self.findings:
            self.findings.append(normalized)

    def build_optimal_chain(self) -> List[Dict]:
        self.chain = []
        self.explored = set()
        current_findings = list(self.findings)

        max_steps = 15
        step = 0

        while current_findings and step < max_steps:
            best_next = None
            best_prob = 0.0

            for finding in current_findings:
                if finding in self.explored:
                    continue

                if finding in self.available_paths:
                    path = self.available_paths[finding]
                    prob = path["base_probability"]

                    requirements = path.get("requires", [])
                    if requirements:
                        met = sum(1 for r in requirements if r in self.explored or r in self.findings)
                        ratio = met / len(requirements) if requirements else 1.0
                        prob *= (0.3 + 0.7 * ratio)

                    for target in path["leads_to"]:
                        if target in current_findings or target in self.explored:
                            prob *= 1.15

                    depth_bonus = 1.0 + (step * 0.05)
                    prob *= depth_bonus

                    prob = min(prob, 0.99)

                    if prob > best_prob:
                        best_prob = prob
                        best_next = finding

            if not best_next or best_prob < 0.15:
                break

            self.explored.add(best_next)
            current_findings.remove(best_next)

            path = self.available_paths.get(best_next, {})
            chain_step = {
                "step": step + 1,
                "technique": best_next,
                "leads_to": path.get("leads_to", []),
                "probability": round(best_prob, 4),
                "requirements_met": True,
            }
            self.chain.append(chain_step)

            for target in path.get("leads_to", []):
                if target not in current_findings and target not in self.explored:
                    current_findings.append(target)

            step += 1

        return self.chain

    def get_chain_risk_score(self) -> float:
        if not self.chain:
            return 0.0

        total_prob = 1.0
        for step in self.chain:
            total_prob *= step["probability"]

        depth_factor = min(len(self.chain) / 5.0, 1.0)

        high_value_targets = {"admin_access", "full_control", "rce", "persistence",
                              "full_cloud_takeover", "credential_harvest", "database_dump"}
        reached_targets = set()
        for step in self.chain:
            for target in step.get("leads_to", []):
                if target in high_value_targets:
                    reached_targets.add(target)

        target_value = len(reached_targets) / max(1, len(high_value_targets))

        score = (total_prob ** (1.0 / max(1, len(self.chain)))) * 0.4 + depth_factor * 0.3 + target_value * 0.3
        return round(min(score, 1.0), 4)

    def generate_report(self) -> Dict:
        return {
            "chain_length": len(self.chain),
            "initial_findings": len(self.findings),
            "explored_nodes": len(self.explored),
            "chain_risk_score": self.get_chain_risk_score(),
            "chain": self.chain,
            "reachable_targets": list(set(
                t for step in self.chain for t in step.get("leads_to", [])
            )),
            "highest_probability_step": max(self.chain, key=lambda s: s["probability"]) if self.chain else None,
            "critical_path": [s["technique"] for s in self.chain if s["probability"] > 0.7],
        }

