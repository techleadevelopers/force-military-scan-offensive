"""
MSE Anti-Forensics Assessment Engine
=======================================
Assesses target's forensic capabilities and evaluates stealth
posture. This is an ASSESSMENT module â€” it analyzes what traces
the scanner would leave and recommends stealth adjustments.
Does NOT perform destructive anti-forensic actions.
"""

import time
from typing import List, Dict, Any, Optional


STEALTH_TECHNIQUES = {
    "user_agent_rotation": {
        "description": "Rotate User-Agent headers to avoid fingerprinting",
        "detection_reduction": 0.15,
        "complexity": "low",
    },
    "request_throttling": {
        "description": "Throttle requests to avoid rate-limit detection",
        "detection_reduction": 0.20,
        "complexity": "low",
    },
    "timing_jitter": {
        "description": "Add random delays between requests to appear organic",
        "detection_reduction": 0.25,
        "complexity": "low",
    },
    "header_normalization": {
        "description": "Normalize HTTP headers to match legitimate browser traffic",
        "detection_reduction": 0.15,
        "complexity": "medium",
    },
    "payload_obfuscation": {
        "description": "Obfuscate attack payloads to evade signature-based detection",
        "detection_reduction": 0.30,
        "complexity": "medium",
    },
    "connection_pooling": {
        "description": "Reuse connections to reduce TCP fingerprinting surface",
        "detection_reduction": 0.10,
        "complexity": "low",
    },
    "dns_over_https": {
        "description": "Use DoH to prevent DNS-based monitoring",
        "detection_reduction": 0.15,
        "complexity": "medium",
    },
    "tls_fingerprint_masking": {
        "description": "Mask TLS client hello to match common browsers",
        "detection_reduction": 0.20,
        "complexity": "high",
    },
    "cache_poisoning_evasion": {
        "description": "Add cache-busting parameters to avoid cached WAF decisions",
        "detection_reduction": 0.10,
        "complexity": "low",
    },
    "ip_rotation": {
        "description": "Rotate source IPs across proxy infrastructure",
        "detection_reduction": 0.35,
        "complexity": "high",
    },
}

DETECTION_INDICATORS = {
    "rate_limiting": {"weight": 0.20, "signals": ["429 responses", "throttled responses", "increasing latency"]},
    "waf_blocking": {"weight": 0.25, "signals": ["403 responses", "challenge pages", "CAPTCHA"]},
    "ip_banning": {"weight": 0.30, "signals": ["connection refused", "timeout increase", "blackhole routing"]},
    "behavioral_analysis": {"weight": 0.15, "signals": ["honeypot responses", "fake data injection", "tarpit delays"]},
    "siem_alerting": {"weight": 0.10, "signals": ["response header changes", "new security headers", "CSP updates"]},
}


class AntiForensicsAssessor:

    def __init__(self):
        self.stealth_score: float = 1.0
        self.detection_events: List[Dict] = []
        self.active_techniques: List[str] = []
        self.assessment_results: Dict = {}

    def assess_detection_risk(self, scan_events: List[Dict]) -> Dict:
        risk_indicators = {}
        total_risk = 0.0

        for indicator_name, indicator_info in DETECTION_INDICATORS.items():
            detected = False
            evidence = []

            for event in scan_events:
                status = event.get("data", {}).get("status_code", 0)
                response_time = event.get("data", {}).get("response_time_ms", 0)

                if indicator_name == "rate_limiting":
                    if status == 429:
                        detected = True
                        evidence.append(f"HTTP 429 at {event.get('type', 'unknown')}")
                elif indicator_name == "waf_blocking":
                    if status == 403:
                        detected = True
                        evidence.append(f"HTTP 403 at {event.get('type', 'unknown')}")
                elif indicator_name == "ip_banning":
                    if status == 0 or response_time > 30000:
                        detected = True
                        evidence.append(f"Connection issue at {event.get('type', 'unknown')}")
                elif indicator_name == "behavioral_analysis":
                    body = str(event.get("data", {}).get("body", ""))
                    if any(kw in body.lower() for kw in ["honeypot", "trap", "canary"]):
                        detected = True
                        evidence.append("Honeypot/canary detected in response")

            risk_indicators[indicator_name] = {
                "detected": detected,
                "risk_weight": indicator_info["weight"],
                "evidence": evidence,
            }

            if detected:
                total_risk += indicator_info["weight"]

        self.stealth_score = max(0.0, 1.0 - total_risk)

        self.assessment_results = {
            "stealth_score": round(self.stealth_score, 4),
            "total_risk": round(total_risk, 4),
            "indicators": risk_indicators,
            "detected_count": sum(1 for v in risk_indicators.values() if v["detected"]),
        }

        return self.assessment_results

    def recommend_techniques(self) -> List[Dict]:
        recommendations = []

        if self.stealth_score >= 0.9:
            return [{"technique": "none_needed", "reason": "Stealth posture is excellent"}]

        sorted_techniques = sorted(
            STEALTH_TECHNIQUES.items(),
            key=lambda t: t[1]["detection_reduction"],
            reverse=True,
        )

        cumulative_reduction = 0.0
        target_improvement = 1.0 - self.stealth_score

        for tech_name, tech_info in sorted_techniques:
            if cumulative_reduction >= target_improvement:
                break

            if tech_name not in self.active_techniques:
                recommendations.append({
                    "technique": tech_name,
                    "description": tech_info["description"],
                    "detection_reduction": tech_info["detection_reduction"],
                    "complexity": tech_info["complexity"],
                    "priority": "high" if tech_info["detection_reduction"] >= 0.20 else "medium",
                })
                cumulative_reduction += tech_info["detection_reduction"]

        return recommendations

    def calculate_evasion_posture(self) -> Dict:
        active_reduction = sum(
            STEALTH_TECHNIQUES[t]["detection_reduction"]
            for t in self.active_techniques
            if t in STEALTH_TECHNIQUES
        )

        theoretical_max = sum(t["detection_reduction"] for t in STEALTH_TECHNIQUES.values())
        evasion_coverage = active_reduction / theoretical_max if theoretical_max > 0 else 0

        return {
            "active_techniques": len(self.active_techniques),
            "total_techniques": len(STEALTH_TECHNIQUES),
            "active_reduction": round(active_reduction, 4),
            "theoretical_max_reduction": round(theoretical_max, 4),
            "evasion_coverage": round(evasion_coverage, 4),
            "stealth_score": round(self.stealth_score, 4),
            "assessment": (
                "GHOST" if evasion_coverage > 0.8 else
                "STEALTH" if evasion_coverage > 0.5 else
                "CAUTIOUS" if evasion_coverage > 0.3 else
                "EXPOSED"
            ),
        }

    def generate_report(self) -> Dict:
        recommendations = self.recommend_techniques()
        posture = self.calculate_evasion_posture()

        return {
            "stealth_score": round(self.stealth_score, 4),
            "evasion_posture": posture,
            "detection_events": len(self.detection_events),
            "recommendations": recommendations,
            "active_techniques": self.active_techniques,
            "assessment": self.assessment_results,
        }

