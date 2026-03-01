"""
MSE Smart Exfiltration Engine
================================
Selective, value-based data exfiltration. Prioritizes high-value
data (credentials, PII, financial) over low-value data (logs, configs).
Classifies data value and prioritizes extraction order.
"""

from typing import List, Dict, Any, Optional


DATA_VALUE_SCORES = {
    "password": 100,
    "aws_secret": 100,
    "private_key": 100,
    "credit_card": 95,
    "ssn": 90,
    "api_key": 85,
    "database_url": 85,
    "database_credential": 90,
    "jwt_secret": 90,
    "session_secret": 85,
    "jwt": 70,
    "session_token": 70,
    "oauth_token": 75,
    "pii": 60,
    "email_list": 55,
    "source_code": 50,
    "config_file": 45,
    "env_file": 80,
    "docker_secret": 75,
    "ssh_key": 95,
    "ssl_cert": 40,
    "log_entry": 20,
    "error_message": 15,
    "html_content": 5,
    "public_api_key": 10,
}

FINANCIAL_IMPACT = {
    "ssh_key": 5000.0,
    "aws_credentials": 3000.0,
    "database_credential": 2000.0,
    "credit_card": 1000.0,
    "cpf": 50.0,
    "email_list": 10.0,
    "env_file": 1000.0,
    "wp_config": 800.0,
    "jwt_secret": 1500.0,
    "api_key": 500.0,
    "session_token": 300.0,
    "pii_record": 100.0,
    "source_code": 200.0,
    "git_history": 1000.0,
    "cloud_metadata": 2000.0,
    "internal_api": 500.0,
}

REGULATORY_CLASSIFICATION = {
    "credit_card": ["PCI-DSS"],
    "ssn": ["GDPR", "HIPAA"],
    "pii": ["GDPR", "CCPA"],
    "email_list": ["GDPR", "CAN-SPAM"],
    "health_data": ["HIPAA"],
    "financial_data": ["SOX", "PCI-DSS"],
    "password": ["SOC2"],
    "database_credential": ["SOC2"],
    "jwt_secret": ["SOC2"],
}


class SmartExfiltrator:

    def __init__(self):
        self.classified_data: List[Dict] = []
        self.extraction_log: List[Dict] = []

    def classify_data_value(self, data: Dict) -> int:
        value = 0
        data_type = (data.get("type", "") or "").lower()

        for pattern, score in DATA_VALUE_SCORES.items():
            if pattern in data_type:
                value = max(value, score)

        content = str(data.get("content", ""))
        if len(content) > 0:
            if any(kw in content.lower() for kw in ["password", "passwd", "secret"]):
                value = max(value, 90)
            elif any(kw in content.lower() for kw in ["key", "token", "credential"]):
                value = max(value, 70)

        record_count = data.get("record_count", 0)
        if record_count > 10000:
            value = min(value + 25, 100)
        elif record_count > 1000:
            value = min(value + 15, 100)
        elif record_count > 100:
            value = min(value + 10, 100)

        env = (data.get("environment", "") or "").lower()
        if "prod" in env:
            value = min(value + 15, 100)
        elif "staging" in env:
            value = min(value + 10, 100)

        return value

    def classify_urgency(self, data: Dict) -> float:
        urgency = 0.5

        value = data.get("value", 0)
        if value >= 90:
            urgency = 1.0
        elif value >= 70:
            urgency = 0.8
        elif value >= 50:
            urgency = 0.6

        if data.get("ephemeral"):
            urgency = min(urgency + 0.3, 1.0)

        if data.get("detected_monitoring"):
            urgency = min(urgency + 0.2, 1.0)

        return round(urgency, 2)

    def prioritize_exfiltration(self, all_data: List[Dict]) -> Dict:
        for item in all_data:
            item["value"] = self.classify_data_value(item)
            item["urgency"] = self.classify_urgency(item)
            item["priority_score"] = round(item["value"] * item["urgency"] / 100.0, 4)
            item["regulatory"] = self._get_regulatory_flags(item)

        sorted_data = sorted(all_data, key=lambda x: x["priority_score"], reverse=True)

        total = len(sorted_data)
        cutoff_high = max(1, int(total * 0.2))
        cutoff_med = max(cutoff_high, int(total * 0.5))

        result = {
            "immediate": sorted_data[:cutoff_high],
            "queued": sorted_data[cutoff_high:cutoff_med],
            "deferred": sorted_data[cutoff_med:],
            "total_value": sum(d["value"] for d in sorted_data),
            "regulatory_exposure": self._aggregate_regulatory(sorted_data),
        }

        self.classified_data = sorted_data
        return result

    def calculate_financial_impact(self, data_items: List[Dict]) -> float:
        total_impact = 0.0
        for item in data_items:
            data_type = (item.get("type", "") or "").lower()
            record_count = item.get("record_count", 1)

            best_value = 0.0
            for key, value in FINANCIAL_IMPACT.items():
                if key in data_type or data_type in key:
                    best_value = max(best_value, value)
            if best_value:
                impact = best_value * record_count
                if "prod" in (item.get("environment", "") or "").lower():
                    impact *= 1.5
                item["financial_impact"] = impact
                total_impact += impact
        return total_impact

    def prioritize_by_roi(self, all_data: List[Dict]) -> List[Dict]:
        for item in all_data:
            financial_value = item.get("financial_impact", self.classify_data_value(item) * 10)
            success_prob = item.get("confidence", 0.5)
            extraction_cost = item.get("extraction_cost", 1.0)
            detection_risk = item.get("detection_risk", 0.3)

            roi = (financial_value * success_prob) / max(extraction_cost * (1 + detection_risk), 0.1)
            item["roi"] = roi
            if roi > 1000:
                item["roi_class"] = "CRITICAL"
            elif roi > 100:
                item["roi_class"] = "HIGH"
            elif roi > 10:
                item["roi_class"] = "MEDIUM"
            else:
                item["roi_class"] = "LOW"

        return sorted(all_data, key=lambda x: x.get("roi", 0), reverse=True)

    def generate_sniper_report(self) -> Dict:
        if not self.classified_data:
            return {"total_items": 0}

        total_financial_impact = self.calculate_financial_impact(self.classified_data)
        prioritized = self.prioritize_by_roi(self.classified_data)

        return {
            "total_items": len(self.classified_data),
            "total_financial_impact": f"${total_financial_impact:,.2f}",
            "roi_distribution": {
                "critical": len([d for d in prioritized if d.get("roi_class") == "CRITICAL"]),
                "high": len([d for d in prioritized if d.get("roi_class") == "HIGH"]),
                "medium": len([d for d in prioritized if d.get("roi_class") == "MEDIUM"]),
                "low": len([d for d in prioritized if d.get("roi_class") == "LOW"]),
            },
            "immediate": [d for d in prioritized if d.get("roi_class") in ("CRITICAL", "HIGH")][:10],
            "queued": [d for d in prioritized if d.get("roi_class") == "MEDIUM"][:10],
            "deferred": [d for d in prioritized if d.get("roi_class") == "LOW"][:10],
            "top_roi": [
                {
                    "type": d.get("type"),
                    "financial_impact": f"${d.get('financial_impact', 0):,.2f}",
                    "roi": f"{d.get('roi', 0):.1f}",
                    "roi_class": d.get("roi_class"),
                }
                for d in prioritized[:5]
            ],
            "regulatory_exposure": self._aggregate_regulatory(prioritized),
        }

    def _get_regulatory_flags(self, data: Dict) -> List[str]:
        flags = set()
        data_type = (data.get("type", "") or "").lower()
        for pattern, regulations in REGULATORY_CLASSIFICATION.items():
            if pattern in data_type:
                flags.update(regulations)
        return list(flags)

    def _aggregate_regulatory(self, data: List[Dict]) -> Dict:
        exposure: Dict[str, int] = {}
        for item in data:
            for reg in item.get("regulatory", []):
                exposure[reg] = exposure.get(reg, 0) + 1
        return exposure

    def generate_report(self) -> Dict:
        if not self.classified_data:
            return {"total_items": 0, "immediate": 0, "queued": 0, "deferred": 0}

        immediate = [d for d in self.classified_data if d.get("priority_score", 0) >= 0.8]
        queued = [d for d in self.classified_data if 0.4 <= d.get("priority_score", 0) < 0.8]
        deferred = [d for d in self.classified_data if d.get("priority_score", 0) < 0.4]

        return {
            "total_items": len(self.classified_data),
            "immediate": len(immediate),
            "queued": len(queued),
            "deferred": len(deferred),
            "total_value": sum(d.get("value", 0) for d in self.classified_data),
            "avg_value": round(sum(d.get("value", 0) for d in self.classified_data) / max(1, len(self.classified_data)), 1),
            "top_targets": [
                {"type": d.get("type"), "value": d.get("value"), "priority": d.get("priority_score")}
                for d in self.classified_data[:5]
            ],
            "regulatory_exposure": self._aggregate_regulatory(self.classified_data),
        }
