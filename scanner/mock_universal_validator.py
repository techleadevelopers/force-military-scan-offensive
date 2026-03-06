from datetime import datetime
from typing import Any, Dict, List


class UniversalMockValidator:
    """
    Backend guardrail to detect mock or fabricated scan outputs before they
    are persisted or exposed. Mirrors the quick TS validator used by the
    diagnostic endpoint but keeps a Python version close to the scanner.
    """

    def __init__(self) -> None:
        self.suspicious_counts: Dict[str, int] = {}
        self.suspicious_patterns: Dict[str, int] = {
            "subdomains_17": 0,
            "ssrf_redis": 0,
            "bulk_dumps": 0,
            "perfect_scores": 0,
        }
        self.logger = None  # Allow scanner to inject logger if available

    def validate_scan(self, scan_id: str, scan_data: Dict[str, Any]) -> bool:
        issues: List[Dict[str, Any]] = []

        # 1. Subdomains
        subdomains = scan_data.get("subdomains", [])
        if len(subdomains) == 17:
            generic_names = [
                "api", "admin", "dev", "staging", "test", "beta",
                "ftp", "vpn", "cdn", "ci", "gitlab", "jira",
                "app", "ws", "socket", "status", "monitor",
            ]
            sub_names = [str(s).split(".")[0] for s in subdomains]
            if all(name in generic_names for name in sub_names):
                issues.append({
                    "type": "subdomain_pattern",
                    "severity": "critical",
                    "message": f"17 subdomÃ­nios genÃ©ricos detectados: {sub_names}",
                    "action": "REJECT",
                })
                self.suspicious_patterns["subdomains_17"] += 1

        # 2. SSRF Redis confirmation
        findings = scan_data.get("findings", [])
        for finding in findings:
            blob = str(finding).lower()
            if "ssrf" in blob and "redis" in blob:
                evidence = str(finding.get("evidence", "")).lower()
                confirmed = bool(finding.get("confirmed"))
                if not confirmed or "redis_version" not in evidence or "connected_clients" not in evidence:
                    issues.append({
                        "type": "ssrf_redis_false_positive",
                        "severity": "high",
                        "message": "SSRF Redis reportado mas NÃƒO confirmado",
                        "action": "REJECT",
                    })
                    self.suspicious_patterns["ssrf_redis"] += 1

        # 3. Dump timestamps
        dumps = scan_data.get("dumps", [])
        ts_count: Dict[str, int] = {}
        for dump in dumps:
            ts = str(dump.get("timestamp") or dump.get("createdAt") or "")
            ts = ts.split(".")[0]
            if ts:
                ts_count[ts] = ts_count.get(ts, 0) + 1
        for ts, count in ts_count.items():
            if count > 5:
                issues.append({
                    "type": "bulk_dumps",
                    "severity": "critical",
                    "message": f"{count} dumps gerados no mesmo segundo ({ts}) - IMPOSSÃVEL",
                    "action": "REJECT",
                })
                self.suspicious_patterns["bulk_dumps"] += 1

        # 4. Perfect numbers
        perfect_numbers = [100, 99, 98, 70, 50, 25, 10, 5, 4, 3, 2, 1]
        metrics = scan_data.get("metrics", {}) or scan_data.get("telemetry", {})
        for key, value in metrics.items():
            if isinstance(value, (int, float)) and value in perfect_numbers and value > 0:
                issues.append({
                    "type": "perfect_number",
                    "severity": "medium",
                    "message": f"MÃ©trica '{key}' tem valor perfeito: {value}",
                    "action": "WARN",
                })

        # 5. Dumps with zero credentials
        if dumps and all((d.get("credentials_count", 0) or d.get("itemCount", 0)) == 0 for d in dumps):
            issues.append({
                "type": "zero_credentials",
                "severity": "high",
                "message": f"ZERO credenciais em {len(dumps)} dumps - estatisticamente improvÃ¡vel",
                "action": "REJECT",
            })

        critical = [i for i in issues if i.get("action") == "REJECT" and i.get("severity") in ("critical", "high")]
        if critical:
            if self.logger:
                self.logger.error(f"âŒ SCAN {scan_id} REJEITADO - {len(critical)} problemas crÃ­ticos")
                for issue in critical:
                    self.logger.error(f"   â†’ {issue['message']}")
            self._mark_as_rejected(scan_id, critical)
            return False

        return True

    def _mark_as_rejected(self, scan_id: str, issues: List[Dict[str, Any]]) -> None:
        """
        Placeholder for persistence hook. Should be wired to storage when available.
        """
        # TODO: implement storage integration to persist rejection reason
        _ = (scan_id, issues, datetime.utcnow())
        return None

