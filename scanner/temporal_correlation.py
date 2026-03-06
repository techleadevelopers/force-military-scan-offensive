"""
MSE Temporal Correlation Engine
=================================
Correlates events across TIME, not just within a single scan.
Identifies patterns that indicate success probability based on
temporal sequences, WAF learning curves, and attack timing.
"""

import time
from typing import List, Dict, Any, Optional
from collections import defaultdict


class TemporalCorrelationEngine:

    def __init__(self, scan_history: Optional[List[Dict]] = None):
        self.history = scan_history or []
        self.temporal_patterns: List[Dict] = []
        self.current_scan_events: List[Dict] = []

    def record_event(self, event_type: str, data: Dict):
        self.current_scan_events.append({
            "type": event_type,
            "timestamp": time.time(),
            "data": data,
        })

    def analyze_temporal_patterns(self, current_findings: List[Dict]) -> List[Dict]:
        patterns = []

        patterns.extend(self._analyze_waf_learning(current_findings))
        patterns.extend(self._analyze_ssrf_credential_correlation())
        patterns.extend(self._analyze_attack_velocity())
        patterns.extend(self._analyze_response_time_drift())
        patterns.extend(self._analyze_finding_cascade())

        self.temporal_patterns = patterns
        return patterns

    def _analyze_waf_learning(self, findings: List[Dict]) -> List[Dict]:
        patterns = []

        waf_events = [e for e in self.current_scan_events if "waf" in e.get("type", "").lower()]
        if len(waf_events) >= 3:
            block_rates = []
            for i in range(0, len(waf_events), max(1, len(waf_events) // 3)):
                window = waf_events[i:i + max(1, len(waf_events) // 3)]
                blocked = sum(1 for e in window if e.get("data", {}).get("blocked"))
                total = len(window) or 1
                block_rates.append(blocked / total)

            if len(block_rates) >= 2:
                trend = block_rates[-1] - block_rates[0]
                if trend < -0.15:
                    patterns.append({
                        "pattern": "waf_learning_success",
                        "decision": "CONTINUE_CURRENT_MUTATION",
                        "confidence": 0.85,
                        "evidence": f"WAF block rate decreased {abs(trend):.0%} across {len(waf_events)} probes",
                        "trend": trend,
                    })
                elif trend > 0.20:
                    patterns.append({
                        "pattern": "waf_adapting",
                        "decision": "SWITCH_MUTATION_STRATEGY",
                        "confidence": 0.80,
                        "evidence": f"WAF block rate increased {trend:.0%}  defenses adapting",
                        "trend": trend,
                    })

        return patterns

    def _analyze_ssrf_credential_correlation(self) -> List[Dict]:
        patterns = []

        ssrf_events = [e for e in self.current_scan_events if "ssrf" in e.get("type", "").lower()]
        cred_events = [e for e in self.current_scan_events if "credential" in e.get("type", "").lower() or "secret" in e.get("type", "").lower()]

        if ssrf_events and cred_events:
            ssrf_times = [e["timestamp"] for e in ssrf_events]
            cred_after_ssrf = sum(
                1 for c in cred_events
                if any(c["timestamp"] > s for s in ssrf_times)
            )

            if len(ssrf_events) > 0:
                ratio = cred_after_ssrf / len(ssrf_events) if ssrf_events else 0
                if ratio > 0.5:
                    patterns.append({
                        "pattern": "ssrf_leads_to_creds",
                        "decision": "PRIORITIZE_SSRF_CHAIN",
                        "confidence": min(0.95, 0.6 + ratio * 0.3),
                        "evidence": f"{cred_after_ssrf}/{len(ssrf_events)} SSRF probes yielded credentials",
                        "ratio": ratio,
                    })

        return patterns

    def _analyze_attack_velocity(self) -> List[Dict]:
        patterns = []

        if len(self.current_scan_events) < 10:
            return patterns

        events_sorted = sorted(self.current_scan_events, key=lambda e: e["timestamp"])
        first_half = events_sorted[:len(events_sorted) // 2]
        second_half = events_sorted[len(events_sorted) // 2:]

        first_findings = sum(1 for e in first_half if e.get("data", {}).get("is_finding"))
        second_findings = sum(1 for e in second_half if e.get("data", {}).get("is_finding"))

        if first_findings > 0 and second_findings > first_findings * 1.5:
            patterns.append({
                "pattern": "accelerating_discovery",
                "decision": "INCREASE_DEPTH",
                "confidence": 0.80,
                "evidence": f"Finding rate accelerating: {first_findings} â†’ {second_findings}",
            })
        elif first_findings > 0 and second_findings < first_findings * 0.3:
            patterns.append({
                "pattern": "diminishing_returns",
                "decision": "PIVOT_ATTACK_VECTOR",
                "confidence": 0.75,
                "evidence": f"Finding rate declining: {first_findings} â†’ {second_findings}",
            })

        return patterns

    def _analyze_response_time_drift(self) -> List[Dict]:
        patterns = []

        timed_events = [
            e for e in self.current_scan_events
            if e.get("data", {}).get("response_time_ms")
        ]

        if len(timed_events) < 5:
            return patterns

        times = [e["data"]["response_time_ms"] for e in timed_events]
        early_avg = sum(times[:len(times) // 3]) / max(1, len(times) // 3)
        late_avg = sum(times[-(len(times) // 3):]) / max(1, len(times) // 3)

        if late_avg > early_avg * 2.0:
            patterns.append({
                "pattern": "response_time_inflation",
                "decision": "THROTTLE_OR_PIVOT",
                "confidence": 0.85,
                "evidence": f"Response time inflated {early_avg:.0f}ms â†’ {late_avg:.0f}ms  possible rate limiting or WAF throttle",
            })
        elif late_avg < early_avg * 0.5 and early_avg > 100:
            patterns.append({
                "pattern": "response_time_deflation",
                "decision": "INCREASE_PROBE_RATE",
                "confidence": 0.70,
                "evidence": f"Response time decreased {early_avg:.0f}ms â†’ {late_avg:.0f}ms  defenses may have backed off",
            })

        return patterns

    def _analyze_finding_cascade(self) -> List[Dict]:
        patterns = []

        finding_events = [
            e for e in self.current_scan_events
            if e.get("data", {}).get("is_finding")
        ]

        if len(finding_events) < 3:
            return patterns

        finding_events_sorted = sorted(finding_events, key=lambda e: e["timestamp"])
        gaps = []
        for i in range(1, len(finding_events_sorted)):
            gaps.append(finding_events_sorted[i]["timestamp"] - finding_events_sorted[i - 1]["timestamp"])

        if gaps:
            recent_gaps = gaps[-(min(5, len(gaps))):]
            avg_gap = sum(recent_gaps) / len(recent_gaps)

            if avg_gap < 2.0:
                patterns.append({
                    "pattern": "finding_cascade",
                    "decision": "MAINTAIN_CURRENT_VECTOR",
                    "confidence": 0.90,
                    "evidence": f"Findings cascading every {avg_gap:.1f}s  rich attack surface",
                })

        return patterns

    def generate_report(self) -> Dict:
        high_conf = [p for p in self.temporal_patterns if p.get("confidence", 0) >= 0.80]
        decisions = {}
        for p in self.temporal_patterns:
            d = p.get("decision", "NONE")
            if d not in decisions:
                decisions[d] = p.get("confidence", 0)
            else:
                decisions[d] = max(decisions[d], p.get("confidence", 0))

        return {
            "total_patterns": len(self.temporal_patterns),
            "high_confidence_patterns": len(high_conf),
            "total_events_analyzed": len(self.current_scan_events),
            "patterns": self.temporal_patterns,
            "decision_summary": decisions,
            "dominant_decision": max(decisions, key=decisions.get) if decisions else "NONE",
        }

