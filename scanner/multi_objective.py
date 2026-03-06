"""
MSE Multi-Objective Optimizer
================================
Optimizes multiple conflicting objectives simultaneously:
- Maximize vulnerability discovery
- Minimize detection (stealth)
- Minimize time
- Maximize extracted data value
Uses Pareto frontier analysis for non-dominated solution selection.
"""

from typing import List, Dict, Any, Optional, Tuple
import math


class MultiObjectiveOptimizer:

    DEFAULT_OBJECTIVES = {
        "vuln_discovery": {"weight": 0.30, "direction": "maximize"},
        "stealth": {"weight": 0.30, "direction": "maximize"},
        "speed": {"weight": 0.20, "direction": "maximize"},
        "data_value": {"weight": 0.20, "direction": "maximize"},
    }

    def __init__(self, objectives: Optional[Dict] = None):
        self.objectives = objectives or dict(self.DEFAULT_OBJECTIVES)
        self.evaluation_history: List[Dict] = []

    def evaluate_action(self, action: Dict, context: Dict) -> Dict:
        scores = {}

        scores["vuln_discovery"] = self._predict_vuln_discovery(action, context)
        scores["stealth"] = self._calculate_stealth_score(action, context)
        scores["speed"] = self._estimate_speed_score(action)
        scores["data_value"] = self._estimate_data_value(action, context)

        weighted_score = sum(
            scores[obj] * self.objectives[obj]["weight"]
            for obj in scores
            if obj in self.objectives
        )

        if weighted_score > 0.7:
            recommendation = "EXECUTE"
        elif weighted_score > 0.4:
            recommendation = "CONSIDER"
        else:
            recommendation = "AVOID"

        result = {
            "action": action.get("name", action.get("vector", "unknown")),
            "scores": {k: round(v, 4) for k, v in scores.items()},
            "weighted_score": round(weighted_score, 4),
            "recommendation": recommendation,
        }

        self.evaluation_history.append(result)
        return result

    def select_optimal_action(self, possible_actions: List[Dict], context: Dict) -> Dict:
        evaluated = [self.evaluate_action(a, context) for a in possible_actions]

        if not evaluated:
            return {"action": "none", "weighted_score": 0, "recommendation": "AVOID"}

        pareto_front = self._pareto_frontier(evaluated)

        if len(pareto_front) == 1:
            return pareto_front[0]

        return max(pareto_front, key=lambda x: x["weighted_score"])

    def _pareto_frontier(self, evaluated: List[Dict]) -> List[Dict]:
        if len(evaluated) <= 1:
            return evaluated

        pareto = []
        for candidate in evaluated:
            dominated = False
            for other in evaluated:
                if other is candidate:
                    continue
                if self._dominates(other, candidate):
                    dominated = True
                    break
            if not dominated:
                pareto.append(candidate)

        return pareto if pareto else [max(evaluated, key=lambda x: x["weighted_score"])]

    def _dominates(self, a: Dict, b: Dict) -> bool:
        a_scores = a.get("scores", {})
        b_scores = b.get("scores", {})

        at_least_one_better = False
        for obj in self.objectives:
            a_val = a_scores.get(obj, 0)
            b_val = b_scores.get(obj, 0)
            if a_val < b_val:
                return False
            if a_val > b_val:
                at_least_one_better = True

        return at_least_one_better

    def _predict_vuln_discovery(self, action: Dict, context: Dict) -> float:
        base = action.get("probability", 0.5)
        vector = action.get("vector", action.get("name", ""))

        high_yield_vectors = {"ssrf", "sqli", "lfi", "ssti", "deserialization", "rce"}
        if vector in high_yield_vectors:
            base *= 1.3

        findings_count = len(context.get("findings", []))
        if findings_count > 20:
            base *= 1.1

        return min(base, 1.0)

    def _calculate_stealth_score(self, action: Dict, context: Dict) -> float:
        stealth = 0.8

        noisy_vectors = {"brute_force", "fuzzing", "dos", "spray"}
        vector = action.get("vector", action.get("name", ""))
        if vector in noisy_vectors:
            stealth *= 0.4

        waf_strength = context.get("waf_strength", "unknown")
        if waf_strength == "strong":
            stealth *= 0.7
        elif waf_strength == "weak":
            stealth *= 1.1

        return min(stealth, 1.0)

    def _estimate_speed_score(self, action: Dict) -> float:
        estimated_time = action.get("estimated_time_s", 30)
        return min(1.0, 60.0 / max(estimated_time, 1))

    def _estimate_data_value(self, action: Dict, context: Dict) -> float:
        value_map = {
            "credential_leak": 1.0,
            "database_dump": 0.95,
            "ssrf": 0.85,
            "sqli": 0.90,
            "lfi": 0.75,
            "rce": 0.95,
            "xss": 0.40,
            "open_redirect": 0.15,
            "cors_misconfiguration": 0.30,
        }

        vector = action.get("vector", action.get("name", ""))
        return value_map.get(vector, 0.5)

    def generate_report(self) -> Dict:
        if not self.evaluation_history:
            return {"total_evaluated": 0}

        execute = [e for e in self.evaluation_history if e["recommendation"] == "EXECUTE"]
        consider = [e for e in self.evaluation_history if e["recommendation"] == "CONSIDER"]
        avoid = [e for e in self.evaluation_history if e["recommendation"] == "AVOID"]

        return {
            "total_evaluated": len(self.evaluation_history),
            "execute_count": len(execute),
            "consider_count": len(consider),
            "avoid_count": len(avoid),
            "best_action": max(self.evaluation_history, key=lambda e: e["weighted_score"]) if self.evaluation_history else None,
            "pareto_front_size": len(self._pareto_frontier(self.evaluation_history)),
            "objective_weights": {k: v["weight"] for k, v in self.objectives.items()},
        }

