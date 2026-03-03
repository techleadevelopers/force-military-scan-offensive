import json
from datetime import datetime
from typing import Dict, Any, List

from scanner.probability_engine import ProbabilityEngine


class DecisionEngine:
    """
    Traduz findings em TOP N ações priorizadas. Mantém histórico in-memory
    para debug/telemetria.
    """

    def __init__(self, dictionary_path: str):
        self.probability = ProbabilityEngine(dictionary_path)
        self.execution_history: List[Dict[str, Any]] = []

    def decide_next_actions(self, snapshot: Dict[str, Any], limit: int = 3) -> Dict[str, Any]:
        findings = snapshot.get("findings", [])

        top_vectors = self.probability.get_top_vectors(findings, limit=limit)

        actions: List[Dict[str, Any]] = []
        for vector in top_vectors:
            if vector["probability"] < 0.6:
                continue
            cfg = vector["config"]
            actions.append({
                "name": vector["name"],
                "category": vector["category"],
                "probability": vector["probability"],
                "payloads": cfg.get("payloads", {}),
                "wordlist": cfg.get("wordlist", []),
                "timeout": cfg.get("timeout", 300),
                "safe_auto": cfg.get("safe_auto", False),
                "prerequisites": cfg.get("prerequisites", []),
            })

        decision = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target": snapshot.get("target"),
            "actions": actions,
            "risk_score": snapshot.get("risk_score", 0),
        }

        self.execution_history.append(decision)
        return decision
