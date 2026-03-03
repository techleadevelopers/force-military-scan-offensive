import json
import os
import argparse
from datetime import datetime
from typing import Dict, Any, List, Optional

from scanner.decision_engine import DecisionEngine
from scanner.execution_engine import ExecutionEngine


class AutonomousConsolidatorV2:
    """
    Versão enxuta para orquestração autônoma baseada no Attack Dictionary.
    Foi desenhada para rodar pós-scan, consumindo um snapshot salvo em disco
    (ou já carregado em memória).
    """

    def __init__(self, dictionary_path: Optional[str] = None):
        if dictionary_path is None:
            base_dir = os.path.dirname(__file__)
            dictionary_path = os.path.join(base_dir, "attack_dictionary.json")

        self.dictionary_path = dictionary_path
        self.decision_engine = DecisionEngine(dictionary_path)
        self.execution_engine = ExecutionEngine()

    # ------------------------------------------------------------------
    def process_snapshot(self, snapshot_path: str) -> Dict[str, Any]:
        with open(snapshot_path, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
        return self.process_snapshot_dict(snapshot, snapshot_path)

    def process_snapshot_dict(self, snapshot: Dict[str, Any], snapshot_path: Optional[str] = None) -> Dict[str, Any]:
        decisions = self.decision_engine.decide_next_actions(snapshot)

        executed: List[Dict[str, Any]] = []
        for action in decisions["actions"]:
            executed.append(self.execution_engine.execute_action(snapshot.get("target", "unknown"), action))

        report = {
            "version": "2.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target": snapshot.get("target"),
            "decisions": decisions,
            "executed_actions": executed,
            "next_actions": [
                a for a in decisions["actions"] if not a.get("safe_auto", False)
            ],
            "original_snapshot": snapshot_path,
            "findings_summary": {
                "total": len(snapshot.get("findings", [])),
                "critical": len([f for f in snapshot.get("findings", []) if f.get("severity") == "critical"]),
                "high": len([f for f in snapshot.get("findings", []) if f.get("severity") == "high"]),
            },
        }

        report_path = self._write_report(snapshot, report)
        report["report_path"] = report_path
        return report

    # ------------------------------------------------------------------
    def _write_report(self, snapshot: Dict[str, Any], report: Dict[str, Any]) -> str:
        target = snapshot.get("target", "unknown")
        safe_target = str(target).replace("/", "_").replace(":", "_")
        path = f"/tmp/motor11_report_{safe_target}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Motor 11 V2 — snapshot -> decisions -> executions")
    parser.add_argument("--snapshot", required=True, help="Caminho do snapshot JSON (findings/assets/probes/risk_score)")
    parser.add_argument("--dictionary", help="Caminho custom do attack_dictionary.json")
    args = parser.parse_args()

    engine = AutonomousConsolidatorV2(dictionary_path=args.dictionary)
    final_report = engine.process_snapshot(args.snapshot)
    print(json.dumps(final_report))
