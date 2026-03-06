import os
import json
import datetime
from typing import Dict, Any


class EvidenceCollector:
    """Coleta evidências de bypass para relatório"""

    def __init__(self, base_dir: str = "dumps/waf"):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)

    def save_evidence(self, scan_id: str, result: Dict[str, Any]):
        """Salva evidência de um teste bem-sucedido"""

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        evidence_dir = f"{self.base_dir}/{scan_id}_{timestamp}"
        os.makedirs(evidence_dir, exist_ok=True)

        with open(f"{evidence_dir}/metadata.json", "w", encoding="utf-8") as f:
            json.dump({"timestamp": timestamp, "scan_id": scan_id, "result": result}, f, indent=2)

        if "payload" in result:
            with open(f"{evidence_dir}/payload.txt", "w", encoding="utf-8") as f:
                f.write(str(result["payload"]))

        if "response_snippet" in result:
            with open(f"{evidence_dir}/response.txt", "w", encoding="utf-8") as f:
                f.write(str(result.get("response_snippet", "")))

        if "headers" in result:
            with open(f"{evidence_dir}/headers.json", "w", encoding="utf-8") as f:
                json.dump(result.get("headers", {}), f, indent=2)

        return evidence_dir

    def get_best_evidence(self, scan_id: str) -> Dict:
        """Recupera melhor evidência para o relatório (mais recente)"""
        if not os.path.isdir(self.base_dir):
            return {}

        candidates = [
            d for d in os.listdir(self.base_dir) if d.startswith(f"{scan_id}_")
        ]
        if not candidates:
            return {}

        latest = sorted(candidates)[-1]
        evidence_dir = os.path.join(self.base_dir, latest)
        meta_path = os.path.join(evidence_dir, "metadata.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

