import json
from typing import Dict, Any, List


class ProbabilityEngine:
    """
    Calcula a probabilidade de sucesso de cada vetor com base em pesos
    declarados no attack_dictionary.json. Mantém lógica isolada para que
    possamos evoluir para modelos bayesianos sem tocar o executor.
    """

    def __init__(self, dictionary_path: str):
        with open(dictionary_path, "r", encoding="utf-8") as f:
            self.dictionary = json.load(f)

    def _find_vector(self, vector_name: str) -> Dict[str, Any]:
        vectors = self.dictionary.get("vectors", {})
        for category in vectors:
            if vector_name in vectors[category]:
                return vectors[category][vector_name]
        return {}

    def finding_exists(self, findings: List[Dict[str, Any]], key: str) -> bool:
        """
        Verifica se um achado com a chave/indicador existe no snapshot.
        Aceita 'port_80_open', 'http_400_detected', etc.
        """
        for f in findings:
            # checa fields genéricos
            if key in f.values():
                return True
            if key == "port_80_open" and f.get("port") == 80 and f.get("status", "").lower() != "closed":
                return True
            if key == "port_443_open" and f.get("port") == 443 and f.get("status", "").lower() != "closed":
                return True
            if key == "port_21_open" and f.get("port") == 21 and f.get("status", "").lower() != "closed":
                return True
            if key == "banner_microsoft" and "Microsoft FTP Service" in str(f.get("banner", "")):
                return True
            if key == "http_400_detected" and f.get("status") == 400:
                return True
            if key == "ssrf_param_detected" and f.get("type") == "param" and f.get("category") == "ssrf":
                return True
            if key == "redis_host_found" and "redis" in str(f.get("value", "")).lower():
                return True
            if key == "no_rate_limit_finding" and f.get("type") == "no_rate_limit":
                return True
        return False

    def detection_matches(self, findings: List[Dict[str, Any]], detection: str) -> bool:
        detection_lower = detection.lower()
        for f in findings:
            blob = json.dumps(f).lower()
            if detection_lower in blob:
                return True
        return False

    def calculate_vector_probability(self, vector_name: str, findings: List[Dict[str, Any]]) -> float:
        config = self._find_vector(vector_name)
        if not config:
            return 0.0

        weights: Dict[str, float] = config.get("probability_weights", {})
        score = 0.0
        total_weight = 0.0

        for finding_key, weight in weights.items():
            if self.finding_exists(findings, finding_key):
                score += weight
            total_weight += weight

        if total_weight == 0:
            return 0.0
        return score / total_weight

    def get_top_vectors(self, findings: List[Dict[str, Any]], limit: int = 3) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        vectors = self.dictionary.get("vectors", {})

        for category in vectors:
            for vector_name, config in vectors[category].items():
                # pré-requisitos
                if "prerequisites" in config:
                    prereqs_ok = all(self.finding_exists(findings, p) for p in config["prerequisites"])
                    if not prereqs_ok:
                        continue

                prob = self.calculate_vector_probability(vector_name, findings)

                if "detection" in config and not self.detection_matches(findings, config["detection"]):
                    prob *= 0.5

                candidates.append({
                    "name": vector_name,
                    "category": category,
                    "probability": prob,
                    "config": config,
                })

        candidates.sort(key=lambda x: x["probability"], reverse=True)
        return candidates[:limit]
