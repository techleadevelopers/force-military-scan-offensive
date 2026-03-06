"""
MSE Sniper Decision Engine  Unified APT Level 5 Decision System
===================================================================
Integrates all 9 decision engines into a single coherent system:
  1. PredictiveDecisionEngine    Predict before scanning
  2. TemporalCorrelationEngine   Correlate across time
  3. BayesianDecisionEngine      Probabilistic decisions
  4. GeneticPayloadEngine        Evolve payloads
  5. DynamicChainBuilder         Adaptive exploit chains
  6. DeepFingerprinter           Version-specific CVE mapping
  7. SmartExfiltrator             Value-based data triage
  8. AntiForensicsAssessor       Stealth posture assessment
  9. MultiObjectiveOptimizer     Pareto-optimal action selection

Designed to be called from SniperPipeline as a new phase without
modifying any existing pipeline logic.
"""

import time
from typing import List, Dict, Any, Optional

from scanner.predictive_engine import PredictiveDecisionEngine
from scanner.temporal_correlation import TemporalCorrelationEngine
from scanner.bayesian_decision import BayesianDecisionEngine
from scanner.genetic_payload import GeneticPayloadEngine
from scanner.dynamic_chain import DynamicChainBuilder
from scanner.deep_fingerprint import DeepFingerprinter
from scanner.smart_exfiltration import SmartExfiltrator
from scanner.anti_forensics import AntiForensicsAssessor
from scanner.multi_objective import MultiObjectiveOptimizer


class SniperDecisionEngine:

    def __init__(self, target: str, target_intelligence: Dict, log_fn=None, emit_fn=None):
        self.target = target
        self.intel = target_intelligence
        self.log = log_fn or (lambda msg, *a, **kw: None)
        self.emit = emit_fn or (lambda evt, data: None)

        self.predictive = PredictiveDecisionEngine(target_intelligence)
        self.temporal = TemporalCorrelationEngine()
        self.bayesian = BayesianDecisionEngine()
        self.genetic = GeneticPayloadEngine()
        self.chain_builder = DynamicChainBuilder()
        self.fingerprinter = DeepFingerprinter()
        self.exfiltrator = SmartExfiltrator()
        self.anti_forensics = AntiForensicsAssessor()
        self.multi_objective = MultiObjectiveOptimizer()

        self.report: Dict = {}

    async def execute(self, findings: List, scan_events: List[Dict] = None,
                      headers: Dict = None, body_samples: List[str] = None,
                      error_samples: List[str] = None) -> Dict:
        start = time.time()

        self.log(
            "[SNIPER DECISION] â˜… APT Level 5 Decision Engine ACTIVATED  "
            "9 cognitive engines initializing...",
            "error", "decision_engine"
        )

        phase1 = self._phase_intelligence(headers, body_samples, error_samples)

        phase2 = self._phase_prediction()

        phase3 = self._phase_temporal(findings, scan_events)

        phase4 = self._phase_bayesian(findings)

        phase5 = self._phase_dynamic_chains(findings)

        phase6 = self._phase_genetic_evolution()

        phase7 = self._phase_exfiltration_triage(findings)

        phase8 = self._phase_anti_forensics(scan_events)

        phase9 = self._phase_multi_objective(findings)

        elapsed = round(time.time() - start, 2)

        self.report = {
            "engine": "SniperDecisionEngine_v1.0",
            "target": self.target,
            "elapsed_seconds": elapsed,
            "intelligence": phase1,
            "predictions": phase2,
            "temporal_analysis": phase3,
            "bayesian_decisions": phase4,
            "dynamic_chains": phase5,
            "genetic_evolution": phase6,
            "exfiltration_triage": phase7,
            "anti_forensics": phase8,
            "multi_objective": phase9,
            "dominant_decision": phase9.get("best_action", {}).get("action", "NONE"),
            "overall_confidence": self._calculate_overall_confidence(),
        }

        self.log(
            f"[SNIPER DECISION] â˜… Engine complete in {elapsed}s  "
            f"dominant={self.report['dominant_decision']}, "
            f"confidence={self.report['overall_confidence']:.1%}",
            "error", "decision_engine"
        )

        self.emit("sniper_decision_report", self.report)

        return self.report

    def _phase_intelligence(self, headers: Dict = None,
                            body_samples: List[str] = None,
                            error_samples: List[str] = None) -> Dict:
        self.log(
            "[DECISION Â§1] DEEP FINGERPRINTING  Extracting exact versions + CVE mapping...",
            "warn", "decision_engine"
        )

        if headers:
            self.fingerprinter.fingerprint_from_headers(headers)

        for body in (body_samples or []):
            self.fingerprinter.fingerprint_from_body(body)

        for error in (error_samples or []):
            self.fingerprinter.fingerprint_from_error(error)

        cves = self.fingerprinter.map_to_cves()
        fp_report = self.fingerprinter.generate_report()

        if cves:
            self.log(
                f"[DECISION Â§1] {fp_report['components_detected']} components, "
                f"{fp_report['total_cves']} CVEs mapped "
                f"({fp_report['exploitable_cves']} with public exploits)",
                "error", "decision_engine"
            )
            for cve in cves[:3]:
                self.log(
                    f"  â””â”€ {cve['id']}: {cve['component']} {cve.get('version', '?')} "
                    f"(CVSS {cve['cvss']})  {cve['description'][:60]}",
                    "error", "decision_engine"
                )
        else:
            self.log(
                f"[DECISION Â§1] {fp_report['components_detected']} components detected, no CVE matches",
                "info", "decision_engine"
            )

        return fp_report

    def _phase_prediction(self) -> Dict:
        self.log(
            "[DECISION Â§2] PREDICTIVE ANALYSIS  Predicting attack surface before scanning...",
            "warn", "decision_engine"
        )

        predictions = self.predictive.predict_attack_surface()
        prioritized = self.predictive.prioritize_by_success_probability(predictions)
        pred_report = self.predictive.generate_report()

        self.log(
            f"[DECISION Â§2] {pred_report['total_predictions']} vulnerabilities predicted "
            f"({pred_report['high_confidence']} high-confidence, "
            f"{pred_report['attack_surface_coverage']} unique vectors)",
            "warn", "decision_engine"
        )

        for pred in prioritized[:3]:
            self.log(
                f"  â””â”€ {pred['vuln']}: {pred.get('confidence', 0):.0%} confidence "
                f"at {', '.join(pred.get('locations', [])[:3])} [{pred.get('source', '')}]",
                "info", "decision_engine"
            )

        return pred_report

    def _phase_temporal(self, findings: List, scan_events: List[Dict] = None) -> Dict:
        self.log(
            "[DECISION Â§3] TEMPORAL CORRELATION  Analyzing event sequences across time...",
            "warn", "decision_engine"
        )

        if scan_events:
            self.temporal.current_scan_events = scan_events

        finding_dicts = []
        for f in findings:
            if isinstance(f, dict):
                finding_dicts.append(f)
            elif hasattr(f, "title"):
                finding_dicts.append({
                    "title": getattr(f, "title", ""),
                    "severity": getattr(f, "severity", "info"),
                    "type": getattr(f, "category", ""),
                })

        patterns = self.temporal.analyze_temporal_patterns(finding_dicts)
        temporal_report = self.temporal.generate_report()

        if patterns:
            for p in patterns[:3]:
                self.log(
                    f"  â””â”€ Pattern: {p['pattern']} â†’ {p['decision']} "
                    f"(confidence: {p['confidence']:.0%})",
                    "warn", "decision_engine"
                )
        else:
            self.log(
                "[DECISION Â§3] No temporal patterns detected (insufficient event history)",
                "info", "decision_engine"
            )

        return temporal_report

    def _phase_bayesian(self, findings: List) -> Dict:
        self.log(
            "[DECISION Â§4] BAYESIAN INFERENCE  Calculating success probabilities...",
            "warn", "decision_engine"
        )

        vectors_to_evaluate = set()
        for f in findings:
            if isinstance(f, dict):
                cat = f.get("category", f.get("type", ""))
            elif hasattr(f, "category"):
                cat = getattr(f, "category", "")
            else:
                cat = ""
            if cat:
                normalized = cat.lower().replace(" ", "_").replace("-", "_")
                vectors_to_evaluate.add(normalized)

        for pred in self.predictive.predictions[:10]:
            vectors_to_evaluate.add(pred.get("vuln", ""))

        context = {
            "stack_vectors": [s for s in self.intel.get("detected_stacks", [])],
            "waf_strength": self.intel.get("waf_strength", "unknown"),
            "findings": findings,
            "auto_dump_triggered": self.intel.get("auto_dump_triggered", False),
        }

        results = self.bayesian.batch_evaluate(list(vectors_to_evaluate)[:20], context)
        bayes_report = self.bayesian.generate_report()

        attack_count = bayes_report["attack_vectors"]
        self.log(
            f"[DECISION Â§4] {bayes_report['total_evaluated']} vectors evaluated  "
            f"{attack_count} ATTACK, {bayes_report['deferred_vectors']} DEFER, "
            f"{bayes_report['skipped_vectors']} SKIP",
            "warn" if attack_count > 0 else "info", "decision_engine"
        )

        for top in bayes_report.get("top_attack_targets", [])[:3]:
            self.log(
                f"  â””â”€ {top['vector']}: P(success)={top['probability']:.0%} â†’ ATTACK",
                "error", "decision_engine"
            )

        return bayes_report

    def _phase_dynamic_chains(self, findings: List) -> Dict:
        self.log(
            "[DECISION Â§5] DYNAMIC CHAIN CONSTRUCTION  Building adaptive exploit paths...",
            "warn", "decision_engine"
        )

        for f in findings:
            if isinstance(f, dict):
                cat = f.get("category", f.get("type", ""))
            elif hasattr(f, "category"):
                cat = getattr(f, "category", "")
            else:
                cat = ""
            if cat:
                self.chain_builder.add_finding(cat)

        for pred in self.predictive.predictions:
            self.chain_builder.add_finding(pred.get("vuln", ""))

        chain = self.chain_builder.build_optimal_chain()
        chain_report = self.chain_builder.generate_report()

        risk_score = chain_report["chain_risk_score"]
        self.log(
            f"[DECISION Â§5] Chain built: {chain_report['chain_length']} steps, "
            f"risk_score={risk_score:.2f}, "
            f"{len(chain_report['reachable_targets'])} reachable targets",
            "error" if risk_score > 0.5 else "warn", "decision_engine"
        )

        for step in chain[:3]:
            self.log(
                f"  â””â”€ Step {step['step']}: {step['technique']} "
                f"(P={step['probability']:.0%}) â†’ {', '.join(step['leads_to'][:3])}",
                "info", "decision_engine"
            )

        return chain_report

    def _phase_genetic_evolution(self) -> Dict:
        self.log(
            "[DECISION Â§6] GENETIC PAYLOAD EVOLUTION  Initializing population + fitness evaluation...",
            "warn", "decision_engine"
        )

        self.genetic.evolve()

        gen_report = self.genetic.generate_report()

        self.log(
            f"[DECISION Â§6] Generation {gen_report['current_generation']}: "
            f"population={gen_report['population_size']}, "
            f"best_fitness={gen_report['best_fitness']:.1f}",
            "info", "decision_engine"
        )

        return gen_report

    def _phase_exfiltration_triage(self, findings: List) -> Dict:
        self.log(
            "[DECISION Â§7] SMART EXFILTRATION TRIAGE  Classifying data value + prioritization...",
            "warn", "decision_engine"
        )

        data_items = []
        for f in findings:
            if isinstance(f, dict):
                data_items.append({
                    "type": f.get("category", f.get("type", "unknown")),
                    "content": f.get("evidence", f.get("description", "")),
                    "record_count": 1,
                    "environment": "unknown",
                })
            elif hasattr(f, "title"):
                data_items.append({
                    "type": getattr(f, "category", "unknown"),
                    "content": getattr(f, "evidence", ""),
                    "record_count": 1,
                    "environment": "unknown",
                })

        if data_items:
            prioritized = self.exfiltrator.prioritize_exfiltration(data_items)
            exfil_report = self.exfiltrator.generate_report()

            self.log(
                f"[DECISION Â§7] {exfil_report['total_items']} items triaged: "
                f"{exfil_report['immediate']} IMMEDIATE, "
                f"{exfil_report['queued']} QUEUED, "
                f"{exfil_report['deferred']} DEFERRED "
                f"(avg value: {exfil_report['avg_value']:.0f}/100)",
                "warn", "decision_engine"
            )

            regulatory = exfil_report.get("regulatory_exposure", {})
            if regulatory:
                regs = ", ".join(f"{k}:{v}" for k, v in regulatory.items())
                self.log(f"  â””â”€ Regulatory exposure: {regs}", "error", "decision_engine")
        else:
            exfil_report = {"total_items": 0, "immediate": 0, "queued": 0, "deferred": 0}
            self.log("[DECISION Â§7] No data items to triage", "info", "decision_engine")

        return exfil_report

    def _phase_anti_forensics(self, scan_events: List[Dict] = None) -> Dict:
        self.log(
            "[DECISION Â§8] ANTI-FORENSICS ASSESSMENT  Evaluating stealth posture...",
            "warn", "decision_engine"
        )

        events = scan_events or self.temporal.current_scan_events
        assessment = self.anti_forensics.assess_detection_risk(events)
        recommendations = self.anti_forensics.recommend_techniques()
        posture = self.anti_forensics.calculate_evasion_posture()
        af_report = self.anti_forensics.generate_report()

        self.log(
            f"[DECISION Â§8] Stealth score: {assessment['stealth_score']:.0%}, "
            f"detection risk: {assessment['total_risk']:.0%}, "
            f"posture: {posture['assessment']}",
            "warn" if assessment["stealth_score"] < 0.7 else "info", "decision_engine"
        )

        if assessment["detected_count"] > 0:
            self.log(
                f"  â””â”€ {assessment['detected_count']} detection indicators triggered",
                "error", "decision_engine"
            )
            for rec in recommendations[:2]:
                self.log(
                    f"  â””â”€ Recommend: {rec['technique']} "
                    f"(-{rec['detection_reduction']:.0%} detection, {rec['complexity']})",
                    "warn", "decision_engine"
                )

        return af_report

    def _phase_multi_objective(self, findings: List) -> Dict:
        self.log(
            "[DECISION Â§9] MULTI-OBJECTIVE OPTIMIZATION  Pareto frontier analysis...",
            "warn", "decision_engine"
        )

        possible_actions = []
        for pred in self.predictive.predictions[:10]:
            possible_actions.append({
                "name": pred.get("vuln", "unknown"),
                "vector": pred.get("vuln", "unknown"),
                "probability": pred.get("confidence", 0.5),
                "estimated_time_s": 30,
            })

        for decision in self.bayesian.posterior_cache:
            if decision not in [a["vector"] for a in possible_actions]:
                possible_actions.append({
                    "name": decision,
                    "vector": decision,
                    "probability": self.bayesian.posterior_cache[decision],
                    "estimated_time_s": 30,
                })

        context = {
            "findings": findings,
            "waf_strength": self.intel.get("waf_strength", "unknown"),
        }

        if possible_actions:
            best = self.multi_objective.select_optimal_action(possible_actions, context)
            mo_report = self.multi_objective.generate_report()

            self.log(
                f"[DECISION Â§9] {mo_report['total_evaluated']} actions evaluated  "
                f"Pareto front: {mo_report['pareto_front_size']} non-dominated, "
                f"best: {best['action']} (score={best['weighted_score']:.2f}, {best['recommendation']})",
                "error", "decision_engine"
            )
            mo_report["best_action"] = best
        else:
            mo_report = {"total_evaluated": 0, "best_action": {"action": "NONE", "weighted_score": 0}}
            self.log("[DECISION Â§9] No actions to optimize", "info", "decision_engine")

        return mo_report

    def _calculate_overall_confidence(self) -> float:
        scores = []

        pred_report = self.report.get("predictions", {})
        if pred_report.get("total_predictions", 0) > 0:
            ratio = pred_report.get("high_confidence", 0) / max(1, pred_report["total_predictions"])
            scores.append(ratio)

        bayes_report = self.report.get("bayesian_decisions", {})
        if bayes_report.get("total_evaluated", 0) > 0:
            ratio = bayes_report.get("attack_vectors", 0) / max(1, bayes_report["total_evaluated"])
            scores.append(ratio)

        chain_report = self.report.get("dynamic_chains", {})
        if chain_report.get("chain_risk_score", 0) > 0:
            scores.append(chain_report["chain_risk_score"])

        af_report = self.report.get("anti_forensics", {})
        stealth = af_report.get("stealth_score", 0.5)
        scores.append(stealth)

        if not scores:
            return 0.5

        return round(sum(scores) / len(scores), 4)

