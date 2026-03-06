"""
MSE Deep Fingerprinter with CVE Mapping
==========================================
Identifies EXACT versions of components and maps them to known CVEs.
Goes beyond stack detection  extracts specific version strings from
headers, JS bundles, error messages, cookies, and source maps.
"""

import re
from typing import List, Dict, Any, Optional


VERSION_SIGNATURES = {
    "express": {
        "header_pattern": r"x-powered-by:\s*express",
        "version_patterns": [
            r"express[/\s]?(\d+\.\d+\.\d+)",
            r"\"express\":\s*\"[~^]?(\d+\.\d+\.\d+)\"",
        ],
    },
    "nginx": {
        "header_pattern": r"server:\s*nginx",
        "version_patterns": [r"nginx/(\d+\.\d+\.\d+)"],
    },
    "apache": {
        "header_pattern": r"server:\s*apache",
        "version_patterns": [r"apache/(\d+\.\d+\.\d+)"],
    },
    "php": {
        "header_pattern": r"x-powered-by:\s*php",
        "version_patterns": [r"php/(\d+\.\d+\.\d+)"],
    },
    "aspnet": {
        "header_pattern": r"x-powered-by:\s*asp\.net",
        "version_patterns": [r"asp\.net\s*version[:\s]*(\d+\.\d+)"],
    },
    "django": {
        "version_patterns": [
            r"django[/\s]?(\d+\.\d+\.\d+)",
            r"\"django\":\s*\"(\d+\.\d+\.\d+)\"",
        ],
    },
    "spring": {
        "version_patterns": [
            r"spring[- ]boot[/\s]?(\d+\.\d+\.\d+)",
            r"x-application-context:\s*\S+:(\d+)",
        ],
    },
    "react": {
        "version_patterns": [
            r"react[/\s@](\d+\.\d+\.\d+)",
            r"\"react\":\s*\"[~^]?(\d+\.\d+\.\d+)\"",
        ],
    },
    "angular": {
        "version_patterns": [
            r"angular[/\s@](\d+\.\d+\.\d+)",
            r"ng-version=\"(\d+\.\d+\.\d+)\"",
        ],
    },
    "jquery": {
        "version_patterns": [
            r"jquery[/\s]?v?(\d+\.\d+\.\d+)",
            r"jquery\.min\.js\?v=(\d+\.\d+\.\d+)",
        ],
    },
    "wordpress": {
        "version_patterns": [
            r"wordpress[/\s]?(\d+\.\d+\.\d+)",
            r"wp-includes/.*\?ver=(\d+\.\d+\.\d+)",
            r"<meta name=\"generator\" content=\"WordPress (\d+\.\d+\.\d+)\"",
        ],
    },
    "nextjs": {
        "version_patterns": [
            r"next\.js[/\s]?(\d+\.\d+\.\d+)",
            r"\"next\":\s*\"(\d+\.\d+\.\d+)\"",
            r"__NEXT_DATA__.*buildId",
        ],
    },
}

KNOWN_CVE_DATABASE = {
    "express": {
        "4.17.1": [
            {"id": "CVE-2022-24999", "cvss": 7.5, "exploit_available": True, "description": "qs prototype pollution via __proto__", "attack_vector": "network", "complexity": "low"},
        ],
        "4.16.0": [
            {"id": "CVE-2022-24999", "cvss": 7.5, "exploit_available": True, "description": "qs prototype pollution", "attack_vector": "network", "complexity": "low"},
            {"id": "CVE-2019-5413", "cvss": 9.8, "exploit_available": True, "description": "Path traversal via malicious URL", "attack_vector": "network", "complexity": "low"},
        ],
    },
    "nginx": {
        "1.16.0": [
            {"id": "CVE-2019-9511", "cvss": 7.5, "exploit_available": True, "description": "HTTP/2 Data Dribble DoS", "attack_vector": "network", "complexity": "low"},
            {"id": "CVE-2019-9513", "cvss": 7.5, "exploit_available": True, "description": "HTTP/2 Resource Loop DoS", "attack_vector": "network", "complexity": "low"},
        ],
    },
    "apache": {
        "2.4.49": [
            {"id": "CVE-2021-41773", "cvss": 9.8, "exploit_available": True, "description": "Path Traversal + RCE", "attack_vector": "network", "complexity": "low"},
        ],
        "2.4.50": [
            {"id": "CVE-2021-42013", "cvss": 9.8, "exploit_available": True, "description": "Path Traversal bypass of CVE-2021-41773", "attack_vector": "network", "complexity": "low"},
        ],
    },
    "php": {
        "8.1.0": [
            {"id": "CVE-2023-0568", "cvss": 8.1, "exploit_available": True, "description": "Buffer overflow in PHP core", "attack_vector": "network", "complexity": "high"},
        ],
    },
    "spring": {
        "2.6.0": [
            {"id": "CVE-2022-22965", "cvss": 9.8, "exploit_available": True, "description": "Spring4Shell RCE via data binding", "attack_vector": "network", "complexity": "low"},
        ],
    },
    "jquery": {
        "1.12.4": [
            {"id": "CVE-2020-11022", "cvss": 6.1, "exploit_available": True, "description": "XSS via htmlPrefilter", "attack_vector": "network", "complexity": "low"},
        ],
        "2.2.4": [
            {"id": "CVE-2020-11022", "cvss": 6.1, "exploit_available": True, "description": "XSS via htmlPrefilter", "attack_vector": "network", "complexity": "low"},
        ],
        "3.4.1": [
            {"id": "CVE-2020-11023", "cvss": 6.1, "exploit_available": True, "description": "XSS in option element", "attack_vector": "network", "complexity": "low"},
        ],
    },
    "wordpress": {
        "5.8.0": [
            {"id": "CVE-2022-21661", "cvss": 7.5, "exploit_available": True, "description": "SQL Injection via WP_Query", "attack_vector": "network", "complexity": "low"},
        ],
    },
}


class DeepFingerprinter:

    def __init__(self):
        self.versions: Dict[str, str] = {}
        self.raw_signals: List[Dict] = []
        self.cves_found: List[Dict] = []

    def fingerprint_from_headers(self, headers: Dict[str, str]):
        headers_lower = {k.lower(): v for k, v in headers.items()}
        headers_text = " ".join(f"{k}: {v}" for k, v in headers_lower.items())

        for component, sig in VERSION_SIGNATURES.items():
            header_pat = sig.get("header_pattern")
            if header_pat and re.search(header_pat, headers_text, re.IGNORECASE):
                self.raw_signals.append({"source": "header", "component": component, "match": header_pat})

                for vpat in sig.get("version_patterns", []):
                    m = re.search(vpat, headers_text, re.IGNORECASE)
                    if m:
                        self.versions[component] = m.group(1)
                        break
                else:
                    if component not in self.versions:
                        self.versions[component] = "detected"

    def fingerprint_from_body(self, body: str):
        for component, sig in VERSION_SIGNATURES.items():
            for vpat in sig.get("version_patterns", []):
                m = re.search(vpat, body, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex else "detected"
                    if component not in self.versions or self.versions[component] == "detected":
                        self.versions[component] = version
                    self.raw_signals.append({
                        "source": "body",
                        "component": component,
                        "version": version,
                        "pattern": vpat,
                    })

    def fingerprint_from_error(self, error_text: str):
        error_patterns = {
            "express": [r"Cannot\s+(?:GET|POST|PUT)\s+/", r"Error:.*at\s+Layer\.handle"],
            "django": [r"django\.core", r"OperationalError", r"ImproperlyConfigured"],
            "spring": [r"Whitelabel Error Page", r"org\.springframework"],
            "flask": [r"werkzeug\.exceptions", r"jinja2\.exceptions"],
            "rails": [r"ActionController", r"ActiveRecord", r"routing error"],
            "php": [r"Fatal error.*in\s+\S+\.php", r"Parse error.*\.php"],
            "aspnet": [r"Server Error in.*Application", r"__VIEWSTATE"],
        }

        for component, patterns in error_patterns.items():
            for pat in patterns:
                if re.search(pat, error_text, re.IGNORECASE):
                    if component not in self.versions:
                        self.versions[component] = "detected_via_error"
                    self.raw_signals.append({
                        "source": "error",
                        "component": component,
                        "pattern": pat,
                    })

    def map_to_cves(self) -> List[Dict]:
        vulnerabilities = []

        for component, version in self.versions.items():
            if version in ("detected", "detected_via_error"):
                comp_cves = KNOWN_CVE_DATABASE.get(component, {})
                for ver, cves in comp_cves.items():
                    for cve in cves:
                        vulnerabilities.append({
                            "component": component,
                            "version": f"unknown (possibly {ver})",
                            "confirmed": False,
                            **cve,
                        })
            else:
                cves = KNOWN_CVE_DATABASE.get(component, {}).get(version, [])
                for cve in cves:
                    vulnerabilities.append({
                        "component": component,
                        "version": version,
                        "confirmed": True,
                        **cve,
                    })

                for known_ver, known_cves in KNOWN_CVE_DATABASE.get(component, {}).items():
                    if known_ver != version and self._version_less_than(version, known_ver):
                        pass
                    elif known_ver != version and self._version_less_than(known_ver, version):
                        pass

        self.cves_found = sorted(vulnerabilities, key=lambda x: x.get("cvss", 0), reverse=True)
        return self.cves_found

    def generate_report(self) -> Dict:
        exploit_available = [c for c in self.cves_found if c.get("exploit_available")]
        confirmed = [c for c in self.cves_found if c.get("confirmed")]

        return {
            "components_detected": len(self.versions),
            "versions": dict(self.versions),
            "total_cves": len(self.cves_found),
            "confirmed_cves": len(confirmed),
            "exploitable_cves": len(exploit_available),
            "critical_cves": [c for c in self.cves_found if c.get("cvss", 0) >= 9.0],
            "high_cves": [c for c in self.cves_found if 7.0 <= c.get("cvss", 0) < 9.0],
            "raw_signals": len(self.raw_signals),
            "top_cves": self.cves_found[:5],
        }

    @staticmethod
    def _version_less_than(v1: str, v2: str) -> bool:
        try:
            parts1 = [int(x) for x in v1.split(".")]
            parts2 = [int(x) for x in v2.split(".")]
            return parts1 < parts2
        except (ValueError, AttributeError):
            return False

