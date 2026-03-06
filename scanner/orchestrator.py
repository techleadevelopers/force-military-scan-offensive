import asyncio
import json
import sys
import time
import signal
from scanner.config import validate_target
from scanner.models import AssessmentJob, Finding
from scanner.modules.surface_mapping import SurfaceMappingModule
from scanner.modules.waf_detector import WAFDetectorModule
from scanner.modules.tls_validator import TLSValidatorModule
from scanner.modules.browser_recon import BrowserReconModule
from scanner.modules.js_secrets_scanner import JSSecretsModule
from scanner.modules.headers_analyzer import HeadersAnalyzerModule
from scanner.modules.cors_analyzer import CORSAnalyzerModule
from scanner.modules.rate_limit import RateLimitModule
from scanner.modules.auth_flow import AuthFlowModule
from scanner.modules.input_validation import InputValidationModule
from scanner.modules.selenium_xss import SeleniumXSSModule


PHASE_MAP = {
    "surface": [SurfaceMappingModule, WAFDetectorModule],
    "exposure": [TLSValidatorModule, BrowserReconModule, JSSecretsModule],
    "misconfig": [HeadersAnalyzerModule, CORSAnalyzerModule],
    "simulation": [RateLimitModule, AuthFlowModule, InputValidationModule, SeleniumXSSModule],
    "report": [],
}

PHASE_ORDER = ["surface", "exposure", "misconfig", "simulation", "report"]

STACK_HYPOTHESIS_MAP = {
    "express": {
        "priority_vectors": ["prototype_pollution", "nosql_injection", "ssrf", "path_traversal"],
        "depriority": ["sqli_traditional"],
        "tech_label": "Express.js",
    },
    "next": {
        "priority_vectors": ["ssrf", "api_exposure", "broken_auth", "path_traversal"],
        "depriority": ["sqli_traditional", "lfi"],
        "tech_label": "Next.js",
    },
    "firebase": {
        "priority_vectors": ["nosql_injection", "broken_auth", "idor", "credential_leak"],
        "depriority": ["sqli_traditional", "lfi", "ssti"],
        "tech_label": "Firebase",
    },
    "django": {
        "priority_vectors": ["ssti", "orm_injection", "csrf", "debug_exposure"],
        "depriority": ["prototype_pollution"],
        "tech_label": "Django",
    },
    "spring": {
        "priority_vectors": ["deserialization", "sqli", "ssti", "path_traversal"],
        "depriority": ["prototype_pollution", "nosql_injection"],
        "tech_label": "Spring Boot",
    },
    "php": {
        "priority_vectors": ["sqli", "lfi", "rce", "deserialization", "ssti"],
        "depriority": ["prototype_pollution", "nosql_injection"],
        "tech_label": "PHP",
    },
    "rails": {
        "priority_vectors": ["deserialization", "sqli", "ssti", "mass_assignment"],
        "depriority": ["prototype_pollution"],
        "tech_label": "Ruby on Rails",
    },
    "flask": {
        "priority_vectors": ["ssti", "ssrf", "debug_exposure", "path_traversal"],
        "depriority": ["prototype_pollution"],
        "tech_label": "Flask",
    },
    "aspnet": {
        "priority_vectors": ["deserialization", "sqli", "path_traversal", "viewstate"],
        "depriority": ["prototype_pollution", "nosql_injection"],
        "tech_label": "ASP.NET",
    },
    "nginx": {
        "priority_vectors": ["path_traversal", "header_injection", "ssrf"],
        "depriority": [],
        "tech_label": "Nginx",
    },
    "apache": {
        "priority_vectors": ["path_traversal", "ssti", "cgi_abuse"],
        "depriority": [],
        "tech_label": "Apache",
    },
    "mongodb": {
        "priority_vectors": ["nosql_injection", "idor", "broken_auth"],
        "depriority": ["sqli_traditional"],
        "tech_label": "MongoDB",
    },
    "redis": {
        "priority_vectors": ["ssrf", "credential_leak", "command_injection"],
        "depriority": [],
        "tech_label": "Redis",
    },
    "graphql": {
        "priority_vectors": ["idor", "broken_auth", "introspection", "injection"],
        "depriority": [],
        "tech_label": "GraphQL",
    },
    "aws": {
        "priority_vectors": ["ssrf", "credential_leak", "iam_escalation"],
        "depriority": [],
        "tech_label": "AWS",
    },
    "cloudflare": {
        "priority_vectors": ["waf_bypass", "ssrf", "api_abuse"],
        "depriority": ["brute_force"],
        "tech_label": "Cloudflare WAF",
    },
}

STACK_DETECT_PATTERNS = {
    "express": [r"express", r"x-powered-by.*express", r"connect\.sid"],
    "next": [r"next\.js", r"_next/", r"__NEXT_DATA__", r"vercel"],
    "firebase": [r"firebase", r"firebaseio\.com", r"firebaseapp\.com"],
    "django": [r"django", r"csrfmiddlewaretoken", r"wsgi"],
    "spring": [r"spring", r"whitelabel error", r"x-application-context"],
    "php": [r"x-powered-by.*php", r"\.php", r"laravel", r"symfony"],
    "rails": [r"x-powered-by.*phusion", r"ruby", r"rails", r"_session_id"],
    "flask": [r"werkzeug", r"flask", r"jinja2"],
    "aspnet": [r"asp\.net", r"__viewstate", r"x-aspnet"],
    "nginx": [r"server.*nginx"],
    "apache": [r"server.*apache"],
    "mongodb": [r"mongodb", r"mongoose", r"nosql"],
    "redis": [r"redis", r"ioredis"],
    "graphql": [r"graphql", r"__schema", r"query.*mutation"],
    "aws": [r"amazonaws", r"x-amz", r"aws", r"lambda", r"s3://"],
    "cloudflare": [r"cloudflare", r"cf-ray", r"cf-cache"],
}


def _build_hypothesis(findings) -> dict:
    detected_stacks = []
    priority_vectors = []
    depriority_vectors = []

    all_text = ""
    for f in findings:
        title = f.title if hasattr(f, "title") else f.get("title", "")
        desc = f.description if hasattr(f, "description") else f.get("description", "")
        evidence = f.evidence if hasattr(f, "evidence") else f.get("evidence", "")
        all_text += f" {title} {desc} {evidence}"

    all_text_lower = all_text.lower()

    import re as _re
    for tech_key, patterns in STACK_DETECT_PATTERNS.items():
        for pat in patterns:
            if _re.search(pat, all_text_lower):
                if tech_key not in detected_stacks:
                    detected_stacks.append(tech_key)
                    hyp = STACK_HYPOTHESIS_MAP.get(tech_key, {})
                    for v in hyp.get("priority_vectors", []):
                        if v not in priority_vectors:
                            priority_vectors.append(v)
                    for v in hyp.get("depriority", []):
                        if v not in depriority_vectors:
                            depriority_vectors.append(v)
                break

    tech_labels = [STACK_HYPOTHESIS_MAP[s]["tech_label"] for s in detected_stacks if s in STACK_HYPOTHESIS_MAP]

    return {
        "detected_stacks": detected_stacks,
        "tech_labels": tech_labels,
        "priority_vectors": priority_vectors,
        "depriority": depriority_vectors,
        "stack_signature": "+".join(detected_stacks) if detected_stacks else "unknown",
    }


def emit(event_type: str, data: dict):
    payload = {"event": event_type, "data": data, "timestamp": time.time()}
    print(json.dumps(payload), flush=True)


async def run_assessment(target: str):
    validation = validate_target(target)
    if not validation["valid"]:
        emit("log_stream", {
            "message": f"TARGET REJECTED: {validation['reason']}",
            "level": "error",
            "phase": "",
        })
        emit("phase_update", {"phase": "surface", "status": "error"})
        emit("completed", {"error": validation["reason"]})
        return

    job = AssessmentJob(
        target=target,
        hostname=validation["hostname"],
        scheme=validation.get("scheme", "https"),
        port=validation.get("port"),
    )

    job.add_audit("assessment_started", f"Target: {target}, Matched rule: {validation.get('matched_rule', 'N/A')}")

    emit("log_stream", {
        "message": f"Assessment authorized  Target: {job.hostname} (rule: {validation.get('matched_rule', 'N/A')})",
        "level": "success",
        "phase": "",
    })
    emit("log_stream", {
        "message": f"Job ID: {job.job_id}",
        "level": "info",
        "phase": "",
    })
    emit("log_stream", {
        "message": f"Base URL: {job.base_url}",
        "level": "info",
        "phase": "",
    })

    total_modules = sum(len(mods) for mods in PHASE_MAP.values())
    completed_modules = 0
    total_findings = 0

    for phase_name in PHASE_ORDER:
        if job.aborted:
            break

        modules = PHASE_MAP[phase_name]

        if phase_name == "report":
            emit("phase_update", {"phase": "report", "status": "running"})
            emit("log_stream", {"message": "Compiling assessment report...", "level": "info", "phase": "report"})

            report = job.to_report()
            emit("log_stream", {
                "message": f"Total findings: {report['summary']['total_findings']}",
                "level": "info",
                "phase": "report",
            })
            emit("log_stream", {
                "message": f"Risk level: {report['summary']['risk_level']}",
                "level": "warn" if report["summary"]["risk_level"] in ("HIGH", "CRITICAL") else "info",
                "phase": "report",
            })
            emit("log_stream", {
                "message": f"Max CVSS: {report['summary']['max_cvss_score']}",
                "level": "info",
                "phase": "report",
            })

            severity_dist = report["summary"]["severity_distribution"]
            for sev, count in severity_dist.items():
                emit("log_stream", {
                    "message": f"  {sev.upper()}: {count}",
                    "level": "error" if sev in ("critical", "high") else "warn" if sev == "medium" else "info",
                    "phase": "report",
                })

            emit("log_stream", {
                "message": f"Assessment duration: {report['duration_seconds']}s",
                "level": "success",
                "phase": "report",
            })
            emit("log_stream", {
                "message": "Report generation complete",
                "level": "success",
                "phase": "report",
            })

            emit("report_generated", report)
            emit("phase_update", {"phase": "report", "status": "completed"})
            job.phases_completed.append("report")
            emit("telemetry_update", {"progress": 100})
            continue

        for ModuleClass in modules:
            if job.aborted:
                break

            module = ModuleClass()
            module._job_id = job.job_id
            job.add_audit("module_started", f"Module: {module.name}", phase=phase_name)

            module_timeout = max(module.timeout, 120)
            try:
                module_findings = await asyncio.wait_for(
                    module.run(job),
                    timeout=module_timeout,
                )
                for f in module_findings:
                    job.findings.append(f)
                    total_findings += 1
            except asyncio.TimeoutError:
                emit("log_stream", {
                    "message": f"Module {module.name} timed out after {module_timeout}s",
                    "level": "error",
                    "phase": phase_name,
                })
                emit("phase_update", {"phase": phase_name, "status": "error"})
                job.add_audit("module_timeout", f"Module: {module.name}", phase=phase_name)

            completed_modules += 1
            progress = int((completed_modules / max(total_modules, 1)) * 90)
            emit("telemetry_update", {
                "progress": progress,
                "activeModules": total_modules - completed_modules,
                "threatsDetected": total_findings,
            })

            job.add_audit("module_completed", f"Module: {module.name}, Findings: {len(module_findings)}", phase=phase_name)

        if not job.aborted:
            job.phases_completed.append(phase_name)

            if phase_name == "surface":
                hypothesis = _build_hypothesis(job.findings)
                job._hypothesis = hypothesis
                if hypothesis["detected_stacks"]:
                    emit("log_stream", {
                        "message": f"[HYPOTHESIS] Stack detected: {hypothesis['stack_signature']} ({', '.join(hypothesis['tech_labels'])})",
                        "level": "warn",
                        "phase": "surface",
                    })
                    emit("log_stream", {
                        "message": f"[HYPOTHESIS] Priority vectors: {', '.join(hypothesis['priority_vectors'][:8])}",
                        "level": "warn",
                        "phase": "surface",
                    })
                    if hypothesis["depriority"]:
                        emit("log_stream", {
                            "message": f"[HYPOTHESIS] Deprioritized: {', '.join(hypothesis['depriority'])}",
                            "level": "info",
                            "phase": "surface",
                        })
                    emit("stack_hypothesis", hypothesis)
                else:
                    emit("log_stream", {
                        "message": "[HYPOTHESIS] No specific stack fingerprint  running full generic scan",
                        "level": "info",
                        "phase": "surface",
                    })

    job.completed_at = time.time()
    job.status = "completed"
    job.add_audit("assessment_completed", f"Total findings: {len(job.findings)}")

    emit("completed", {})


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"event": "error", "data": {"message": "Usage: python -m scanner.orchestrator <target>"}}), flush=True)
        sys.exit(1)

    target = sys.argv[1]

    def handle_signal(sig, frame):
        emit("log_stream", {"message": "Scan aborted by signal", "level": "warn", "phase": ""})
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    asyncio.run(run_assessment(target))


if __name__ == "__main__":
    main()

