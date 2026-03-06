import asyncio
import json
import sys

sys.path.insert(0, ".")

from scanner.modules.selenium_xss import SeleniumXSSModule
from scanner.models import AssessmentJob
from scanner.config import validate_target


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"event": "error", "message": "Usage: python3 -m scanner.run_selenium_xss <target_url>"}), flush=True)
        sys.exit(1)

    target_url = sys.argv[1]

    validation = validate_target(target_url)
    if not validation["valid"]:
        print(json.dumps({"event": "error", "message": f"Target rejected: {validation.get('reason', 'unknown')}"}), flush=True)
        sys.exit(1)

    job = AssessmentJob(
        target=target_url,
        hostname=validation["hostname"],
        scheme=validation.get("scheme", "https"),
        port=validation.get("port"),
    )

    module = SeleniumXSSModule()
    findings = asyncio.run(module.run(job))

    report = {
        "event": "SELENIUM_XSS_REPORT",
        "type": "SELENIUM_XSS_REPORT",
        "target": target_url,
        "total_findings": len(findings),
        "xss_confirmed": len([f for f in findings if "Confirmed" in f.title]),
        "dom_sinks": len([f for f in findings if "DOM" in f.title]),
        "csp_issues": len([f for f in findings if "CSP" in f.title or "Content-Security" in f.title]),
        "findings": [
            {
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
                "cvss_score": f.cvss_score,
            }
            for f in findings
        ],
        "findings_count": {
            "critical": len([f for f in findings if f.severity == "critical"]),
            "high": len([f for f in findings if f.severity == "high"]),
            "medium": len([f for f in findings if f.severity == "medium"]),
            "low": len([f for f in findings if f.severity == "low"]),
        },
    }
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()

