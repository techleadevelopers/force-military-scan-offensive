import os
import json
import re
from typing import List
from urllib.parse import urlparse

ALLOWLIST_FILE = os.path.join(os.path.dirname(__file__), "allowlist.json")

DEFAULT_ALLOWLIST = [
    "*.example.com",
    "*.test.local",
    "localhost",
    "127.0.0.1",
    "10.*.*.*",
    "192.168.*.*",
    "172.16.*.*",
]

MAX_CONCURRENT_JOBS = 3
PHASE_TIMEOUT_SECONDS = 120
MAX_REQUESTS_PER_MODULE = 50
REQUEST_DELAY_MS = 200
USER_AGENT = "OSLO-SecurityAssessment/2.0 (Authorized-Internal-Audit)"


def load_allowlist() -> List[str]:
    if os.path.exists(ALLOWLIST_FILE):
        with open(ALLOWLIST_FILE, "r") as f:
            data = json.load(f)
            return data.get("allowed_targets", DEFAULT_ALLOWLIST)
    return DEFAULT_ALLOWLIST


def save_allowlist(targets: List[str]):
    with open(ALLOWLIST_FILE, "w") as f:
        json.dump({"allowed_targets": targets}, f, indent=2)


def _pattern_to_regex(pattern: str) -> str:
    escaped = re.escape(pattern)
    return "^" + escaped.replace(r"\*", ".*") + "$"


def validate_target(target: str) -> dict:
    try:
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.path
        if not hostname:
            return {"valid": False, "reason": "Could not extract hostname from target"}

        if parsed.scheme and parsed.scheme not in ("http", "https"):
            return {"valid": False, "reason": f"Unsupported scheme: {parsed.scheme}"}

        allowlist = load_allowlist()
        for pattern in allowlist:
            regex = _pattern_to_regex(pattern)
            if re.match(regex, hostname, re.IGNORECASE):
                return {
                    "valid": True,
                    "hostname": hostname,
                    "scheme": parsed.scheme or "https",
                    "port": parsed.port,
                    "matched_rule": pattern,
                }

        return {
            "valid": False,
            "reason": f"Target '{hostname}' is not in the allowlist. Only pre-authorized targets can be assessed.",
        }
    except Exception as e:
        return {"valid": False, "reason": f"Invalid target format: {str(e)}"}

