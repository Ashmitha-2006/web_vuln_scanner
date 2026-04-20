"""
directory_scan.py — Discover hidden directories and endpoints.

Improvements vs original:
  - Returns List[Finding] instead of writing to a shared file object.
    (The original code had a race condition — multiple threads writing
    to the same file without a lock.)
  - Expanded wordlist (45 paths, up from 14).
  - Severity is based on both HTTP status and path sensitivity.
  - Baseline length comparison kept and improved.
"""

import logging
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from modules.colors import Colors
from modules.finding import Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebVulnScanner/2.0)"}

DIRECTORIES = [
    # Admin / authentication
    "admin", "administrator", "admin-panel", "wp-admin", "login",
    "dashboard", "cpanel", "webmail", "phpmyadmin",
    # Source / version control
    ".git", ".svn", ".hg", ".env", ".DS_Store",
    # Common app paths
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui",
    "docs", "doc", "openapi.json",
    # Uploads / files
    "uploads", "files", "media", "static", "assets",
    # Config / backup
    "config", "backup", "bak", "old", "archive", "tmp",
    # Server diagnostics
    "server-status", "server-info", "status", "health", "metrics",
    # Dev / test
    "test", "dev", "debug", "staging", "beta",
    # Database / sensitive
    "db", "database", "data", "private", "secret",
]

# Paths that are high-risk if they respond
HIGH_RISK_PATHS = {".git", ".svn", ".hg", ".env", "backup", "bak",
                   "phpmyadmin", "admin", "wp-admin", "database", "db"}

STATUS_MEANINGS = {
    200: "Publicly accessible",
    301: "Permanent redirect",
    302: "Temporary redirect",
    401: "Authentication required (resource exists)",
    403: "Forbidden — resource exists but access is denied",
}


def _check_directory(base_url: str, path: str, baseline_len: int) -> List[Finding]:
    target = f"{base_url}/{path}"
    findings: List[Finding] = []

    try:
        resp = requests.get(target, headers=_HEADERS, timeout=10,
                            verify=False, allow_redirects=False)
        code = resp.status_code
        length = len(resp.text)

        if code not in STATUS_MEANINGS:
            return findings

        # Filter soft-404 / catch-all pages
        if abs(length - baseline_len) < 50 and code == 200:
            return findings

        is_high_risk = path.split("/")[0] in HIGH_RISK_PATHS

        if code == 200:
            severity = "HIGH" if is_high_risk else "MEDIUM"
        elif code in (401, 403):
            severity = "MEDIUM" if is_high_risk else "LOW"
        else:
            severity = "INFO"

        color = Colors.severity(severity)
        print(f"{color}[{severity}]{Colors.RESET} Directory found: {target} (HTTP {code})")

        findings.append(Finding(
            severity=severity,
            category="Directory Discovery",
            title=f"Accessible path: /{path}",
            description=STATUS_MEANINGS[code],
            url=target,
            evidence=f"HTTP {code}, response length {length} bytes",
            recommendation=(
                "Restrict access to sensitive directories via server config "
                "(e.g., deny all in .htaccess or nginx location block)."
            ),
        ))

    except requests.exceptions.RequestException:
        pass  # Connection refused, timeout — not a finding

    return findings


def scan_directories(url: str, threads: int = 15) -> List[Finding]:
    url = url.rstrip("/")
    all_findings: List[Finding] = []

    print(f"\n{Colors.BLUE}[+] Scanning for common directories ({len(DIRECTORIES)} paths)...{Colors.RESET}")

    # Baseline — used to detect catch-all / custom 404 pages
    try:
        baseline = requests.get(
            f"{url}/this-path-definitely-does-not-exist-xyzabc123",
            headers=_HEADERS, timeout=10, verify=False,
        )
        baseline_len = len(baseline.text)
    except Exception:
        baseline_len = 0

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(_check_directory, url, d, baseline_len): d
            for d in DIRECTORIES
        }
        for future in as_completed(futures):
            try:
                all_findings.extend(future.result())
            except Exception as exc:
                logger.debug("Directory check error: %s", exc)

    return all_findings
