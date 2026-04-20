"""
sql_injection_detector.py — Detect SQL injection vulnerabilities.

Improvements vs original:
  - Returns List[Finding].
  - Does NOT stop at first finding — tests all parameters.
  - Adds time-based blind detection (sleep-based).
  - Boolean-based detection via response length comparison.
  - Error-based detection retained with expanded error signatures.
"""

import logging
import time
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List

from modules.colors import Colors
from modules.finding import Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebVulnScanner/2.0)"}

ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR ''='",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "; SELECT 1--",
]

# Time-based blind payloads (5-second delay)
TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",              # MSSQL
    "' OR SLEEP(5)--",                          # MySQL
    "' OR pg_sleep(5)--",                       # PostgreSQL
    "'; SELECT pg_sleep(5)--",                  # PostgreSQL
    "1; WAITFOR DELAY '0:0:5'",                 # MSSQL no quote
]

SQL_ERRORS = [
    "sql syntax", "mysql", "syntax error", "database error", "odbc driver",
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "pg_query", "pg_exec", "sqlite_", "sqlite error", "fatal error",
    "sqlstate", "ora-", "oracle error", "microsoft sql", "db2 sql error",
    "jdbc", "invalid query", "unexpected token",
]

TIME_THRESHOLD = 4.5   # seconds — flag if response takes longer than this


def _build_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, new_query, parsed.fragment))


def detect_sql_injection(url: str) -> List[Finding]:
    findings: List[Finding] = []

    print(f"\n{Colors.BLUE}[+] Testing for SQL Injection...{Colors.RESET}")

    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query) or {"id": ["1"]}

        # Baseline
        baseline_resp = requests.get(url, headers=_HEADERS, timeout=15, verify=False)
        baseline_len = len(baseline_resp.text)
        baseline_time = None

    except requests.exceptions.RequestException as exc:
        logger.warning("SQLi baseline failed for %s: %s", url, exc)
        return findings

    for param in params:
        print(f"  {Colors.CYAN}[PARAM]{Colors.RESET} {param}")
        param_found = False

        # ── 1. Error-based ────────────────────────────────────────────────
        for payload in ERROR_PAYLOADS:
            test_url = _build_url(url, param, payload)
            print(f"  {Colors.YELLOW}[TESTING]{Colors.RESET} {test_url[:100]}")

            try:
                resp = requests.get(test_url, headers=_HEADERS, timeout=15, verify=False)
            except requests.exceptions.RequestException:
                continue

            content = resp.text.lower()

            # Error-based
            for error in SQL_ERRORS:
                if error in content:
                    print(f"{Colors.RED}[HIGH]{Colors.RESET} SQL Injection (Error-Based) — param '{param}'")
                    findings.append(Finding(
                        severity="HIGH",
                        category="SQL Injection",
                        title="Error-Based SQL Injection",
                        description=(
                            f"Database error message exposed via parameter '{param}'. "
                            "The application is likely vulnerable to SQL injection."
                        ),
                        url=test_url,
                        evidence=f"Payload: {payload} | Trigger: {error}",
                        parameter=param,
                        recommendation=(
                            "Use parameterised queries / prepared statements. "
                            "Never concatenate user input into SQL strings. "
                            "Suppress database error messages in production."
                        ),
                    ))
                    param_found = True
                    break

            if param_found:
                break

            # Boolean-based (significant content change)
            delta = abs(len(resp.text) - baseline_len)
            if delta > 200:
                print(f"{Colors.YELLOW}[MEDIUM]{Colors.RESET} Possible SQLi (Content Change) — param '{param}' (delta {delta}B)")
                findings.append(Finding(
                    severity="MEDIUM",
                    category="SQL Injection",
                    title="Possible Boolean-Based SQL Injection",
                    description=(
                        f"Response length changed significantly (+{delta} bytes) "
                        f"for parameter '{param}', suggesting conditional SQL logic."
                    ),
                    url=test_url,
                    evidence=f"Payload: {payload} | Length delta: {delta} bytes",
                    parameter=param,
                    recommendation="Use parameterised queries and validate all numeric inputs.",
                ))
                param_found = True
                break

        if param_found:
            continue

        # ── 2. Time-based blind ───────────────────────────────────────────
        print(f"  {Colors.CYAN}[INFO]{Colors.RESET} Trying time-based blind payloads for '{param}'...")
        for payload in TIME_PAYLOADS:
            test_url = _build_url(url, param, payload)
            try:
                t0 = time.monotonic()
                requests.get(test_url, headers=_HEADERS, timeout=20, verify=False)
                elapsed = time.monotonic() - t0
            except requests.exceptions.RequestException:
                continue

            if elapsed >= TIME_THRESHOLD:
                print(f"{Colors.RED}[HIGH]{Colors.RESET} Time-Based Blind SQLi — param '{param}' ({elapsed:.1f}s delay)")
                findings.append(Finding(
                    severity="HIGH",
                    category="SQL Injection",
                    title="Time-Based Blind SQL Injection",
                    description=(
                        f"Parameter '{param}' caused a {elapsed:.1f}s server-side delay, "
                        "consistent with a successful sleep-based SQL injection."
                    ),
                    url=test_url,
                    evidence=f"Payload: {payload} | Delay: {elapsed:.2f}s",
                    parameter=param,
                    recommendation=(
                        "Use parameterised queries. Audit all database calls. "
                        "Apply least-privilege DB accounts."
                    ),
                ))
                break

    if not findings:
        print(f"{Colors.GREEN}[INFO]{Colors.RESET} No SQL Injection indicators found")

    return findings
