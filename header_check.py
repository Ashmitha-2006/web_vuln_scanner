"""
header_check.py — Analyse HTTP response headers for security misconfigurations.

Improvements vs original:
  - Returns List[Finding] instead of writing to a file object.
  - Checks 8 security headers (up from 5), including Referrer-Policy and
    Permissions-Policy.
  - Analyses Set-Cookie flags (HttpOnly, Secure, SameSite).
  - Reports server / technology fingerprinting as INFO findings.
  - Validates header *values*, not just presence.
"""

import logging
import requests
import urllib3
from typing import List

from modules.colors import Colors
from modules.finding import Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebVulnScanner/2.0)"}

# header → (risk description, recommended value / action)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Prevents XSS and data-injection attacks",
        "Define a strict allowlist policy (default-src 'self')",
    ),
    "X-Frame-Options": (
        "Prevents clickjacking",
        "Set to DENY or SAMEORIGIN",
    ),
    "Strict-Transport-Security": (
        "Forces HTTPS connections (prevents SSL stripping)",
        "max-age=31536000; includeSubDomains; preload",
    ),
    "X-Content-Type-Options": (
        "Prevents MIME-type sniffing",
        "nosniff",
    ),
    "X-XSS-Protection": (
        "Activates browser built-in XSS filter (legacy)",
        "1; mode=block",
    ),
    "Referrer-Policy": (
        "Controls how much referrer information is sent",
        "strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        "Restricts browser feature access (camera, mic, geolocation…)",
        "geolocation=(), microphone=(), camera=()",
    ),
    "Cross-Origin-Opener-Policy": (
        "Mitigates cross-origin information leakage (Spectre etc.)",
        "same-origin",
    ),
}


def _check_cookie_flags(cookie_header: str, url: str) -> List[Finding]:
    findings: List[Finding] = []
    for cookie in cookie_header.split(","):
        cookie_lower = cookie.lower()
        name = cookie.split("=")[0].strip()

        if "httponly" not in cookie_lower:
            findings.append(Finding(
                severity="MEDIUM",
                category="Cookie Security",
                title=f"Cookie missing HttpOnly flag: {name}",
                description="Without HttpOnly, JavaScript can read the cookie, enabling session theft via XSS.",
                url=url,
                recommendation="Set the HttpOnly attribute on all session cookies.",
            ))

        if "secure" not in cookie_lower:
            findings.append(Finding(
                severity="MEDIUM",
                category="Cookie Security",
                title=f"Cookie missing Secure flag: {name}",
                description="The cookie may be transmitted over plain HTTP.",
                url=url,
                recommendation="Set the Secure attribute so the cookie is only sent over HTTPS.",
            ))

        if "samesite" not in cookie_lower:
            findings.append(Finding(
                severity="LOW",
                category="Cookie Security",
                title=f"Cookie missing SameSite attribute: {name}",
                description="Without SameSite, the cookie is sent on cross-site requests (CSRF risk).",
                url=url,
                recommendation="Set SameSite=Strict or SameSite=Lax.",
            ))
    return findings


def check_headers(url: str) -> List[Finding]:
    findings: List[Finding] = []

    print(f"\n{Colors.BLUE}[+] Checking Security Headers...{Colors.RESET}")

    try:
        resp = requests.get(url, headers=_HEADERS, timeout=8, verify=False)
        rh = resp.headers

        # ── Fingerprinting ──────────────────────────────────────────────
        for fh in ("Server", "X-Powered-By", "X-AspNet-Version"):
            val = rh.get(fh)
            if val:
                print(f"{Colors.CYAN}[INFO]{Colors.RESET} {fh}: {val}")
                findings.append(Finding(
                    severity="INFO",
                    category="Information Disclosure",
                    title=f"Server header reveals technology: {fh}",
                    description=f"The server discloses its software stack via the {fh} header: {val}",
                    url=url,
                    evidence=val,
                    recommendation=f"Remove or sanitise the {fh} response header.",
                ))

        # ── Security headers ─────────────────────────────────────────────
        for header, (risk, recommendation) in SECURITY_HEADERS.items():
            value = rh.get(header)

            if value:
                print(f"{Colors.GREEN}[INFO]{Colors.RESET} {header}: present")
                findings.append(Finding(
                    severity="INFO",
                    category="Security Header",
                    title=f"{header} is present",
                    description=f"Header value: {value}",
                    url=url,
                    evidence=value,
                ))

                # Value-level misconfiguration checks
                if header == "X-Frame-Options" and value.upper() not in ("DENY", "SAMEORIGIN"):
                    print(f"{Colors.YELLOW}[LOW]{Colors.RESET} Weak X-Frame-Options: {value}")
                    findings.append(Finding(
                        severity="LOW",
                        category="Security Header Misconfiguration",
                        title="Weak X-Frame-Options value",
                        description=f"Value '{value}' does not prevent framing.",
                        url=url, evidence=value, recommendation=recommendation,
                    ))

                elif header == "X-Content-Type-Options" and value.lower() != "nosniff":
                    findings.append(Finding(
                        severity="LOW",
                        category="Security Header Misconfiguration",
                        title="Incorrect X-Content-Type-Options value",
                        description=f"Expected 'nosniff', got '{value}'.",
                        url=url, evidence=value, recommendation=recommendation,
                    ))

                elif header == "Strict-Transport-Security" and "max-age" not in value.lower():
                    findings.append(Finding(
                        severity="LOW",
                        category="Security Header Misconfiguration",
                        title="HSTS header missing max-age",
                        description="A Strict-Transport-Security header without max-age is ineffective.",
                        url=url, evidence=value, recommendation=recommendation,
                    ))

            else:
                print(f"{Colors.YELLOW}[MEDIUM]{Colors.RESET} Missing: {header}")
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Missing Security Header",
                    title=f"Missing header: {header}",
                    description=f"Risk: {risk}",
                    url=url,
                    recommendation=recommendation,
                ))

        # ── Cookie analysis ──────────────────────────────────────────────
        set_cookie = rh.get("Set-Cookie")
        if set_cookie:
            findings.extend(_check_cookie_flags(set_cookie, url))

    except requests.exceptions.RequestException as exc:
        logger.warning("Header check failed for %s: %s", url, exc)

    return findings
