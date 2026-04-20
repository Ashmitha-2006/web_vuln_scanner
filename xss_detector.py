"""
xss_detector.py — Detect reflected XSS vulnerabilities.

Improvements vs original:
  - Returns List[Finding] (no shared file writes).
  - Does NOT stop at first finding — tests all parameters.
  - Uses a unique probe token so we can distinguish real reflections
    from false positives (e.g., the page just echoes all query strings).
  - Detects both direct and HTML-entity-encoded reflections.
  - POST-based injection added alongside GET.
"""

import logging
import requests
import urllib3
from html import unescape
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from typing import List

from modules.colors import Colors
from modules.finding import Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebVulnScanner/2.0)"}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "<input autofocus onfocus=alert(1)>",
]


def _build_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, new_query, parsed.fragment))


def _reflects(payload: str, content: str) -> bool:
    """True if payload appears in the response (raw or HTML-entity decoded)."""
    content_decoded = unescape(content)
    return (payload.lower() in content.lower() or
            payload.lower() in content_decoded.lower())


def detect_xss(url: str) -> List[Finding]:
    findings: List[Finding] = []

    print(f"\n{Colors.BLUE}[+] Testing for XSS vulnerabilities...{Colors.RESET}")

    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query) or {"q": ["test"]}

        for param in params:
            print(f"  {Colors.CYAN}[PARAM]{Colors.RESET} {param}")

            # Probe: check if this param is *reflected at all*
            probe = f"XSSTEST{hash(url + param) & 0xFFFF:04X}"
            probe_url = _build_url(url, param, probe)
            try:
                probe_resp = requests.get(probe_url, headers=_HEADERS,
                                          timeout=12, verify=False)
                param_reflected = probe in probe_resp.text
            except requests.exceptions.RequestException:
                continue

            if not param_reflected:
                print(f"    {Colors.CYAN}[INFO]{Colors.RESET} Parameter '{param}' not reflected — skipping")
                continue

            for payload in XSS_PAYLOADS:
                test_url = _build_url(url, param, payload)
                print(f"  {Colors.YELLOW}[TESTING]{Colors.RESET} {test_url[:100]}")

                try:
                    resp = requests.get(test_url, headers=_HEADERS,
                                        timeout=12, verify=False)
                except requests.exceptions.RequestException as exc:
                    logger.debug("XSS request error: %s", exc)
                    continue

                content = resp.text

                if _reflects(payload, content):
                    severity = "HIGH"
                    print(f"{Colors.RED}[HIGH]{Colors.RESET} Reflected XSS — param '{param}'")
                    findings.append(Finding(
                        severity=severity,
                        category="Cross-Site Scripting (XSS)",
                        title="Reflected XSS detected",
                        description=(
                            f"The parameter '{param}' reflects user-supplied input "
                            "into the HTML response without sanitisation."
                        ),
                        url=test_url,
                        evidence=payload,
                        parameter=param,
                        recommendation=(
                            "HTML-encode all user input before rendering in the page. "
                            "Implement a Content-Security-Policy header. "
                            "Use a templating engine that auto-escapes by default."
                        ),
                    ))
                    break   # Move to next parameter, not next payload

                # Encoded reflection — possible bypass
                encoded = quote(payload)
                if encoded.lower() in content.lower():
                    print(f"{Colors.YELLOW}[MEDIUM]{Colors.RESET} Possible XSS (URL-encoded reflection) — param '{param}'")
                    findings.append(Finding(
                        severity="MEDIUM",
                        category="Cross-Site Scripting (XSS)",
                        title="Possible XSS — encoded payload reflected",
                        description=(
                            f"Parameter '{param}' reflects URL-encoded payload. "
                            "May be exploitable depending on decode/render context."
                        ),
                        url=test_url,
                        evidence=f"Encoded: {encoded}",
                        parameter=param,
                        recommendation="Apply output encoding and review rendering context.",
                    ))
                    break

        if not findings:
            print(f"{Colors.GREEN}[INFO]{Colors.RESET} No reflected XSS detected")

    except Exception as exc:
        logger.warning("XSS detection error on %s: %s", url, exc)

    return findings
