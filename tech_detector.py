"""
tech_detector.py — Detect technologies and software versions.

This is a NEW module not present in the original scanner.

Detects:
  - CMS (WordPress, Joomla, Drupal, etc.)
  - Web frameworks (Django, Laravel, Rails, Express, etc.)
  - Web servers (Apache, Nginx, IIS) and versions
  - JavaScript libraries from script tags
  - CDN / WAF indicators

All detections are reported as INFO findings (fingerprinting),
with MEDIUM severity for any version disclosure.
"""

import logging
import re
import requests
import urllib3
from bs4 import BeautifulSoup
from typing import List

from modules.colors import Colors
from modules.finding import Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebVulnScanner/2.0)"}

# (regex pattern, tech name, severity)
HEADER_SIGNATURES = [
    (r"Apache(?:/(\S+))?", "Apache", "Server"),
    (r"nginx(?:/(\S+))?", "Nginx", "Server"),
    (r"Microsoft-IIS(?:/(\S+))?", "Microsoft IIS", "Server"),
    (r"PHP(?:/(\S+))?", "PHP", "X-Powered-By"),
    (r"ASP\.NET", "ASP.NET", "X-Powered-By"),
    (r"Express", "Express.js", "X-Powered-By"),
]

# HTML-based fingerprints: (pattern, name)
HTML_SIGNATURES = [
    (r"/wp-content/", "WordPress"),
    (r"/wp-includes/", "WordPress"),
    (r"wp-json", "WordPress REST API"),
    (r'content="Joomla', "Joomla"),
    (r"/sites/default/files/", "Drupal"),
    (r'<meta name="generator" content="Drupal', "Drupal"),
    (r"Magento", "Magento"),
    (r"PrestaShop", "PrestaShop"),
    (r"__VIEWSTATE", "ASP.NET WebForms"),
    (r"Laravel", "Laravel"),
    (r"csrf-token", "CSRF Token (generic)"),
    (r"react(?:\.min)?\.js", "React"),
    (r"vue(?:\.min)?\.js", "Vue.js"),
    (r"angular(?:\.min)?\.js", "Angular"),
    (r"jquery(?:\.min)?\.js", "jQuery"),
    (r"bootstrap(?:\.min)?\.js", "Bootstrap"),
    (r"cloudflare", "Cloudflare CDN/WAF"),
    (r"__cf_bm", "Cloudflare Bot Management"),
    (r"akamai", "Akamai CDN"),
]

# Version-disclosure regex for server headers
VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def detect_technologies(url: str) -> List[Finding]:
    findings: List[Finding] = []
    detected = set()   # Avoid duplicate findings for same tech

    print(f"\n{Colors.BLUE}[+] Detecting technologies...{Colors.RESET}")

    try:
        resp = requests.get(url, headers=_HEADERS, timeout=10, verify=False)
        rh = resp.headers
        html = resp.text

    except requests.exceptions.RequestException as exc:
        logger.warning("Tech detection failed for %s: %s", url, exc)
        return findings

    # ── Header-based detection ────────────────────────────────────────────
    for pattern, tech, header_name in HEADER_SIGNATURES:
        for hname in ("Server", "X-Powered-By", "Via"):
            value = rh.get(hname, "")
            match = re.search(pattern, value, re.IGNORECASE)
            if match and tech not in detected:
                detected.add(tech)
                version = match.group(1) if match.lastindex else None

                if version:
                    severity = "MEDIUM"
                    title = f"Version disclosure: {tech} {version}"
                    desc = (
                        f"The server reveals {tech} version {version} in the "
                        f"'{hname}' header. Attackers can use this to find "
                        "known CVEs for that exact version."
                    )
                    rec = f"Remove or sanitise the {hname} header to suppress version info."
                else:
                    severity = "INFO"
                    title = f"Technology detected: {tech}"
                    desc = f"{tech} identified via the '{hname}' response header."
                    rec = f"Consider removing the {hname} header to reduce fingerprinting surface."

                color = Colors.severity(severity)
                print(f"  {color}[{severity}]{Colors.RESET} {title}")

                findings.append(Finding(
                    severity=severity,
                    category="Technology Fingerprinting",
                    title=title,
                    description=desc,
                    url=url,
                    evidence=f"{hname}: {value}",
                    recommendation=rec,
                ))

    # ── HTML / script-based detection ────────────────────────────────────
    for pattern, tech in HTML_SIGNATURES:
        if tech in detected:
            continue
        if re.search(pattern, html, re.IGNORECASE):
            detected.add(tech)
            color = Colors.CYAN
            print(f"  {color}[INFO]{Colors.RESET} Technology detected: {tech}")
            findings.append(Finding(
                severity="INFO",
                category="Technology Fingerprinting",
                title=f"Technology detected: {tech}",
                description=f"{tech} identified from page source / scripts.",
                url=url,
                evidence=f"Pattern: {pattern}",
                recommendation="Keep all libraries and CMS versions up to date.",
            ))

    # ── Cookie-based detection ────────────────────────────────────────────
    cookie_header = rh.get("Set-Cookie", "")
    if "PHPSESSID" in cookie_header and "PHP" not in detected:
        detected.add("PHP")
        findings.append(Finding(
            severity="INFO",
            category="Technology Fingerprinting",
            title="PHP session cookie detected",
            description="PHPSESSID cookie indicates a PHP backend.",
            url=url,
            evidence="Set-Cookie: PHPSESSID",
        ))
    if "JSESSIONID" in cookie_header:
        findings.append(Finding(
            severity="INFO",
            category="Technology Fingerprinting",
            title="Java/JVM session cookie detected",
            description="JSESSIONID indicates a Java EE or Spring backend.",
            url=url,
            evidence="Set-Cookie: JSESSIONID",
        ))

    if not detected:
        print(f"  {Colors.CYAN}[INFO]{Colors.RESET} No specific technologies identified")

    return findings
