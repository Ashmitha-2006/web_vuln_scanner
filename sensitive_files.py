"""
sensitive_files.py — Check for publicly accessible sensitive files.

Improvements vs original:
  - Returns List[Finding].
  - 18 file paths (up from 9).
  - Severity is pre-classified per file type (no guessing from keywords alone).
  - Content-keyword sniffing kept as a secondary signal.
  - Baseline filtering retained to avoid false positives.
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

# file path → (severity, description, recommendation)
SENSITIVE_FILES = {
    ".env":                ("HIGH",   "Environment variables (API keys, DB creds)",        "Remove from web root; use server-side env injection"),
    ".env.local":          ("HIGH",   "Local environment overrides",                        "Remove from web root"),
    ".env.production":     ("HIGH",   "Production environment file",                        "Remove from web root"),
    "database.sql":        ("HIGH",   "Database dump — full data exposure",                 "Never store DB dumps in a web-accessible location"),
    "db.sql":              ("HIGH",   "Database dump",                                      "Store outside the web root"),
    "id_rsa":              ("HIGH",   "Private SSH key",                                    "Revoke immediately; remove from server"),
    "id_rsa.pub":          ("MEDIUM", "Public SSH key (reveals server identity)",           "Remove from web root"),
    ".git/config":         ("HIGH",   "Git config — may expose remote URLs / tokens",       "Block .git/ access in server config"),
    ".git/HEAD":           ("HIGH",   "Git repository exposed — source code retrievable",   "Block .git/ access; add to .gitignore"),
    ".htpasswd":           ("HIGH",   "Hashed credentials",                                 "Move outside web root; restrict access"),
    "config.php":          ("HIGH",   "PHP configuration (DB credentials likely)",          "Move outside web root"),
    "wp-config.php":       ("HIGH",   "WordPress config (DB creds, secret keys)",           "Move outside web root; restrict permissions"),
    "web.config":          ("MEDIUM", "IIS/ASP.NET configuration",                          "Restrict access via server rules"),
    "docker-compose.yml":  ("MEDIUM", "Docker service config (may contain secrets)",        "Remove from web root"),
    "Dockerfile":          ("LOW",    "Docker build instructions (reveals stack)",           "Remove from web root"),
    "backup.zip":          ("HIGH",   "Backup archive — source code / data exposure",       "Remove from web root; never store backups here"),
    "backup.tar.gz":       ("HIGH",   "Backup archive",                                     "Remove from web root"),
    "phpinfo.php":         ("MEDIUM", "PHP info page — exposes server configuration",       "Delete phpinfo.php from production servers"),
    "info.php":            ("MEDIUM", "PHP info page",                                      "Delete from production"),
    "server-status":       ("LOW",    "Apache server-status page",                          "Restrict to localhost only"),
    "crossdomain.xml":     ("LOW",    "Flash cross-domain policy (may allow broad access)", "Restrict origin allowlist"),
    "robots.txt":          ("INFO",   "Robots exclusion file (reveals hidden paths)",        "Review disallowed paths for sensitive information"),
}

_SENSITIVE_KEYWORDS = {
    "password", "passwd", "pwd", "secret", "token", "api_key",
    "apikey", "username", "root", "admin", "db_", "database",
    "private_key", "auth", "credentials",
}


def check_sensitive_files(url: str) -> List[Finding]:
    url = url.rstrip("/")
    findings: List[Finding] = []

    print(f"\n{Colors.BLUE}[+] Checking for exposed sensitive files ({len(SENSITIVE_FILES)} targets)...{Colors.RESET}")

    # Baseline to filter catch-all responses
    try:
        baseline = requests.get(
            f"{url}/definitely-not-a-real-file-xyzabc123.txt",
            headers=_HEADERS, timeout=8, verify=False,
        )
        baseline_len = len(baseline.text)
    except Exception:
        baseline_len = 0

    for file_path, (default_severity, description, recommendation) in SENSITIVE_FILES.items():
        target = f"{url}/{file_path}"
        try:
            resp = requests.get(target, headers=_HEADERS, timeout=8, verify=False)

            if resp.status_code != 200:
                continue

            content_len = len(resp.text)
            # Skip soft-404 / catch-all pages
            if abs(content_len - baseline_len) < 50:
                continue

            content_lower = resp.text.lower()
            has_sensitive_keywords = any(kw in content_lower for kw in _SENSITIVE_KEYWORDS)

            # Upgrade severity if sensitive content is confirmed
            severity = default_severity
            if has_sensitive_keywords and severity in ("MEDIUM", "LOW"):
                severity = "HIGH"

            color = Colors.severity(severity)
            print(f"{color}[{severity}]{Colors.RESET} Exposed file: {target}")

            evidence = f"HTTP 200, {content_len} bytes"
            if has_sensitive_keywords:
                evidence += " — sensitive keywords detected in content"

            findings.append(Finding(
                severity=severity,
                category="Sensitive File Exposure",
                title=f"Exposed file: {file_path}",
                description=description,
                url=target,
                evidence=evidence,
                recommendation=recommendation,
            ))

        except requests.exceptions.RequestException:
            continue

    return findings
