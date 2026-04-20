"""
bruteforce_detector.py — Credential brute-force module.

Improvements vs original:
  - Returns List[Finding] instead of printing only.
  - Configurable delay between attempts (rate limiting / stealth).
  - Detects account lockout responses to avoid pointless hammering.
  - Supports custom field names (not hardcoded to 'username'/'password').
  - Detects CSRF tokens and includes them in POST data automatically.
  - Success detection is multi-signal: status code, redirect, and content keywords.
"""

import logging
import time
import requests
import urllib3
from bs4 import BeautifulSoup
from typing import List, Optional

from modules.colors import Colors
from modules.finding import Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebVulnScanner/2.0)"}

SUCCESS_KEYWORDS   = ["logout", "dashboard", "welcome", "my account", "profile", "sign out"]
FAILURE_KEYWORDS   = ["invalid", "incorrect", "wrong", "failed", "error", "try again"]
LOCKOUT_KEYWORDS   = ["locked", "too many", "temporarily", "blocked", "captcha", "banned"]


def _get_csrf_token(session: requests.Session, url: str) -> Optional[tuple]:
    """
    Fetch the login page and look for a CSRF token field.
    Returns (field_name, field_value) or None.
    """
    try:
        resp = session.get(url, headers=_HEADERS, timeout=8, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        for field in soup.find_all("input", {"type": "hidden"}):
            name = field.get("name", "").lower()
            if any(t in name for t in ("csrf", "token", "_token", "nonce")):
                return field.get("name"), field.get("value", "")
    except Exception:
        pass
    return None


def brute_force_login(
    url: str,
    usernames: List[str],
    passwords: List[str],
    username_field: str = "username",
    password_field: str = "password",
    delay: float = 0.5,
) -> List[Finding]:
    """
    Attempt credential combinations against a login form.

    Args:
        url:            Login endpoint URL.
        usernames:      List of usernames to try.
        passwords:      List of passwords to try.
        username_field: HTML form field name for username.
        password_field: HTML form field name for password.
        delay:          Seconds to wait between attempts (avoid lockout).

    Returns:
        List of Finding objects.
    """
    findings: List[Finding] = []
    print(f"\n{Colors.BLUE}[+] Starting credential brute-force ({len(usernames) * len(passwords)} combinations)...{Colors.RESET}")

    with requests.Session() as session:
        session.headers.update(_HEADERS)

        csrf = _get_csrf_token(session, url)
        if csrf:
            print(f"  {Colors.CYAN}[INFO]{Colors.RESET} CSRF token detected: {csrf[0]}")

        for username in usernames:
            for password in passwords:
                data = {
                    username_field: username,
                    password_field: password,
                }
                if csrf:
                    data[csrf[0]] = csrf[1]

                print(f"  {Colors.YELLOW}[TESTING]{Colors.RESET} {username}:{password}")

                try:
                    resp = session.post(
                        url, data=data,
                        allow_redirects=False,
                        timeout=10, verify=False,
                    )
                except requests.exceptions.RequestException as exc:
                    logger.warning("Brute-force request failed: %s", exc)
                    continue

                content = resp.text.lower()
                code = resp.status_code

                # ── Lockout detection ─────────────────────────────────────
                if any(kw in content for kw in LOCKOUT_KEYWORDS):
                    print(f"\n{Colors.YELLOW}[WARN]{Colors.RESET} Account lockout / CAPTCHA detected — stopping")
                    findings.append(Finding(
                        severity="INFO",
                        category="Brute-Force",
                        title="Account lockout or CAPTCHA triggered",
                        description="The target appears to have rate limiting or lockout protection.",
                        url=url,
                        evidence=f"Triggered on {username}:{password}",
                        recommendation="Ensure lockout thresholds are set appropriately.",
                    ))
                    return findings

                # ── Success detection ─────────────────────────────────────
                success = (
                    code == 302
                    or any(kw in content for kw in SUCCESS_KEYWORDS)
                    and not any(kw in content for kw in FAILURE_KEYWORDS)
                )

                if success:
                    print(f"\n{Colors.RED}[HIGH]{Colors.RESET} Valid credentials: {username}:{password}")
                    findings.append(Finding(
                        severity="HIGH",
                        category="Brute-Force / Weak Credentials",
                        title="Valid credentials discovered",
                        description=f"Login succeeded with username='{username}' and password='{password}'.",
                        url=url,
                        evidence=f"HTTP {code} | Credentials: {username}:{password}",
                        recommendation=(
                            "Enforce strong password policies. "
                            "Implement multi-factor authentication. "
                            "Apply account lockout after N failed attempts."
                        ),
                    ))
                    return findings

                time.sleep(delay)

    print(f"\n{Colors.CYAN}[-]{Colors.RESET} No valid credentials found")
    return findings
