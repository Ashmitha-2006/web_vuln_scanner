"""
crawler.py — Crawl a target and return all in-scope URLs.

Fixes vs original:
  - Removed the module-level `visited` global (caused state leak between scans).
  - Added recursive depth control so we don't crawl forever.
  - Collects <form action> URLs in addition to <a href> links.
  - Skips mailto:, tel:, javascript: and other non-HTTP schemes.
  - Suppresses SSL warnings cleanly.
"""

import logging
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import List, Set

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebVulnScanner/2.0)"}
_SKIP_SCHEMES = {"mailto", "tel", "javascript", "data", "ftp"}


def _is_in_scope(url: str, domain: str) -> bool:
    parsed = urlparse(url)
    return parsed.netloc == domain and parsed.scheme in ("http", "https")


def _extract_urls(base_url: str, html: str, domain: str) -> Set[str]:
    soup = BeautifulSoup(html, "html.parser")
    found: Set[str] = set()

    # <a href>
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if any(href.startswith(s + ":") for s in _SKIP_SCHEMES):
            continue
        full = urljoin(base_url, href)
        # Strip fragments
        full = full.split("#")[0]
        if _is_in_scope(full, domain):
            found.add(full)

    # <form action> — forms are prime injection targets
    for tag in soup.find_all("form", action=True):
        action = tag["action"].strip()
        full = urljoin(base_url, action)
        full = full.split("#")[0]
        if _is_in_scope(full, domain):
            found.add(full)

    return found


def crawl(start_url: str, max_urls: int = 20, max_depth: int = 2) -> List[str]:
    """
    BFS crawl starting from *start_url*.

    Returns a list of discovered in-scope URLs (excluding start_url itself).
    """
    domain = urlparse(start_url).netloc
    visited: Set[str] = {start_url}
    queue: List[tuple] = [(start_url, 0)]   # (url, depth)
    results: List[str] = []

    while queue and len(results) < max_urls:
        url, depth = queue.pop(0)

        if depth > max_depth:
            continue

        try:
            resp = requests.get(url, headers=_HEADERS, timeout=8, verify=False)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            for found in _extract_urls(url, resp.text, domain):
                if found not in visited:
                    visited.add(found)
                    results.append(found)
                    queue.append((found, depth + 1))

                    if len(results) >= max_urls:
                        break

        except requests.exceptions.RequestException as exc:
            logger.debug("Crawl error on %s: %s", url, exc)

    logger.info("Crawled %d URLs from %s", len(results), start_url)
    return results
