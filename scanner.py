"""
scanner.py — Web Vulnerability Scanner v2.0

Usage examples:
  python scanner.py --url https://example.com
  python scanner.py --url https://example.com --threads 20 --no-crawl
  python scanner.py --url https://example.com --brute --login-url https://example.com/login
  python scanner.py --url https://example.com --skip xss,sqli
  python scanner.py --url https://example.com --output-dir /tmp/reports
"""

import argparse
import datetime
import logging
import os
import sys
import time
from typing import List

from modules.colors import Colors
from modules.finding import Finding
from modules.crawler import crawl
from modules.header_check import check_headers
from modules.directory_scan import scan_directories
from modules.sensitive_files import check_sensitive_files
from modules.xss_detector import detect_xss
from modules.sql_injection_detector import detect_sql_injection
from modules.bruteforce_detector import brute_force_login
from modules.tech_detector import detect_technologies
from reports.report_generator import generate_html_report, generate_json_report


# ── Logging setup ──────────────────────────────────────────────────────────────

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="%(levelname)s [%(name)s] %(message)s",
        level=level,
    )


# ── Banner ─────────────────────────────────────────────────────────────────────

BANNER = f"""
{Colors.BOLD}{Colors.BLUE}
  ██╗    ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║    ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║ █╗ ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
  ██║███╗██║██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚███╔███╔╝╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
   ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Colors.RESET}
  {Colors.CYAN}Web Vulnerability Scanner v2.0{Colors.RESET}  |  {Colors.YELLOW}For authorised testing only{Colors.RESET}
"""


# ── CLI argument parser ────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner",
        description="Web Vulnerability Scanner — discovers common web security issues.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    p.add_argument("--url", "-u", required=True,
                   help="Target URL (e.g. https://example.com)")

    p.add_argument("--threads", "-t", type=int, default=15, metavar="N",
                   help="Thread count for directory scan (default: 15)")

    p.add_argument("--max-urls", type=int, default=20, metavar="N",
                   help="Max URLs to crawl (default: 20)")

    p.add_argument("--no-crawl", action="store_true",
                   help="Disable crawler — scan root URL only")

    p.add_argument("--skip", metavar="MODULES",
                   help="Comma-separated modules to skip: headers,dirs,files,xss,sqli,tech")

    p.add_argument("--brute", action="store_true",
                   help="Enable brute-force login module")

    p.add_argument("--login-url", metavar="URL",
                   help="Login endpoint for brute-force (requires --brute)")

    p.add_argument("--usernames", metavar="LIST",
                   help="Comma-separated usernames (requires --brute)")

    p.add_argument("--passwords", metavar="LIST",
                   help="Comma-separated passwords (requires --brute)")

    p.add_argument("--wordlist-users", metavar="FILE",
                   help="File with one username per line (requires --brute)")

    p.add_argument("--wordlist-pass", metavar="FILE",
                   help="File with one password per line (requires --brute)")

    p.add_argument("--output-dir", default="reports", metavar="DIR",
                   help="Directory for report output (default: reports/)")

    p.add_argument("--verbose", "-v", action="store_true",
                   help="Enable debug logging")

    return p


# ── Scan orchestration ─────────────────────────────────────────────────────────

def scan_url(url: str, skip: set, threads: int) -> List[Finding]:
    """Run all enabled scan modules against a single URL."""
    findings: List[Finding] = []

    if "tech" not in skip:
        findings.extend(detect_technologies(url))

    if "headers" not in skip:
        findings.extend(check_headers(url))

    if "files" not in skip:
        findings.extend(check_sensitive_files(url))

    if "xss" not in skip:
        findings.extend(detect_xss(url))

    if "sqli" not in skip:
        findings.extend(detect_sql_injection(url))

    return findings


def print_summary(findings: List[Finding], duration: float) -> None:
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in ("HIGH", "MEDIUM", "LOW", "INFO")}
    print(f"\n{Colors.BOLD}{'═' * 50}")
    print("             SCAN SUMMARY")
    print(f"{'═' * 50}{Colors.RESET}")
    print(f"  {Colors.RED}HIGH    : {counts['HIGH']}{Colors.RESET}")
    print(f"  {Colors.YELLOW}MEDIUM  : {counts['MEDIUM']}{Colors.RESET}")
    print(f"  {Colors.GREEN}LOW     : {counts['LOW']}{Colors.RESET}")
    print(f"  {Colors.CYAN}INFO    : {counts['INFO']}{Colors.RESET}")
    print(f"\n  Duration : {duration:.2f}s")
    print(f"  Total    : {len(findings)} findings")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)
    print(BANNER)

    # Normalise URL
    target = args.url.strip()
    if not target.startswith("http"):
        target = "http://" + target

    skip = set(s.strip().lower() for s in (args.skip or "").split(",") if s.strip())

    print(f"  {Colors.BOLD}Target  :{Colors.RESET} {target}")
    print(f"  {Colors.BOLD}Threads :{Colors.RESET} {args.threads}")
    print(f"  {Colors.BOLD}Crawl   :{Colors.RESET} {'No' if args.no_crawl else f'Yes (max {args.max_urls} URLs)'}")
    print(f"  {Colors.BOLD}Skip    :{Colors.RESET} {skip or 'none'}")
    print()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start_time = time.monotonic()
    all_findings: List[Finding] = []

    # Discover URLs
    if args.no_crawl:
        urls_to_scan = [target]
    else:
        print(f"{Colors.BLUE}[+] Crawling...{Colors.RESET}")
        discovered = crawl(target, max_urls=args.max_urls)
        urls_to_scan = [target] + discovered
        print(f"    Found {len(discovered)} additional URL(s)\n")

    # Directory scan is done once against the root
    if "dirs" not in skip:
        print(f"{Colors.BLUE}[+] Running directory scan on root...{Colors.RESET}")
        all_findings.extend(scan_directories(target, threads=args.threads))

    # Per-URL scans
    for url in urls_to_scan:
        sep = "─" * 60
        print(f"\n{Colors.BOLD}{sep}")
        print(f"  Scanning: {url}")
        print(f"{sep}{Colors.RESET}")
        all_findings.extend(scan_url(url, skip, args.threads))

    # Optional brute force
    if args.brute:
        login_url = args.login_url or input("\nLogin URL: ").strip()

        usernames: List[str] = []
        passwords: List[str] = []

        if args.wordlist_users:
            with open(args.wordlist_users) as fh:
                usernames = [l.strip() for l in fh if l.strip()]
        elif args.usernames:
            usernames = [u.strip() for u in args.usernames.split(",")]
        else:
            usernames = [u.strip() for u in input("Usernames (comma-separated): ").split(",")]

        if args.wordlist_pass:
            with open(args.wordlist_pass) as fh:
                passwords = [l.strip() for l in fh if l.strip()]
        elif args.passwords:
            passwords = [p.strip() for p in args.passwords.split(",")]
        else:
            passwords = [p.strip() for p in input("Passwords (comma-separated): ").split(",")]

        all_findings.extend(brute_force_login(login_url, usernames, passwords))

    # Reports
    duration = time.monotonic() - start_time
    os.makedirs(args.output_dir, exist_ok=True)

    html_path = os.path.join(args.output_dir, "report.html")
    json_path = os.path.join(args.output_dir, "report.json")
    txt_path  = os.path.join(args.output_dir, "report.txt")

    generate_html_report(html_path, target, timestamp, duration, all_findings)
    generate_json_report(json_path, target, timestamp, duration, all_findings)

    # Plain-text report
    with open(txt_path, "w") as fh:
        fh.write(f"Web Vulnerability Report\n{'='*40}\n")
        fh.write(f"Target  : {target}\n")
        fh.write(f"Time    : {timestamp}\n")
        fh.write(f"Duration: {duration:.2f}s\n\n")
        for f in sorted(all_findings):
            fh.write(f"[{f.severity}] {f.title}\n")
            fh.write(f"  URL  : {f.url}\n")
            fh.write(f"  Desc : {f.description}\n")
            if f.evidence:
                fh.write(f"  Evid : {f.evidence}\n")
            if f.recommendation:
                fh.write(f"  Fix  : {f.recommendation}\n")
            fh.write("\n")

    print_summary(all_findings, duration)
    print(f"\n  {Colors.GREEN}[✓]{Colors.RESET} HTML report : {html_path}")
    print(f"  {Colors.GREEN}[✓]{Colors.RESET} JSON report : {json_path}")
    print(f"  {Colors.GREEN}[✓]{Colors.RESET} Text report : {txt_path}\n")

    return 0 if not any(f.severity == "HIGH" for f in all_findings) else 1


if __name__ == "__main__":
    sys.exit(main())
