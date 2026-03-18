import os
import datetime
import time

from modules.header_check import check_headers
from modules.directory_scan import scan_directories
from modules.sensitive_files import check_sensitive_files
from modules.xss_detector import detect_xss
from modules.sql_injection_detector import detect_sql_injection
from modules.bruteforce_detector import brute_force_login
from modules.crawler import crawl

from reports.report_generator import generate_html_report


def start_scan():

    print("\n=================================")
    print("      Web Vulnerability Scanner")
    print("=================================\n")

    target = input("Enter target URL (example: https://example.com): ").strip()

    use_brute = input("Do you want to run brute-force login attack? (y/n): ").strip().lower()

    # Normalize URL
    if not target.startswith("http"):
        target = "http://" + target

    print("\nStarting scan on:", target)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start_time = time.time()

    os.makedirs("reports", exist_ok=True)

    # 🔥 Results for HTML report
    results = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "details": ""
    }

    # 🔥 CRAWLER ADDED HERE
    print("\n[+] Crawling target...\n")
    urls = crawl(target)
    urls.insert(0, target)

    with open("reports/scan_report.txt", "w") as report:

        report.write("=========================================\n")
        report.write("        WEB VULNERABILITY REPORT\n")
        report.write("=========================================\n\n")

        report.write(f"Target URL : {target}\n")
        report.write(f"Scan Time  : {timestamp}\n\n")

        report.write("=========================================\n")
        report.write("SCAN RESULTS\n")
        report.write("=========================================\n\n")

        # 🔥 LOOP THROUGH ALL URLS
        for url in urls:

            print(f"\n[+] Scanning: {url}\n")

            report.write(f"\n[+] Scanning: {url}\n\n")

            # Run modules
            check_headers(url, report)
            scan_directories(url, report)
            check_sensitive_files(url, report)
            detect_xss(url, report)
            detect_sql_injection(url, report)

    # 🔥 SUMMARY FROM TEXT REPORT
    with open("reports/scan_report.txt", "r") as f:
        data = f.read()

    results["high"] = data.count("HIGH:")
    results["medium"] = data.count("MEDIUM:")
    results["low"] = data.count("LOW:")
    results["info"] = data.count("INFO:")

    # 🔥 Convert findings into HTML cards
    lines = data.split("\n")
    for line in lines:
        if "HIGH:" in line:
            results["details"] += f"<div class='card high'>{line}</div>"
        elif "MEDIUM:" in line:
            results["details"] += f"<div class='card medium'>{line}</div>"
        elif "LOW:" in line:
            results["details"] += f"<div class='card low'>{line}</div>"
        elif "INFO:" in line:
            results["details"] += f"<div class='card info'>{line}</div>"

    # 🔥 GENERATE HTML REPORT
    generate_html_report(
        "reports/report.html",
        target,
        timestamp,
        results
    )

    # 🔥 OPTIONAL BRUTE FORCE (kept same)
    if use_brute == "y":
        print("\n=================================")
        print("     BRUTE FORCE MODULE")
        print("=================================\n")

        login_url = input("Enter login URL (example: https://example.com/login): ").strip()

        usernames = input("Enter usernames (comma-separated): ").split(",")
        passwords = input("Enter passwords (comma-separated): ").split(",")

        usernames = [u.strip() for u in usernames]
        passwords = [p.strip() for p in passwords]

        print("\n[+] Running Brute-Force Module...\n")
        brute_force_login(login_url, usernames, passwords)

        print("\n[✓] Brute-force module completed\n")

    # 🔥 PRINT SUMMARY
    print("\n==========================")
    print("       SCAN SUMMARY")
    print("==========================")
    print(f"HIGH vulnerabilities   : {results['high']}")
    print(f"MEDIUM vulnerabilities : {results['medium']}")
    print(f"LOW findings           : {results['low']}")
    print(f"INFO messages          : {results['info']}")

    end_time = time.time()
    scan_duration = round(end_time - start_time, 2)

    print(f"\nScan duration          : {scan_duration} seconds")

    print("\n[✓] Vulnerability scan completed successfully")
    print("[+] Text report saved to reports/scan_report.txt")
    print("[+] HTML report saved to reports/report.html")


if __name__ == "__main__":
    start_scan()
