import os
import datetime
import time

from modules.header_check import check_headers
from modules.directory_scan import scan_directories
from modules.sensitive_files import check_sensitive_files
from modules.xss_detector import detect_xss
from modules.sql_injection_detector import detect_sql_injection
from modules.bruteforce_detector import brute_force_login


def start_scan():

    print("\n=================================")
    print("      Web Vulnerability Scanner")
    print("=================================\n")

    target = input("Enter target URL (example: https://example.com): ").strip()

    # Improved input handling
    use_brute = input("Do you want to run brute-force login attack? (y/n): ").strip().lower()

    # URL normalization
    if not target.startswith("http"):
        target = "http://" + target

    print("\nStarting scan on:", target)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Start scan timer
    start_time = time.time()

    os.makedirs("reports", exist_ok=True)

    # Safer file handling
    with open("reports/scan_report.txt", "w") as report:

        report.write("=========================================\n")
        report.write("        WEB VULNERABILITY REPORT\n")
        report.write("=========================================\n\n")

        report.write(f"Target URL : {target}\n")
        report.write(f"Scan Time  : {timestamp}\n\n")

        report.write("=========================================\n")
        report.write("SCAN RESULTS\n")
        report.write("=========================================\n\n")

        # Run modules
        check_headers(target, report)
        scan_directories(target, report)
        check_sensitive_files(target, report)
        detect_xss(target, report)
        detect_sql_injection(target, report)

        # Optional brute-force attack
        if use_brute == "y":
            print("\n=================================")
            print("     BRUTE FORCE MODULE")
            print("=================================\n")

            login_url = input("Enter login URL (example: https://example.com/login): ").strip()
            print(f"[+] Target Login URL: {login_url}")

            usernames = input("Enter usernames (comma-separated): ").split(",")
            passwords = input("Enter passwords (comma-separated): ").split(",")

            usernames = [u.strip() for u in usernames]
            passwords = [p.strip() for p in passwords]

            print("\n[+] Running Brute-Force Module...\n")
            brute_force_login(login_url, usernames, passwords)

            print("\n[✓] Brute-force module completed\n")

        report.write("\n=========================================\n")
        report.write("SCAN COMPLETED\n")
        report.write("=========================================\n")

    # Read report for summary
    with open("reports/scan_report.txt", "r") as f:
        data = f.read()

    high = data.count("HIGH:")
    medium = data.count("MEDIUM:")
    low = data.count("LOW:")
    info = data.count("INFO:")

    print("\n==========================")
    print("       SCAN SUMMARY")
    print("==========================")
    print(f"HIGH vulnerabilities   : {high}")
    print(f"MEDIUM vulnerabilities : {medium}")
    print(f"LOW findings           : {low}")
    print(f"INFO messages          : {info}")

    # End timer
    end_time = time.time()
    scan_duration = round(end_time - start_time, 2)

    print(f"\nScan duration          : {scan_duration} seconds")

    print("\n[✓] Vulnerability scan completed successfully")
    print("[+] Report saved to reports/scan_report.txt")


if __name__ == "__main__":
    start_scan()
