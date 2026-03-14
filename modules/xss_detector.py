import requests
import urllib3
from modules.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "User-Agent": "Mozilla/5.0"
}

def detect_xss(url, report):

    print(f"\n{Colors.BLUE}[+] Testing for XSS vulnerabilities...{Colors.RESET}\n")

    report.write("XSS Vulnerability Test\n")
    report.write("----------------------\n")

    # XSS payloads
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    ]

    try:

        # Determine parameter style
        if "?" in url:
            base_url = url.split("=")[0] + "="
        else:
            base_url = url + "?q="

        for payload in payloads:

            test_url = base_url + payload

            print(f"{Colors.YELLOW}[TESTING]{Colors.RESET} {test_url}")

            response = requests.get(test_url, headers=headers, timeout=15, verify=False)

            if payload.lower() in response.text.lower():

                print(f"{Colors.RED}[HIGH]{Colors.RESET} Possible XSS detected")
                print(f"{Colors.CYAN}Payload used: {payload}{Colors.RESET}")

                report.write("HIGH: Possible reflected XSS detected\n")
                report.write(f"Payload used: {payload}\n")
                report.write("Detection Mechanism:\n")
                report.write("- Injected JavaScript payload\n")
                report.write("- Payload reflected in response\n\n")

                return

        print(f"{Colors.GREEN}[INFO]{Colors.RESET} No reflected XSS detected")
        report.write("INFO: No reflected XSS detected\n\n")

    except requests.exceptions.RequestException as e:
        print("XSS test error:", e)