import requests
import urllib3
from modules.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "User-Agent": "Mozilla/5.0"
}


def check_headers(url, report):

    print(f"\n{Colors.BLUE}[+] Checking Security Headers...{Colors.RESET}\n")

    report.write("Security Header Analysis\n")
    report.write("------------------------\n")

    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        headers_response = response.headers

        # Server fingerprinting
        server = headers_response.get("Server")
        powered = headers_response.get("X-Powered-By")

        if server:
            print(f"{Colors.CYAN}[INFO]{Colors.RESET} Server detected: {server}")
            report.write(f"INFO: Server detected {server}\n")

        if powered:
            print(f"{Colors.CYAN}[INFO]{Colors.RESET} X-Powered-By: {powered}")
            report.write(f"INFO: X-Powered-By {powered}\n")

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-XSS-Protection",
            "X-Content-Type-Options"
        ]

        for header in security_headers:

            if header in headers_response:
                print(f"{Colors.GREEN}[INFO]{Colors.RESET} {header} is present")
                report.write(f"INFO: {header} present\n")

            else:
                print(f"{Colors.YELLOW}[MEDIUM]{Colors.RESET} Missing header: {header}")
                report.write(f"MEDIUM: Missing header {header}\n")

        report.write("\n")

    except Exception as e:
        print("Connection error:", e)