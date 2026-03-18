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

        # 🔍 Server fingerprinting
        server = headers_response.get("Server")
        powered = headers_response.get("X-Powered-By")

        if server:
            print(f"{Colors.CYAN}[INFO]{Colors.RESET} Server detected: {server}")
            report.write(f"INFO: Server detected: {server}\n")

        if powered:
            print(f"{Colors.CYAN}[INFO]{Colors.RESET} X-Powered-By: {powered}")
            report.write(f"INFO: X-Powered-By: {powered}\n")

        # 🔐 Security headers with explanations + recommendations
        security_headers = {
            "Content-Security-Policy": {
                "risk": "Helps prevent XSS attacks",
                "recommendation": "Define a strict CSP policy"
            },
            "X-Frame-Options": {
                "risk": "Prevents clickjacking",
                "recommendation": "Set to DENY or SAMEORIGIN"
            },
            "Strict-Transport-Security": {
                "risk": "Forces HTTPS (prevents SSL stripping)",
                "recommendation": "Enable HSTS with long max-age"
            },
            "X-XSS-Protection": {
                "risk": "Enables browser XSS filtering",
                "recommendation": "Set to 1; mode=block"
            },
            "X-Content-Type-Options": {
                "risk": "Prevents MIME sniffing",
                "recommendation": "Set to nosniff"
            }
        }

        for header, details in security_headers.items():

            value = headers_response.get(header)

            if value:
                print(f"{Colors.GREEN}[INFO]{Colors.RESET} {header} is present")

                report.write(f"INFO: {header} present\n")

                # 🔥 Basic misconfiguration checks
                if header == "X-Frame-Options" and value.upper() not in ["DENY", "SAMEORIGIN"]:
                    print(f"{Colors.YELLOW}[LOW]{Colors.RESET} Weak X-Frame-Options: {value}")
                    report.write(f"LOW: Weak X-Frame-Options value: {value}\n")

                if header == "X-Content-Type-Options" and value.lower() != "nosniff":
                    print(f"{Colors.YELLOW}[LOW]{Colors.RESET} Incorrect X-Content-Type-Options: {value}")
                    report.write(f"LOW: Incorrect X-Content-Type-Options value: {value}\n")

                if header == "Strict-Transport-Security" and "max-age" not in value:
                    print(f"{Colors.YELLOW}[LOW]{Colors.RESET} Weak HSTS configuration")
                    report.write("LOW: Weak Strict-Transport-Security configuration\n")

            else:
                print(f"{Colors.YELLOW}[MEDIUM]{Colors.RESET} Missing header: {header}")

                report.write(f"MEDIUM: Missing header: {header}\n")
                report.write(f"→ Risk: {details['risk']}\n")
                report.write(f"→ Recommendation: {details['recommendation']}\n\n")

        report.write("\n")

    except Exception as e:
        print("Connection error:", e)
