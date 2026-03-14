import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor
from modules.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "User-Agent": "Mozilla/5.0"
}

directories = [
    "admin",
    "login",
    "dashboard",
    "backup",
    ".git",
    "config",
    "uploads",
    "api"
]

def check_directory(url, directory, report):

    target = f"{url}/{directory}"

    try:

        print(f"{Colors.YELLOW}[TESTING]{Colors.RESET} {target}")

        response = requests.get(target, headers=headers, timeout=15, verify=False)

        if response.status_code in [200, 301, 302, 401, 403]:

            code = response.status_code

            explanation = {
                200: "Page exists and is accessible",
                301: "Page exists but redirects",
                302: "Temporary redirect",
                401: "Authentication required",
                403: "Page exists but access forbidden"
            }

            print(f"{Colors.GREEN}[LOW]{Colors.RESET} Directory discovered: {target} ({code})")
            print(f"{Colors.CYAN}Explanation: {explanation.get(code)}{Colors.RESET}")

            report.write(f"LOW: Directory discovered {target} (HTTP {code})\n")
            report.write(f"Explanation: {explanation.get(code)}\n\n")

    except requests.exceptions.RequestException:
        return


def scan_directories(url, report):

    url = url.rstrip("/")

    print(f"\n{Colors.BLUE}[+] Scanning for common directories...{Colors.RESET}\n")

    report.write("Directory Discovery\n")
    report.write("-------------------\n")

    with ThreadPoolExecutor(max_workers=10) as executor:
        for directory in directories:
            executor.submit(check_directory, url, directory, report)

    report.write("\n")