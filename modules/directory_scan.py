import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor
from modules.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "User-Agent": "Mozilla/5.0"
}

directories = [
    "admin", "login", "dashboard", "backup", ".git",
    "config", "uploads", "api", "test", "dev",
    "old", "private", "db", "server-status"
]


def check_directory(url, directory, report, baseline_length):

    target = f"{url}/{directory}"

    try:
        print(f"{Colors.YELLOW}[TESTING]{Colors.RESET} {target}")

        response = requests.get(target, headers=headers, timeout=10, verify=False)
        code = response.status_code
        length = len(response.text)

        explanation = {
            200: "Accessible directory/page",
            301: "Redirected resource",
            302: "Temporary redirect",
            401: "Authentication required",
            403: "Forbidden but exists"
        }

        # 🔥 Improved detection logic
        if code in [200, 301, 302, 401, 403]:

            # 🧠 Filter false positives using content length
            if abs(length - baseline_length) < 30:
                return  # likely a generic 404 page

            # 🎯 Severity classification
            if code == 200:
                severity = "MEDIUM"
                color = Colors.RED
            elif code in [401, 403]:
                severity = "LOW"
                color = Colors.GREEN
            else:
                severity = "INFO"
                color = Colors.CYAN

            print(f"{color}[{severity}]{Colors.RESET} Found: {target} ({code})")
            print(f"{Colors.CYAN}Explanation: {explanation.get(code)}{Colors.RESET}")

            report.write(f"{severity}: Directory found {target} (HTTP {code})\n")
            report.write(f"Explanation: {explanation.get(code)}\n\n")

    except requests.exceptions.RequestException:
        return


def scan_directories(url, report):

    url = url.rstrip("/")

    print(f"\n{Colors.BLUE}[+] Scanning for common directories...{Colors.RESET}\n")

    report.write("Directory Discovery\n")
    report.write("-------------------\n")

    try:
        # 🔥 Baseline request (important upgrade)
        baseline = requests.get(url, headers=headers, timeout=10, verify=False)
        baseline_length = len(baseline.text)
    except:
        baseline_length = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        for directory in directories:
            executor.submit(check_directory, url, directory, report, baseline_length)

    report.write("\n")
