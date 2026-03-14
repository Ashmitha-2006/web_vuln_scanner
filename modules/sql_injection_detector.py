import requests
import urllib3
from modules.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "User-Agent": "Mozilla/5.0"
}

def detect_sql_injection(url, report):

    print(f"\n{Colors.BLUE}[+] Testing for SQL Injection...{Colors.RESET}\n")

    report.write("SQL Injection Test\n")
    report.write("------------------\n")

    # SQL payloads
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "' OR 'a'='a",
        "' OR 1=1#"
    ]

    # Common SQL error messages
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

        # Check if URL already contains parameters
        if "?" in url:
            base_url = url.split("=")[0] + "="
        else:
            base_url = url + "?id="

        for payload in payloads:

            test_url = base_url + payload

            print(f"{Colors.YELLOW}[TESTING]{Colors.RESET} {test_url}")

            response = requests.get(test_url, headers=headers, timeout=15, verify=False)

            content = response.text.lower()

            for error in errors:

                if error in content:

                    print(f"{Colors.RED}[HIGH]{Colors.RESET} Possible SQL Injection detected")
                    print(f"{Colors.CYAN}Payload used: {payload}{Colors.RESET}")

                    report.write("HIGH: Possible SQL Injection detected\n")
                    report.write(f"Payload used: {payload}\n")
                    report.write("Detection Mechanism:\n")
                    report.write("- SQL payload injected\n")
                    report.write("- Database error detected\n\n")

                    return

        print(f"{Colors.GREEN}[INFO]{Colors.RESET} No SQL Injection indicators found")
        report.write("INFO: No SQL Injection indicators found\n\n")

    except requests.exceptions.RequestException as e:
        print("SQL test error:", e)