import requests
import urllib3
from modules.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "User-Agent": "Mozilla/5.0"
}

def check_sensitive_files(url, report):

    print(f"\n{Colors.BLUE}[+] Checking for exposed sensitive files...{Colors.RESET}\n")

    report.write("Sensitive File Exposure Test\n")
    report.write("-----------------------------\n")

    files = [
        ".env",
        "backup.zip",
        "config.php",
        "database.sql",
        ".git/config"
    ]

    for file in files:

        target = f"{url}/{file}"

        try:
            response = requests.get(target, headers=headers, timeout=5, verify=False)

            if response.status_code == 200:

                print(f"{Colors.RED}[HIGH]{Colors.RESET} Sensitive file exposed: {target}")
                report.write(f"HIGH: Sensitive file exposed {target}\n")

        except:
            pass

    report.write("\n")