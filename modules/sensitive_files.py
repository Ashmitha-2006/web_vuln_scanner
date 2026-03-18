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

    # 🔥 Expanded file list + risk context
    files = {
        ".env": "Environment variables (may contain API keys, DB creds)",
        "backup.zip": "Backup archive (source code/data exposure)",
        "config.php": "Configuration file (DB credentials)",
        "database.sql": "Database dump (full data exposure)",
        ".git/config": "Git repository info (can lead to source disclosure)",
        ".htpasswd": "Contains hashed passwords",
        "web.config": "Server configuration (Windows/IIS)",
        "id_rsa": "Private SSH key (CRITICAL)",
        "docker-compose.yml": "Service configs (secrets possible)"
    }

    try:
        # 🔥 Baseline request (to avoid false positives)
        baseline = requests.get(url, headers=headers, timeout=5, verify=False)
        baseline_length = len(baseline.text)

    except:
        baseline_length = 0

    for file, description in files.items():

        target = f"{url}/{file}"

        try:
            response = requests.get(target, headers=headers, timeout=5, verify=False)
            content = response.text.lower()
            length = len(response.text)

            if response.status_code == 200:

                # 🧠 Filter fake responses (same as homepage)
                if abs(length - baseline_length) < 30:
                    continue

                # 🔥 Content validation (VERY IMPORTANT)
                sensitive_keywords = [
                    "password", "username", "root", "admin",
                    "db_", "database", "secret", "key", "token"
                ]

                is_sensitive = any(keyword in content for keyword in sensitive_keywords)

                # 🎯 Severity logic
                if file in [".env", "database.sql", "id_rsa"]:
                    severity = "HIGH"
                    color = Colors.RED
                elif is_sensitive:
                    severity = "HIGH"
                    color = Colors.RED
                else:
                    severity = "MEDIUM"
                    color = Colors.YELLOW

                print(f"{color}[{severity}]{Colors.RESET} Exposed: {target}")
                print(f"{Colors.CYAN}Description: {description}{Colors.RESET}")

                report.write(f"{severity}: Sensitive file exposed: {target}\n")
                report.write(f"Description: {description}\n")

                if is_sensitive:
                    report.write("Evidence: Sensitive keywords detected in file\n")

                report.write("\n")

        except requests.exceptions.RequestException:
            continue

    report.write("\n")
