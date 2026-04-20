# 🔐 Web Vulnerability Scanner v2.0

A modular, internship-grade web vulnerability scanner written in Python.  
Built for **educational and authorised penetration testing** purposes.

---

## 🚀 Features

| Module | What it does |
|---|---|
| **Crawler** | BFS-crawls in-scope pages, collects `<a>` and `<form>` links |
| **Header Checker** | Audits 8 security headers + cookie flags (HttpOnly, Secure, SameSite) |
| **Directory Scanner** | Discovers hidden paths (45 wordlist) with threading + false-positive filtering |
| **Sensitive File Checker** | Finds exposed `.env`, `.git`, backup files, SSH keys, etc. (21 targets) |
| **XSS Detector** | Probe-based reflected XSS across all GET parameters (10 payloads) |
| **SQLi Detector** | Error-based + boolean-based + **time-based blind** SQL injection |
| **Tech Detector** | Fingerprints CMS, frameworks, servers and JS libraries (NEW) |
| **Brute-Force** | Credential brute-force with CSRF token auto-extraction and lockout detection |
| **Report Generator** | Dark-mode HTML report with Chart.js pie chart + JSON + plain-text export |

---

## 📦 Installation

```bash
git clone https://github.com/yourname/web-vuln-scanner
cd web-vuln-scanner
pip install -r requirements.txt
```

---

## ⚡ Usage

### Basic scan
```bash
python scanner.py --url https://example.com
```

### Full scan with all options
```bash
python scanner.py \
  --url https://example.com \
  --threads 20 \
  --max-urls 30 \
  --output-dir ./my_reports
```

### Skip specific modules
```bash
python scanner.py --url https://example.com --skip xss,sqli
```

### With brute-force module
```bash
python scanner.py \
  --url https://example.com \
  --brute \
  --login-url https://example.com/login \
  --usernames admin,root,user \
  --passwords password,admin123,qwerty
```

### Using wordlist files
```bash
python scanner.py \
  --url https://example.com \
  --brute \
  --login-url https://example.com/login \
  --wordlist-users wordlists/users.txt \
  --wordlist-pass wordlists/passwords.txt
```

### Disable crawling (root URL only)
```bash
python scanner.py --url https://example.com --no-crawl
```

---

## 📊 Reports

After scanning, three report files are generated in `reports/` (or `--output-dir`):

| File | Description |
|---|---|
| `report.html` | Interactive dark-mode report with severity chart and filters |
| `report.json` | Machine-readable structured output (for CI/CD integration) |
| `report.txt`  | Plain-text log |

---

## 🧪 Local Testing

A deliberately vulnerable Flask app is included for safe local testing:

```bash
# Terminal 1 — start the vulnerable app
python vuln_test/app.py

# Terminal 2 — scan it
python scanner.py --url http://127.0.0.1:5000
```

Available vulnerable endpoints:

| Endpoint | Vulnerability |
|---|---|
| `/xss?name=` | Reflected XSS (direct reflection) |
| `/xss2?name=` | Reflected XSS (attribute injection) |
| `/sqli?id=` | Error-based SQL Injection |
| `/sqli2?id=` | Time-based Blind SQL Injection |
| `/login` | Weak credentials (admin:password123) |

---

## 🏗️ Architecture

```
web_vuln_scanner/
├── scanner.py                  ← CLI entry point (argparse)
├── requirements.txt
├── modules/
│   ├── finding.py              ← Core Finding dataclass (shared data model)
│   ├── colors.py               ← Terminal colour helpers
│   ├── crawler.py              ← BFS web crawler
│   ├── header_check.py         ← HTTP security header analysis
│   ├── directory_scan.py       ← Threaded directory brute-force
│   ├── sensitive_files.py      ← Exposed file detection
│   ├── xss_detector.py         ← Reflected XSS testing
│   ├── sql_injection_detector.py ← Error / Boolean / Time-based SQLi
│   ├── tech_detector.py        ← Technology fingerprinting (new)
│   └── bruteforce_detector.py  ← Credential brute-force
├── reports/
│   └── report_generator.py     ← HTML + JSON + TXT report generation
└── vuln_test/
    └── app.py                  ← Deliberately vulnerable Flask app
```

---

## 🔑 Key Improvements Over v1.0

- **Thread-safe**: Modules return `List[Finding]` objects instead of writing directly to a shared file — eliminates race conditions.
- **No global state**: Fixed the `visited` set leak in the crawler that persisted between scans.
- **Proper CLI**: `argparse`-based interface with `--help`, flags, and exit codes (non-zero on HIGH findings — useful for CI pipelines).
- **Time-based blind SQLi**: Detects injection even when no errors are shown.
- **Probe-based XSS**: Verifies parameter reflection before firing payloads — fewer false positives.
- **Structured data model**: All findings share a `Finding` dataclass, making output format-agnostic.
- **Professional reports**: Chart.js severity distribution chart, filter buttons, JSON download.
- **New tech detection module**: Fingerprints server, CMS, JS libraries, CDN/WAF.

---

## ⚠️ Legal Notice

This tool is for **authorised security testing only**.  
Never run it against systems you do not own or have explicit written permission to test.  
Unauthorised scanning may violate computer fraud laws in your jurisdiction.

---

## 📄 License

MIT — free to use, modify, and share with attribution.
