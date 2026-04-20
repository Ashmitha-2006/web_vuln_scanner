"""
vuln_test/app.py — Deliberately vulnerable Flask app with professional dark UI.
FOR LOCAL TESTING ONLY. Never deploy publicly.
"""

from flask import Flask, request, make_response
from markupsafe import Markup
import html as _html
import sqlite3, time

app = Flask(__name__)

# ── Helper: escape user data safely BEFORE it touches any template ─────────────
def esc(value):
    """HTML-escape a string and return a Markup so Jinja2 won't double-escape."""
    return Markup(_html.escape(str(value)))

# ── Base page builder (no user data passed here) ───────────────────────────────
def base_page(page_title, active, body_html):
    active_home  = 'on' if active == 'home'  else ''
    active_xss   = 'on' if active == 'xss'   else ''
    active_sqli  = 'on' if active == 'sqli'  else ''
    active_login = 'on' if active == 'login' else ''
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VulnLab — {_html.escape(page_title)}</title>
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root{{
      --bg:#050a0f;--surface:#0b1520;--border:#0f2a40;
      --accent:#00d4ff;--red:#ff3e6c;--green:#00ff9d;--yellow:#ffc845;
      --text:#c8d8e8;--muted:#4a6a7a;
      --mono:'Share Tech Mono',monospace;--sans:'Rajdhani',sans-serif;
    }}
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:16px;min-height:100vh;overflow-x:hidden}}
    body::before{{content:'';position:fixed;inset:0;
      background-image:linear-gradient(rgba(0,212,255,.03) 1px,transparent 1px),
                       linear-gradient(90deg,rgba(0,212,255,.03) 1px,transparent 1px);
      background-size:40px 40px;pointer-events:none;z-index:0}}
    @keyframes scan{{0%{{top:-2px}}100%{{top:100vh}}}}
    .scanline{{position:fixed;left:0;right:0;height:2px;
      background:linear-gradient(90deg,transparent,rgba(0,212,255,.12),transparent);
      animation:scan 7s linear infinite;z-index:999;pointer-events:none}}
    nav{{position:sticky;top:0;z-index:100;background:rgba(5,10,15,.94);
        backdrop-filter:blur(12px);border-bottom:1px solid var(--border);
        padding:0 32px;display:flex;align-items:center;height:60px;gap:28px}}
    .brand{{font-family:var(--mono);font-size:1.05rem;color:var(--accent);
           text-decoration:none;display:flex;align-items:center;gap:6px;white-space:nowrap}}
    .brand .br{{color:var(--muted)}}
    .navlinks{{display:flex;gap:4px;list-style:none}}
    .navlinks a{{padding:5px 13px;border-radius:4px;text-decoration:none;color:var(--muted);
                font-size:.82rem;font-weight:600;letter-spacing:.5px;text-transform:uppercase;
                transition:.2s;border:1px solid transparent}}
    .navlinks a:hover,.navlinks a.on{{color:var(--accent);border-color:var(--border);background:rgba(0,212,255,.05)}}
    .warn-badge{{margin-left:auto;font-family:var(--mono);font-size:.7rem;color:var(--red);
                border:1px solid rgba(255,62,108,.3);padding:4px 12px;border-radius:4px;
                background:rgba(255,62,108,.05);white-space:nowrap}}
    .page{{position:relative;z-index:1;padding:40px 32px;max-width:1100px;margin:0 auto}}
    .ptitle{{font-family:var(--mono);font-size:1.5rem;color:var(--accent);
            margin-bottom:6px;display:flex;align-items:center;gap:12px}}
    .ptitle::after{{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}}
    .psub{{color:var(--muted);font-size:.88rem;margin-bottom:32px}}
    .info{{background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.15);
          border-radius:8px;padding:14px 18px;margin-bottom:24px;
          font-size:.85rem;color:var(--muted);line-height:1.6}}
    .info strong{{color:var(--accent)}}
    .tag{{font-family:var(--mono);font-size:.8rem;background:rgba(0,212,255,.08);
         color:var(--accent);padding:1px 7px;border-radius:3px}}
    .term{{background:#010a10;border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-top:20px}}
    .termbar{{background:#0b1a25;padding:9px 16px;display:flex;align-items:center;
             gap:7px;border-bottom:1px solid var(--border)}}
    .dot{{width:10px;height:10px;border-radius:50%}}
    .dr{{background:#ff5f56}}.dy{{background:#ffbd2e}}.dg{{background:#27c93f}}
    .tlabel{{font-family:var(--mono);font-size:.72rem;color:var(--muted);margin-left:8px}}
    .termbody{{padding:18px 22px;font-family:var(--mono);font-size:.86rem;line-height:1.75;
              color:var(--green);min-height:80px}}
    .tp{{color:var(--accent)}}.te{{color:var(--red)}}.tw{{color:var(--yellow)}}.tm{{color:var(--muted)}}
    @keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:0}}}}
    .cur{{animation:blink 1s step-end infinite}}
    .grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px;margin-bottom:36px}}
    .card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;
          padding:22px;position:relative;overflow:hidden;text-decoration:none;
          display:block;transition:border-color .25s,transform .2s}}
    .card:hover{{border-color:var(--accent);transform:translateY(-2px)}}
    .card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px}}
    .cH::before{{background:var(--red)}}.cM::before{{background:var(--yellow)}}
    .cL::before{{background:var(--green)}}.cI::before{{background:var(--accent)}}
    .cbadge{{display:inline-block;font-family:var(--mono);font-size:.62rem;padding:2px 8px;
            border-radius:3px;margin-bottom:10px;font-weight:700;letter-spacing:1px}}
    .bH{{background:rgba(255,62,108,.12);color:var(--red);border:1px solid rgba(255,62,108,.3)}}
    .bM{{background:rgba(255,200,69,.1);color:var(--yellow);border:1px solid rgba(255,200,69,.3)}}
    .bI{{background:rgba(0,212,255,.08);color:var(--accent);border:1px solid rgba(0,212,255,.25)}}
    .cicon{{font-size:1.7rem;margin-bottom:8px}}
    .cname{{font-size:1.05rem;font-weight:700;color:#e8f0f8;margin-bottom:5px}}
    .cdesc{{font-size:.82rem;color:var(--muted);line-height:1.5}}
    .carrow{{position:absolute;bottom:18px;right:18px;color:var(--muted);font-size:1rem;transition:.2s}}
    .card:hover .carrow{{color:var(--accent);transform:translateX(3px)}}
    .stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}}
    .stat{{background:var(--surface);border:1px solid var(--border);border-radius:6px;
          padding:14px 20px;text-align:center;min-width:105px}}
    .sv{{font-family:var(--mono);font-size:1.35rem;color:var(--accent)}}
    .sl{{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:3px}}
    .fbox{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:28px;max-width:400px}}
    .fbox h2{{font-family:var(--mono);color:var(--accent);margin-bottom:18px;font-size:.95rem}}
    .fg{{margin-bottom:14px}}
    label{{display:block;font-size:.75rem;color:var(--muted);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}}
    input[type=text],input[type=password]{{width:100%;background:#010a10;
      border:1px solid var(--border);border-radius:4px;padding:9px 12px;
      color:var(--text);font-family:var(--mono);font-size:.88rem;outline:none;transition:.2s}}
    input:focus{{border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,212,255,.1)}}
    .btn{{width:100%;padding:10px;background:var(--accent);color:#050a0f;border:none;
         border-radius:4px;font-family:var(--mono);font-size:.88rem;font-weight:700;
         cursor:pointer;margin-top:6px;letter-spacing:.5px;transition:.2s}}
    .btn:hover{{background:#00b8e0}}
    .alert{{padding:11px 16px;border-radius:6px;margin-bottom:18px;font-size:.85rem;font-family:var(--mono)}}
    .ok{{background:rgba(0,255,157,.08);border:1px solid rgba(0,255,157,.3);color:var(--green)}}
    .er{{background:rgba(255,62,108,.08);border:1px solid rgba(255,62,108,.3);color:var(--red)}}
    .back{{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:.8rem;
          text-decoration:none;margin-bottom:22px;font-family:var(--mono);transition:.2s}}
    .back:hover{{color:var(--accent)}}
  </style>
</head>
<body>
<div class="scanline"></div>
<nav>
  <a class="brand" href="/"><span class="br">[</span>VulnLab<span class="br">]</span></a>
  <ul class="navlinks">
    <li><a href="/" class="{active_home}">Dashboard</a></li>
    <li><a href="/xss" class="{active_xss}">XSS</a></li>
    <li><a href="/sqli" class="{active_sqli}">SQLi</a></li>
    <li><a href="/login" class="{active_login}">Brute Force</a></li>
  </ul>
  <span class="warn-badge">⚠ LOCAL TESTING ONLY</span>
</nav>
<div class="page">
{body_html}
</div>
</body>
</html>"""


# ── Home ───────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    body = """
<div class="ptitle">// Vulnerability Lab</div>
<p class="psub">Deliberately vulnerable web app for scanner testing and security education.</p>
<div class="stats">
  <div class="stat"><div class="sv">5</div><div class="sl">Endpoints</div></div>
  <div class="stat"><div class="sv">3</div><div class="sl">Vuln Types</div></div>
  <div class="stat"><div class="sv" style="color:var(--red)">HIGH</div><div class="sl">Risk Level</div></div>
  <div class="stat"><div class="sv">v2.0</div><div class="sl">Version</div></div>
</div>
<div class="info">
  <strong>Run the scanner:</strong>&nbsp;
  <span class="tag">python scanner.py --url http://127.0.0.1:5000</span>
</div>
<div class="grid">
  <a class="card cH" href="/xss?name=World">
    <div class="cbadge bH">HIGH</div><div class="cicon">⚡</div>
    <div class="cname">XSS — Direct Reflection</div>
    <div class="cdesc">User input echoed raw into HTML. Classic reflected XSS via <code>?name=</code>.</div>
    <span class="carrow">→</span>
  </a>
  <a class="card cH" href="/xss2?name=World">
    <div class="cbadge bH">HIGH</div><div class="cicon">🧬</div>
    <div class="cname">XSS — Attribute Injection</div>
    <div class="cdesc">Input inside an HTML attribute — enables event handler injection.</div>
    <span class="carrow">→</span>
  </a>
  <a class="card cH" href="/sqli?id=1">
    <div class="cbadge bH">HIGH</div><div class="cicon">🗄️</div>
    <div class="cname">SQLi — Error Based</div>
    <div class="cdesc">String concatenation into SQL + verbose error disclosure.</div>
    <span class="carrow">→</span>
  </a>
  <a class="card cH" href="/sqli2?id=1">
    <div class="cbadge bH">HIGH</div><div class="cicon">⏱️</div>
    <div class="cname">SQLi — Time-Based Blind</div>
    <div class="cdesc">No error output. Detectable only via response time delay.</div>
    <span class="carrow">→</span>
  </a>
  <a class="card cM" href="/login">
    <div class="cbadge bM">MEDIUM</div><div class="cicon">🔑</div>
    <div class="cname">Weak Credentials</div>
    <div class="cdesc">No rate limiting, no lockout. Missing HttpOnly / Secure cookie flags.</div>
    <span class="carrow">→</span>
  </a>
  <a class="card cI" href="/headers">
    <div class="cbadge bI">INFO</div><div class="cicon">📋</div>
    <div class="cname">Missing Security Headers</div>
    <div class="cdesc">No CSP, no X-Frame-Options, no HSTS. Good header scanner target.</div>
    <span class="carrow">→</span>
  </a>
</div>
<div class="term">
  <div class="termbar"><div class="dot dr"></div><div class="dot dy"></div><div class="dot dg"></div><span class="tlabel">scanner live output</span></div>
  <div class="termbody">
    <div><span class="tp">$</span> python scanner.py --url http://127.0.0.1:5000</div>
    <div class="tm">  [+] Crawling... Found 5 URLs</div>
    <div>  [+] Checking Security Headers...</div>
    <div class="tw">  [MEDIUM] Missing header: Content-Security-Policy</div>
    <div>  [+] Testing for XSS vulnerabilities...</div>
    <div class="te">  [HIGH] Reflected XSS — param 'name'</div>
    <div>  [+] Testing for SQL Injection...</div>
    <div class="te">  [HIGH] Error-Based SQLi — param 'id'</div>
    <div>  <span class="cur">_</span></div>
  </div>
</div>"""
    return base_page("Dashboard", "home", body)


# ── XSS ───────────────────────────────────────────────────────────────────────
@app.route("/xss")
def xss_direct():
    name = request.args.get("name", "World")
    # Deliberately NOT escaping name — this is the vulnerability
    raw_output = f"<h1>Hello {name}</h1>"
    body = f"""
<a class="back" href="/">← dashboard</a>
<div class="ptitle">// XSS — Direct Reflection</div>
<p class="psub">The <span class="tag">?name=</span> value is placed raw into the HTML response.</p>
<div class="info">
  <strong>Vulnerable code:</strong> <span class="tag">return f"&lt;h1&gt;Hello {{name}}&lt;/h1&gt;"</span><br><br>
  Try: <span class="tag">&lt;img src=x onerror=alert(1)&gt;</span> &nbsp;|&nbsp; <span class="tag">&lt;svg onload=alert(1)&gt;</span>
</div>
<div class="term">
  <div class="termbar"><div class="dot dr"></div><div class="dot dy"></div><div class="dot dg"></div><span class="tlabel">raw server output (no encoding)</span></div>
  <div class="termbody"><div>{raw_output}</div></div>
</div>"""
    return base_page("XSS Direct", "xss", body)


@app.route("/xss2")
def xss_attr():
    name = request.args.get("name", "World")
    # Deliberately NOT escaping — vulnerability
    raw_output = f'<input type="text" value="{name}">'
    body = f"""
<a class="back" href="/">← dashboard</a>
<div class="ptitle">// XSS — Attribute Injection</div>
<p class="psub">Input placed inside an HTML attribute — enables injecting event handlers.</p>
<div class="info">
  <strong>Vulnerable code:</strong> <span class="tag">return f'&lt;input value="{{name}}"&gt;'</span><br><br>
  Try: <span class="tag">" onmouseover="alert(1)</span>
</div>
<div class="term">
  <div class="termbar"><div class="dot dr"></div><div class="dot dy"></div><div class="dot dg"></div><span class="tlabel">rendered input element</span></div>
  <div class="termbody"><div>{raw_output}</div></div>
</div>"""
    return base_page("XSS Attribute", "xss", body)


# ── SQLi ───────────────────────────────────────────────────────────────────────
@app.route("/sqli")
def sqli_error():
    uid = request.args.get("id", "1")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES (1,'admin','secret')")
    conn.execute("INSERT INTO users VALUES (2,'user','pass123')")
    query = f"SELECT * FROM users WHERE id = '{uid}'"
    try:
        result = conn.execute(query).fetchall()
        output = str(result) if result else "No results"
        css = ""
    except Exception as e:
        output = f"Database error: {e}"
        css = "te"
    # Escape AFTER building — safe to display, shows SQL errors clearly
    body = f"""
<a class="back" href="/">← dashboard</a>
<div class="ptitle">// SQLi — Error Based</div>
<p class="psub">Raw input concatenated into SQL. Errors are disclosed in the response.</p>
<div class="info">
  <strong>Vulnerable code:</strong> <span class="tag">f"SELECT * FROM users WHERE id = '{{uid}}'"</span><br><br>
  Try: <span class="tag">?id=' OR '1'='1</span> &nbsp;|&nbsp; <span class="tag">?id=' UNION SELECT NULL--</span>
</div>
<div class="term">
  <div class="termbar"><div class="dot dr"></div><div class="dot dy"></div><div class="dot dg"></div><span class="tlabel">query result / error</span></div>
  <div class="termbody">
    <div class="tm"># Query: {_html.escape(query)}</div>
    <div class="{css}">{_html.escape(output)}</div>
  </div>
</div>"""
    return base_page("SQLi Error", "sqli", body)


@app.route("/sqli2")
def sqli_time():
    uid = request.args.get("id", "1")
    t0 = time.monotonic()
    if any(k in uid.lower() for k in ("sleep", "waitfor", "pg_sleep")):
        time.sleep(5)
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT)")
    conn.execute("INSERT INTO users VALUES (1,'admin')")
    try:
        result = conn.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall()
        output, css = str(result), ""
    except Exception as e:
        output, css = str(e), "te"
    elapsed = round(time.monotonic() - t0, 2)
    body = f"""
<a class="back" href="/">← dashboard</a>
<div class="ptitle">// SQLi — Time-Based Blind</div>
<p class="psub">No errors exposed. Injection detected only by measuring response delay.</p>
<div class="info">
  <strong>Detection:</strong> Send <span class="tag">?id=1 AND SLEEP(5)</span> and measure response time.
  A 5-second delay confirms execution inside the SQL engine.
</div>
<div class="term">
  <div class="termbar"><div class="dot dr"></div><div class="dot dy"></div><div class="dot dg"></div><span class="tlabel">response</span></div>
  <div class="termbody">
    <div class="tm"># Response time: {elapsed}s {"⚠ DELAY DETECTED — injection successful!" if elapsed >= 4.5 else ""}</div>
    <div class="{css}">{_html.escape(output)}</div>
  </div>
</div>"""
    return base_page("SQLi Blind", "sqli", body)


# ── Login ──────────────────────────────────────────────────────────────────────
VALID = {"admin": "password123", "user": "qwerty"}

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    msg_css = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if VALID.get(u) == p:
            msg = f"✓ Authenticated as '{_html.escape(u)}' — session granted (no HttpOnly/Secure flags set)"
            msg_css = "ok"
        else:
            msg = "✗ Invalid credentials"
            msg_css = "er"

    alert_html = f'<div class="alert {msg_css}">{msg}</div>' if msg else ""
    body = f"""
<a class="back" href="/">← dashboard</a>
<div class="ptitle">// Brute Force Target</div>
<p class="psub">No rate limiting or lockout. Valid creds: <span class="tag">admin:password123</span></p>
{alert_html}
<div class="fbox">
  <h2>// secure_login.php</h2>
  <form method="POST">
    <div class="fg"><label>Username</label><input type="text" name="username" placeholder="admin" autocomplete="off"></div>
    <div class="fg"><label>Password</label><input type="password" name="password" placeholder="••••••••"></div>
    <button type="submit" class="btn">Authenticate →</button>
  </form>
</div>
<div class="term" style="margin-top:24px">
  <div class="termbar"><div class="dot dr"></div><div class="dot dy"></div><div class="dot dg"></div><span class="tlabel">scanner brute-force command</span></div>
  <div class="termbody">
    <div><span class="tp">$</span> python scanner.py --url http://127.0.0.1:5000 \\</div>
    <div>&nbsp;&nbsp;--brute --login-url http://127.0.0.1:5000/login \\</div>
    <div>&nbsp;&nbsp;--usernames admin,user,root \\</div>
    <div>&nbsp;&nbsp;--passwords password123,admin,qwerty</div>
  </div>
</div>"""
    return base_page("Login", "login", body)


@app.route("/logout")
def logout():
    return "Logged out"


@app.route("/headers")
def no_headers():
    return make_response("<h1>No security headers here</h1>")


if __name__ == "__main__":
    print("\n\033[96m[VulnLab]\033[0m Running → \033[93mhttp://127.0.0.1:5000\033[0m")
    print("\033[91m  FOR LOCAL TESTING ONLY\033[0m\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
