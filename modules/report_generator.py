def generate_html_report(filename, target, scan_time, results):

    html_content = f"""
    <html>
    <head>
        <title>Vulnerability Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #0f172a;
                color: #e2e8f0;
                padding: 20px;
            }}

            h1 {{
                color: #38bdf8;
            }}

            .section {{
                margin-top: 30px;
                padding: 15px;
                border-radius: 10px;
                background-color: #1e293b;
            }}

            .high {{ color: #ef4444; }}
            .medium {{ color: #facc15; }}
            .low {{ color: #22c55e; }}
            .info {{ color: #38bdf8; }}

            .card {{
                margin-top: 10px;
                padding: 10px;
                border-left: 5px solid #38bdf8;
                background-color: #020617;
            }}
        </style>
    </head>

    <body>

        <h1>🔐 Web Vulnerability Report</h1>

        <p><b>Target:</b> {target}</p>
        <p><b>Scan Time:</b> {scan_time}</p>

        <div class="section">
            <h2>📊 Summary</h2>
            <p class="high">HIGH: {results['high']}</p>
            <p class="medium">MEDIUM: {results['medium']}</p>
            <p class="low">LOW: {results['low']}</p>
            <p class="info">INFO: {results['info']}</p>
        </div>

        <div class="section">
            <h2>📋 Findings</h2>
            {results['details']}
        </div>

    </body>
    </html>
    """

    with open(filename, "w") as f:
        f.write(html_content)
