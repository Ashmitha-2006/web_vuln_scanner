"""
report_generator.py — Generate HTML and JSON vulnerability reports.

Improvements vs original:
  - Takes List[Finding] directly (not a pre-built string).
  - Professional dark-mode HTML with Chart.js severity pie chart.
  - Findings grouped by category, sortable by severity.
  - JSON export baked into the HTML page (download button).
  - Separate generate_json_report() for machine-readable output.
"""

import json
import datetime
from typing import List
from modules.finding import Finding


_SEVERITY_COLORS = {
    "HIGH":   "#ef4444",
    "MEDIUM": "#f97316",
    "LOW":    "#22c55e",
    "INFO":   "#38bdf8",
}

_SEVERITY_BADGE = {
    "HIGH":   "badge-high",
    "MEDIUM": "badge-medium",
    "LOW":    "badge-low",
    "INFO":   "badge-info",
}


def _finding_card(f: Finding) -> str:
    evidence_html = (
        f"<div class='evidence'>🔍 <b>Evidence:</b> {f.evidence}</div>"
        if f.evidence else ""
    )
    rec_html = (
        f"<div class='rec'>💡 <b>Recommendation:</b> {f.recommendation}</div>"
        if f.recommendation else ""
    )
    param_html = (
        f"<div class='param'>📌 <b>Parameter:</b> {f.parameter}</div>"
        if f.parameter else ""
    )
    return f"""
    <div class="card {_SEVERITY_BADGE.get(f.severity, '')}">
      <div class="card-header">
        <span class="badge {_SEVERITY_BADGE.get(f.severity, '')}">{f.severity}</span>
        <span class="card-title">{f.title}</span>
        <span class="category-tag">{f.category}</span>
      </div>
      <div class="card-body">
        <div class="desc">{f.description}</div>
        {param_html}
        <div class="url">🔗 <b>URL:</b> <a href="{f.url}" target="_blank">{f.url}</a></div>
        {evidence_html}
        {rec_html}
      </div>
    </div>"""


def generate_html_report(
    filepath: str,
    target: str,
    scan_time: str,
    duration: float,
    findings: List[Finding],
) -> None:
    sorted_findings = sorted(findings)
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in ("HIGH", "MEDIUM", "LOW", "INFO")}

    cards_html = "\n".join(_finding_card(f) for f in sorted_findings) or \
        "<p style='color:#94a3b8;text-align:center;'>No findings recorded.</p>"

    findings_json = json.dumps([f.to_dict() for f in findings], indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Report — {target}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: #0b1120;
      color: #e2e8f0;
      min-height: 100vh;
    }}

    /* ── Header ── */
    .header {{
      background: linear-gradient(135deg, #1e3a5f 0%, #0f2444 100%);
      border-bottom: 1px solid #1e40af;
      padding: 28px 40px;
    }}
    .header h1 {{ font-size: 1.8rem; color: #60a5fa; display: flex; align-items: center; gap: 10px; }}
    .header .meta {{ margin-top: 8px; color: #94a3b8; font-size: 0.85rem; }}
    .header .meta span {{ margin-right: 24px; }}

    /* ── Layout ── */
    .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}

    /* ── Summary cards ── */
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 16px;
      margin-bottom: 36px;
    }}
    .summary-card {{
      background: #1e293b;
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      border-top: 4px solid;
    }}
    .summary-card.high   {{ border-color: #ef4444; }}
    .summary-card.medium {{ border-color: #f97316; }}
    .summary-card.low    {{ border-color: #22c55e; }}
    .summary-card.info   {{ border-color: #38bdf8; }}
    .summary-card .count {{ font-size: 2.5rem; font-weight: 700; }}
    .summary-card.high   .count {{ color: #ef4444; }}
    .summary-card.medium .count {{ color: #f97316; }}
    .summary-card.low    .count {{ color: #22c55e; }}
    .summary-card.info   .count {{ color: #38bdf8; }}
    .summary-card .label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; margin-top: 4px; }}

    /* ── Chart section ── */
    .chart-section {{
      display: flex;
      justify-content: center;
      margin-bottom: 36px;
    }}
    .chart-wrapper {{
      background: #1e293b;
      border-radius: 16px;
      padding: 24px 32px;
      width: 380px;
      text-align: center;
    }}
    .chart-wrapper h2 {{ color: #60a5fa; margin-bottom: 16px; font-size: 1rem; }}
    canvas {{ max-height: 240px; }}

    /* ── Toolbar ── */
    .toolbar {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 20px;
      align-items: center;
    }}
    .filter-btn {{
      padding: 6px 16px;
      border-radius: 999px;
      border: 1px solid #334155;
      background: #1e293b;
      color: #94a3b8;
      cursor: pointer;
      font-size: 0.8rem;
      transition: all 0.2s;
    }}
    .filter-btn:hover, .filter-btn.active {{ background: #38bdf8; color: #0b1120; border-color: #38bdf8; }}
    .export-btn {{
      margin-left: auto;
      padding: 6px 20px;
      border-radius: 8px;
      border: none;
      background: #1d4ed8;
      color: #fff;
      cursor: pointer;
      font-size: 0.8rem;
    }}
    .export-btn:hover {{ background: #2563eb; }}

    /* ── Findings ── */
    #findings {{ display: flex; flex-direction: column; gap: 12px; }}

    .card {{
      background: #1e293b;
      border-radius: 12px;
      border-left: 5px solid #334155;
      overflow: hidden;
      transition: transform 0.15s;
    }}
    .card:hover {{ transform: translateX(2px); }}
    .card.badge-high   {{ border-left-color: #ef4444; }}
    .card.badge-medium {{ border-left-color: #f97316; }}
    .card.badge-low    {{ border-left-color: #22c55e; }}
    .card.badge-info   {{ border-left-color: #38bdf8; }}

    .card-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 18px;
      background: rgba(255,255,255,0.03);
      cursor: pointer;
      flex-wrap: wrap;
    }}
    .badge {{
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 0.7rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      white-space: nowrap;
    }}
    .badge-high   {{ background: #450a0a; color: #ef4444; }}
    .badge-medium {{ background: #431407; color: #f97316; }}
    .badge-low    {{ background: #052e16; color: #22c55e; }}
    .badge-info   {{ background: #0c1a2e; color: #38bdf8; }}

    .card-title {{ font-weight: 600; font-size: 0.95rem; flex: 1; }}
    .category-tag {{
      font-size: 0.72rem;
      color: #64748b;
      background: #0f172a;
      padding: 2px 10px;
      border-radius: 999px;
      white-space: nowrap;
    }}

    .card-body {{
      padding: 14px 18px;
      font-size: 0.87rem;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}
    .desc  {{ color: #cbd5e1; }}
    .url a {{ color: #60a5fa; text-decoration: none; word-break: break-all; }}
    .url a:hover {{ text-decoration: underline; }}
    .evidence {{ color: #fbbf24; font-family: monospace; font-size: 0.82rem; word-break: break-all; }}
    .rec   {{ color: #86efac; }}
    .param {{ color: #c084fc; }}

    /* ── Footer ── */
    .footer {{
      text-align: center;
      padding: 24px;
      color: #475569;
      font-size: 0.78rem;
      border-top: 1px solid #1e293b;
      margin-top: 48px;
    }}

    @media (max-width: 600px) {{
      .header {{ padding: 20px 16px; }}
      .container {{ padding: 20px 12px; }}
    }}
  </style>
</head>
<body>

<div class="header">
  <h1>🔐 Web Vulnerability Report</h1>
  <div class="meta">
    <span>🎯 <b>Target:</b> {target}</span>
    <span>🕐 <b>Scan Time:</b> {scan_time}</span>
    <span>⏱ <b>Duration:</b> {duration:.1f}s</span>
    <span>📋 <b>Total Findings:</b> {len(findings)}</span>
  </div>
</div>

<div class="container">

  <!-- Summary Cards -->
  <div class="summary-grid">
    <div class="summary-card high">
      <div class="count">{counts['HIGH']}</div>
      <div class="label">High</div>
    </div>
    <div class="summary-card medium">
      <div class="count">{counts['MEDIUM']}</div>
      <div class="label">Medium</div>
    </div>
    <div class="summary-card low">
      <div class="count">{counts['LOW']}</div>
      <div class="label">Low</div>
    </div>
    <div class="summary-card info">
      <div class="count">{counts['INFO']}</div>
      <div class="label">Info</div>
    </div>
  </div>

  <!-- Chart -->
  <div class="chart-section">
    <div class="chart-wrapper">
      <h2>Severity Distribution</h2>
      <canvas id="severityChart"></canvas>
    </div>
  </div>

  <!-- Toolbar -->
  <div class="toolbar">
    <button class="filter-btn active" onclick="filterFindings('ALL')">All ({len(findings)})</button>
    <button class="filter-btn" onclick="filterFindings('HIGH')">High ({counts['HIGH']})</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium ({counts['MEDIUM']})</button>
    <button class="filter-btn" onclick="filterFindings('LOW')">Low ({counts['LOW']})</button>
    <button class="filter-btn" onclick="filterFindings('INFO')">Info ({counts['INFO']})</button>
    <button class="export-btn" onclick="exportJSON()">⬇ Export JSON</button>
  </div>

  <!-- Findings -->
  <div id="findings">
    {cards_html}
  </div>

</div>

<div class="footer">
  Generated by WebVulnScanner 2.0 &mdash; {scan_time}
</div>

<script>
// Chart
new Chart(document.getElementById('severityChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['High', 'Medium', 'Low', 'Info'],
    datasets: [{{
      data: [{counts['HIGH']}, {counts['MEDIUM']}, {counts['LOW']}, {counts['INFO']}],
      backgroundColor: ['#ef4444', '#f97316', '#22c55e', '#38bdf8'],
      borderColor: '#1e293b',
      borderWidth: 3,
      hoverOffset: 6,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{
        position: 'bottom',
        labels: {{ color: '#94a3b8', padding: 16, font: {{ size: 12 }} }}
      }}
    }}
  }}
}});

// Filter
function filterFindings(severity) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#findings .card').forEach(card => {{
    card.style.display = (severity === 'ALL' || card.classList.contains('badge-' + severity.toLowerCase()))
      ? 'block' : 'none';
  }});
}}

// JSON export
const findingsData = {findings_json};
function exportJSON() {{
  const blob = new Blob([JSON.stringify(findingsData, null, 2)], {{type: 'application/json'}});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'vulnerability_report.json';
  a.click();
}}
</script>
</body>
</html>
"""
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html)


def generate_json_report(
    filepath: str,
    target: str,
    scan_time: str,
    duration: float,
    findings: List[Finding],
) -> None:
    data = {
        "meta": {
            "target": target,
            "scan_time": scan_time,
            "duration_seconds": round(duration, 2),
            "total_findings": len(findings),
            "summary": {
                s: sum(1 for f in findings if f.severity == s)
                for s in ("HIGH", "MEDIUM", "LOW", "INFO")
            },
        },
        "findings": [f.to_dict() for f in sorted(findings)],
    }
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
