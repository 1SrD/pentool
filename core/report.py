"""
Report generator - HTML reports from session findings.
Self-contained (inline CSS) - no external dependencies.
"""
import os
from datetime import datetime
from pathlib import Path
from html import escape


REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


SEVERITY_COLORS = {
    "critical": "#ff2d55",
    "high":     "#ff4560",
    "medium":   "#ff9500",
    "low":      "#ffd166",
    "info":     "#0af",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PenTool Report — {session_name}</title>
<style>
:root {{
    --bg:       #0d0f14;
    --bg2:      #13161e;
    --bg3:      #1a1e28;
    --border:   #1f2535;
    --accent:   #00ff9d;
    --accent2:  #0af;
    --text:     #c8d0e0;
    --text-dim: #5a6070;
    --text-bright: #eef2f8;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 40px 20px;
}}
.container {{ max-width: 1100px; margin: 0 auto; }}
header {{
    border-bottom: 2px solid var(--accent);
    padding-bottom: 30px; margin-bottom: 40px;
}}
h1 {{
    font-size: 2.6rem; color: var(--accent);
    letter-spacing: -1px; margin-bottom: 8px;
}}
h1::before {{ content: "⬡ "; }}
.subtitle {{ color: var(--text-dim); font-size: 0.9rem; }}
.meta {{
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 16px; margin-top: 24px;
}}
.meta-item {{
    background: var(--bg2); padding: 14px 18px;
    border-left: 3px solid var(--accent2); border-radius: 2px;
}}
.meta-label {{ color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; }}
.meta-value {{ color: var(--text-bright); font-size: 1.05rem; margin-top: 4px; word-break: break-word; }}
h2 {{
    color: var(--text-bright); font-size: 1.4rem;
    margin: 50px 0 20px; padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
}}
h2::before {{ content: "── "; color: var(--accent); }}
.summary-grid {{
    display: grid; grid-template-columns: repeat(5, 1fr);
    gap: 12px; margin-bottom: 24px;
}}
.sev-box {{
    padding: 20px 14px; text-align: center;
    border-radius: 3px; background: var(--bg2);
    border-top: 3px solid var(--border);
}}
.sev-count {{ font-size: 2rem; font-weight: bold; color: var(--text-bright); }}
.sev-label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); margin-top: 4px; letter-spacing: 1px; }}
.finding {{
    background: var(--bg2); margin-bottom: 18px;
    border-radius: 4px; overflow: hidden;
    border-left: 4px solid var(--border);
}}
.finding.critical {{ border-left-color: #ff2d55; }}
.finding.high     {{ border-left-color: #ff4560; }}
.finding.medium   {{ border-left-color: #ff9500; }}
.finding.low      {{ border-left-color: #ffd166; }}
.finding.info     {{ border-left-color: #0af; }}
.finding-header {{
    padding: 16px 20px; display: flex; align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
}}
.finding-title {{ color: var(--text-bright); font-size: 1.05rem; font-weight: 600; }}
.badge {{
    padding: 4px 10px; border-radius: 2px;
    font-size: 0.7rem; text-transform: uppercase;
    letter-spacing: 1px; font-weight: bold;
}}
.badge.critical {{ background: #ff2d55; color: #fff; }}
.badge.high     {{ background: #ff4560; color: #fff; }}
.badge.medium   {{ background: #ff9500; color: #000; }}
.badge.low      {{ background: #ffd166; color: #000; }}
.badge.info     {{ background: #0af;    color: #000; }}
.finding-body {{ padding: 18px 20px; }}
.finding-section {{ margin-bottom: 14px; }}
.finding-section:last-child {{ margin-bottom: 0; }}
.finding-label {{
    color: var(--accent2); font-size: 0.72rem;
    text-transform: uppercase; letter-spacing: 1px;
    margin-bottom: 6px;
}}
pre {{
    background: var(--bg); padding: 12px 16px;
    border-radius: 3px; overflow-x: auto;
    color: var(--text); font-size: 0.85rem;
    white-space: pre-wrap; word-break: break-word;
}}
.history-item {{
    background: var(--bg2); padding: 10px 14px;
    margin-bottom: 8px; border-radius: 3px;
    font-size: 0.85rem; display: flex;
    justify-content: space-between; align-items: center;
}}
.history-cmd {{ color: var(--accent2); font-family: monospace; }}
.history-meta {{ color: var(--text-dim); font-size: 0.75rem; }}
.notes {{
    background: var(--bg2); padding: 20px;
    border-radius: 4px; white-space: pre-wrap;
    border-left: 3px solid var(--accent);
}}
footer {{
    margin-top: 60px; padding-top: 20px;
    border-top: 1px solid var(--border);
    color: var(--text-dim); font-size: 0.8rem;
    text-align: center;
}}
.empty {{ color: var(--text-dim); font-style: italic; padding: 20px; }}
</style>
</head>
<body>
<div class="container">

<header>
<h1>PenTool Report</h1>
<div class="subtitle">{session_name} — generated {now}</div>
<div class="meta">
    <div class="meta-item">
        <div class="meta-label">Target</div>
        <div class="meta-value">{target}</div>
    </div>
    <div class="meta-item">
        <div class="meta-label">Platform</div>
        <div class="meta-value">{platform}</div>
    </div>
    <div class="meta-item">
        <div class="meta-label">Created</div>
        <div class="meta-value">{created}</div>
    </div>
    <div class="meta-item">
        <div class="meta-label">Findings</div>
        <div class="meta-value">{findings_count}</div>
    </div>
</div>
</header>

<h2>Severity Summary</h2>
<div class="summary-grid">
{severity_summary}
</div>

<h2>Findings</h2>
{findings_html}

<h2>Notes</h2>
<div class="notes">{notes}</div>

<h2>Command History ({history_count})</h2>
{history_html}

<h2>Loot ({loot_count})</h2>
{loot_html}

<footer>
PenTool — Ethical Hacking Toolkit • by 1SrD • Report generated {now}
</footer>

</div>
</body>
</html>
"""


def _severity_summary(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1

    html = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        html += f"""
<div class="sev-box" style="border-top-color: {SEVERITY_COLORS[sev]}">
    <div class="sev-count">{counts[sev]}</div>
    <div class="sev-label">{sev}</div>
</div>"""
    return html


def _findings_html(findings):
    if not findings:
        return '<div class="empty">No findings recorded yet.</div>'
    sorted_f = sorted(findings,
                      key=lambda f: SEVERITY_ORDER.get(f.get("severity","info"), 4))
    html = ""
    for f in sorted_f:
        sev = f.get("severity", "info")
        html += f"""
<div class="finding {sev}">
    <div class="finding-header">
        <div class="finding-title">#{f.get('id','?')} — {escape(f.get('title',''))}</div>
        <span class="badge {sev}">{sev}</span>
    </div>
    <div class="finding-body">"""
        if f.get("description"):
            html += f"""
        <div class="finding-section">
            <div class="finding-label">Description</div>
            <div>{escape(f['description'])}</div>
        </div>"""
        if f.get("evidence"):
            html += f"""
        <div class="finding-section">
            <div class="finding-label">Evidence</div>
            <pre>{escape(f['evidence'])}</pre>
        </div>"""
        if f.get("recommendation"):
            html += f"""
        <div class="finding-section">
            <div class="finding-label">Recommendation</div>
            <div>{escape(f['recommendation'])}</div>
        </div>"""
        html += """
    </div>
</div>"""
    return html


def _history_html(history):
    if not history:
        return '<div class="empty">No commands executed.</div>'
    html = ""
    for h in history[-50:]:  # last 50
        html += f"""
<div class="history-item">
    <span class="history-cmd">$ {escape(h.get('command','')[:120])}</span>
    <span class="history-meta">{h.get('module','')} • {h.get('timestamp','')[:19]}</span>
</div>"""
    return html


def _loot_html(loot):
    if not loot:
        return '<div class="empty">No loot collected.</div>'
    html = "<pre>"
    for l in loot:
        html += f"[{l.get('kind','?').upper()}] {escape(l.get('value',''))} "
        if l.get("context"):
            html += f"— {escape(l['context'])}"
        html += "\n"
    html += "</pre>"
    return html


def generate_report(session) -> str:
    """Generate HTML report. Returns output file path."""
    from html import escape as _e
    findings = session.findings
    history = session.history
    loot = session.loot

    html = HTML_TEMPLATE.format(
        session_name=_e(session.name),
        target=_e(session.target or "—"),
        platform=_e(session.platform),
        created=session.created_at[:19].replace("T", " "),
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings_count=len(findings),
        history_count=len(history),
        loot_count=len(loot),
        severity_summary=_severity_summary(findings),
        findings_html=_findings_html(findings),
        notes=_e(session.notes) if session.notes else "No notes.",
        history_html=_history_html(history),
        loot_html=_loot_html(loot),
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c for c in session.name if c.isalnum() or c in "-_")
    filename = REPORTS_DIR / f"report_{safe}_{ts}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return str(filename)
