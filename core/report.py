"""Report Generator - Generate HTML and JSON reports."""

import json
import os
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from lib.logger import log
from lib.utils import save_json, timestamp


class ReportGenerator:
    """Generate vulnerability scan reports."""

    def __init__(self, target, vulnerabilities, stats, ai_summary=None):
        self.target = target
        self.vulnerabilities = [v.to_dict() if hasattr(v, 'to_dict') else v for v in vulnerabilities]
        self.stats = stats
        self.ai_summary = ai_summary
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self, format="both"):
        """Generate report in specified format."""
        os.makedirs(config.REPORT_DIR, exist_ok=True)
        ts = timestamp()
        base_name = f"scan_{ts}"

        paths = {}
        if format in ("json", "both"):
            json_path = os.path.join(config.REPORT_DIR, f"{base_name}.json")
            self._generate_json(json_path)
            paths["json"] = json_path

        if format in ("html", "both"):
            html_path = os.path.join(config.REPORT_DIR, f"{base_name}.html")
            self._generate_html(html_path)
            paths["html"] = html_path

        return paths

    def _generate_json(self, filepath):
        """Generate JSON report."""
        report = {
            "target": self.target,
            "timestamp": self.timestamp,
            "stats": self.stats,
            "ai_summary": self.ai_summary,
            "vulnerabilities": self.vulnerabilities,
            "by_severity": self._count_by_severity(),
        }
        save_json(report, filepath)
        log.info(f"JSON report saved: {filepath}")

    def _count_by_severity(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in self.vulnerabilities:
            sev = v.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _generate_html(self, filepath):
        """Generate HTML report."""
        by_severity = self._count_by_severity()
        total = len(self.vulnerabilities)

        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }

        vuln_rows = ""
        for v in self.vulnerabilities:
            sev = v.get("severity", "info")
            color = severity_colors.get(sev, "#6c757d")
            ai_info = ""
            if v.get("ai_analysis"):
                ai = v["ai_analysis"]
                ai_info = f'<br><small>AI: {ai.get("description", "")[:200]}</small>'
                if ai.get("remediation"):
                    ai_info += f'<br><small><b>Fix:</b> {ai["remediation"][:200]}</small>'

            vuln_rows += f"""
            <tr>
                <td><span style="color:{color};font-weight:bold">{sev.upper()}</span></td>
                <td>{v.get('type', '')}</td>
                <td style="word-break:break-all;max-width:400px">{v.get('url', '')}</td>
                <td>{v.get('param', '')}</td>
                <td style="font-family:monospace;font-size:12px;word-break:break-all">{v.get('payload', '')[:100]}</td>
                <td style="word-break:break-all">{v.get('evidence', '')[:200]}{ai_info}</td>
            </tr>"""

        ai_section = ""
        if self.ai_summary:
            ai_section = f"""
            <div style="background:#f8f9fa;padding:20px;border-radius:8px;margin:20px 0">
                <h3>AI Executive Summary</h3>
                <pre style="white-space:pre-wrap">{self.ai_summary}</pre>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Vulnerability Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .header p {{ margin: 5px 0 0; opacity: 0.8; }}
        .stats {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; flex: 1; min-width: 120px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-card .number {{ font-size: 28px; font-weight: bold; }}
        .stat-card .label {{ font-size: 12px; color: #666; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #1a1a2e; color: white; padding: 12px; text-align: left; font-size: 13px; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; font-size: 13px; vertical-align: top; }}
        tr:hover {{ background: #f8f9fa; }}
        h2 {{ color: #1a1a2e; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Web Vulnerability Scan Report</h1>
            <p>Target: {self.target} | Generated: {self.timestamp}</p>
        </div>

        <div class="stats">
            <div class="stat-card"><div class="number" style="color:#dc3545">{by_severity.get("critical",0)}</div><div class="label">Critical</div></div>
            <div class="stat-card"><div class="number" style="color:#fd7e14">{by_severity.get("high",0)}</div><div class="label">High</div></div>
            <div class="stat-card"><div class="number" style="color:#ffc107">{by_severity.get("medium",0)}</div><div class="label">Medium</div></div>
            <div class="stat-card"><div class="number" style="color:#28a745">{by_severity.get("low",0)}</div><div class="label">Low</div></div>
            <div class="stat-card"><div class="number" style="color:#17a2b8">{by_severity.get("info",0)}</div><div class="label">Info</div></div>
            <div class="stat-card"><div class="number">{total}</div><div class="label">Total</div></div>
        </div>

        {ai_section}

        <h2>Vulnerability Details</h2>
        <table>
            <thead>
                <tr><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Payload</th><th>Evidence / AI Analysis</th></tr>
            </thead>
            <tbody>{vuln_rows if vuln_rows else '<tr><td colspan="6" style="text-align:center;padding:20px">No vulnerabilities found</td></tr>'}</tbody>
        </table>

        <div style="margin-top:30px;padding:20px;background:white;border-radius:8px;font-size:12px;color:#666">
            <b>Disclaimer:</b> This report is generated by an automated scanner. Results should be manually verified.
            False positives may occur. Use this tool only on systems you have authorization to test.
        </div>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        log.info(f"HTML report saved: {filepath}")
