import os
import json
from rich.console import Console
from rich.panel import Panel

console = Console()

class ToolBanner:
    def __init__(self, name="Advanced Universal Static Malware Forensics Analyzer", version="v2.0", author="Rashid Dewewe", github="https://github.com/Rashid-dewewe/static-malware-analysis"):
        self.name = name
        self.version = version
        self.author = author
        self.github = github

    def display(self, target_path):
        banner_text = (
            f"[bold cyan]{self.name} {self.version}[/bold cyan]\n"
            f"[dim]Author: {self.author} | Repository: {self.github}[/dim]\n"
            f"Target: {target_path}"
        )
        console.print(Panel(banner_text, expand=False))


class Reporting:
    def __init__(self, report_data):
        self.report_data = report_data

    def export_json(self):
        print(json.dumps(self.report_data, indent=4))

    def export_html(self, output_html_path):
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Static Malware Triage Report - {os.path.basename(self.report_data['metadata'].get('target', 'Target'))}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e2e; color: #cdd6f4; margin: 20px; }}
        h1, h2, h3 {{ color: #89b4fa; }}
        .card {{ background-color: #181825; border-radius: 8px; padding: 15px; margin-bottom: 20px; border: 1px solid #313244; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #313244; }}
        th {{ background-color: #313244; color: #cba6f7; }}
        .badge {{ background-color: #f38ba8; color: #11111b; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }}
        pre {{ background-color: #11111b; padding: 10px; border-radius: 5px; overflow-x: auto; color: #a6e3a1; }}
    </style>
</head>
<body>
    <h1>Advanced Static Malware Analysis Report (v2.0)</h1>
    
    <div class="card">
        <h2>File Overview</h2>
        <p><strong>Target File:</strong> {self.report_data['metadata'].get('target')}</p>
        <p><strong>Size:</strong> {self.report_data['metadata'].get('size_bytes')} bytes</p>
        <p><strong>Classification:</strong> {self.report_data['metadata'].get('specific_format')}</p>
        <p><strong>Magic Details:</strong> {self.report_data['metadata'].get('magic_type')}</p>
        <p><strong>MD5:</strong> {self.report_data['hashes'].get('md5')}</p>
        <p><strong>SHA256:</strong> {self.report_data['hashes'].get('sha256')}</p>
    </div>

    <div class="card">
        <h2>Threat Intelligence Lookup</h2>
        <p><strong>Provider:</strong> {self.report_data.get('threat_intel', {}).get('provider', 'N/A')}</p>
        <p><strong>Status:</strong> {self.report_data.get('threat_intel', {}).get('status', 'N/A')}</p>
        {"<p><strong>Detections:</strong> " + str(self.report_data.get('threat_intel', {}).get('detections')) + "</p>" if 'detections' in self.report_data.get('threat_intel', {}) else ""}
        {"<p><strong>Signature:</strong> " + str(self.report_data.get('threat_intel', {}).get('signature')) + "</p>" if 'signature' in self.report_data.get('threat_intel', {}) else ""}
    </div>

    {"<div class='card'><h2>MITRE ATT&CK Mappings</h2><table><tr><th>Source / Alert</th><th>Technique ID</th><th>Technique Name</th><th>Tactic</th></tr>" + "".join([f"<tr><td>{m['source']}</td><td><span class='badge'>{m['id']}</span></td><td>{m['name']}</td><td>{m['tactic']}</td></tr>" for m in self.report_data.get('mitre_attack', [])]) + "</table></div>" if self.report_data.get('mitre_attack') else ""}

    <div class="card">
        <h2>Extracted Indicators of Compromise (IOCs)</h2>
        <pre>{json.dumps(self.report_data.get('iocs', {}), indent=2)}</pre>
    </div>
</body>
</html>"""
        with open(output_html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
