import os
import json

class HTMLReporter:
    def __init__(self, report_data):
        self.report_data = report_data

    def generate_html(self) -> str:
        """Compiles all triage data into a comprehensive, standalone dark-themed HTML report."""
        target_name = os.path.basename(
            self.report_data.get('metadata', {}).get('target', 'Target')
        )
        
        metadata = self.report_data.get('metadata', {})
        hashes = self.report_data.get('hashes', {})
        threat_intel = self.report_data.get('threat_intel', {})
        pe_analysis = self.report_data.get('pe_analysis', {})
        yara_matches = self.report_data.get('yara_matches', [])
        mitre_attack = self.report_data.get('mitre_attack', [])
        floss = self.report_data.get('floss', {})
        iocs = self.report_data.get('iocs', {})
        strings_count = self.report_data.get('strings_count', 0)

        # PE Sections Table
        sections = pe_analysis.get('sections', [])
        sections_rows = "".join([
            f"<tr>"
            f"<td>{sec.get('name', 'N/A')}</td>"
            f"<td>{sec.get('virtual_address', 'N/A')}</td>"
            f"<td>{sec.get('virtual_size', 'N/A')}</td>"
            f"<td>{sec.get('raw_size', 0)}</td>"
            f"<td>{sec.get('entropy', 0.0)}</td>"
            f"<td>{sec.get('flags', 'N/A')}</td>"
            f"</tr>"
            for sec in sections
        ]) if sections else ""

        pe_section_card = f"""
        <div class="card">
            <h2>PE Sections Analysis</h2>
            <table>
                <tr>
                    <th>Section Name</th>
                    <th>Virtual Address</th>
                    <th>Virtual Size</th>
                    <th>Raw Size</th>
                    <th>Entropy</th>
                    <th>Flags</th>
                </tr>
                {sections_rows}
            </table>
        </div>
        """ if sections else ""

        # YARA Rule Matches Table
        yara_rows = "".join([
            f"<tr>"
            f"<td>{y.get('rule', 'N/A')}</td>"
            f"<td>{y.get('namespace', 'N/A')}</td>"
            f"<td>{y.get('meta', {}).get('severity', 'N/A')}</td>"
            f"<td>{y.get('meta', {}).get('description', 'N/A')}</td>"
            f"</tr>"
            for y in yara_matches
        ]) if yara_matches else ""

        yara_card = f"""
        <div class="card">
            <h2>YARA Rule Matches</h2>
            <table>
                <tr>
                    <th>Rule Name</th>
                    <th>Namespace</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
                {yara_rows}
            </table>
        </div>
        """ if yara_matches else ""

        # MITRE ATT&CK Mappings Table
        mitre_rows = "".join([
            f"<tr>"
            f"<td>{m.get('source', 'N/A')}</td>"
            f"<td><span class='badge'>{m.get('id', 'N/A')}</span></td>"
            f"<td>{m.get('name', 'N/A')}</td>"
            f"<td>{m.get('tactic', 'N/A')}</td>"
            f"</tr>"
            for m in mitre_attack
        ]) if mitre_attack else ""

        mitre_section = f"""
        <div class="card">
            <h2>MITRE ATT&CK Mappings</h2>
            <table>
                <tr>
                    <th>Source / Alert</th>
                    <th>Technique ID</th>
                    <th>Technique Name</th>
                    <th>Tactic</th>
                </tr>
                {mitre_rows}
            </table>
        </div>
        """ if mitre_attack else ""

        detections_p = (
            f"<p><strong>Detections:</strong> {threat_intel.get('detections')}</p>"
            if 'detections' in threat_intel else ""
        )
        signature_p = (
            f"<p><strong>Signature:</strong> {threat_intel.get('signature')}</p>"
            if 'signature' in threat_intel else ""
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Static Malware Triage Report - {target_name}</title>
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
        <h2>File Overview & Metadata</h2>
        <p><strong>Target File:</strong> {metadata.get('target', 'N/A')}</p>
        <p><strong>Size:</strong> {metadata.get('size_bytes', 0)} bytes</p>
        <p><strong>Classification:</strong> {metadata.get('specific_format', 'N/A')}</p>
        <p><strong>Magic Type:</strong> {metadata.get('magic_type', 'N/A')}</p>
        <p><strong>Header Hex:</strong> {metadata.get('header_hex', 'N/A')}</p>
        <p><strong>Header ASCII:</strong> {metadata.get('header_ascii', 'N/A')}</p>
        <p><strong>Is PE:</strong> {metadata.get('is_pe', False)} | <strong>Is ELF:</strong> {metadata.get('is_elf', False)} | <strong>Is Archive:</strong> {metadata.get('is_archive', False)}</p>
        <p><strong>Extracted Strings Count:</strong> {strings_count}</p>
    </div>

    <div class="card">
        <h2>Cryptographic Hashes</h2>
        <p><strong>MD5:</strong> {hashes.get('md5', 'N/A')}</p>
        <p><strong>SHA1:</strong> {hashes.get('sha1', 'N/A')}</p>
        <p><strong>SHA256:</strong> {hashes.get('sha256', 'N/A')}</p>
        <p><strong>Imphash:</strong> {hashes.get('imphash', 'N/A') or 'N/A'}</p>
    </div>

    <div class="card">
        <h2>Threat Intelligence Lookup</h2>
        <p><strong>Provider:</strong> {threat_intel.get('provider', 'N/A')}</p>
        <p><strong>Status:</strong> {threat_intel.get('status', 'N/A')}</p>
        {detections_p}
        {signature_p}
    </div>

    {pe_section_card}

    {yara_card}

    {mitre_section}

    <div class="card">
        <h2>Mandiant FLOSS Extraction</h2>
        <p><strong>Status:</strong> {floss.get('status', 'N/A')}</p>
        <pre>{json.dumps(floss.get('strings', []), indent=2)}</pre>
    </div>

    <div class="card">
        <h2>Indicators of Compromise (IOCs)</h2>
        <pre>{json.dumps(iocs, indent=2)}</pre>
    </div>
</body>
</html>"""

    def export(self, output_html_path: str):
        """Writes the compiled HTML content to the specified disk path."""
        content = self.generate_html()
        with open(output_html_path, "w", encoding="utf-8") as f:
            f.write(content)
