import logging
from rich.console import Console
from rich.table import Table

from static_analyzer.modules.banner import ToolBanner, Reporting
from static_analyzer.modules.metadata import FileHeaderIdentification, StringIOCExtractor
from static_analyzer.modules.pe_analyzer import PEAnalyzer
from static_analyzer.modules.non_pe import NonPEAnalyzer
from static_analyzer.modules.elf_analyzer import ELFAnalyzer
from static_analyzer.modules.archives import ZipJarInspector
from static_analyzer.modules.floss_wrap import FlareFloss
from static_analyzer.modules.yara_engine import YaraMitreAttack
from static_analyzer.modules.threat_intel import ThreatIntel

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

console = Console()

class TriageOrchestrator:
    def __init__(self, args):
        self.args = args
        self.file_path = args.file_path
        self.report = {}
        self.mitre_attack_summary = []

    def execute(self):
        logging.info(f"Starting analysis on: {self.file_path}")

        if not self.args.json:
            banner = ToolBanner()
            banner.display(self.file_path)

        # 1. Metadata & Fingerprints
        identifier = FileHeaderIdentification(self.file_path)
        meta = identifier.get_metadata()
        self.report['metadata'] = meta

        pe_obj = None
        is_pe_file = meta.get('is_pe', False)
        
        if is_pe_file and PEFILE_AVAILABLE:
            try:
                pe_obj = pefile.PE(self.file_path, fast_load=True)
            except Exception as e:
                logging.warning(f"Failed fast-load PE: {e}")

        hashes = identifier.generate_hashes(pe_obj)
        self.report['hashes'] = hashes

        if not self.args.json:
            console.print("\n[bold yellow][*] Cryptographic Fingerprints[/bold yellow]")
            for k, v in hashes.items():
                if k == 'imphash' and v == '':
                    continue
                console.print(f"  [cyan]{k.upper():<8}:[/cyan] {v}")

            console.print("\n[bold yellow][*] File Identification & Header Analysis[/bold yellow]")
            console.print(f"  [cyan]Size:[/cyan] {meta.get('size_bytes')} bytes")
            console.print(f"  [cyan]File Classification:[/cyan] [green]{meta.get('specific_format')}[/green]")
            console.print(f"  [cyan]Magic Details:[/cyan] {meta.get('magic_type').strip()}")
            console.print(f"  [cyan]Header Hex (16 bytes):[/cyan] {meta.get('header_hex')}")
            console.print(f"  [cyan]Header ASCII:[/cyan] {meta.get('header_ascii')}")

        # 2. Threat Intel Query
        if self.args.threat_intel:
            if not self.args.json:
                console.print(f"\n[bold yellow][*] Querying Threat Intelligence ({self.args.ti_provider.capitalize()})...[/bold yellow]")
            ti = ThreatIntel(hashes['sha256'], provider=self.args.ti_provider, api_key=self.args.api_key)
            intel_res = ti.query()
            self.report['threat_intel'] = intel_res
            if not self.args.json:
                console.print(f"  [cyan]Provider:[/cyan] {intel_res.get('provider', self.args.ti_provider.capitalize())}")
                console.print(f"  [cyan]Status:[/cyan] {intel_res['status']}")
                if "detections" in intel_res:
                    console.print(f"  [cyan]Detections:[/cyan] [bold red]{intel_res['detections']}[/bold red]")
                if "suggested_threat_label" in intel_res and intel_res["suggested_threat_label"] != "N/A":
                    console.print(f"  [cyan]Threat Label:[/cyan] [bold red]{intel_res['suggested_threat_label']}[/bold red]")
                if "threat_categories" in intel_res and intel_res["threat_categories"]:
                    console.print(f"  [cyan]Categories:[/cyan] {', '.join(intel_res['threat_categories'])}")
                if "family_labels" in intel_res and intel_res["family_labels"]:
                    console.print(f"  [cyan]Family Labels:[/cyan] [bold yellow]{', '.join(intel_res['family_labels'])}[/bold yellow]")
                if "signature" in intel_res:
                    console.print(f"  [cyan]Signature:[/cyan] [bold red]{intel_res['signature']}[/bold red]")
                if "file_name" in intel_res:
                    console.print(f"  [cyan]File Name:[/cyan] {intel_res['file_name']}")
                if "date_utc" in intel_res:
                    console.print(f"  [cyan]Date (UTC):[/cyan] {intel_res['date_utc']}")
                if "type" in intel_res:
                    console.print(f"  [cyan]Type:[/cyan] {intel_res['type']}")
                if "tags" in intel_res and intel_res["tags"]:
                    tags_val = intel_res['tags']
                    tags_str = ", ".join(tags_val) if isinstance(tags_val, list) else str(tags_val)
                    console.print(f"  [cyan]Tags:[/cyan] [magenta]{tags_str}[/magenta]")
                if "reporter" in intel_res:
                    console.print(f"  [cyan]Reporter:[/cyan] {intel_res['reporter']}")
                if "report_id" in intel_res:
                    console.print(f"  [cyan]Report ID:[/cyan] {intel_res['report_id']}")
                if "environment" in intel_res:
                    console.print(f"  [cyan]Environment:[/cyan] {intel_res['environment']}")
                if "verdict" in intel_res:
                    verdict_color = "red" if intel_res['verdict'].lower() == "malicious" else "green"
                    console.print(f"  [cyan]Verdict:[/cyan] [{verdict_color}]{intel_res['verdict']}[/{verdict_color}]")

        # 3. Structure Analysis
        if is_pe_file and PEFILE_AVAILABLE:
            try:
                if not pe_obj:
                    pe_obj = pefile.PE(self.file_path, fast_load=False)
                else:
                    pe_obj.full_load()

                pe_analyzer = PEAnalyzer(self.file_path, pe_obj)
                sections, sec_warnings = pe_analyzer.analyze_sections()
                suspicious_apis, api_mitre = pe_analyzer.check_suspicious_imports()
                self.mitre_attack_summary.extend(api_mitre)
                
                self.report['pe_analysis'] = {
                    "sections": sections,
                    "warnings": sec_warnings,
                    "suspicious_apis": suspicious_apis
                }

                if not self.args.json:
                    console.print("\n[bold yellow][*] PE Sections & Entropy Analysis[/bold yellow]")
                    table = Table(show_header=True, header_style="bold magenta")
                    table.add_column("Section Name")
                    table.add_column("Virtual Address")
                    table.add_column("Raw Size")
                    table.add_column("Entropy")
                    table.add_column("Flags / Status")

                    for sec in sections:
                        entropy_color = "red" if sec['entropy'] > 7.2 else "green"
                        table.add_row(
                            sec['name'],
                            sec['virtual_address'],
                            str(sec['raw_size']),
                            f"[{entropy_color}]{sec['entropy']}[/{entropy_color}]",
                            sec['flags']
                        )
                    console.print(table)

                    if sec_warnings:
                        console.print("\n[bold red][!] Section Anomalies Detected:[/bold red]")
                        for w in sec_warnings:
                            console.print(f"  - {w}")

                    if suspicious_apis:
                        console.print("\n[bold red][!] Suspicious API Imports Detected:[/bold red]")
                        for category, apis in suspicious_apis.items():
                            console.print(f"  [cyan]{category}:[/cyan] {', '.join(apis)}")

            except Exception as e:
                self.report['pe_error'] = str(e)
                logging.error(f"Error parsing PE structure: {e}")
                if not self.args.json:
                    console.print(f"[bold red]Error parsing PE structure: {e}[/bold red]")
        else:
            if meta.get('is_archive', False):
                if not self.args.json:
                    console.print("\n[bold yellow][*] Archive Contents & Inner File Inspection (JAR/ZIP/APK)[/bold yellow]")
                
                zip_inspector = ZipJarInspector(self.file_path)
                archive_entries, archive_warnings = zip_inspector.inspect_contents()
                self.report['archive_analysis'] = {
                    "total_files": len(archive_entries),
                    "entries": archive_entries,
                    "warnings": archive_warnings
                }

                if not self.args.json:
                    table = Table(show_header=True, header_style="bold magenta")
                    table.add_column("Inner File Path")
                    table.add_column("Uncompressed Size")
                    table.add_column("Status / Flags")

                    for entry in archive_entries[:25]:
                        table.add_row(
                            entry['filename'],
                            str(entry['uncompressed_size']),
                            entry['flags']
                        )
                    console.print(table)

                    if len(archive_entries) > 25:
                        console.print(f"  [dim]... and {len(archive_entries) - 25} more inner files omitted from table.[/dim]")

                    if archive_warnings:
                        console.print("\n[bold red][!] Archive Anomalies Detected:[/bold red]")
                        for w in archive_warnings:
                            console.print(f"  - {w}")

            if not self.args.json:
                console.print("\n[bold yellow][*] Universal Chunk Entropy & Non-PE Heuristic Analysis[/bold yellow]")
            
            with open(self.file_path, 'rb') as f:
                raw_file_bytes = f.read()

            text_content = raw_file_bytes.decode('utf-8', errors='ignore')

            # Deep ELF Binary Analysis integration
            is_elf_file = meta.get('is_elf', False)
            if is_elf_file:
                if not self.args.json:
                    console.print("\n[bold yellow][*] Deep ELF Binary Complete Analysis[/bold yellow]")
                elf_parser = ELFAnalyzer(self.file_path, raw_file_bytes)
                elf_results = elf_parser.analyze()
                self.report['elf_analysis'] = elf_results
                if not self.args.json:
                    console.print(f"  [cyan]Architecture:[/cyan] {elf_results['architecture']} ({elf_results['endianness']})")
                    console.print(f"  [cyan]Entry Point:[/cyan] {elf_results['entry_point']}")
                    console.print(f"  [cyan]Program Segments:[/cyan] {elf_results['segments_count']} | [cyan]Sections:[/cyan] {elf_results['sections_count']}")
                    if elf_results['linked_libraries']:
                        console.print(f"  [cyan]Linked Shared Libraries (.so):[/cyan] {', '.join(elf_results['linked_libraries'])}")
                    if elf_results['warnings']:
                        for w in elf_results['warnings']:
                            console.print(f"  [bold red][!] {w}[/bold red]")

            non_pe = NonPEAnalyzer(self.file_path)
            chunks, univ_warnings = non_pe.analyze_universal_entropy()
            script_heuristics = non_pe.analyze_heuristics(raw_file_bytes)
            decoded_b64_payloads = non_pe.inspect_and_decode_base64(text_content)

            all_non_pe_warnings = univ_warnings + script_heuristics

            self.report['non_pe_heuristics'] = {
                "chunks_scanned": len(chunks),
                "base64_payloads_found": len(decoded_b64_payloads),
                "decoded_details": decoded_b64_payloads,
                "warnings": all_non_pe_warnings
            }

            if not self.args.json and all_non_pe_warnings:
                console.print("\n[bold red][!] Non-PE / Obfuscation Anomalies Detected:[/bold red]")
                for w in all_non_pe_warnings:
                    console.print(f"  - {w}")

            if not self.args.json and decoded_b64_payloads:
                console.print(f"\n[bold red][!] Uncovered {len(decoded_b64_payloads)} Decoded Base64 Payload(s):[/bold red]")
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Sample Offset / String")
                table.add_column("Decoded Size")
                table.add_column("Payload Type")
                table.add_column("Preview / Extracted Content")

                for item in decoded_b64_payloads[:10]:
                    table.add_row(
                        item['encoded_sample'],
                        f"{item['decoded_size']} bytes",
                        f"[bold yellow]{item['payload_type']}[/bold yellow]",
                        item['preview']
                    )
                console.print(table)

        # 4. YARA Scanning
        if self.args.yara_rules:
            if not self.args.json:
                console.print(f"\n[bold yellow][*] Running YARA Scan using rules: {self.args.yara_rules}[/bold yellow]")
            yara_engine = YaraMitreAttack(self.file_path, self.args.yara_rules)
            yara_matches, yara_mitre = yara_engine.scan()
            self.mitre_attack_summary.extend(yara_mitre)
            self.report['yara_matches'] = yara_matches
            if not self.args.json:
                if yara_matches and isinstance(yara_matches, list) and isinstance(yara_matches[0], dict):
                    for match in yara_matches:
                        console.print(f"  [bold green][+] Match Rule:[/bold green] {match['rule']} (Namespace: {match['namespace']})")
                else:
                    for msg in yara_matches:
                        console.print(f"  [yellow]{msg if isinstance(msg, str) else msg}[/yellow]")

        # 5. MITRE ATT&CK Dashboard
        self.report['mitre_attack'] = self.mitre_attack_summary
        if not self.args.json and self.mitre_attack_summary:
            console.print("\n[bold yellow][*] Correlated MITRE ATT&CK Techniques[/bold yellow]")
            table = Table(show_header=True, header_style="bold yellow")
            table.add_column("Detection Source")
            table.add_column("Technique ID")
            table.add_column("Technique Name")
            table.add_column("Tactic")

            for m in self.mitre_attack_summary:
                table.add_row(m['source'], f"[bold red]{m['id']}[/bold red]", m['name'], m['tactic'])
            console.print(table)

        # 6. FLOSS Analysis
        if self.args.enable_floss:
            if not self.args.json:
                console.print("\n[bold yellow][*] Running Mandiant FLOSS for Advanced Strings...[/bold yellow]")
            floss_tool = FlareFloss(self.file_path)
            floss_res = floss_tool.run()
            self.report['floss'] = floss_res
            if not self.args.json:
                console.print(f"  [cyan]Status:[/cyan] {floss_res['status']}")
                if floss_res.get('strings'):
                    console.print("  [cyan]Extracted Decoded/Stacked Strings:[/cyan]")
                    for s in floss_res['strings'][:15]:
                        console.print(f"    - {s}")

        # 7. Strings & IOC Parsing
        extractor = StringIOCExtractor(self.file_path)
        strings, iocs = extractor.extract()
        
        if 'decoded_b64_payloads' in locals():
            for item in decoded_b64_payloads:
                if item.get("iocs"):
                    for ip in item["iocs"].get("ips", []):
                        if ip not in iocs['ips']:
                            iocs['ips'].append(f"{ip} (Decoded from Base64)")
                    for url in item["iocs"].get("urls", []):
                        if url not in iocs['urls']:
                            iocs['urls'].append(f"{url} (Decoded from Base64)")

        self.report['iocs'] = iocs
        self.report['strings_count'] = len(strings)

        if not self.args.json:
            console.print("\n[bold yellow][*] Extracted Indicators of Compromise (IOCs)[/bold yellow]")
            has_iocs = False
            for ioc_type, items in iocs.items():
                if items:
                    has_iocs = True
                    console.print(f"  [cyan]{ioc_type.upper()}[/cyan]:")
                    for item in items[:10]:
                        console.print(f"    - {item}")
                    if len(items) > 10:
                        console.print(f"    ... and {len(items) - 10} more.")
            if not has_iocs:
                console.print("  [dim]No high-value IOCs found via regex triage.[/dim]")

        # 8. Report Exporting
        reporter = Reporting(self.report)
        if self.args.export_html:
            reporter.export_html(self.args.export_html)
            if not self.args.json:
                console.print(f"\n[bold green][+] Exported HTML report to: {self.args.export_html}[/bold green]")

        if self.args.json:
            reporter.export_json()

        logging.info(f"Finished analysis on: {self.file_path}")