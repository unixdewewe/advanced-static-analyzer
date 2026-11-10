import argparse
import sys
import os
import logging
from rich.console import Console
from static_analyzer.orchestrator import TriageOrchestrator

console = Console()

logging.basicConfig(
    filename="analysis.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def main():
    parser = argparse.ArgumentParser(description="Advanced Universal File Forensics & Malware Triage Tool (v2.0)")
    parser.add_argument("file_path", help="Path to the file to analyze")
    parser.add_argument("--yara-rules", help="Path to a YARA rule file (.yar) or a directory of rules", default=None)
    parser.add_argument("--enable-floss", action="store_true", help="Run Mandiant FLOSS for advanced/obfuscated string extraction")
    parser.add_argument("--threat-intel", action="store_true", help="Perform online hash reputation query via Threat Intelligence API")
    parser.add_argument("--ti-provider", choices=["virustotal", "malwarebazaar", "hybridanalysis"], default="virustotal", help="Choose TI Provider (default: virustotal)")
    parser.add_argument("--api-key", help="API key for the selected TI provider (or set VT_API_KEY / HA_API_KEY env vars)", default=None)
    parser.add_argument("--export-html", help="Export clean standalone HTML report to given path (e.g. report.html)", default=None)
    parser.add_argument("--json", action="store_true", help="Export full report in JSON format")
    args = parser.parse_args()

    if not os.path.exists(args.file_path):
        console.print(f"[bold red]Error: File not found -> {args.file_path}[/bold red]")
        sys.exit(1)

    orchestrator = TriageOrchestrator(args)
    orchestrator.execute()

if __name__ == "__main__":
    main()
