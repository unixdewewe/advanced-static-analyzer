import json
import random
import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .html_reporter import HTMLReporter

console = Console()

class ToolBanner:
    def __init__(self, name="staticAnalyzer", version="v2.0", author="Rashid Dewewe", github="https://github.com/unixdewewe/advanced-static-analyzer"):
        self.name = name
        self.version = version
        self.author = author
        self.github = github

    def display(self, target_path):
        ascii_art = pyfiglet.figlet_format(self.name, font="standard")
        
        color_palette = ["cyan", "green", "magenta", "bright_blue", "bright_cyan", "bright_green", "yellow"]
        selected_color = random.choice(color_palette)

        title_text = Text(ascii_art, style=f"bold {selected_color}")
        
        info_text = Text.assemble(
            (" Version      : ", "bold yellow"), (f"{self.version}\n", "bold cyan"),
            (" Author       : ", "bold yellow"), (f"{self.author}\n", "bold white on blue"),
            (" Repository   : ", "bold yellow"), (f"{self.github}\n", "bold underline red"),
            (" Target File  : ", "bold yellow"), (f"{target_path}\n", "bold green"),
        )
        
        combined_content = Text.assemble(
            title_text,
            "\n",
            ("─" * 70 + "\n", f"dim {selected_color}"),
            info_text
        )
        
        console.print(Panel(combined_content, expand=False, border_style=selected_color))


class Reporting:
    def __init__(self, report_data):
        self.report_data = report_data

    def export_json(self):
        print(json.dumps(self.report_data, indent=4))

    def export_html(self, output_html_path):
        reporter = HTMLReporter(self.report_data)
        reporter.export(output_html_path)