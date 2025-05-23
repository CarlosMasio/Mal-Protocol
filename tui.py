from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.prompt import Prompt
import core_scanner
import report

console = Console()

def pretty_print_section(title, content):
    if isinstance(content, list):
        if not content:
            console.print(f"[bold]{title}:[/bold] None")
            return
        table = Table(title=title)
        table.add_column("Value", style="cyan")
        for item in content:
            table.add_row(str(item))
        console.print(table)
    elif isinstance(content, dict):
        table = Table(title=title)
        table.add_column("Key", style="magenta")
        table.add_column("Value", style="green")
        for k,v in content.items():
            table.add_row(str(k), str(v))
        console.print(table)
    else:
        console.print(Panel(str(content), title=title))

def run_tui(filepath):
    console.print(f"[bold green]Scanning file:[/bold green] {filepath}")
    result = core_scanner.scan(filepath)
    if "error" in result:
        console.print(f"[bold red]Error:[/bold red] {result['error']}")
        return

    # Display summary info
    console.rule("[bold yellow]Scan Summary[/bold yellow]")
    console.print(f"File: [cyan]{result.get('file')}[/cyan]")
    console.print(f"File Type: [cyan]{result.get('file_type')}[/cyan]")
    console.print(f"Hashes: [cyan]{result.get('hashes')}[/cyan]")

    # Display detailed sections
    pretty_print_section("YARA Matches", result.get("yara_matches"))
    pretty_print_section("URLs Found", result.get("urls"))
    pretty_print_section("IPs Found", result.get("ips"))
    pretty_print_section("Domains Found", result.get("domains"))
    pretty_print_section("Base64 Payloads Detected", result.get("base64_payloads"))
    pretty_print_section("Binary Info", result.get("binary_info"))
    pretty_print_section("Embedded Files", result.get("embedded_files"))
    pretty_print_section("Metadata", result.get("metadata"))
    pretty_print_section("Macros", result.get("macros"))

    # Ask to save report
    save = Prompt.ask("Save JSON/CSV report?", choices=["y","n"], default="y")
    if save.lower() == "y":
        json_file = report.save_report_json(result)
        csv_file = report.save_report_csv(result)
        console.print(f"Reports saved: [green]{json_file}[/green], [green]{csv_file}[/green]")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python tui.py /path/to/file")
        sys.exit(1)
    run_tui(sys.argv[1])

