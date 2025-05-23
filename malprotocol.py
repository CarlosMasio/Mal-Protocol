import sys
import os
import core_scanner
import vt_lookup
import report
from rich.console import Console
from rich.prompt import Prompt

console = Console()

banner = r"""
888b     d888          888        8888888b.                  888                             888 
8888b   d8888          888        888   Y88b                 888                             888 
88888b.d88888          888        888    888                 888                             888 
888Y88888P888  8888b.  888        888   d88P 888d888 .d88b.  888888 .d88b.   .d8888b .d88b.  888 
888 Y888P 888     "88b 888        8888888P"  888P"  d88""88b 888   d88""88b d88P"   d88""88b 888 
888  Y8P  888 .d888888 888 888888 888        888    888  888 888   888  888 888     888  888 888 
888   "   888 888  888 888        888        888    Y88..88P Y88b. Y88..88P Y88b.   Y88..88P 888 
888       888 "Y888888 888        888        888     "Y88P"   "Y888 "Y88P"   "Y8888P "Y88P"  888 
"""

def interpret_yara(matches):
    if not matches:
        return "No known malicious patterns detected."
    else:
        return f"Warning: Detected suspicious patterns: {', '.join(matches)}"

def interpret_vt(vt_result):
    verdict = vt_result.get("verdict", "Unknown")
    if verdict == "Malicious":
        return f"[bold red]VirusTotal indicates this file is MALICIOUS![/bold red]"
    elif verdict == "Clean or Unknown":
        return "VirusTotal scan shows no clear signs of malware."
    elif verdict == "File not found on VirusTotal":
        return "This file has not been scanned before on VirusTotal."
    else:
        return f"VirusTotal returned an error: {verdict}"

def main():
    print(banner)  # Show ASCII banner

    if len(sys.argv) < 2:
        console.print("[bold red]Please provide the path to the file you want to scan.[/bold red]")
        console.print("Example: python malprotocol.py /path/to/file")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        console.print(f"[bold red]File not found:[/bold red] {filepath}")
        sys.exit(1)

    console.print(f"[bold green]Scanning file:[/bold green] {filepath}")
    result = core_scanner.scan(filepath)

    if "error" in result:
        console.print(f"[bold red]Error during scan:[/bold red] {result['error']}")
        sys.exit(1)

    # File info
    console.print(f"\nFile type detected: [cyan]{result.get('file_type')}[/cyan]")
    console.print("File hashes:")
    for htype, hval in result.get("hashes", {}).items():
        console.print(f"  - {htype.upper()}: {hval}")

    # YARA
    console.print("\n[bold]Malicious Pattern Check:[/bold]")
    console.print(interpret_yara(result.get("yara_matches")))

    # IOCs
    if any(result.get(x) for x in ("urls", "ips", "domains")):
        console.print("\n[bold]Potential Indicators Found:[/bold]")
        if result.get("urls"):
            console.print(f"URLs: {', '.join(result['urls'])}")
        if result.get("ips"):
            console.print(f"IP Addresses: {', '.join(result['ips'])}")
        if result.get("domains"):
            console.print(f"Domains: {', '.join(result['domains'])}")

    # Base64 warnings
    if result.get("base64_payloads"):
        console.print("\n[bold yellow]Warning:[/bold yellow] Base64-encoded suspicious data detected.")

    # VirusTotal
    try:
        vt_result = vt_lookup.query_virustotal(result['hashes']['sha256'])
        console.print("\n[bold]VirusTotal Scan Summary:[/bold]")
        console.print(interpret_vt(vt_result))
    except Exception as e:
        console.print(f"\n[bold yellow]Warning:[/bold yellow] Could not check VirusTotal: {e}")

    # Final summary
    console.print("\n[bold]Scan Complete.[/bold]")
    if result.get("yara_matches") or (vt_result and vt_result.get("verdict") == "Malicious"):
        console.print("[bold red]This file is likely MALICIOUS. Do not open or execute it.[/bold red]")
    else:
        console.print("[bold green]No obvious threats detected. File appears safe, but always be cautious.[/bold green]")

    # Report save prompt
    save = Prompt.ask("\nDo you want to save a detailed report (JSON and CSV)?", choices=["y", "n"], default="y")
    if save.lower() == "y":
        json_file = report.save_report_json(result)
        csv_file = report.save_report_csv(result)
        console.print(f"Reports saved as: [green]{json_file}[/green], [green]{csv_file}[/green]")

if __name__ == "__main__":
    main()
