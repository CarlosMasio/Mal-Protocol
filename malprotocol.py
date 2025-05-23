import sys
import os
import core_scanner
import vt_lookup
import report
import zipfile
import tempfile
import shutil
import re
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

def analyze_apk_payload(file_path):
    if not file_path.endswith(".apk"):
        return

    console.print("\n[bold yellow][🔍] Performing APK Payload Inspection...[/bold yellow]")

    suspicious_patterns = [
        r'DexClassLoader',
        r'Base64\.decode',
        r'Runtime\.exec',
        r'ProcessBuilder',
        r'su\b',
        r'chmod\b',
        r'chattr\b',
        r'getRuntime',
    ]

    permission_patterns = [
        'RECEIVE_BOOT_COMPLETED',
        'SEND_SMS',
        'READ_SMS',
        'WRITE_SETTINGS',
        'SYSTEM_ALERT_WINDOW',
    ]

    found_suspicious = []
    found_permissions = []

    tmpdir = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(tmpdir)

        for root, _, files in os.walk(tmpdir):
            for name in files:
                if name.endswith(('.xml', '.smali', '.dex', '.txt', '.json', '.conf')):
                    try:
                        with open(os.path.join(root, name), 'r', errors='ignore') as f:
                            content = f.read()
                            for pattern in suspicious_patterns:
                                if re.search(pattern, content):
                                    found_suspicious.append(pattern)

                            for perm in permission_patterns:
                                if perm in content:
                                    found_permissions.append(perm)
                    except Exception:
                        continue

        if found_suspicious or found_permissions:
            console.print("[bold red]⚠️ Potential Payload Indicators Found:[/bold red]")
            if found_suspicious:
                console.print("  [red]- Suspicious Code Patterns:[/red]")
                for pattern in set(found_suspicious):
                    console.print(f"    • {pattern}")
            if found_permissions:
                console.print("  [red]- Dangerous Permissions:[/red]")
                for perm in set(found_permissions):
                    console.print(f"    • {perm}")
        else:
            console.print("[bold green]✅ No obvious payload indicators found in the APK structure.[/bold green]")

    finally:
        shutil.rmtree(tmpdir)

def main():
    print(banner)
    console.print("[bold cyan]Developed by : ig.masio[/bold cyan]")
    console.print("[bold blue]Github      : https://github.com/CarlosMasio/Mal-Protocol.git[/bold blue]\n")

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

    console.print(f"\nFile type detected: [cyan]{result.get('file_type')}[/cyan]")
    console.print("File hashes:")
    for htype, hval in result.get("hashes", {}).items():
        console.print(f"  - {htype.upper()}: {hval}")

    # 🛡️ YARA Matches (colorized)
    console.print("\n[bold]Malicious Pattern Check:[/bold]")
    yara_matches = result.get("yara_matches")
    if yara_matches:
        console.print(f"[bold red]Warning: Detected suspicious patterns:[/bold red] {', '.join(yara_matches)}")
    else:
        console.print("[bold green]No known malicious patterns detected.[/bold green]")

    # Indicators
    if any(result.get(x) for x in ("urls", "ips", "domains")):
        console.print("\n[bold]Potential Indicators Found:[/bold]")
        if result.get("urls"):
            console.print(f"URLs: {', '.join(result['urls'])}")
        if result.get("ips"):
            console.print(f"IP Addresses: {', '.join(result['ips'])}")
        if result.get("domains"):
            console.print(f"Domains: {', '.join(result['domains'])}")

    if result.get("base64_payloads"):
        console.print("\n[bold yellow]Warning:[/bold yellow] Base64-encoded suspicious data detected.")

    analyze_apk_payload(filepath)

    try:
        vt_result = vt_lookup.query_virustotal(result['hashes']['sha256'])
        console.print("\n[bold]VirusTotal Scan Summary:[/bold]")
        verdict = vt_result.get("verdict", "")
        if verdict == "Malicious":
            console.print("[bold red]VirusTotal indicates this file is MALICIOUS![/bold red]")
        elif verdict == "Clean or Unknown":
            console.print("VirusTotal scan shows no clear signs of malware.")
        elif verdict == "File not found on VirusTotal":
            console.print("This file has not been scanned before on VirusTotal.")
        else:
            console.print(f"VirusTotal returned: {verdict}")
    except Exception as e:
        console.print(f"\n[bold yellow]Warning:[/bold yellow] Could not check VirusTotal: {e}")

    console.print("\n[bold]Scan Complete.[/bold]")
    if yara_matches or (vt_result and vt_result.get("verdict") == "Malicious"):
        console.print("[bold red]This file is likely MALICIOUS. Do not open or execute it.[/bold red]")
    else:
        console.print("[bold green]No obvious threats detected. File appears safe, but always be cautious.[/bold green]")

    save = Prompt.ask("\nDo you want to save a detailed report (JSON and CSV)?", choices=["y", "n"], default="y")
    if save.lower() == "y":
        json_file = report.save_report_json(result)
        csv_file = report.save_report_csv(result)
        console.print(f"Reports saved as: [green]{json_file}[/green], [green]{csv_file}[/green]")

if __name__ == "__main__":
    main()
