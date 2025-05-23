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

def interpret_yara(matches):
    if not matches:
        return "[bold green]No known malicious patterns detected.[/bold green]"
    else:
        return f"[bold red]Warning: Detected suspicious patterns: {', '.join(matches)}[/bold red]"

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

def analyze_apk_payload(file_path):
    if not file_path.endswith(".apk"):
        return

    print("\n[🔍] Performing APK Payload Inspection...")

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
            print("[⚠️] Potential Payload Indicators Found:")
            if found_suspicious:
                print("  - Suspicious Code Patterns:")
                for pattern in set(found_suspicious):
                    print(f"    • {pattern}")
            if found_permissions:
                print("  - Dangerous Permissions:")
                for perm in set(found_permissions):
                    print(f"    • {perm}")
        else:
            print("[✅] No obvious payload indicators found in the APK structure.")

    finally:
        shutil.rmtree(tmpdir)

def detect_phishing_links(urls):
    suspicious_keywords = [
        "login", "verify", "account", "update", "secure", "signin", "paypal", "webmail", "banking", "reset"
    ]
    fake_domain_patterns = [
        r"faceb[o0]{2}k", r"goog1e", r"ama[z2]on", r"micr[o0]soft", r"whatsap[p]+", r"app1e", r"out1ook"
    ]
    flagged = []

    for url in urls:
        url_lower = url.lower()
        if url_lower.startswith("http://"):
            flagged.append(f"[non-secure] {url}")
        if any(kw in url_lower for kw in suspicious_keywords):
            flagged.append(f"[keyword] {url}")
        for pattern in fake_domain_patterns:
            if re.search(pattern, url_lower):
                flagged.append(f"[spoofed domain] {url}")
                break
    return flagged

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
            phishing = detect_phishing_links(result['urls'])
            if phishing:
                console.print(f"[bold red]⚠️  Suspicious / Phishing URLs detected:[/bold red]")
                for entry in phishing:
                    console.print(f"  - {entry}")
        if result.get("ips"):
            console.print(f"IP Addresses: {', '.join(result['ips'])}")
        if result.get("domains"):
            console.print(f"Domains: {', '.join(result['domains'])}")

    # Base64 warnings
    if result.get("base64_payloads"):
        console.print("\n[bold yellow]Warning:[/bold yellow] Base64-encoded suspicious data detected.")

    # APK-specific payload check
    analyze_apk_payload(filepath)

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
