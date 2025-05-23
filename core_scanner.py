import yara
import magic
import os
import base64
import re
import hashlib
import subprocess

try:
    import pefile
except ImportError:
    pefile = None

try:
    import lief
except ImportError:
    lief = None

try:
    from oletools.olevba import VBA_Parser
except ImportError:
    VBA_Parser = None

def load_yara_rules():
    """Load YARA rules from local file."""
    rule_path = os.path.join(os.path.dirname(__file__), "rules/basic_rules.yar")
    if os.path.exists(rule_path):
        return yara.compile(filepath=rule_path)
    return None

def get_hashes(data):
    """Calculate file hashes."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }

def extract_iocs(data):
    """Extract URLs, IPs, domains."""
    text = data.decode(errors="ignore")
    urls = re.findall(r'https?://[^\s\'"]+', text)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    domains = re.findall(r'\b[a-zA-Z0-9.-]+\.(com|net|org|info|io|in|ru|biz|gov|co)\b', text)
    return urls, ips, list(set(domains))

def detect_base64_strings(data):
    """Find and decode suspicious base64-encoded payloads."""
    text = data.decode(errors="ignore")
    b64_matches = re.findall(r'[A-Za-z0-9+/=]{50,}', text)
    suspicious = []
    for encoded in b64_matches:
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
            if any(keyword in decoded for keyword in ["bash", "cmd", "nc", "/dev/tcp", "powershell"]):
                suspicious.append(decoded)
        except Exception:
            continue
    return suspicious

def analyze_binary(filepath):
    """Extract binary-level info from PE or ELF files."""
    results = []
    if pefile:
        try:
            pe = pefile.PE(filepath)
            results.append(f"PE Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for imp in pe.DIRECTORY_ENTRY_IMPORT:
                    for func in imp.imports:
                        name = func.name.decode() if func.name else "UNKNOWN"
                        results.append(f"Import: {name}")
        except Exception:
            pass

    if lief:
        try:
            binary = lief.parse(filepath)
            results.append(f"LIEF Format: {binary.format.name}")
            for lib in binary.libraries:
                results.append(f"Library: {lib}")
        except Exception:
            pass

    return results

def run_tool(command):
    """Run a shell command and return non-empty output lines."""
    try:
        res = subprocess.run(command, capture_output=True, text=True, check=True)
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]
    except Exception:
        return []

def run_binwalk(filepath):
    """Run binwalk to detect embedded files."""
    return run_tool(["binwalk", "--quiet", filepath])

def run_exiftool(filepath):
    """Run exiftool to extract metadata."""
    return run_tool(["exiftool", filepath])

def analyze_macros(filepath):
    """Analyze MS Office macros using oletools."""
    macros = []
    if VBA_Parser:
        try:
            parser = VBA_Parser(filepath)
            if parser.detect_vba_macros():
                for (_, _, _, code) in parser.extract_macros():
                    if "AutoOpen" in code or "Shell" in code:
                        macros.append("Suspicious macro: Shell or AutoOpen")
        except Exception:
            pass
    return macros

def scan(filepath):
    """Main scan routine for any file type."""
    if not os.path.isfile(filepath):
        return {"error": "File not found."}

    result = {}
    with open(filepath, "rb") as f:
        data = f.read()

    result["file"] = filepath
    result["file_type"] = magic.Magic(mime=True).from_file(filepath)
    result["hashes"] = get_hashes(data)

    yara_rules = load_yara_rules()
    if yara_rules:
        try:
            matches = yara_rules.match(data=data)
            result["yara_matches"] = [match.rule for match in matches]
        except Exception:
            result["yara_matches"] = []
    else:
        result["yara_matches"] = []

    urls, ips, domains = extract_iocs(data)
    result["urls"] = urls
    result["ips"] = ips
    result["domains"] = domains
    result["base64_payloads"] = detect_base64_strings(data)
    result["binary_info"] = analyze_binary(filepath)
    result["embedded_files"] = run_binwalk(filepath)
    result["metadata"] = run_exiftool(filepath)
    result["macros"] = analyze_macros(filepath)

    return result

