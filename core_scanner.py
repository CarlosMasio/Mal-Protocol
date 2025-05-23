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

# Load yara rules from rules directory
def load_yara_rules():
    rule_path = os.path.join(os.path.dirname(__file__), "rules/basic_rules.yar")
    if not os.path.exists(rule_path):
        return None
    return yara.compile(filepath=rule_path)

# Get file hashes
def get_hashes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

# Extract URLs, IPs, domains
def extract_iocs(data):
    text = data.decode(errors="ignore")
    urls = re.findall(r'https?://[^\s\'"]+', text)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    domains = re.findall(r'\b[a-zA-Z0-9.-]+\.(com|net|org|info|io|in|ru)\b', text)
    return urls, ips, domains

# Detect base64-encoded suspicious payloads
def detect_base64_strings(data):
    text = data.decode(errors="ignore")
    b64_strings = re.findall(r'[A-Za-z0-9+/=]{50,}', text)
    suspicious = []
    for b64 in b64_strings:
        try:
            decoded = base64.b64decode(b64).decode("utf-8")
            if any(cmd in decoded for cmd in ["bash", "powershell", "cmd", "nc", "/dev/tcp"]):
                suspicious.append(decoded)
        except Exception:
            continue
    return suspicious

# Analyze PE and ELF binaries
def analyze_binary(filepath):
    results = []
    if pefile:
        try:
            pe = pefile.PE(filepath)
            results.append(f"PE Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
            for imp in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
                for imp_func in imp.imports:
                    results.append(f"Import: {imp_func.name.decode() if imp_func.name else 'None'}")
        except Exception:
            pass

    if lief:
        try:
            binary = lief.parse(filepath)
            results.append(f"LIEF Binary Format: {binary.format.name}")
            for lib in binary.libraries:
                results.append(f"Library: {lib}")
        except Exception:
            pass

    return results

# Run binwalk
def run_binwalk(filepath):
    try:
        res = subprocess.run(["binwalk", "--quiet", filepath], capture_output=True, text=True)
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]
    except Exception:
        return []

# Run exiftool to extract metadata
def run_exiftool(filepath):
    try:
        res = subprocess.run(["exiftool", filepath], capture_output=True, text=True)
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]
    except Exception:
        return []

# Analyze Office macros using oletools
def analyze_macros(filepath):
    findings = []
    if VBA_Parser:
        try:
            vbaparser = VBA_Parser(filepath)
            if vbaparser.detect_vba_macros():
                for (_, _, _, code) in vbaparser.extract_macros():
                    if "AutoOpen" in code or "Shell" in code:
                        findings.append("Suspicious Macro found")
        except Exception:
            pass
    return findings

def scan(filepath):
    if not os.path.isfile(filepath):
        return {"error": "File not found."}

    result = {}
    data = open(filepath, "rb").read()

    # Basic info
    result["file"] = filepath
    result["file_type"] = magic.Magic(mime=True).from_file(filepath)
    result["hashes"] = get_hashes(data)

    # YARA
    yara_rules = load_yara_rules()
    if yara_rules:
        matches = yara_rules.match(data=data)
        result["yara_matches"] = [m.rule for m in matches]
    else:
        result["yara_matches"] = []

    # IOC extraction
    urls, ips, domains = extract_iocs(data)
    result["urls"] = urls
    result["ips"] = ips
    result["domains"] = domains

    # Base64 payloads
    result["base64_payloads"] = detect_base64_strings(data)

    # Binary analysis
    result["binary_info"] = analyze_binary(filepath)

    # Binwalk embedded files
    result["embedded_files"] = run_binwalk(filepath)

    # Metadata
    result["metadata"] = run_exiftool(filepath)

    # Macros
    result["macros"] = analyze_macros(filepath)

    return result

