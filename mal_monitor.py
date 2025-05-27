import os
import time
import subprocess

CONFIG_PATH = os.path.expanduser("~/.malprotocol_path.conf")
EXCLUDED_DIRS = ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/lib/docker", "/snap", "/mnt", "/media", "/root"]
MALICIOUS_PATTERNS = [
    "Warning: Detected suspicious patterns:",
    "VirusTotal indicates this file is MALICIOUS!",
    "This file is likely MALICIOUS. Do not open or execute it.",
    "Potential Payload Indicators Found:"
]

def get_malprotocol_path():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            return f.read().strip()
    path = input("ENTER THE FILE PATH OF malprotocol.py: ").strip()
    if not os.path.isfile(path):
        print("Invalid path.")
        exit(1)
    with open(CONFIG_PATH, "w") as f:
        f.write(path)
    return path

def is_excluded(path):
    return any(path.startswith(excl) for excl in EXCLUDED_DIRS)

def scan_file(mal_path, file_path):
    try:
        result = subprocess.run(
            ["python3", mal_path, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30
        )
        output = result.stdout.strip()
        print(f"[SCAN OUTPUT] {file_path}\n{output}\n")

        # If malprotocol crashed or is broken, stop
        if "Traceback" in output or "ModuleNotFoundError" in output or "ImportError" in output:
            print(f"[!] malprotocol.py FAILED to run properly. Fix the error first.")
            return

        # Check for malicious indicators
        for pattern in MALICIOUS_PATTERNS:
            if pattern in output:
                os.remove(file_path)
                print(f"[!] Malicious file deleted: {file_path}")
                return
        print(f"[+] File clean: {file_path}")
    except Exception as e:
        print(f"[ERROR] Could not scan {file_path}: {e}")

def watch_for_new_files(mal_path):
    print("[*] Watching for new files (no sudo)...")
    seen_files = set()

    for root, dirs, files in os.walk("/", topdown=True):
        if is_excluded(root):
            dirs[:] = []
            continue
        for f in files:
            seen_files.add(os.path.join(root, f))

    while True:
        for root, dirs, files in os.walk("/", topdown=True):
            if is_excluded(root):
                dirs[:] = []
                continue
            for f in files:
                full_path = os.path.join(root, f)
                if full_path not in seen_files:
                    seen_files.add(full_path)
                    if os.access(full_path, os.R_OK | os.W_OK):
                        print(f"[+] New file detected: {full_path}")
                        scan_file(mal_path, full_path)
        time.sleep(5)

if __name__ == "__main__":
    mal_path = get_malprotocol_path()
    watch_for_new_files(mal_path)
