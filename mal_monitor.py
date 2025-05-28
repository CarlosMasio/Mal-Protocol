import os
import time
import json
import subprocess
from pathlib import Path
import threading

CONFIG_FILE = Path.home() / ".malprotocol_config.json"
EXCLUDED_DIRS = [
    "/proc", "/sys", "/dev", "/run", "/tmp", "/var/lib/docker", "/snap",
    "/mnt", "/media", "/root", "/boot", "/lib", "/lib64", "/srv", "/lost+found"
]

MALICIOUS_PATTERNS = [
    "Warning: Detected suspicious patterns:",
    "VirusTotal indicates this file is MALICIOUS!",
    "This file is likely MALICIOUS. Do not open or execute it.",
    "Potential Payload Indicators Found:"
]

def get_malprotocol_path():
    # Hardcoded path as requested
    return "/k0/Mal-Protocol/malprotocol.py"

def scan_and_handle_file(mal_path, file_path):
    print(f"[*] Scanning file: {file_path}")
    try:
        proc = subprocess.Popen(
            ["python3", mal_path, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        def kill_proc_after_timeout(p, timeout=30):
            time.sleep(timeout)
            if p.poll() is None:
                print(f"[ERROR] Scan timed out for file: {file_path}, killing process.")
                p.kill()

        killer = threading.Thread(target=kill_proc_after_timeout, args=(proc,))
        killer.start()

        stdout, stderr = proc.communicate()
        killer.join()

        output = stdout + stderr
        print("---- malprotocol.py output ----")
        print(output.strip())
        print("---- end output ----")

        if any(pattern in output for pattern in MALICIOUS_PATTERNS):
            print(f"[!] Malicious file detected: {file_path}")
            try:
                os.remove(file_path)
                print(f"[x] Deleted file: {file_path}")
            except Exception as e:
                print(f"[ERROR] Could not delete file: {e}")
        else:
            print(f"[+] File clean: {file_path}")

    except Exception as e:
        print(f"[ERROR] Exception during scanning: {e}")

def watch_entire_system(mal_path):
    seen_files = set()
    print(f"[*] Watching entire system for new files...")

    for root, dirs, files in os.walk("/", topdown=True):
        if any(root.startswith(excl) for excl in EXCLUDED_DIRS):
            dirs[:] = []
            continue
        for f in files:
            seen_files.add(os.path.join(root, f))

    while True:
        time.sleep(3)
        for root, dirs, files in os.walk("/", topdown=True):
            if any(root.startswith(excl) for excl in EXCLUDED_DIRS):
                dirs[:] = []
                continue
            for f in files:
                full_path = os.path.join(root, f)
                if full_path not in seen_files:
                    seen_files.add(full_path)
                    if os.path.isfile(full_path) and os.access(full_path, os.R_OK | os.W_OK):
                        print(f"[+] New file detected: {full_path}")
                        scan_and_handle_file(mal_path, full_path)

if __name__ == "__main__":
    malprotocol_path = get_malprotocol_path()
    watch_entire_system(malprotocol_path)
