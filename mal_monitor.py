import os
import time
import json
import subprocess
from pathlib import Path
import threading

CONFIG_FILE = Path.home() / ".malprotocol_config.json"
WATCH_DIR = "/home/kali/Downloads"

MALICIOUS_PATTERNS = [
    "Warning: Detected suspicious patterns:",
    "VirusTotal indicates this file is MALICIOUS!",
    "This file is likely MALICIOUS. Do not open or execute it.",
    "Potential Payload Indicators Found:"
]

import os

def get_malprotocol_path():
    config_path = os.path.expanduser("~/.malprotocol_path.conf")
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return f.read().strip()
    else:
        # Fallback value (hardcoded path)
        return "/home/kali/Mal-Protocol/malprotocol.py"

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

def watch_folder(mal_path):
    seen_files = set(os.listdir(WATCH_DIR))
    print(f"[*] Watching folder: {WATCH_DIR}")
    while True:
        time.sleep(3)
        current_files = set(os.listdir(WATCH_DIR))
        new_files = current_files - seen_files
        for f in new_files:
            full_path = os.path.join(WATCH_DIR, f)
            if os.path.isfile(full_path):
                print(f"[+] New file detected: {full_path}")
                scan_and_handle_file(mal_path, full_path)
        seen_files = current_files

if __name__ == "__main__":
    malprotocol_path = get_malprotocol_path()
    watch_folder(malprotocol_path)
