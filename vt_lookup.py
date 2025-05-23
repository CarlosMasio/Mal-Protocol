import requests
import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

def load_api_key():
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError("config.json with VirusTotal API key not found")
    with open(CONFIG_PATH, "r") as f:
        data = json.load(f)
    return data.get("virustotal_api_key", "")

def query_virustotal(sha256_hash):
    api_key = load_api_key()
    if not api_key:
        raise ValueError("VirusTotal API key is missing in config.json")

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        # Extract summary info
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        verdict = "Malicious" if stats.get("malicious", 0) > 0 else "Clean or Unknown"
        return {
            "verdict": verdict,
            "malicious_count": stats.get("malicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "undetected_count": stats.get("undetected", 0),
            "total_scans": sum(stats.values()),
            "scan_date": attributes.get("last_analysis_date", "N/A"),
            "vt_url": f"https://www.virustotal.com/gui/file/{sha256_hash}/detection"
        }
    elif response.status_code == 404:
        return {"verdict": "File not found on VirusTotal"}
    else:
        return {"verdict": f"Error: HTTP {response.status_code}"}

