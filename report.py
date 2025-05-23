import json
import csv
import os

def save_report_json(data, filename="report.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    return filename

def save_report_csv(data, filename="report.csv"):
    # Flatten the data for CSV output (only basic fields)
    keys = ["file", "file_type", "hashes", "yara_matches", "urls", "ips", "domains", "base64_payloads", "binary_info", "embedded_files", "metadata", "macros"]
    
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(keys)
        
        # Prepare row by converting lists/dicts to strings
        row = []
        for key in keys:
            val = data.get(key, "")
            if isinstance(val, (list, dict)):
                if isinstance(val, dict):
                    val = json.dumps(val)
                else:
                    val = "; ".join(str(i) for i in val)
            row.append(val)
        writer.writerow(row)
    return filename

