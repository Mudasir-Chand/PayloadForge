import json

def export_to_json(payloads, filename):
    with open(filename, "w") as f:
        json.dump(payloads, f, indent=4)
    print(f"[+] Exported to {filename}")
