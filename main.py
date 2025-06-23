import argparse
from modules import xss, sqli, cmdinj
from modules.encoder import encode_payload
from utils.obfuscate import obfuscate
from utils.export import export_to_json
from utils.pdf_report import generate_pdf_report
from utils.html_report import generate_html_report
import pyperclip

def print_banner():
    banner = r"""
   ____             _             _   ______                  
  |  _ \ __ _ _ __ | | ___   __ _| | |  ____|__  __ _ _ __ ___  
  | |_) / _` | '_ \| |/ _ \ / _` | | |  _| / _ \/ _` | '__/ _ \ 
  |  __/ (_| | |_) | | (_) | (_| | | | |__|  __/ (_| | | |  __/ 
  |_|   \__,_| .__/|_|\___/ \__,_|_| |_____|\___|\__,_|_|  \___| 
            |_|                                                  
        Web Exploitation Payload Generator — by Mudasir Rasheed
"""
    print(banner)

print_banner()

parser = argparse.ArgumentParser(description="PayloadForge - Custom Payload Generator")
parser.add_argument('--xss', action='store_true', help="Generate XSS payloads")
parser.add_argument('--sqli', action='store_true', help="Generate SQLi payloads")
parser.add_argument('--cmd', action='store_true', help="Generate Command Injection payloads")
parser.add_argument('--encode', choices=['url', 'base64', 'unicode', 'hex'], help="Encoding method")
parser.add_argument('--obfuscate', action='store_true', help="Apply obfuscation to payloads")
parser.add_argument('--export', help="Export payloads to JSON")
parser.add_argument('--copy', action='store_true', help="Copy first payload to clipboard")

args = parser.parse_args()
categorized_payloads = {}

# Load selected modules
if args.xss:
    categorized_payloads["XSS"] = xss.generate_xss_payloads()
if args.sqli:
    categorized_payloads["SQLi"] = sqli.generate_sqli_payloads()
if args.cmd:
    categorized_payloads["CMDi"] = cmdinj.generate_cmd_payloads()

# Ensure at least one module is selected
if not categorized_payloads:
    print("[-] Please specify at least one module using --xss, --sqli, or --cmd.")
    exit(1)



# Apply encoding and obfuscation
for category in categorized_payloads:
    if args.encode:
        categorized_payloads[category] = [encode_payload(p, args.encode) for p in categorized_payloads[category]]
    if args.obfuscate:
        categorized_payloads[category] = [obfuscate(p) for p in categorized_payloads[category]]


# Copy first payload to clipboard
all_payloads = sum(categorized_payloads.values(), [])

if args.copy and all_payloads:
    pyperclip.copy(all_payloads[0])
    print("[+] First payload copied to clipboard.")

if args.export:
    export_to_json(all_payloads, args.export)

# Export to JSON
if args.export:
    export_to_json(all_payloads, args.export)

# Create combined report name
report_tag = "_".join([cat.lower() for cat in categorized_payloads])
report_title = ", ".join(categorized_payloads)

generate_pdf_report(categorized_payloads, f"{'_'.join(categorized_payloads.keys()).lower()}_payloads.pdf")
generate_html_report(categorized_payloads, f"{'_'.join(categorized_payloads.keys()).lower()}_payloads.html")


# Output payloads
for i, payload in enumerate(all_payloads):
    print(f"{i+1}: {payload}")
