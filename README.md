# PayloadForge

🚀 **PayloadForge** – Custom Payload Generator for Web Exploitation  
🔐 A modular, extensible tool to generate advanced payloads for XSS, SQL Injection, and Command Injection with support for encoding, obfuscation, report generation, and WAF evasion.

---

## 🧰 Features

### ✅ Core Modules
- **XSS Payloads**
  - Reflected, Stored, DOM-based variants
  - Bypasses using `<svg>`, `srcdoc`, event handlers, null bytes, malformed tags

- **SQL Injection Payloads**
  - Error-based, Union-based, Blind SQLi
  - Evasion via casing, inline comments, special characters

- **Command Injection Payloads**
  - Linux & Windows payloads (`; whoami`, `&& net user`, etc.)

### ✨ Advanced Capabilities
- Payload encoding:
  - Base64, URL, Unicode, Hex
- Obfuscation filters:
  - Spacing, comment injection, keyword splitting
- Export formats:
  - JSON, HTML, PDF
- Clipboard copy support
- Simple GUI with buttons for each payload type
- Packaged `.deb` for Linux deployment

---

## 🖥️ Usage

### CLI Mode

```bash
python3 main.py --xss --encode=base64 --obfuscate --export=xss_payloads.json
```

### Supported Flags

| Flag               | Description                                |
|--------------------|--------------------------------------------|
| `--xss`            | Generate XSS payloads                      |
| `--sqli`           | Generate SQLi payloads                     |
| `--cmd`            | Generate Command Injection payloads        |
| `--encode`         | Encode payloads (`base64`, `url`, `hex`, `unicode`) |
| `--obfuscate`      | Obfuscate payloads                         |
| `--export`         | Export payloads to JSON                    |
| `--copy`           | Copy first payload to clipboard            |

### GUI Mode (Optional)

```bash
python3 gui.py
```

---

## 📦 Installation

### 🔧 Requirements

```bash
pip install -r requirements.txt
```

### 🐧 Build `.deb` Package

1. Make the entrypoint executable:
   ```bash
   chmod +x usr/bin/payloadforge
   ```

2. Build the `.deb`:
   ```bash
   dpkg-deb --build PayloadForge
   ```

3. Install:
   ```bash
   sudo dpkg -i PayloadForge.deb
   ```

---

## 📄 Output Examples

- `all_payloads.json` – raw payloads in structured format
- `xss_payloads.pdf` – categorized printable report
- `xss_payloads.html` – interactive accordion-based browser report

---

## 📁 Project Structure

```
PayloadForge/
├── main.py
├── gui.py
├── requirements.txt
├── modules/
│   ├── xss.py
│   ├── sqli.py
│   ├── cmdinj.py
│   └── encoder.py
├── utils/
│   ├── obfuscate.py
│   ├── export.py
│   ├── pdf_report.py
│   └── html_report.py
├── templates/
│   └── report_template.html
├── payload_samples/
│   └── sample_payloads.json
├── DEBIAN/
│   └── control
├── usr/
│   ├── bin/
│   │   └── payloadforge
│   └── share/
│       └── payloadforge/
│           └── (all source files)
```

---

## 📚 References & Credits

- [XSS Filter Evasion Cheat Sheet – PortSwigger](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [PayloadAllTheThings – GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OWASP SQLi & Command Injection Docs](https://owasp.org/)
- [Acunetix SQLi Techniques](https://www.acunetix.com/websitesecurity/sql-injection/)

---

## 🙌 Author

👤 **Mudasir Rasheed**  
Developer, Security Researcher  
Feel free to connect with me or contribute to the project!

---

## 📜 License

MIT License – Free to use, modify, and distribute.