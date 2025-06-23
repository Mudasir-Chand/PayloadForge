from fpdf import FPDF
from datetime import datetime

def chunk_payload(payload, length=90):
    """Forcefully break long strings into printable chunks."""
    return [payload[i:i+length] for i in range(0, len(payload), length)]

def generate_pdf_report(payloads_dict, filename="report.pdf", category="Payload Report"):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", 'B', 16)
    pdf.set_text_color(0, 102, 204)
    pdf.cell(0, 10, "PayloadForge Report", ln=True, align="C")

    pdf.set_font("Helvetica", '', 12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
    pdf.cell(0, 10, f"Categories: {', '.join(payloads_dict.keys())}", ln=True, align="C")
    pdf.ln(10)

    # Sections
    for category, payloads in payloads_dict.items():
        pdf.set_font("Helvetica", 'B', 14)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(0, 10, f"=== {category} Payloads ===", ln=True)
        pdf.ln(2)

        pdf.set_font("Courier", '', 10)
        pdf.set_text_color(0, 0, 0)

        for i, payload in enumerate(payloads, 1):
            chunks = chunk_payload(payload, 80)
            pdf.set_font("Courier", 'B', 10)
            pdf.cell(0, 8, f"{i}.", ln=True)
            pdf.set_font("Courier", '', 10)
            for chunk in chunks:
                pdf.cell(0, 6, chunk, ln=True)  # ✅ Safe fixed width, line-by-line printing
            pdf.ln(3)

        pdf.ln(5)

    try:
        pdf.output(filename)
        print(f"[+] PDF report saved as: {filename}")
    except Exception as e:
        print(f"[!] Failed to generate PDF: {e}")
