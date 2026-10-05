import fitz  # PyMuPDF
import os

pdf_path = r"D:\BaoCao_Malware_Analysis\reports\security_incidents\Security_Audit_Invoice_Exploit_Payload_1791191975.pdf"
doc = fitz.open(pdf_path)

output_dir = r"C:\Users\LONG NGO\.gemini\antigravity-ide\brain\c4866ef2-b945-477d-8857-154b6ce6966c"

for i, page in enumerate(doc):
    pix = page.get_pixmap(dpi=150)
    out_file = os.path.join(output_dir, f"virus_report_page_{i+1}.png")
    pix.save(out_file)
    print(f"Saved page {i+1} to {out_file}")
