import os
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

samples_dir = "samples"
os.makedirs(samples_dir, exist_ok=True)

# 1. File PDF Lành tính (Clean Standard Document)
clean_pdf_content = (
    b"%PDF-1.4\n"
    b"1 0 obj\n"
    b"<< /Type /Catalog /Pages 2 0 R >>\n"
    b"endobj\n"
    b"2 0 obj\n"
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
    b"endobj\n"
    b"3 0 obj\n"
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\n"
    b"endobj\n"
    b"4 0 obj\n"
    b"<< /Length 44 >>\n"
    b"stream\n"
    b"BT /F1 12 Tf 72 712 Td (Tai lieu hop le va an toan) ET\n"
    b"endstream\n"
    b"endobj\n"
    b"xref\n"
    b"0 5\n"
    b"0000000000 65535 f \n"
    b"0000000010 00000 n \n"
    b"0000000060 00000 n \n"
    b"0000000117 00000 n \n"
    b"0000000206 00000 n \n"
    b"trailer\n"
    b"<< /Size 5 /Root 1 0 R >>\n"
    b"startxref\n"
    b"300\n"
    b"%%EOF\n"
)

clean_path = os.path.join(samples_dir, "file_lanh_tinh.pdf")
with open(clean_path, "wb") as f:
    f.write(clean_pdf_content)

print(f"[✓] Đã tạo file lành tính: {clean_path}")

# 2. File PDF Kiểm thử mô phỏng đặc trưng mã độc (Simulated Security Test Sample)
# File này chứa các thẻ cấu trúc /JavaScript và /OpenAction hoàn toàn an toàn (vô hại)
# để kiểm thử khả năng nhận diện của mô hình AI.
suspicious_pdf_content = (
    b"%PDF-1.4\n"
    b"1 0 obj\n"
    b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>\n"
    b"endobj\n"
    b"2 0 obj\n"
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
    b"endobj\n"
    b"3 0 obj\n"
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\n"
    b"endobj\n"
    b"4 0 obj\n"
    b"<< /Length 40 >>\n"
    b"stream\n"
    b"BT /F1 12 Tf 72 712 Td (Mau kiem thu ma nhung) ET\n"
    b"endstream\n"
    b"endobj\n"
    b"5 0 obj\n"
    b"<< /Type /Action /S /JavaScript /JS (// Test sample for malware scanner verification) >>\n"
    b"endobj\n"
    b"xref\n"
    b"0 6\n"
    b"0000000000 65535 f \n"
    b"0000000010 00000 n \n"
    b"0000000078 00000 n \n"
    b"0000000135 00000 n \n"
    b"0000000224 00000 n \n"
    b"0000000314 00000 n \n"
    b"trailer\n"
    b"<< /Size 6 /Root 1 0 R >>\n"
    b"startxref\n"
    b"415\n"
    b"%%EOF\n"
)

suspicious_path = os.path.join(samples_dir, "file_kiem_thu_mo_phong_doc_hai.pdf")
with open(suspicious_path, "wb") as f:
    f.write(suspicious_pdf_content)

print(f"[✓] Đã tạo file kiểm thử mô phỏng: {suspicious_path}")
