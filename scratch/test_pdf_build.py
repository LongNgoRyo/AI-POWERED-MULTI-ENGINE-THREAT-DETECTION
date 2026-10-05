import os
import sys

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pdf_report_generator import generate_pdf_incident_report

scan_result = {
    "file_name": "Invoice_Exploit_Payload.pdf",
    "file_size_human": "48.10 KB",
    "detected_type": "PDF DOCUMENT",
    "is_malicious": True,
    "confidence_score": 99.6,
    "risk_level": "MÃ ĐỘC TÀI LIỆU (PDF EXPLOIT)",
    "engine_used": "AI PDF Structure Analyzer (Random Forest)",
    "overall_entropy": 6.85,
    "hashes": {
        "sha256": "3b29074cb62660dcfb94098939c0f9942a129188046b0d91d0339dcfbb01f687",
        "md5": "a8f30739c9261019001150119283f510"
    },
    "details": {
        "features": {
            "/JavaScript": 4,
            "/JS": 2,
            "/OpenAction": 1,
            "/Launch": 1,
            "obj": 110,
            "stream": 37
        }
    }
}

behavior_analysis = {
    "behavior_summary": "Tài liệu PDF chứa 4 đoạn mã JavaScript thực thi ngầm và thẻ /OpenAction tự động kích hoạt zero-click.",
    "threat_actions": [
        "Thực thi 4 đoạn mã JavaScript ngầm khi mở tài liệu.",
        "Cờ /OpenAction tự động chạy lệnh mà không có sự đồng ý của nạn nhân.",
        "Cờ /Launch gọi tiến trình Command Prompt bên ngoài hệ điều hành."
    ],
    "mitre_attacks": [
        {"tactic": "Execution", "technique_id": "T1059.007", "technique_name": "JavaScript in Documents", "description": "Thực thi mã nhúng trong PDF."},
        {"tactic": "Initial Access", "technique_id": "T1204.002", "technique_name": "Malicious File Execution Trigger", "description": "Tự động kích hoạt lệnh."}
    ],
    "recommended_action": "Khử độc tài liệu (CDR Disarm) hoặc cách ly vào Quarantine Vault."
}

remediation_info = {
    "vault_status": "Đã mã hóa XOR 0x5A lưu tại vault/quarantine/",
    "cdr_status": "Đã loại bỏ toàn bộ /JavaScript và /OpenAction"
}

pdf_path = generate_pdf_incident_report(scan_result, behavior_analysis, remediation_info)
print("PDF generated successfully at:", pdf_path)
print("File exists:", os.path.exists(pdf_path))
print("File size:", os.path.getsize(pdf_path), "bytes")
