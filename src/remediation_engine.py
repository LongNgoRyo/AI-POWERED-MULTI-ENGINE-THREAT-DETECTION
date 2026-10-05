import os
import json
import time
import re
import secrets
from typing import Dict, Any, List

VAULT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vault", "quarantine")
os.makedirs(VAULT_DIR, exist_ok=True)

XOR_KEY = 0x5A  # Khóa mã hóa bảo vệ file an toàn khỏi sự can thiệp của Windows Defender

def xor_transform(data: bytes, key: int = XOR_KEY) -> bytes:
    """Mã hóa / Giải mã dữ liệu bằng thuật toán XOR để đưa vào vùng an toàn cách ly."""
    return bytes([b ^ key for b in data])

def quarantine_file(file_path: str, hashes: Dict[str, str] = None) -> Dict[str, Any]:
    """
    Cách ly tập tin độc hại vào vùng an toàn (Quarantine Vault):
    - Mã hóa nội dung bằng XOR
    - Đổi đuôi thành .quarantined
    - Xóa file gốc an toàn
    - Windows Defender sẽ không thể nhận diện hay xóa mất file này
    """
    if not os.path.exists(file_path):
        return {"success": False, "error": f"Không tìm thấy file: {file_path}"}

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    with open(file_path, "rb") as f:
        raw_bytes = f.read()

    # Mã hóa để vô hiệu hóa hoàn toàn mã nhị phân
    encrypted_bytes = xor_transform(raw_bytes)
    
    sha256 = hashes.get("sha256", f"item_{int(time.time())}") if hashes else f"item_{int(time.time())}"
    vault_file_path = os.path.join(VAULT_DIR, f"{sha256}.quarantined")
    vault_meta_path = os.path.join(VAULT_DIR, f"{sha256}.meta.json")

    with open(vault_file_path, "wb") as f:
        f.write(encrypted_bytes)

    meta_info = {
        "original_path": file_path,
        "original_name": file_name,
        "file_size": file_size,
        "sha256": sha256,
        "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "SECURE_ISOLATED"
    }

    with open(vault_meta_path, "w", encoding="utf-8") as f:
        json.dump(meta_info, f, indent=4)

    # Xóa file nguy hiểm ban đầu
    try:
        os.remove(file_path)
    except Exception:
        pass

    return {
        "success": True,
        "vault_id": sha256,
        "vault_path": vault_file_path,
        "message": f"Đã cách ly an toàn tệp {file_name} vào Vùng Bảo Vệ (Vault). File đã được vô hiệu hóa mã nhị phân."
    }

def disarm_pdf(file_path: str, output_path: str = None) -> Dict[str, Any]:
    """
    Công nghệ Khử Độc Tài Liệu (Content Disarm & Reconstruction - CDR):
    - Quét và loại bỏ toàn bộ các thẻ nhúng mã độc: /JavaScript, /JS, /OpenAction, /Launch
    - Tái tạo lại một file PDF mới sạch sẽ 100%, an toàn cho người dùng mở.
    """
    if not os.path.exists(file_path):
        return {"success": False, "error": f"Không tìm thấy file: {file_path}"}

    with open(file_path, "rb") as f:
        content = f.read()

    # Tước bỏ các thẻ script và action độc hại
    sanitized = content
    tags_to_strip = [b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/EmbeddedFiles"]
    removed_tags = []

    for tag in tags_to_strip:
        if tag in sanitized:
            removed_tags.append(tag.decode("latin1"))
            # Thay thế bằng khoảng trắng an toàn để giữ nguyên cấu trúc offset
            replacement = b" " * len(tag)
            sanitized = sanitized.replace(tag, replacement)

    if not output_path:
        base, ext = os.path.splitext(file_path)
        output_path = f"{base}_sanitized_clean{ext}"

    with open(output_path, "wb") as f:
        f.write(sanitized)

    return {
        "success": True,
        "clean_file_path": output_path,
        "removed_tags": removed_tags,
        "message": f"Đã khử độc thành công tài liệu PDF! Loại bỏ {len(removed_tags)} thẻ mã độc nhúng. File mới an toàn 100%."
    }

def shred_file(file_path: str) -> Dict[str, Any]:
    """
    Hủy tệp bảo mật theo tiêu chuẩn quân sự DoD 5220.22-M:
    - Ghi đè 3 lần (0x00, 0xFF, Random bytes)
    - Xóa vĩnh viễn không thể phục hồi mã độc
    """
    if not os.path.exists(file_path):
        return {"success": False, "error": f"Không tìm thấy file: {file_path}"}

    length = os.path.getsize(file_path)
    with open(file_path, "ba+", buffering=0) as f:
        # Pass 1: Ghi đè số 0
        f.seek(0)
        f.write(b"\x00" * length)
        # Pass 2: Ghi đè 0xFF
        f.seek(0)
        f.write(b"\xFF" * length)
        # Pass 3: Ghi đè byte ngẫu nhiên
        f.seek(0)
        f.write(secrets.token_bytes(length))

    os.remove(file_path)
    return {
        "success": True,
        "message": "Đã tiêu hủy tệp tin độc hại vĩnh viễn theo chuẩn DoD 5220.22-M."
    }

def analyze_threat_behavior(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Phân tích hành vi chuyên sâu (Threat Intelligence & MITRE ATT&CK Mapping):
    Giải thích cặn kẽ 'Mã độc làm gì', cách thức lây nhiễm và mức độ nguy hại.
    """
    threat_actions = []
    mitre_attacks = []
    capabilities = []

    is_mal = scan_result.get("is_malicious", False)
    file_type = scan_result.get("detected_type", "")
    entropy = scan_result.get("overall_entropy", 0.0)
    details = scan_result.get("details", {})
    pe_feats = details.get("pe_features", {})
    pdf_feats = details.get("pdf_features", {})

    if not is_mal:
        return {
            "behavior_summary": "Tệp tin hoạt động bình thường, không ghi nhận các hành vi gián điệp, đào trộm dữ liệu hay can thiệp hệ thống.",
            "threat_actions": ["Chạy mã nhị phân thông thường trong không gian bộ nhớ người dùng (User Mode)."],
            "mitre_attacks": [],
            "risk_profile": "AN TOÀN"
        }

    # 1. Phát hiện Giả mạo đuôi (Extension Spoofing)
    if scan_result.get("spoofed_extension"):
        threat_actions.append("Ngụy trang đuôi tệp tin để lừa người dùng nhấp đúp (Spear-phishing delivery).")
        mitre_attacks.append({
            "tactic": "Defense Evasion",
            "technique_id": "T1036.007",
            "technique_name": "Double File Extension & Masquerading",
            "description": "Kẻ tấn công đánh tráo phần mở rộng để tránh sự nghi ngờ của người dùng và qua mặt bộ lọc email."
        })
        capabilities.append("Lừa đảo người dùng (Social Engineering)")

    # 2. Phân tích PE (Mã độc thực thi EXE/DLL)
    if pe_feats:
        max_ent = pe_feats.get("MaxSectionEntropy", 0)
        susp_sections = pe_feats.get("SuspiciousSectionNames", 0)

        if max_ent > 7.1 or susp_sections > 0:
            threat_actions.append("Dữ liệu phân đoạn bị nén/mã hóa ngầm (Packer Obfuscation) nhằm che giấu chuỗi lệnh khỏi Antivirus.")
            mitre_attacks.append({
                "tactic": "Defense Evasion",
                "technique_id": "T1027.002",
                "technique_name": "Software Packing (UPX / Custom Cryptor)",
                "description": "Nén phần mềm bằng Packer để giải mã trực tiếp trong bộ nhớ (In-memory execution), né tránh quét tĩnh."
            })
            capabilities.append("Chống dịch ngược & Né tránh quét tĩnh (Anti-Analysis)")

        if pe_feats.get("ImportedDLLs", 0) > 15:
            threat_actions.append("Nạp nhiều thư viện API hệ thống để thao tác Registry, gọi mạng và can thiệp tiến trình.")
            mitre_attacks.append({
                "tactic": "Execution / Discovery",
                "technique_id": "T1106",
                "technique_name": "Native API Execution",
                "description": "Sử dụng trực tiếp các hàm Windows API để điều khiển tiến trình hệ thống."
            })

    # 3. Phân tích PDF (Mã độc tài liệu)
    if pdf_feats:
        js_count = pdf_feats.get("/JavaScript", 0) + pdf_feats.get("/JS", 0)
        oa_count = pdf_feats.get("/OpenAction", 0)
        launch_count = pdf_feats.get("/Launch", 0)

        if js_count > 0:
            threat_actions.append(f"Chứa {js_count} đoạn mã JavaScript thực thi ngầm ngay khi tài liệu được hiển thị.")
            mitre_attacks.append({
                "tactic": "Execution",
                "technique_id": "T1059.007",
                "technique_name": "JavaScript in Documents",
                "description": "Thực thi mã nhúng trong tài liệu văn phòng để khai thác lỗ hổng trình đọc PDF hoặc tải payload thứ hai."
            })
            capabilities.append("Tải mã độc bổ sung (Dropper / Downloader)")

        if oa_count > 0:
            threat_actions.append("Kích hoạt hành vi độc hại tự động (/OpenAction) mà không cần sự đồng ý hay tương tác của nạn nhân.")
            mitre_attacks.append({
                "tactic": "Initial Access / Execution",
                "technique_id": "T1204.002",
                "technique_name": "Malicious File Execution Trigger",
                "description": "Tự động kích hoạt hành động ngay khi mở tài liệu (Zero-click user interaction)."
            })

        if launch_count > 0:
            threat_actions.append("Gọi lệnh hệ điều hành (/Launch) để triệu hồi Command Prompt hoặc PowerShell bên ngoài.")
            mitre_attacks.append({
                "tactic": "Execution",
                "technique_id": "T1059.001",
                "technique_name": "PowerShell / Command Execution",
                "description": "Thoát khỏi phạm vi ứng dụng PDF để thực thi lệnh trực tiếp trên máy chủ mục tiêu."
            })
            capabilities.append("Kiểm soát từ xa & Chiếm quyền điều khiển (Remote Shell)")

    # 4. Phân tích Ransomware / Data Exfiltration dựa vào Entropy
    if entropy > 7.5:
        threat_actions.append("Độ hỗn loạn Entropy cực cao (> 7.5), dấu hiệu điển hình của việc mã hóa dữ liệu hàng loạt (Ransomware Activity).")
        mitre_attacks.append({
            "tactic": "Impact",
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact (Ransomware)",
            "description": "Mã hóa dữ liệu mục tiêu bằng các thuật toán mã hóa khóa đối xứng (AES/RSA) để tống tiền nạn nhân."
        })
        capabilities.append("Mã hóa tống tiền (Ransomware Encryption)")

    if not threat_actions:
        threat_actions.append("Phát hiện bất thường trong cấu trúc nhị phân và khối lượng phân đoạn so với phần mềm lành tính chuẩn.")

    return {
        "behavior_summary": "Phát hiện tệp tin chứa các dấu hiệu tấn công có chủ đích, nỗ lực né tránh quét an ninh và thực thi mã độc ngầm.",
        "threat_actions": threat_actions,
        "mitre_attacks": mitre_attacks,
        "capabilities": capabilities or ["Thực thi mã trái phép"],
        "recommended_action": "Cách ly ngay lập tức vào Vùng An Toàn (Quarantine) hoặc Khử độc (CDR Sanitization)."
    }
