import os
import json
import joblib
import pandas as pd
from typing import Dict, Any

from src.feature_extractor import (
    detect_file_type,
    calculate_file_hashes,
    calculate_shannon_entropy,
    extract_pe_features,
    extract_pdf_features
)

class UnifiedMalwareScanner:
    """
    Engine quét và nhận diện mã độc đa định dạng (Multi-Engine AI Scanner).
    Tự động điều phối file theo định dạng và áp dụng mô hình AI tương ứng.
    """
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self.pe_model = None
        self.pe_features = []
        self.pdf_model = None
        self.pdf_features = []
        self._load_models()

    def _load_models(self):
        # 1. Nạp PE Model
        pe_model_path = os.path.join(self.models_dir, "pe_detector_model.pkl")
        pe_feat_path = os.path.join(self.models_dir, "pe_features.json")
        if os.path.exists(pe_model_path) and os.path.exists(pe_feat_path):
            try:
                self.pe_model = joblib.load(pe_model_path)
                with open(pe_feat_path, "r", encoding="utf-8") as f:
                    self.pe_features = json.load(f)
                print("[✓] Đã nạp thành công PE Malware Model.")
            except Exception as e:
                print(f"[!] Lỗi khi nạp PE Model: {e}")

        # 2. Nạp PDF Model
        pdf_model_path = os.path.join(self.models_dir, "pdf_detector_model.pkl")
        pdf_feat_path = os.path.join(self.models_dir, "pdf_features.json")
        if os.path.exists(pdf_model_path) and os.path.exists(pdf_feat_path):
            try:
                self.pdf_model = joblib.load(pdf_model_path)
                with open(pdf_feat_path, "r", encoding="utf-8") as f:
                    self.pdf_features = json.load(f)
                print("[✓] Đã nạp thành công PDF Malware Model.")
            except Exception as e:
                print(f"[!] Lỗi khi nạp PDF Model: {e}")

        # 3. Nạp Behavior Model (100.000 mẫu)
        beh_model_path = os.path.join(self.models_dir, "behavior_detector_model.pkl")
        beh_feat_path = os.path.join(self.models_dir, "behavior_features.json")
        self.beh_model = None
        self.beh_features = []
        if os.path.exists(beh_model_path) and os.path.exists(beh_feat_path):
            try:
                self.beh_model = joblib.load(beh_model_path)
                with open(beh_feat_path, "r", encoding="utf-8") as f:
                    self.beh_features = json.load(f)
                print("[✓] Đã nạp thành công Behavior/Memory Malware Model (100.000 mẫu).")
            except Exception as e:
                print(f"[!] Lỗi khi nạp Behavior Model: {e}")

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Quét và phân tích toàn diện một file bất kỳ trên hệ thống."""
        if not os.path.exists(file_path):
            return {"error": f"Không tìm thấy file: {file_path}"}

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        type_info = detect_file_type(file_path)
        hashes = calculate_file_hashes(file_path)

        # Tính tổng thể file entropy
        with open(file_path, "rb") as f:
            raw_sample = f.read(256 * 1024) # Đọc tối đa 256KB đầu để đo entropy nhanh
        overall_entropy = calculate_shannon_entropy(raw_sample)

        result = {
            "file_name": file_name,
            "file_size": file_size,
            "file_size_human": f"{file_size / 1024:.2f} KB" if file_size < 1024*1024 else f"{file_size / (1024*1024):.2f} MB",
            "detected_type": type_info["detected_type"],
            "extension": type_info["extension"],
            "spoofed_extension": type_info["spoofed_extension"],
            "hashes": hashes,
            "overall_entropy": round(overall_entropy, 3),
            "engine_used": None,
            "is_malicious": False,
            "confidence_score": 0.0,
            "risk_level": "AN TOÀN",
            "details": {}
        }

        # CẢNH BÁO NGUY HIỂM NGAY LẬP TỨC: Giả mạo đuôi file
        if type_info["spoofed_extension"]:
            result["is_malicious"] = True
            result["confidence_score"] = 99.9
            result["risk_level"] = "NGUY HIỂM CAO (GIẢ MẠO ĐUÔI FILE)"
            result["details"]["spoofing_warning"] = (
                f"Phát hiện tệp tin giả mạo! Đuôi file hiển thị là '{type_info['extension']}' "
                f"nhưng cấu trúc nhị phân thực tế là '{type_info['detected_type']}'!"
            )
            return result

        # -----------------------------------------------------------------
        # Nhánh 1: File thực thi PE (EXE / DLL / SYS / SCR)
        # -----------------------------------------------------------------
        if type_info["is_pe"]:
            result["engine_used"] = "AI PE Header Classifier"
            try:
                pe_feats = extract_pe_features(file_path)
                result["details"]["pe_features"] = pe_feats

                if self.pe_model and self.pe_features:
                    df_in = pd.DataFrame([pe_feats])[self.pe_features]
                    pred = self.pe_model.predict(df_in)[0]
                    prob = self.pe_model.predict_proba(df_in)[0]

                    is_mal = bool(pred == 1)
                    confidence = float(prob[1] if is_mal else prob[0]) * 100.0

                    result["is_malicious"] = is_mal
                    result["confidence_score"] = round(confidence, 2)
                    result["risk_level"] = "MÃ ĐỘC NGUY HIỂM" if is_mal else "AN TOÀN / LÀNH TÍNH"
                else:
                    result["details"]["note"] = "PE Model chưa được nạp, chỉ phân tích tĩnh."
            except Exception as e:
                result["details"]["error"] = f"Lỗi bóc tách PE: {str(e)}"

        # -----------------------------------------------------------------
        # Nhánh 2: File tài liệu PDF
        # -----------------------------------------------------------------
        elif type_info["is_pdf"]:
            result["engine_used"] = "AI PDF Structure Analyzer"
            try:
                pdf_feats = extract_pdf_features(file_path)
                result["details"]["pdf_features"] = pdf_feats

                if self.pdf_model and self.pdf_features:
                    df_in = pd.DataFrame([pdf_feats])[self.pdf_features]
                    pred = self.pdf_model.predict(df_in)[0]
                    prob = self.pdf_model.predict_proba(df_in)[0]
                    is_mal = bool(pred == 1)
                    confidence = float(prob[1] if is_mal else prob[0]) * 100.0

                    result["is_malicious"] = is_mal
                    result["confidence_score"] = round(confidence, 2)
                    result["risk_level"] = "MÃ ĐỘC PDF" if is_mal else "TÀI LIỆU AN TOÀN"
                else:
                    # Heuristic Engine cho PDF nếu chưa train model PDF
                    js_count = pdf_feats.get("/JavaScript", 0) + pdf_feats.get("/JS", 0)
                    oa_count = pdf_feats.get("/OpenAction", 0)
                    if js_count > 0 or oa_count > 0:
                        result["is_malicious"] = True
                        result["confidence_score"] = 85.0
                        result["risk_level"] = "NGHI VẤN ĐỘC HẠI (CHỨA MÃ NHÚNG)"
                        result["details"]["heuristic"] = f"Phát hiện {js_count} đoạn JS và {oa_count} thẻ OpenAction tự động kích hoạt."
                    else:
                        result["is_malicious"] = False
                        result["confidence_score"] = 95.0
                        result["risk_level"] = "TÀI LIỆU AN TOÀN"
            except Exception as e:
                result["details"]["error"] = f"Lỗi phân tích PDF: {str(e)}"

        # -----------------------------------------------------------------
        # Nhánh 3: Các loại file khác (Generic Heuristic Engine)
        # -----------------------------------------------------------------
        else:
            result["engine_used"] = "Generic Heuristic & Entropy Engine"
            # Nếu entropy > 7.2 đối với file tài liệu/text thông thường -> Dấu hiệu mã hóa Ransomware
            if overall_entropy > 7.5:
                result["is_malicious"] = True
                result["confidence_score"] = 80.0
                result["risk_level"] = "ĐỘ HỖN LOẠN DỮ LIỆU CAO (NGHI VẤN MÃ HÓA/RANSOMWARE)"
            else:
                result["is_malicious"] = False
                result["confidence_score"] = 90.0
                result["risk_level"] = "AN TOÀN"

        return result
