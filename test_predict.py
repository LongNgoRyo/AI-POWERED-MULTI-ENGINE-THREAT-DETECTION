import os
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import joblib
import json
import pandas as pd
from src.feature_extractor import extract_pe_features, calculate_file_hashes, detect_file_type

test_file = r"C:\Windows\System32\cmd.exe"
if not os.path.exists(test_file):
    test_file = r"C:\Windows\explorer.exe"

print(f"[*] Kiểm tra thử nghiệm trên file thực tế: {test_file}")
info = detect_file_type(test_file)
hashes = calculate_file_hashes(test_file)
features = extract_pe_features(test_file)

print(f"[*] Định dạng phát hiện: {info['detected_type']} (Giả mạo: {info['spoofed_extension']})")
print(f"[*] SHA-256: {hashes['sha256']}")
print(f"[*] MD5: {hashes['md5']}")
print(f"[*] Entropy trung bình các section: {features['AvgSectionEntropy']:.2f}")

# Nạp model
model = joblib.load("models/pe_detector_model.pkl")
with open("models/pe_features.json", "r", encoding="utf-8") as f:
    feature_names = json.load(f)

df_input = pd.DataFrame([features])[feature_names]
pred = model.predict(df_input)[0]
prob = model.predict_proba(df_input)[0]

result_str = "MÃ ĐỘC (MALWARE)" if pred == 1 else "AN TOÀN / LÀNH TÍNH (BENIGN)"
print(f"\n🎯 KẾT QUẢ DỰ ĐOÁN CỦA AI: {result_str}")
print(f"📊 Độ tin cậy (An toàn / Mã độc): {prob[0]*100:.2f}% / {prob[1]*100:.2f}%")
