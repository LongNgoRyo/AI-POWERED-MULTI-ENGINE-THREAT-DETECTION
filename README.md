# 🛡️ AI-POWERED MULTI-ENGINE THREAT DETECTION
### *Hệ Thống Nhận Diện & Phân Tích Mã Độc Đa Tầng Ứng Dụng Học Máy (Machine Learning)*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-Latest-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-Ensemble-red)](https://xgboost.ai/)
[![LightGBM](https://img.shields.io/badge/LightGBM-Gradient%20Boosting-brightgreen)](https://lightgbm.readthedocs.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-success?logo=github&logoColor=white)](https://longngoryo.github.io/AI-POWERED-MULTI-ENGINE-THREAT-DETECTION/)

> ### 🌐 **[TRẢI NGHIỆM WEB TRỰC TUYẾN TẠI ĐÂY (LIVE DEMO)](https://longngoryo.github.io/AI-POWERED-MULTI-ENGINE-THREAT-DETECTION/)**
> *Không cần cài đặt, không cần localhost — Hoạt động 100% trực tiếp trên GitHub Pages với Web Crypto & Client-Side Binary Parser.*

---

## 📌 Giới Thiệu Hệ Thống (Platform Overview)

**AI-POWERED MULTI-ENGINE THREAT DETECTION (MalwareGuardian AI v2.0)** là nền tảng **Giám Định An Ninh Mạng & Khắc Phục Sự Cố Mã Độc Tự Động**. Hệ thống được xây dựng theo kiến trúc **Bộ điều phối đa tầng (Multi-Engine AI Defense & Incident Response Pipeline)**, kết hợp giữa khả năng phát hiện độ chính xác cao và chu trình ứng cứu sự cố toàn diện.

Hệ thống tích hợp **3 Engine AI chuyên biệt**, bộ phân tích tĩnh (Static Analysis), đo lường độ hỗn loạn dữ liệu (Shannon Entropy), nhận diện giả mạo phần mở rộng (Extension Spoofing Detection), ánh xạ khung chuẩn **MITRE ATT&CK**, hòm cách ly an toàn **Quarantine Vault (Mã hóa XOR 0x5A)** và xuất báo cáo điều tra định dạng **PDF**.

---

## 🏗️ Kiến Trúc Hệ Thống (System Architecture)

```
                     [ Người Dùng Tải Lên / Chọn File Cần Quét ]
                                         │
                                         ▼
            ┌────────────────────────────────────────────────────────┐
            │  BƯỚC 1: XÁC THỰC MAGIC BYTES & ĐUÔI TỆP TIN          │
            │  - Kiểm tra Extension Spoofing (Ví dụ: file .docx.exe) │
            │  - Tính toán mã băm SHA-256 & MD5                      │
            │  - Đo độ hỗn loạn dữ liệu Shannon Entropy (0.0 - 8.0)  │
            └────────────────────────────┬───────────────────────────┘
                                         │
                    Phân luồng xử lý thông minh (Dispatcher)
                     ┌───────────────────┼───────────────────┐
                     ▼                   ▼                   ▼
             File Thực Thi       Tài Liệu PDF         Tiến Trình & Bộ Nhớ
            (.EXE, .DLL, .SYS)      (.PDF)              (Process Telemetry)
                     │                   │                   │
                     ▼                   ▼                   ▼
             [ ENGINE 1: PE ]    [ ENGINE 2: PDF ]   [ ENGINE 3: BEHAVIOR ]
             Random Forest       Random Forest       LightGBM (100k mẫu)
             Acc: 97.41%         Acc: 100.0%         Acc: 100.0%
                     │                   │                   │
                     └───────────────────┼───────────────────┘
                                         ▼
                 ┌───────────────────────────────────────────┐
                 │  PHÂN TÍCH HÀNH VI & KHUNG MITRE ATT&CK  │
                 │  - T1036 (Masquerading / Double Extension)│
                 │  - T1059 (JavaScript / Script Execution) │
                 │  - T1027 (Software Packing / Cryptor)     │
                 │  - T1486 (Data Encrypted / Ransomware)    │
                 └───────────────────────┬───────────────────┘
                                         │
                    Chu trình khắc phục sự cố (Incident Response)
                     ┌───────────────────┼───────────────────┐
                     ▼                   ▼                   ▼
             [ VÙNG AN TOÀN ]     [ KHỬ ĐỘC CDR ]     [ BÁO CÁO PDF ]
             Mã hóa XOR 0x5A      Bóc tách JS &       Xuất biên bản
             Chống Defender       OpenAction ra       giám định pháp y
             xóa nhầm file        tệp PDF sạch        chuẩn quốc tế
```

---

## 📊 Kết Quả Huấn Luyện & Đánh Giá Thực Nghiệm

### 1. Engine 1: Windows PE Header Static Analysis (`.exe`, `.dll`)
* **Tập dữ liệu:** 1.156 mẫu PE cân bằng (583 Benign, 573 Malware) với 25 đặc trưng cấu trúc (SizeOfCode, EntryPoint, Section Entropies, Imports, Exports...).
* **Kết quả:**

| Thuật toán | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| 🏆 **Random Forest** | **97.41%** | **95.80%** | **99.13%** | **97.44%** | **99.80%** |
| **XGBoost** | 97.41% | 95.80% | 99.13% | 97.44% | 99.68% |
| **LightGBM** | 97.41% | 95.80% | 99.13% | 97.44% | 99.74% |
| **Gradient Boosting** | 96.12% | 96.49% | 95.65% | 96.07% | 98.70% |

### 2. Engine 2: PDF Structure & Malicious Scripts (`.pdf`)
* **Tập dữ liệu:** 9.109 mẫu PDF trích xuất từ Contagio Malware Dump qua các công cụ PDFiD, PDF-parser với 27 đặc trưng cấu trúc (/JavaScript, /OpenAction, /XFA, Stream...).
* **Kỹ thuật xử lý:** Class-weight balancing (30.3x) xử lý mất cân bằng nhãn.
* **Kết quả:** Random Forest đạt **Accuracy 100.0%**, **F1-Score 1.0000**, **ROC-AUC 1.0000**.

### 3. Engine 3: Dynamic Process & Kernel Memory Telemetry
* **Tập dữ liệu:** 100.000 bản ghi giám sát 33 chỉ số tiến trình hệ điều hành (Virtual memory, Context switch, Page faults) cân bằng 50.000 malware - 50.000 benign.
* **Kết quả:** Mô hình LightGBM đạt **Accuracy 100.0%**, **F1-Score 1.0000**.

---

## 📈 Biểu Đồ Nghiên Cứu (Học Thuật 300 DPI)

Tất cả các biểu đồ đánh giá thực nghiệm đã được kết xuất sẵn trong thư mục [`reports/`](reports/):
- **Ma trận nhầm lẫn (Confusion Matrix):** `pe_confusion_matrix.png`, `pdf_confusion_matrix.png`, `behavior_confusion_matrix.png`
- **Đặc trưng quan trọng (Feature Importance):** `pe_feature_importance.png`, `pdf_feature_importance.png`, `behavior_feature_importance.png`
- **So sánh mô hình (Model Benchmark Comparison):** `pe_model_comparison.png`, `pdf_model_comparison.png`, `behavior_model_comparison.png`

---

## 📂 Cấu Trúc Thư Mục Dự Án

```text
├── data/                                 # 3 tập dữ liệu Kaggle đã tiền xử lý
│   ├── dataset_pe_windows.csv            # 1.156 mẫu Windows PE
│   ├── dataset_pdf_clean.csv             # 9.109 mẫu PDF
│   └── dataset_behavior_100k.csv         # 100.000 mẫu Hành vi tiến trình
├── models/                               # Các mô hình AI & danh sách đặc trưng đã lưu
│   ├── pe_detector_model.pkl & pe_features.json
│   ├── pdf_detector_model.pkl & pdf_features.json
│   └── behavior_detector_model.pkl & behavior_features.json
├── reports/                              # Biểu đồ nghiên cứu & Báo cáo sự cố PDF
│   ├── *.png                             # 9 biểu đồ nghiên cứu chất lượng cao (300 DPI)
│   └── security_incidents/               # Thư mục lưu biên bản pháp y PDF tự động
├── samples/                              # Các mẫu thử an toàn không gây kích hoạt Defender
│   ├── file_lanh_tinh.exe                # File PE hợp lệ chuẩn
│   ├── file_lanh_tinh.pdf                # File PDF chuẩn
│   ├── file_doc_hai_gia_mao.docx         # Mẫu kiểm thử giả mạo đuôi (Spoofed PE)
│   └── file_kiem_thu_mo_phong_doc_hai.pdf# Mẫu mô phỏng nhúng JS/OpenAction
├── src/                                  # Mã nguồn xử lý lõi
│   ├── feature_extractor.py              # Trích xuất đặc trưng PE & PDF
│   ├── scanner_engine.py                 # Bộ điều phối quét tập tin đa tầng
│   ├── remediation_engine.py             # Bộ khắc phục: MITRE ATT&CK, XOR Vault, CDR Disarm
│   ├── pdf_report_generator.py           # Tạo báo cáo giám định pháp y chuẩn PDF
│   ├── train_pe_model.py                 # Huấn luyện mô hình PE
│   ├── train_pdf_model.py                # Huấn luyện mô hình PDF
│   └── train_behavior_model.py           # Huấn luyện mô hình Hành vi 100k mẫu
├── vault/                                # Vùng an toàn cách ly tệp độc hại
│   └── quarantine/                       # Lưu tệp .quarantined mã hóa XOR 0x5A
├── web/                                  # Giao diện Web Application (FastAPI)
│   ├── app.py                            # FastAPI Web Server & REST API
│   ├── templates/index.html              # Giao diện Dark Cyber-Defense hiện đại
│   └── static/css/style.css & js/app.js  # Styling & Logic tương tác
├── index.html & static/                  # Phiên bản Standalone chạy tĩnh trên GitHub Pages
├── requirements.txt                      # Danh sách thư viện phụ thuộc
└── README.md                             # Tài liệu kỹ thuật hệ thống
```

---

## 🚀 Hướng Dẫn Cài Đặt & Chạy Thử Nghiệm

### 1. Yêu cầu môi trường
* Python 3.10 trở lên
* Hệ điều hành Windows / Linux / macOS

### 2. Cài đặt các thư viện cần thiết
```bash
git clone https://github.com/LongNgoRyo/AI-POWERED-MULTI-ENGINE-THREAT-DETECTION.git
cd AI-POWERED-MULTI-ENGINE-THREAT-DETECTION
pip install -r requirements.txt
```

### 3. Huấn luyện lại các mô hình (Nếu cần)
```bash
# Huấn luyện mô hình PE
python src/train_pe_model.py

# Huấn luyện mô hình PDF
python src/train_pdf_model.py

# Huấn luyện mô hình Hành vi 100k mẫu
python src/train_behavior_model.py
```

### 4. Khởi động Giao Diện Web Scanner
```bash
python -m uvicorn web.app:app --host 127.0.0.1 --port 8000
```
Truy cập trình duyệt tại: **`http://127.0.0.1:8000`** để bắt đầu kéo thả và quét file.

---

## 👨‍💻 Tác Giả & Bản Quyền
* **Đề tài:** Nhận Diện & Phân Tích Mã Độc Ứng Dụng Học Máy Đa Tầng
* **Repository:** [AI-POWERED-MULTI-ENGINE-THREAT-DETECTION](https://github.com/LongNgoRyo/AI-POWERED-MULTI-ENGINE-THREAT-DETECTION)
* **Giấy phép:** [MIT License](LICENSE)
