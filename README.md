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

## 📌 Giới Thiệu Đồ Án (Project Overview)

**AI-POWERED MULTI-ENGINE THREAT DETECTION (MalwareGuardian AI)** là đồ án môn học cuối kỳ về **An Toàn Thông Tin & Ứng Dụng Trí Tuệ Nhân Tạo**. Hệ thống được xây dựng theo kiến trúc **Bộ điều phối đa tầng (Multi-Engine AI Defense Pipeline)**, khắc phục nhược điểm của các giải pháp truyền thống chỉ quét được một định dạng file cố định.

Hệ thống tích hợp **3 Engine AI chuyên biệt** cùng bộ phân tích tĩnh (Static Analysis), đo lường độ hỗn loạn dữ liệu (Shannon Entropy) và nhận diện giả mạo phần mở rộng (Extension Spoofing Detection) theo thời gian thực.

---

## 🏗️ Kiến Trúc Hệ Thống (System Architecture)

```
                     [ Người Dùng Tải Lên / Chọn File Cần Quét ]
                                         │
                                         ▼
            ┌────────────────────────────────────────────────────────┐
            │  BƯỚC 1: XÁC THỰC MAGIC BYTES & ĐUÔI TỆP TIN          │
            │  - Kiểm tra Extension Spoofing (Ví dụ: file .pdf.exe)  │
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
                 │  BÁO CÁO BẢO MẬT & TRỰC QUAN HÓA WEB      │
                 │  - Kết luận: Safe / Suspicious / Malware │
                 │  - Điểm số độ tin cậy AI (Confidence %)   │
                 │  - Bảng bóc tách 25-33 thông số kỹ thuật  │
                 │  - Xuất báo cáo chuẩn JSON                │
                 └───────────────────────────────────────────┘
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
├── reports/                              # Trọn bộ 9 biểu đồ nghiên cứu chất lượng cao
├── src/                                  # Mã nguồn xử lý lõi
│   ├── feature_extractor.py              # Trích xuất đặc trưng PE (.exe) & PDF từ file thật
│   ├── scanner_engine.py                 # Bộ điều phối quét tập tin đa tầng
│   ├── train_pe_model.py                 # Huấn luyện mô hình PE
│   ├── train_pdf_model.py                # Huấn luyện mô hình PDF
│   └── train_behavior_model.py           # Huấn luyện mô hình Hành vi 100k mẫu
├── web/                                  # Giao diện Web Application
│   ├── app.py                            # FastAPI Web Server
│   ├── templates/index.html              # Giao diện Dark Cyber-Defense hiện đại
│   └── static/css/style.css & js/app.js  # Styling & Logic tương tác
├── requirements.txt                      # Danh sách thư viện phụ thuộc
├── test_scanner.py                       # Script kiểm thử quét file trực tiếp
└── README.md                             # Tài liệu báo cáo dự án
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
