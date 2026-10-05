import os
import sys
import io
import shutil
import json

# Dam bao terminal Windows khong bi loi ma hoa font Unicode/Emoji
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import pandas as pd

# Chen thu muc goc vao sys.path de import cac module trong src
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.scanner_engine import UnifiedMalwareScanner

app = FastAPI(
    title="MalwareGuardian AI API",
    description="Backend API cho hệ thống nhận diện mã độc đa tầng",
    version="2.0.0"
)

# Khoi tao bo quet toan dien
scanner = UnifiedMalwareScanner(models_dir=os.path.join(BASE_DIR, "models"))

# Static directories
STATIC_DIR = os.path.join(BASE_DIR, "web", "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "web", "templates")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
TEMP_DIR = os.path.join(BASE_DIR, "web", "temp")

os.makedirs(TEMP_DIR, exist_ok=True)

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

if os.path.exists(REPORTS_DIR):
    app.mount("/reports", StaticFiles(directory=REPORTS_DIR), name="reports")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = os.path.join(TEMPLATES_DIR, "index.html")
    if not os.path.exists(index_file):
        raise HTTPException(status_code=404, detail="index.html not found")
    with open(index_file, "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/scan-upload")
async def scan_uploaded_file(file: UploadFile = File(...)):
    """API nhan file upload tu trinh duyet va quet phan tich."""
    try:
        temp_file_path = os.path.join(TEMP_DIR, file.filename)
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Chay bo quet da dinh dang
        scan_result = scanner.scan_file(temp_file_path)

        # Xoa file tam sau khi quet xong de bao mat
        try:
            os.remove(temp_file_path)
        except Exception:
            pass

        return JSONResponse(content=scan_result)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

class ScanPathRequest(BaseModel):
    file_path: str

@app.post("/api/scan-path")
async def scan_local_path(req: ScanPathRequest):
    """API quet file truc tiep qua duong dan tren may tinh."""
    target_path = req.file_path.strip().strip('"').strip("'")
    if not os.path.exists(target_path):
        return JSONResponse(status_code=404, content={"error": f"Tệp tin không tồn tại: {target_path}"})
    
    try:
        scan_result = scanner.scan_file(target_path)
        return JSONResponse(content=scan_result)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

class BehaviorSimRequest(BaseModel):
    total_vm: float = 150.0
    exec_vm: float = 124.0
    shared_vm: float = 120.0
    map_count: float = 6850.0
    nvcsw: float = 341974.0
    min_flt: float = 0.0
    maj_flt: float = 120.0
    utime: float = 380690.0
    prio: float = 3069378560.0

@app.post("/api/simulate-behavior")
async def simulate_process_behavior(req: BehaviorSimRequest):
    """API du doan hanh vi tien trinh dua tren model 100k."""
    if not scanner.beh_model or not scanner.beh_features:
        return JSONResponse(content={
            "is_malicious": False,
            "confidence_score": 50.0,
            "risk_level": "Mô hình hành vi chưa sẵn sàng"
        })

    # Tao dictionary cac dac trung voi gia tri mac dinh
    feat_dict = {f: 0 for f in scanner.beh_features}
    feat_dict.update({
        "total_vm": req.total_vm,
        "exec_vm": req.exec_vm,
        "shared_vm": req.shared_vm,
        "map_count": req.map_count,
        "nvcsw": req.nvcsw,
        "min_flt": req.min_flt,
        "maj_flt": req.maj_flt,
        "utime": req.utime,
        "prio": req.prio
    })

    df_in = pd.DataFrame([feat_dict])[scanner.beh_features]
    pred = scanner.beh_model.predict(df_in)[0]
    prob = scanner.beh_model.predict_proba(df_in)[0]

    is_mal = bool(pred == 1)
    confidence = float(prob[1] if is_mal else prob[0]) * 100.0

    return JSONResponse(content={
        "is_malicious": is_mal,
        "confidence_score": round(confidence, 2),
        "risk_level": "MÃ ĐỘC TIẾN TRÌNH" if is_mal else "TIẾN TRÌNH LÀNH TÍNH",
        "probabilities": {
            "benign": round(float(prob[0]) * 100, 2),
            "malware": round(float(prob[1]) * 100, 2)
        }
    })

@app.get("/api/system-status")
async def get_system_status():
    return {
        "status": "ONLINE",
        "engines": {
            "pe_header_model": scanner.pe_model is not None,
            "pdf_structure_model": scanner.pdf_model is not None,
            "behavior_100k_model": scanner.beh_model is not None
        }
    }

if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 60)
    print("🚀 KHỞI ĐỘNG MÁY CHỦ MALWAREGUARDIAN AI...")
    print("🌐 Truy cập Web App tại: http://127.0.0.1:8000")
    print("=" * 60 + "\n")
    uvicorn.run("web.app:app", host="127.0.0.1", port=8000, reload=False)
