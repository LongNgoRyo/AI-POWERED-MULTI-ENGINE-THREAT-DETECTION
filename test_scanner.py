import os
import sys
import io
import json

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from src.scanner_engine import UnifiedMalwareScanner

scanner = UnifiedMalwareScanner()

# Test 1: Windows PE
notepad_path = r"C:\Windows\System32\notepad.exe"
if not os.path.exists(notepad_path):
    notepad_path = r"C:\Windows\notepad.exe"

res1 = scanner.scan_file(notepad_path)
print("=== Test 1: PE File ===")
print(f"File: {res1['file_name']} | Engine: {res1['engine_used']}")
print(f"Verdict: {res1['risk_level']} (Độ tin cậy: {res1['confidence_score']}%)")
print(f"SHA-256: {res1['hashes']['sha256']}")

# Test 2: Real PDF
pdf_path = r"C:\Users\LONG NGO\Downloads\Multi_Task_Tabular_Ensemble_for_PE_Malware_Triage_and_Family_Attribution__6_.pdf"
if os.path.exists(pdf_path):
    res2 = scanner.scan_file(pdf_path)
    print("\n=== Test 2: PDF File ===")
    print(f"File: {res2['file_name']} | Engine: {res2['engine_used']}")
    print(f"Verdict: {res2['risk_level']} (Độ tin cậy: {res2['confidence_score']}%)")
    print(f"SHA-256: {res2['hashes']['sha256']}")
