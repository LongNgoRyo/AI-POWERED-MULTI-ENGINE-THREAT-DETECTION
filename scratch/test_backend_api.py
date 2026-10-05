import urllib.request
import json
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

base_url = "http://127.0.0.1:8000"

print("1. Testing GET /api/system-status...")
req = urllib.request.urlopen(f"{base_url}/api/system-status")
print(json.loads(req.read().decode("utf-8")))

print("\n2. Testing GET /api/vault/list...")
req = urllib.request.urlopen(f"{base_url}/api/vault/list")
vault_res = json.loads(req.read().decode("utf-8"))
print(vault_res)

sample_pdf = os.path.abspath("samples/file_kiem_thu_mo_phong_doc_hai.pdf")
print(f"\n3. Testing POST /api/scan-path with sample PDF...")
data = json.dumps({"file_path": sample_pdf}).encode("utf-8")
req = urllib.request.Request(f"{base_url}/api/scan-path", data=data, headers={"Content-Type": "application/json"})
res = urllib.request.urlopen(req)
scan_data = json.loads(res.read().decode("utf-8"))
print("Detected Type:", scan_data.get("detected_type"))
print("Is Malicious:", scan_data.get("is_malicious"))
print("Risk Level:", scan_data.get("risk_level"))
print("SHA256:", scan_data.get("hashes", {}).get("sha256"))

print("\n4. Testing POST /api/remediate/quarantine...")
q_data = json.dumps({
    "file_path": "samples/test_quarantine_temp.pdf",
    "hashes": {"sha256": "test_sha256_hash_12345"}
}).encode("utf-8")
with open("samples/test_quarantine_temp.pdf", "w", encoding="utf-8") as f:
    f.write("DUMMY VIRUS PAYLOAD FOR VAULT TEST")

req = urllib.request.Request(f"{base_url}/api/remediate/quarantine", data=q_data, headers={"Content-Type": "application/json"})
res = urllib.request.urlopen(req)
q_res = json.loads(res.read().decode("utf-8"))
print("Quarantine Result:", q_res)

print("\n5. Testing GET /api/vault/list again...")
req = urllib.request.urlopen(f"{base_url}/api/vault/list")
vault_res2 = json.loads(req.read().decode("utf-8"))
print("Vault Items Count:", vault_res2.get("count"))
print("Vault Item 0 Original Name:", vault_res2.get("items", [{}])[0].get("original_name"))

print("\n6. Testing POST /api/vault/restore...")
r_data = json.dumps({
    "sha256": "test_sha256_hash_12345"
}).encode("utf-8")
req = urllib.request.Request(f"{base_url}/api/vault/restore", data=r_data, headers={"Content-Type": "application/json"})
res = urllib.request.urlopen(req)
restore_res = json.loads(res.read().decode("utf-8"))
print("Restore Result:", restore_res)
