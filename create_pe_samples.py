import os
import shutil

samples_dir = "samples"
os.makedirs(samples_dir, exist_ok=True)

# 1. File EXE Lành Tính (.exe chuẩn hợp lệ của Windows)
src_exe = r"C:\Windows\System32\whoami.exe"
dst_clean_exe = os.path.join(samples_dir, "file_lanh_tinh.exe")
shutil.copyfile(src_exe, dst_clean_exe)
print(f"[1] Da tao file EXE Lanh Tinh: {dst_clean_exe}")

# 2. File Giả Mạo Đuôi (Extension Spoofing - Kỹ thuật mã độc phổ biến)
# Đây là file thực thi PE nhị phân nhưng được cố tình đổi đuôi thành .docx / .jpg
# để lừa người dùng bấm mở. AI sẽ quét trúng Magic Bytes 'MZ' và cảnh báo nguy hiểm ngay!
dst_spoofed = os.path.join(samples_dir, "file_doc_hai_gia_mao.docx")
shutil.copyfile(src_exe, dst_spoofed)
print(f"[2] Da tao file Gia Mao Duoi Doc Hai: {dst_spoofed}")

# 3. Chuẩn Kiểm Thử Antivirus Quốc Tế EICAR (Hoàn toàn an toàn, chuẩn bảo mật)
eicar_str = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
eicar_file = os.path.join(samples_dir, "eicar_antivirus_test.com")
with open(eicar_file, "wb") as f:
    f.write(eicar_str)
print(f"[3] Da tao file chuan kiem thu EICAR: {eicar_file}")
