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

# 3. Vùng An Toàn (Safe Vault Simulation)
# Lưu ý quan trọng: KHÔNG BAO GIỜ ghi chuỗi thô EICAR ra đĩa vì Windows Defender 
# sẽ tự động xóa file và hiện cảnh báo gây gián đoạn.
# Thay vào đó, tất cả mẫu mã độc thử nghiệm đều được mã hóa an toàn XOR 0x5A trong vault/.
print("[i] Tất cả mẫu thử nghiệm được bảo vệ an toàn, không kích hoạt Windows Defender.")
