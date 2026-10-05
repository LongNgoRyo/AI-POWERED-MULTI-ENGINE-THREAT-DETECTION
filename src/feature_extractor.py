import os
import math
import hashlib
import pefile
from typing import Dict, Any, Tuple

def calculate_shannon_entropy(data: bytes) -> float:
    """Tính độ hỗn loạn Shannon Entropy (0.0 đến 8.0) của một khối byte."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    for count in occurrences:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def calculate_file_hashes(file_path: str) -> Dict[str, str]:
    """Tính mã băm MD5 và SHA-256 của file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest()
    }

def detect_file_type(file_path: str) -> Dict[str, Any]:
    """
    Xác định định dạng file dựa trên Magic Bytes và Extension.
    Phát hiện Extension Spoofing (giả mạo đuôi file).
    """
    ext = os.path.splitext(file_path)[1].lower()
    file_size = os.path.getsize(file_path)

    with open(file_path, "rb") as f:
        header = f.read(16)

    # Magic Bytes nổi tiếng
    is_pe = header.startswith(b"MZ")
    is_pdf = header.startswith(b"%PDF")
    is_zip = header.startswith(b"PK\x03\x04")

    detected_type = "UNKNOWN"
    spoofed = False

    if is_pe:
        detected_type = "PE"
        if ext not in [".exe", ".dll", ".sys", ".scr", ".ocx"]:
            spoofed = True
    elif is_pdf:
        detected_type = "PDF"
        if ext != ".pdf":
            spoofed = True
    elif is_zip:
        detected_type = "ARCHIVE"
    else:
        detected_type = ext.replace(".", "").upper() if ext else "GENERIC"

    return {
        "detected_type": detected_type,
        "extension": ext,
        "is_pe": is_pe,
        "is_pdf": is_pdf,
        "spoofed_extension": spoofed,
        "size_bytes": file_size
    }

def extract_pe_features(file_path: str) -> Dict[str, Any]:
    """
    Trích xuất đúng 25 đặc trưng PE Header tương thích với mô hình AI đã huấn luyện.
    """
    pe = pefile.PE(file_path)
    
    # 1. Các thông số Optional Header & File Header
    size_of_code = getattr(pe.OPTIONAL_HEADER, 'SizeOfCode', 0)
    size_of_init_data = getattr(pe.OPTIONAL_HEADER, 'SizeOfInitializedData', 0)
    size_of_uninit_data = getattr(pe.OPTIONAL_HEADER, 'SizeOfUninitializedData', 0)
    entry_point = getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0)
    base_of_code = getattr(pe.OPTIONAL_HEADER, 'BaseOfCode', 0)
    base_of_data = getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0)
    image_base = getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0)
    dll_characteristics = getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0)
    size_of_image = getattr(pe.OPTIONAL_HEADER, 'SizeOfImage', 0)
    size_of_headers = getattr(pe.OPTIONAL_HEADER, 'SizeOfHeaders', 0)
    subsystem = getattr(pe.OPTIONAL_HEADER, 'Subsystem', 0)
    characteristics = getattr(pe.FILE_HEADER, 'Characteristics', 0)
    number_of_sections = getattr(pe.FILE_HEADER, 'NumberOfSections', len(pe.sections))

    # 2. Phân tích các Section
    entropies = []
    text_size = 0
    data_size = 0
    suspicious_section_names = 0
    standard_names = {".text", ".data", ".rdata", ".idata", ".edata", ".rsrc", ".reloc", ".pdata", ".tls"}

    for section in pe.sections:
        sec_name = section.Name.decode(errors="ignore").strip("\x00").lower()
        sec_data = section.get_data()
        sec_entropy = calculate_shannon_entropy(sec_data)
        entropies.append(sec_entropy)

        if sec_name not in standard_names:
            suspicious_section_names += 1

        if ".text" in sec_name:
            text_size = section.SizeOfRawData
        elif ".data" in sec_name:
            data_size = section.SizeOfRawData

    avg_entropy = float(sum(entropies) / len(entropies)) if entropies else 0.0
    max_entropy = float(max(entropies)) if entropies else 0.0
    min_entropy = float(min(entropies)) if entropies else 0.0

    # 3. Phân tích Imports & Exports
    imported_dlls = 0
    imported_functions = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        imported_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imported_functions += len(entry.imports)

    has_export = 1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
    exported_functions = 0
    if has_export:
        exported_functions = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

    # 4. Overlay Size (dữ liệu thừa gắn vào đuôi file, thường thấy ở mã độc/packer)
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
    except Exception:
        overlay_offset = None
    file_size = os.path.getsize(file_path)
    overlay_size = file_size - overlay_offset if overlay_offset is not None else 0
    if overlay_size < 0:
        overlay_size = 0

    pe.close()

    # Dictionary khớp 100% với tên cột huấn luyện
    return {
        "SizeOfCode": size_of_code,
        "SizeOfInitializedData": size_of_init_data,
        "SizeOfUninitializedData": size_of_uninit_data,
        "AddressOfEntryPoint": entry_point,
        "BaseOfCode": base_of_code,
        "BaseOfData": base_of_data,
        "ImageBase": image_base,
        "NumberOfSections": number_of_sections,
        "DllCharacteristics": dll_characteristics,
        "SizeOfImage": size_of_image,
        "SizeOfHeaders": size_of_headers,
        "Characteristics": characteristics,
        "Subsystem": subsystem,
        "SectionCount": len(pe.sections),
        "AvgSectionEntropy": avg_entropy,
        "MaxSectionEntropy": max_entropy,
        "MinSectionEntropy": min_entropy,
        "TextSectionSize": text_size,
        "DataSectionSize": data_size,
        "SuspiciousSectionNames": suspicious_section_names,
        "ImportedDLLs": imported_dlls,
        "ImportedFunctions": imported_functions,
        "HasExportTable": has_export,
        "ExportedFunctions": exported_functions,
        "OverlaySize": overlay_size
    }

def extract_pdf_features(file_path: str) -> Dict[str, Any]:
    """
    Trích xuất các đặc trưng cấu trúc PDF tương ứng với các thẻ PDFiD / PDF-parser.
    """
    with open(file_path, "rb") as f:
        content = f.read()

    size_kb = len(content) / 1024.0

    # Đếm số lượng các thẻ nhạy cảm
    def count_tag(tag_bytes: bytes) -> int:
        return content.count(tag_bytes)

    # Header length
    header_end = content.find(b"\n")
    header_length = header_end if header_end != -1 else 0

    features = {
        "/JS": count_tag(b"/JS"),
        "/JavaScript": count_tag(b"/JavaScript"),
        "startxref": count_tag(b"startxref"),
        "xref": count_tag(b"xref"),
        "obj": count_tag(b"obj"),
        "endobj": count_tag(b"endobj"),
        "stream": count_tag(b"stream"),
        "/OpenAction": count_tag(b"/OpenAction"),
        "/XFA": count_tag(b"/XFA"),
        "Filesize_kb": size_kb,
        "MetadataStream": count_tag(b"/Metadata"),
        "Optimized": 1 if b"/Linearized" in content else 0,
        "Pages": count_tag(b"/Type /Page") or count_tag(b"/Type/Page"),
        "/Size": count_tag(b"/Size"),
        "%EOF": count_tag(b"%%EOF"),
        "/Producer": count_tag(b"/Producer"),
        "/ProcSet": count_tag(b"/ProcSet"),
        "/ID": count_tag(b"/ID"),
        "/S": count_tag(b"/S"),
        "/CreationDate": count_tag(b"/CreationDate"),
        "/Info": count_tag(b"/Info"),
        "/Font": count_tag(b"/Font"),
        "/XML": count_tag(b"/XML"),
        "/Rect": count_tag(b"/Rect"),
        "Referencing": count_tag(b"R "),
        "Headerlength": header_length,
        "small_content": 1 if size_kb < 10 else 0,
        "Malicecontent": 1 if (count_tag(b"/JavaScript") > 0 or count_tag(b"/Launch") > 0 or count_tag(b"/OpenAction") > 0) else 0
    }
    return features
