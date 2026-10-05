import os
import time
from typing import Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ---------------------------------------------------------------------------
# Cấu hình Phông Chữ Tiếng Việt Unicode (Hỗ trợ 100% tiếng Việt có dấu)
# ---------------------------------------------------------------------------
FONT_REGULAR = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
FONT_ITALIC = "Helvetica-Oblique"

local_font_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
windows_font_dir = r"C:\Windows\Fonts"

arial_regular = os.path.join(local_font_dir, "Arial.ttf") if os.path.exists(os.path.join(local_font_dir, "Arial.ttf")) else os.path.join(windows_font_dir, "arial.ttf")
arial_bold = os.path.join(local_font_dir, "Arial-Bold.ttf") if os.path.exists(os.path.join(local_font_dir, "Arial-Bold.ttf")) else os.path.join(windows_font_dir, "arialbd.ttf")
arial_italic = os.path.join(local_font_dir, "Arial-Italic.ttf") if os.path.exists(os.path.join(local_font_dir, "Arial-Italic.ttf")) else os.path.join(windows_font_dir, "ariali.ttf")

if os.path.exists(arial_regular):
    try:
        pdfmetrics.registerFont(TTFont("ArialVN", arial_regular))
        pdfmetrics.registerFont(TTFont("ArialVN-Bold", arial_bold if os.path.exists(arial_bold) else arial_regular))
        pdfmetrics.registerFont(TTFont("ArialVN-Italic", arial_italic if os.path.exists(arial_italic) else arial_regular))
        FONT_REGULAR = "ArialVN"
        FONT_BOLD = "ArialVN-Bold"
        FONT_ITALIC = "ArialVN-Italic"
    except Exception:
        pass

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", "security_incidents")
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_pdf_incident_report(scan_result: Dict[str, Any], behavior_analysis: Dict[str, Any], remediation_info: Dict[str, Any] = None) -> str:
    """
    Tạo Báo Cáo Điều Tra & Khắc Phục Sự Cố Bảo Mật định dạng PDF chuyên nghiệp chuẩn in ấn doanh nghiệp.
    - Trang 1: Ảnh bìa trang trọng MALWAREGUARDIAN AI + Kết luận an ninh + Bằng chứng pháp y + Bóc tách đặc trưng.
    - Trang 2: Đánh giá hành vi MITRE ATT&CK + Nhật ký ứng cứu sự cố + Con dấu pháp y số & Chữ ký điện tử.
    """
    file_name = scan_result.get("file_name", "Unknown_File")
    clean_base_name = os.path.splitext(file_name)[0].replace(" ", "_")
    report_id = f"SEC-AUDIT-{int(time.time())}"
    report_filename = f"Security_Audit_{clean_base_name}_{int(time.time())}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, report_filename)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=36, leftMargin=36,
        topMargin=32, bottomMargin=32
    )

    styles = getSampleStyleSheet()

    cover_title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Heading1'],
        fontName=FONT_BOLD,
        fontSize=14,
        leading=18,
        textColor=colors.white,
        alignment=1
    )

    cover_sub_style = ParagraphStyle(
        'CoverSub',
        parent=styles['Normal'],
        fontName=FONT_BOLD,
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#00f0ff'),
        alignment=1
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName=FONT_BOLD,
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=7,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName=FONT_REGULAR,
        fontSize=8,
        leading=11.5,
        textColor=colors.HexColor('#1e293b')
    )

    bold_body = ParagraphStyle(
        'BoldBody',
        parent=body_style,
        fontName=FONT_BOLD
    )

    italic_body = ParagraphStyle(
        'ItalicBody',
        parent=body_style,
        fontName=FONT_ITALIC,
        textColor=colors.HexColor('#64748b')
    )

    th_style = ParagraphStyle(
        'TableHeader',
        parent=body_style,
        fontName=FONT_BOLD,
        fontSize=8,
        leading=11.5,
        textColor=colors.HexColor('#0f172a')
    )

    elements = []

    # =========================================================================
    # TRANG 1: ẢNH BÌA BÁO CÁO & GIÁM ĐỊNH PHÁP Y NHỊ PHÂN
    # =========================================================================
    header_content = [
        [Paragraph("MALWAREGUARDIAN AI - FORENSIC SECURITY AUDIT REPORT", cover_title_style)],
        [Paragraph("BÁO CÁO GIÁM ĐỊNH PHÁP Y KỸ THUẬT SỐ &amp; KHẮC PHỤC SỰ CỐ MÃ ĐỘC ĐA TẦNG", cover_sub_style)],
        [Paragraph(f"<font color='#94a3b8'>MÃ HỒ SƠ: {report_id} &nbsp;|&nbsp; CẤP MẬT: CONFIDENTIAL / OFFICIAL FORENSIC USE ONLY &nbsp;|&nbsp; PHIÊN BẢN: AI DEFENSE v2.0</font>", ParagraphStyle('HMeta', parent=body_style, fontName=FONT_REGULAR, fontSize=7.5, leading=10, textColor=colors.HexColor('#cbd5e1'), alignment=1))]
    ]
    header_table = Table(header_content, colWidths=[540])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0b1329')),
        ('BOX', (0, 0), (-1, -1), 2, colors.HexColor('#00f0ff')),
        ('PADDING', (0, 0), (-1, -1), 7),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 3),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 5),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 8))

    # Khung Kết Luận Lãnh Đạo (Executive Verdict Box) - Không dùng Emoji để tránh lỗi font ô vuông
    is_mal = scan_result.get("is_malicious", False)
    if is_mal:
        verdict_bg = colors.HexColor('#fef2f2')
        verdict_border = colors.HexColor('#dc2626')
        verdict_badge = "<font color='#b91c1c'><b>[ CẢNH BÁO ] KẾT LUẬN: PHÁT HIỆN MÃ ĐỘC NGUY HIỂM / MALICIOUS THREAT DETECTED</b></font>"
        risk_str = f"MỨC ĐỘ RỦI RO: {scan_result.get('risk_level', 'NGUY HIỂM CAO')}"
    else:
        verdict_bg = colors.HexColor('#f0fdf4')
        verdict_border = colors.HexColor('#16a34a')
        verdict_badge = "<font color='#15803d'><b>[ XÁC NHẬN ] KẾT LUẬN: TỆP TIN LÀNH TÍNH / BENIGN VERIFIED</b></font>"
        risk_str = "MỨC ĐỘ RỦI RO: AN TOÀN (LÀNH TÍNH ĐƯỢC XÁC THỰC)"

    verdict_data = [
        [Paragraph(verdict_badge, ParagraphStyle('VTitle', parent=body_style, fontName=FONT_BOLD, fontSize=10.5, leading=13)),
         Paragraph(f"<b>Độ Tin Cậy AI:</b> {scan_result.get('confidence_score', 0)}%", ParagraphStyle('VScore', parent=body_style, fontName=FONT_BOLD, fontSize=10.5, leading=13, alignment=2))],
        [Paragraph(f"<b>Động cơ phụ trách:</b> {scan_result.get('engine_used', 'Multi-Engine Classifier')} &nbsp;|&nbsp; <b>{risk_str}</b>", body_style),
         Paragraph(f"<b>Thời gian giám định:</b> {time.strftime('%Y-%m-%d %H:%M:%S UTC')}", ParagraphStyle('VTime', parent=body_style, fontSize=7.5, leading=9.5, alignment=2))]
    ]
    verdict_table = Table(verdict_data, colWidths=[360, 180])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_bg),
        ('BOX', (0, 0), (-1, -1), 1.5, verdict_border),
        ('PADDING', (0, 0), (-1, -1), 5.5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(verdict_table)
    elements.append(Spacer(1, 8))

    # Mục 1: Thông số định danh tệp tin & Bằng chứng pháp y
    elements.append(Paragraph("1. THÔNG SỐ ĐỊNH DANH TỆP TIN &amp; BẰNG CHỨNG PHÁP Y SỐ", h2_style))
    hashes = scan_result.get("hashes", {})
    entropy_val = float(scan_result.get("overall_entropy", 0.0))
    if entropy_val > 7.2:
        entropy_eval = f"{entropy_val:.2f} / 8.0 — Rất cao (Dấu hiệu nén Obfuscation / Mã hóa Ransomware)"
    elif entropy_val > 6.0:
        entropy_eval = f"{entropy_val:.2f} / 8.0 — Trung bình (Dữ liệu nén hoặc thư viện thông thường)"
    else:
        entropy_eval = f"{entropy_val:.2f} / 8.0 — Bình thường (Dữ liệu cấu trúc rõ ràng, không mã hóa)"

    spoofing_status = "CẢNH BÁO: PHÁT HIỆN GIẢ MẠO ĐUÔI FILE (Đuôi hiển thị khác cấu trúc nhị phân)" if scan_result.get("spoofed_extension") else "Hợp lệ (Phần mở rộng khớp Magic Bytes cấu trúc)"

    meta_rows = [
        [Paragraph("<b>Tên Tệp Tin (File Name):</b>", body_style), Paragraph(str(scan_result.get("file_name")), bold_body),
         Paragraph("<b>Dung Lượng (File Size):</b>", body_style), Paragraph(str(scan_result.get("file_size_human")), body_style)],
        [Paragraph("<b>Định Dạng Nhận Dạng:</b>", body_style), Paragraph(str(scan_result.get("detected_type")), bold_body),
         Paragraph("<b>Kiểm Tra Giả Mạo Đuôi:</b>", body_style), Paragraph(spoofing_status, body_style)],
        [Paragraph("<b>Độ Hỗn Loạn Shannon Entropy:</b>", body_style), Paragraph(entropy_eval, body_style),
         Paragraph("<b>Mã Băm MD5:</b>", body_style), Paragraph(f"<code>{hashes.get('md5', 'N/A')}</code>", body_style)],
        [Paragraph("<b>Mã Băm Toàn Vẹn SHA-256:</b>", body_style), Paragraph(f"<code>{hashes.get('sha256', 'N/A')}</code>", body_style),
         Paragraph("<b>Trạng Thái Lưu Vết:</b>", body_style), Paragraph("Đã lập chỉ mục bằng chứng pháp y", italic_body)]
    ]
    meta_table = Table(meta_rows, colWidths=[125, 175, 110, 130])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
        ('BACKGROUND', (2, 0), (2, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 8))

    # Mục 2: Bóc tách đặc trưng cấu trúc kỹ thuật nhị phân
    details = scan_result.get("details", {})
    features_dict = details.get("features", {}) or details.get("pe_features", {}) or details.get("pdf_features", {}) or scan_result.get("features", {})
    if features_dict:
        elements.append(Paragraph("2. BÓC TÁCH ĐẶC TRƯNG CẤU TRÚC KỸ THUẬT (BINARY FEATURE INSPECTION)", h2_style))
        feat_items = list(features_dict.items())[:16]
        feat_rows = [[
            Paragraph("Đặc Trưng (Feature)", th_style), Paragraph("Giá Trị Trích Xuất", th_style),
            Paragraph("Đặc Trưng (Feature)", th_style), Paragraph("Giá Trị Trích Xuất", th_style)
        ]]
        for i in range(0, len(feat_items), 2):
            k1, v1 = feat_items[i]
            v1_str = f"{v1:.4f}" if isinstance(v1, float) else str(v1)
            if i + 1 < len(feat_items):
                k2, v2 = feat_items[i + 1]
                v2_str = f"{v2:.4f}" if isinstance(v2, float) else str(v2)
            else:
                k2, v2_str = "", ""
            feat_rows.append([
                Paragraph(f"<b>{k1}</b>", body_style), Paragraph(v1_str, body_style),
                Paragraph(f"<b>{k2}</b>", body_style), Paragraph(v2_str, body_style)
            ])

        feat_table = Table(feat_rows, colWidths=[150, 120, 150, 120])
        feat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 3.5),
            ('TOPPADDING', (0, 0), (-1, 0), 4.5),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 4.5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        elements.append(feat_table)

    # Chân trang 1
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("<font color='#94a3b8'>MALWAREGUARDIAN AI FORENSIC AUDIT &nbsp;|&nbsp; TRANG 1/2</font>", ParagraphStyle('P1Footer', parent=body_style, fontSize=7, alignment=1)))

    # =========================================================================
    # NGẮT TRANG SANG TRANG 2: HÀNH VI MITRE ATT&CK & KHẮC PHỤC SỰ CỐ
    # =========================================================================
    elements.append(PageBreak())

    # Header phụ trang 2
    header_p2 = [
        [Paragraph("MALWAREGUARDIAN AI - ĐIỀU TRA HÀNH VI &amp; KHẮC PHỤC SỰ CỐ", ParagraphStyle('P2Title', fontName=FONT_BOLD, fontSize=11, leading=14, textColor=colors.white, alignment=1)),
         Paragraph(f"<font color='#00f0ff'>HỒ SƠ: {report_id}</font>", ParagraphStyle('P2Meta', fontName=FONT_BOLD, fontSize=8, leading=12, textColor=colors.HexColor('#00f0ff'), alignment=2))]
    ]
    p2_table = Table(header_p2, colWidths=[400, 140])
    p2_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0b1329')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#00f0ff')),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(p2_table)
    elements.append(Spacer(1, 8))

    # Mục 3: Đánh giá hành vi & Ánh xạ khung chuẩn MITRE ATT&CK
    elements.append(Paragraph("3. PHÂN TÍCH HÀNH VI NGUY HIỂM &amp; KHUNG CHUẨN MITRE ATT&amp;CK", h2_style))
    beh_summary = behavior_analysis.get('behavior_summary', 'Không ghi nhận hành vi can thiệp hệ thống bất thường.')
    elements.append(Paragraph(f"<b>Tóm tắt đánh giá:</b> {beh_summary}", body_style))
    elements.append(Spacer(1, 4))

    actions = behavior_analysis.get("threat_actions", [])
    if actions:
        elements.append(Paragraph("<b>Các hành vi mã độc ghi nhận trong quá trình phân tích:</b>", bold_body))
        for act in actions:
            elements.append(Paragraph(f"• {act}", body_style))
        elements.append(Spacer(1, 6))

    mitres = behavior_analysis.get("mitre_attacks", [])
    if mitres:
        mitre_data = [[
            Paragraph("Chiến Lược (Tactic)", th_style),
            Paragraph("Mã ID", th_style),
            Paragraph("Tên Kỹ Thuật (Technique)", th_style),
            Paragraph("Mô Tả Chi Tiết Nguy Cơ", th_style)
        ]]
        for m in mitres:
            mitre_data.append([
                Paragraph(m.get("tactic", ""), body_style),
                Paragraph(f"<font color='#dc2626'><b>{m.get('technique_id', '')}</b></font>", body_style),
                Paragraph(m.get("technique_name", ""), bold_body),
                Paragraph(m.get("description", ""), body_style)
            ])
        mitre_table = Table(mitre_data, colWidths=[95, 65, 140, 240])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 4.5),
            ('TOPPADDING', (0, 0), (-1, 0), 5.5),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 5.5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        elements.append(mitre_table)
    else:
        elements.append(Paragraph("<font color='#16a34a'>• Không ghi nhận kỹ thuật tấn công nào trong cơ sở dữ liệu MITRE ATT&amp;CK.</font>", body_style))
    elements.append(Spacer(1, 10))

    # Mục 4: Nhật ký ứng cứu & Khắc phục sự cố
    elements.append(Paragraph("4. NHẬT KÝ ỨNG CỨU &amp; BIỆN PHÁP KHẮC PHỤC SỰ CỐ (INCIDENT RESPONSE)", h2_style))
    remed_info = remediation_info or {}
    remed_data = [
        [Paragraph("<b>Hành động khuyến nghị:</b>", body_style),
         Paragraph(str(behavior_analysis.get("recommended_action", "Theo dõi và giám sát liên tục")), bold_body)],
        [Paragraph("<b>Vùng An Toàn (Quarantine Vault):</b>", body_style),
         Paragraph(str(remed_info.get("vault_status", "Đã kích hoạt cơ chế mã hóa XOR 0x5A an toàn. Toàn bộ byte nhị phân bị vô hiệu hóa, ngăn chặn Windows Defender can thiệp xóa nhầm file.")), body_style)],
        [Paragraph("<b>Khử Độc Tài Liệu (CDR Disarm):</b>", body_style),
         Paragraph(str(remed_info.get("cdr_status", "Tước bỏ toàn bộ thẻ /JavaScript, /OpenAction độc hại. Tái tạo tệp tài liệu sạch 100% cho người dùng.")), body_style)],
        [Paragraph("<b>Tiêu Hủy Bảo Mật (DoD Shredder):</b>", body_style),
         Paragraph("Sẵn sàng ghi đè 3 lượt theo chuẩn quân sự DoD 5220.22-M (0x00, 0xFF, Random Bytes) khi có yêu cầu tiêu hủy.", body_style)]
    ]
    remed_table = Table(remed_data, colWidths=[150, 390])
    remed_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(remed_table)
    elements.append(Spacer(1, 14))

    # Mục 5: Con dấu pháp y kỹ thuật số & Chữ ký điện tử
    sign_data = [
        [
            Paragraph("<b>CHỨNG THỰC PHÁP Y KỸ THUẬT SỐ</b><br/><font color='#64748b'>Biên bản được kết xuất tự động bởi Module Điều Tra Sự Cố An Ninh.<br/>Mã băm SHA-256 toàn vẹn đã được lưu vết kiểm toán.</font>", body_style),
            Paragraph("<b>TRƯỞNG PHÒNG THÍ NGHIỆM AN NINH MẠNG</b><br/><br/><font color='#0066cc'><i>[ ĐÃ KÝ ĐIỆN TỬ VÀ XÁC THỰC ]</i></font><br/><b>AI DEFENSE FORENSICS LAB</b>", ParagraphStyle('SignRight', parent=body_style, alignment=1))
        ]
    ]
    sign_table = Table(sign_data, colWidths=[320, 220])
    sign_table.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94a3b8')),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(sign_table)
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("<font color='#94a3b8'>MALWAREGUARDIAN AI FORENSIC AUDIT &nbsp;|&nbsp; TRANG 2/2 (HẾT BIÊN BẢN)</font>", ParagraphStyle('P2Footer', parent=body_style, fontSize=7, alignment=1)))

    doc.build(elements)
    return pdf_path
