import os
import time
from typing import Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", "security_incidents")
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_pdf_incident_report(scan_result: Dict[str, Any], behavior_analysis: Dict[str, Any], remediation_info: Dict[str, Any] = None) -> str:
    """
    Tạo Báo Cáo Điều Tra & Khắc Phục Sự Cố Bảo Mật định dạng PDF chuyên nghiệp chuẩn học thuật.
    """
    file_name = scan_result.get("file_name", "Unknown_File")
    clean_base_name = os.path.splitext(file_name)[0].replace(" ", "_")
    report_filename = f"Security_Audit_{clean_base_name}_{int(time.time())}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, report_filename)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=40, leftMargin=40,
        topMargin=40, bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        alignment=1 # Center
    )

    sub_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        alignment=1
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1e293b')
    )

    bold_body = ParagraphStyle(
        'BoldBody',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    elements = []

    # 1. Header
    elements.append(Paragraph("MALWAREGUARDIAN AI - FORENSIC SECURITY AUDIT REPORT", title_style))
    elements.append(Paragraph("HE THONG GIAM DINH AN NINH & KHAC PHUC SU CO MA DOC DA TANG", sub_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00f0ff'), spaceAfter=15))

    # 2. Executive Summary Box
    is_mal = scan_result.get("is_malicious", False)
    status_color = colors.HexColor('#dc2626') if is_mal else colors.HexColor('#16a34a')
    status_text = "PHAT HIEN NGUY HIEM / MALICIOUS THREAT" if is_mal else "AN TOAN / BENIGN VERIFIED"

    meta_data = [
        [Paragraph("<b>Ma So Bao Cao:</b>", body_style), Paragraph(f"SEC-AUDIT-{int(time.time())}", body_style),
         Paragraph("<b>Thoi Gian Giam Dinh:</b>", body_style), Paragraph(time.strftime("%Y-%m-%d %H:%M:%S UTC"), body_style)],
        [Paragraph("<b>Ket Luan An Ninh:</b>", bold_body), Paragraph(f"<font color='{status_color.hexval()}'><b>{status_text}</b></font>", bold_body),
         Paragraph("<b>Do Tin Cay AI:</b>", body_style), Paragraph(f"{scan_result.get('confidence_score', 0)}%", bold_body)],
        [Paragraph("<b>Dong Co AI Phu Trach:</b>", body_style), Paragraph(str(scan_result.get("engine_used", "Generic")), body_style),
         Paragraph("<b>Dinh Dang Tep:</b>", body_style), Paragraph(str(scan_result.get("detected_type", "Unknown")), body_style)]
    ]

    meta_table = Table(meta_data, colWidths=[120, 150, 110, 150])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 15))

    # 3. File Telemetry Table
    elements.append(Paragraph("1. THONG SO NHI PHAN & MA BAM XAC THUC", h2_style))
    hashes = scan_result.get("hashes", {})
    file_data = [
        [Paragraph("<b>Ten Tap Tin (File Name):</b>", body_style), Paragraph(str(scan_result.get("file_name")), body_style)],
        [Paragraph("<b>Kich Thuoc (File Size):</b>", body_style), Paragraph(str(scan_result.get("file_size_human")), body_style)],
        [Paragraph("<b>Do Hon Loan Shannon Entropy:</b>", body_style), Paragraph(f"{scan_result.get('overall_entropy', 0.0)} / 8.0", body_style)],
        [Paragraph("<b>Ma Bam SHA-256:</b>", body_style), Paragraph(str(hashes.get("sha256")), body_style)],
        [Paragraph("<b>Ma Bam MD5:</b>", body_style), Paragraph(str(hashes.get("md5")), body_style)],
        [Paragraph("<b>Gia Mao Duoi (Spoofing):</b>", body_style), Paragraph("CO NGUY HIEM" if scan_result.get("spoofed_extension") else "Khong phat hien", body_style)]
    ]
    file_table = Table(file_data, colWidths=[160, 370])
    file_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(file_table)
    elements.append(Spacer(1, 15))

    # 4. Threat Behavior & MITRE ATT&CK Mapping
    elements.append(Paragraph("2. PHAN TICH HANH VI & KHUNG MITRE ATT&CK", h2_style))
    elements.append(Paragraph(f"<b>Tong quan hanh vi:</b> {behavior_analysis.get('behavior_summary', '')}", body_style))
    elements.append(Spacer(1, 6))

    actions = behavior_analysis.get("threat_actions", [])
    if actions:
        elements.append(Paragraph("<b>Cac hanh vi ghi nhan:</b>", bold_body))
        for act in actions:
            elements.append(Paragraph(f"• {act}", body_style))
        elements.append(Spacer(1, 8))

    mitres = behavior_analysis.get("mitre_attacks", [])
    if mitres:
        mitre_data = [["Tactic", "Technique ID", "Technique Name", "Mo ta nguy co"]]
        for m in mitres:
            mitre_data.append([
                Paragraph(m.get("tactic", ""), body_style),
                Paragraph(f"<b>{m.get('technique_id', '')}</b>", body_style),
                Paragraph(m.get("technique_name", ""), body_style),
                Paragraph(m.get("description", ""), body_style)
            ])
        mitre_table = Table(mitre_data, colWidths=[80, 75, 130, 245])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(mitre_table)
    elements.append(Spacer(1, 15))

    # 5. Incident Remediation Status
    elements.append(Paragraph("3. HANH DONG KHAC PHUC SU CO (INCIDENT RESPONSE)", h2_style))
    remed_info = remediation_info or {}
    remed_data = [
        [Paragraph("<b>Hanh dong de xuat:</b>", body_style), Paragraph(str(behavior_analysis.get("recommended_action", "Theo doi he thong")), body_style)],
        [Paragraph("<b>Vung an toan (Quarantine Vault):</b>", body_style), Paragraph(str(remed_info.get("vault_status", "File duoc ma hoa XOR 0x5A an toan chong Defender xoa nham")), body_style)],
        [Paragraph("<b>Khu doc tai lieu (CDR Disarm):</b>", body_style), Paragraph(str(remed_info.get("cdr_status", "San sang tuoc bo script doc hai")), body_style)]
    ]
    remed_table = Table(remed_data, colWidths=[160, 370])
    remed_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(remed_table)
    elements.append(Spacer(1, 20))

    # 6. Forensic Stamp & Sign-off
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=10))
    elements.append(Paragraph("Bao cao duoc xuat tu dong boi Module Phap Y Kỹ Thuat So (Digital Forensics Engine) - MalwareGuardian AI", sub_style))

    doc.build(elements)
    return pdf_path
