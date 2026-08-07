import io

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


def generate_pdf_report(data: dict) -> bytes:
    """Generate professional PDF assessment report buffer."""
    if not HAS_REPORTLAB:
        # Fallback simple text buffer if reportlab is absent
        text = f"CyberShield Security Assessment Report\nTarget: {data.get('target')}\nScore: {data.get('security_score')}\nRisk: {data.get('overall_risk')}\n"
        return text.encode("utf-8")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=12,
    )
    story.append(Paragraph("CyberShield Executive Security Report", title_style))
    story.append(Spacer(1, 10))

    # General info summary
    target = data.get("target", "Unknown Target")
    score = data.get("security_score", 0)
    risk = data.get("overall_risk", "Unknown")

    summary_text = f"<b>Target:</b> {target}<br/><b>Security Score:</b> {score}/100<br/><b>Overall Risk Level:</b> {risk}"
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 15))

    # Modules Table
    table_data = [["Assessment Module", "Status / Grade", "Risk Level"]]
    modules = data.get("modules", {})

    for key, name in [
        ("headers", "HTTP Security Headers"),
        ("ssl", "SSL/TLS Certificate"),
        ("dns", "DNS & Email Security"),
        ("ports", "Open Port Scan"),
        ("reputation", "Domain Reputation"),
        ("threatintel", "Threat Intelligence"),
        ("typosquatting", "Typosquatting Risk"),
        ("brand_detection", "Brand Impersonation"),
        ("whois", "WHOIS Registration"),
    ]:
        mod = modules.get(key, {})
        status = mod.get("grade") or mod.get("status") or mod.get("spf_status") or "Completed"
        risk_lvl = mod.get("overall_risk") or mod.get("risk") or mod.get("risk_level") or mod.get("threat_level") or "Low"
        table_data.append([name, str(status), str(risk_lvl)])

    t = Table(table_data, colWidths=[240, 150, 150])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # Issues / Findings
    story.append(Paragraph("Key Findings & Vulnerabilities", styles['Heading2']))
    story.append(Spacer(1, 8))
    issues = data.get("issues", [])
    if issues:
        for issue in issues:
            story.append(Paragraph(f"• {issue}", styles['Normal']))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No critical issues detected during this automated assessment.", styles['Normal']))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
