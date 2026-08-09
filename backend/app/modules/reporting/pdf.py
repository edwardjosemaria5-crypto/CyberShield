"""PDF report exporter for CyberShield.

Repaired to be robust on Windows and macOS:

- Fonts are resolved from the module directory, common OS font locations,
  and — only as an optional last resort — the font bundled with matplotlib.
  No dependency is *required*; when no Unicode TrueType font is loadable the
  report falls back to the built-in Helvetica base font and degrades
  characters it cannot render instead of failing or emitting corruption.
- Table column widths are computed from the actual printable width of the
  page (letter size minus the document margins) so content never overflows
  or clips.
- All layout is built from Platypus flowables (Paragraph/Table/Spacer) so
  long findings, recommendations and URLs wrap, split across pages
  naturally, and never need manual positioning.
"""

import io
import os
from xml.sax.saxutils import escape as _xml_escape

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ---------------------------------------------------------------------------
# Layout constants (letter = 612 x 792 pt)
# ---------------------------------------------------------------------------
_MARGIN = 0.8 * inch  # 57.6pt each side
PAGE_WIDTH = letter[0]
AVAILABLE_PAGE_WIDTH = PAGE_WIDTH - 2 * _MARGIN  # 496.8pt

# ---------------------------------------------------------------------------
# Font resolution: bundled -> known OS font paths -> optional matplotlib.
# PDF output must never fail just because a font file is missing.
# ---------------------------------------------------------------------------
_FONT_NAME = "Helvetica"
_HAS_UNICODE_FONT = False


def _find_unicode_font() -> str | None:
    """Return a path to a usable Unicode TrueType font, or None."""
    candidates = [
        os.path.join(os.path.dirname(__file__), "DejaVuSans.ttf"),
        os.path.join(os.path.dirname(__file__), "fonts", "DejaVuSans.ttf"),
        r"C:\Windows\Fonts\DejaVuSans.ttf",
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/System/Library/Fonts/DejaVuSans.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    try:
        import matplotlib

        candidates.append(
            os.path.join(os.path.dirname(matplotlib.__file__), "mpl-data", "fonts", "ttf", "DejaVuSans.ttf")
        )
    except Exception:
        pass
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


if REPORTLAB_AVAILABLE:
    _font_path = _find_unicode_font()
    if _font_path:
        try:
            pdfmetrics.registerFont(TTFont("ShieldUnicode", _font_path))
            pdfmetrics.registerFontFamily(
                "ShieldUnicode",
                normal="ShieldUnicode",
                bold="ShieldUnicode",
                italic="ShieldUnicode",
                boldItalic="ShieldUnicode",
            )
            _FONT_NAME = "ShieldUnicode"
            _HAS_UNICODE_FONT = True
        except Exception:
            _FONT_NAME = "Helvetica"
            _HAS_UNICODE_FONT = False


def _escape(value: object) -> str:
    """XML-escape untrusted text, so it is text, never markup."""
    text = str(value).replace("\x00", "\ufffd")
    return _xml_escape(text)


def _text_for_pdf(value: object) -> str:
    """Escape, clamp, and make a value renderable on the active font."""
    text = _escape(value)
    if len(text) > 4000:
        text = f"{text[:4000]}…"
    if not _HAS_UNICODE_FONT:
        text = text.encode("latin-1", "replace").decode("latin-1")
    return text


def _table_widths(ratios: list[float]) -> list[float]:
    """Distribute the available page width across columns by ratio."""
    total = sum(ratios)
    widths = [AVAILABLE_PAGE_WIDTH * (r / total) for r in ratios]
    widths[-1] = AVAILABLE_PAGE_WIDTH - sum(widths[:-1])
    return widths


def _summary_styles():
    base = getSampleStyleSheet()
    body = ParagraphStyle(
        "body",
        parent=base["Normal"],
        fontName=_FONT_NAME,
        fontSize=9.5,
        leading=13,
    )
    title = ParagraphStyle(
        "docTitle",
        parent=base["Heading1"],
        fontName=_FONT_NAME,
        fontSize=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    heading = ParagraphStyle(
        "section",
        parent=base["Heading2"],
        fontName=_FONT_NAME,
        fontSize=13,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=6,
    )
    cell = ParagraphStyle(
        "cell",
        parent=body,
        fontName=_FONT_NAME,
        fontSize=8.5,
        leading=11,
        splitLongWords=1,  # long URLs/evidence wrap instead of overflowing
    )
    return {"body": body, "title": title, "heading": heading, "cell": cell}


def _make_table(header, rows, cell_style, ratios):
    """Column widths always fit the page; cells are wrapping Paragraphs."""
    data = [header] + [list(r) for r in rows]
    wrapped = [[Paragraph(_text_for_pdf(c), cell_style) for c in row] for row in data]
    table = Table(
        wrapped,
        colWidths=_table_widths(ratios),
        repeatRows=1,
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8.5),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _find_module(data: dict, name: str) -> dict | None:
    """Return the module dict matching ``name`` from the response, or None."""
    for module in data.get("modules") or []:
        if module.get("module") == name:
            return module
    return None


def _threat_intel_blocks(data: dict) -> tuple[dict | None, list[dict]]:
    """Extract ``(correlation, signals)`` from the normalized threatintel
    module details; empty containers when the module or correlation is absent."""
    module = _find_module(data, "threatintel")
    details = (module or {}).get("details") or {}
    correlation = details.get("threat_intel_correlation")
    if not isinstance(correlation, dict):
        return None, []
    signals = [s for s in correlation.get("signals") or [] if isinstance(s, dict)]
    return correlation, signals


def generate_pdf_report(data: dict) -> bytes:
    """Generate a professional PDF assessment report from an AnalysisResponse.

    The input is treated strictly as untrusted data: every user-controlled
    value is escaped before reaching ReportLab's markup parser, and no value
    is ever used to derive a filesystem path. The output is a real PDF in
    memory; when ReportLab itself is absent we fail loudly rather than
    emitting a bytes blob that browsers would mistake for a valid PDF.
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("PDF export requires 'reportlab'; install it with pip install reportlab")

    styles = _summary_styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=_MARGIN,
        leftMargin=_MARGIN,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
    )
    story = []

    story.append(Paragraph("CyberShield Security Assessment Report", styles["title"]))
    story.append(Paragraph(f"Scan ID: {_text_for_pdf(data.get('scan_id', ''))}", styles["body"]))
    story.append(Spacer(1, 10))

    summary_rows = [
        ("Target", data.get("target", "Unknown Target")),
        ("Normalized URL", data.get("normalized_url", "")),
        ("Domain", data.get("domain", "")),
        ("Trust Score", f"{data.get('trust_score', 0)}/100"),
        ("Confidence", f"{data.get('confidence', 0)}/100"),
        ("Verdict", data.get("verdict", "Unknown")),
        ("Started", data.get("started_at", "")),
        ("Completed", data.get("completed_at", "")),
    ]
    story.append(_make_table(["Field", "Value"], summary_rows, styles["cell"], [0.28, 0.72]))
    story.append(Spacer(1, 6))

    summary = data.get("summary") or {}
    if isinstance(summary, dict):
        severity_summary = [
            ("Critical", summary.get("critical", 0)),
            ("High", summary.get("high", 0)),
            ("Medium", summary.get("medium", 0)),
            ("Low", summary.get("low", 0)),
            ("Info", summary.get("info", 0)),
        ]
        story.append(Paragraph("Findings Summary", styles["heading"]))
        story.append(
            _make_table(
                ["Severity", "Count"],
                severity_summary,
                styles["cell"],
                [0.28, 0.72],
            )
        )
    story.append(Spacer(1, 6))

    modules = data.get("modules") or []
    story.append(Paragraph("Module Results", styles["heading"]))
    if modules:
        module_rows = [
            (
                m.get("module", m.get("name", "Unknown")),
                m.get("score", ""),
                m.get("confidence", ""),
                m.get("status", ""),
                str(len(m.get("findings") or [])),
            )
            for m in modules
        ]
        story.append(
            _make_table(
                ["Module", "Score", "Confidence", "Status", "Findings"],
                module_rows,
                styles["cell"],
                [0.36, 0.14, 0.16, 0.18, 0.16],
            )
        )
    else:
        story.append(Paragraph("No module results were recorded.", styles["body"]))

    findings = data.get("findings") or []
    story.append(Paragraph(f"Key Findings ({len(findings)})", styles["heading"]))
    if findings:
        for index, finding in enumerate(findings, start=1):
            severity = _text_for_pdf(finding.get("severity", ""))
            title = _text_for_pdf(finding.get("title", ""))
            story.append(
                Paragraph(f"<b>{index}. [{severity.upper()}] {title}</b>", styles["cell"])
            )
            for label, key in (
                ("Description", "description"),
                ("Explanation", "explanation"),
                ("Recommendation", "recommendation"),
                ("Evidence", "evidence"),
            ):
                value = finding.get(key)
                if value:
                    story.append(
                        Paragraph(f"<b>{label}:</b> {_text_for_pdf(value)}", styles["cell"])
                    )
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No findings were recorded for this scan.", styles["body"]))

    correlation, signals = _threat_intel_blocks(data)
    if correlation:
        story.append(Paragraph("Threat Intelligence", styles["heading"]))
        correlation_rows = [
            ("Providers Available", correlation.get("available_count", 0)),
            ("Malicious Providers", correlation.get("malicious_count", 0)),
            ("Suspicious Providers", correlation.get("suspicious_count", 0)),
            ("Clean Providers", correlation.get("clean_count", 0)),
            ("Unavailable Providers", correlation.get("unavailable_count", 0)),
            ("Agreement", correlation.get("agreement", "")),
            ("Consensus", correlation.get("consensus", "")),
            ("Provider Conflict", "Yes" if correlation.get("conflict") else "No"),
            ("Malicious Confidence", correlation.get("malicious_confidence", 0)),
            ("Suspicious Confidence", correlation.get("suspicious_confidence", 0)),
        ]
        story.append(
            _make_table(
                ["Field", "Value"],
                correlation_rows,
                styles["cell"],
                [0.42, 0.58],
            )
        )
        if signals:
            signal_rows = [
                (
                    signal.get("provider", ""),
                    signal.get("status", ""),
                    "Yes" if signal.get("malicious") else "No",
                    "Yes" if signal.get("suspicious") else "No",
                    signal.get("confidence", 0),
                    ", ".join(str(c) for c in (signal.get("categories") or [])),
                )
                for signal in signals
            ]
            story.append(Spacer(1, 6))
            story.append(
                _make_table(
                    ["Provider", "Status", "Malicious", "Suspicious", "Confidence", "Categories"],
                    signal_rows,
                    styles["cell"],
                    [0.22, 0.14, 0.12, 0.12, 0.12, 0.28],
                )
            )

    ai = data.get("ai_explanation")
    if isinstance(ai, dict):
        story.append(Paragraph("AI Security Explanation", styles["heading"]))
        if ai.get("summary"):
            story.append(Paragraph(f"<b>Summary:</b> {_text_for_pdf(ai.get('summary'))}", styles["cell"]))
        if ai.get("why_risky"):
            story.append(Paragraph(f"<b>Why this assessment:</b> {_text_for_pdf(ai.get('why_risky'))}", styles["cell"]))
        for label, items in (
            ("Key risk factors", ai.get("key_risk_factors") or []),
            ("Recommended actions", ai.get("recommended_actions") or []),
        ):
            listed = [str(i) for i in items if i] if isinstance(items, list) else []
            if listed:
                story.append(Spacer(1, 4))
                story.append(Paragraph(f"<b>{label}:</b>", styles["cell"]))
                for item in listed:
                    story.append(Paragraph(f"• {_text_for_pdf(item)}", styles["cell"]))
        if ai.get("technical_explanation"):
            story.append(Spacer(1, 4))
            story.append(
                Paragraph(f"<b>Technical explanation:</b> {_text_for_pdf(ai.get('technical_explanation'))}", styles["cell"])
            )
        story.append(
            Paragraph(
                "<i>AI-generated text for informational purposes only; it does not affect the assessment.</i>",
                styles["cell"],
            )
        )

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()