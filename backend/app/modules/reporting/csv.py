import csv
import io


def _cell(value: object) -> str:
    """Flatten a value for CSV output, guarding against injection."""
    text = str(value) if value is not None else ""
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        text = f"'{text}"
    return text


def generate_csv_report(analysis) -> str:
    """Generate a CSV report from a CyberShield ``AnalysisResponse``.

    Rows follow a ``Category,Key,Value`` shape so spreadsheet tools can
    pivot on the first column. Cells that could be interpreted as formulas
    are prefixed with an apostrophe to prevent CSV formula injection.

    Covers the full report surface: general fields, severity summary,
    findings (including explanation/confidence), module states, the
    threat-intelligence correlation block with per-provider signals, and
    the optional AI explanation.
    """
    if hasattr(analysis, "model_dump"):
        data = analysis.model_dump(mode="json")
    else:
        data = analysis

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Category", "Key", "Value"])

    writer.writerow(["General", "Scan ID", _cell(data.get("scan_id", "N/A"))])
    writer.writerow(["General", "Target URL", _cell(data.get("target", "N/A"))])
    writer.writerow(["General", "Normalized URL", _cell(data.get("normalized_url", "N/A"))])
    writer.writerow(["General", "Domain", _cell(data.get("domain", "N/A"))])
    writer.writerow(["General", "Trust Score", _cell(data.get("trust_score", 0))])
    writer.writerow(["General", "Confidence", _cell(data.get("confidence", 0))])
    writer.writerow(["General", "Verdict", _cell(data.get("verdict", "N/A"))])

    summary = data.get("summary") or {}
    if isinstance(summary, dict):
        for severity in ("critical", "high", "medium", "low", "info"):
            writer.writerow(["Summary", severity.capitalize(), _cell(summary.get(severity, 0))])

    for finding in data.get("findings", []) or []:
        writer.writerow(["Finding", "Severity", _cell(finding.get("severity", ""))])
        writer.writerow(["Finding", "Title", _cell(finding.get("title", ""))])
        writer.writerow(["Finding", "Description", _cell(finding.get("description", ""))])
        writer.writerow(["Finding", "Explanation", _cell(finding.get("explanation", ""))])
        writer.writerow(["Finding", "Confidence", _cell(finding.get("confidence", ""))])
        writer.writerow(["Finding", "Recommendation", _cell(finding.get("recommendation", ""))])
        writer.writerow(["Finding", "Evidence", _cell(finding.get("evidence", ""))])

    for module in data.get("modules", []) or []:
        writer.writerow(
            [
                "Module",
                _cell(module.get("module", "")),
                f"{_cell(module.get('status', ''))} / {_cell(module.get('score', ''))} / {_cell(module.get('confidence', ''))}",
            ]
        )
        for finding in module.get("findings", []) or []:
            writer.writerow(["Module Finding", _cell(finding.get("title", "")), _cell(finding.get("severity", ""))])

        if module.get("module") == "threatintel":
            _write_threat_intel(writer, module.get("details"))

    _write_ai_explanation(writer, data.get("ai_explanation"))

    return output.getvalue()


def _write_threat_intel(writer: "csv._writer", details: object) -> None:
    """Emit the normalized threat-intel correlation and per-provider signals."""
    if not isinstance(details, dict):
        return
    correlation = details.get("threat_intel_correlation")
    if isinstance(correlation, dict):
        for key in (
            "available_count",
            "malicious_count",
            "suspicious_count",
            "clean_count",
            "unavailable_count",
            "agreement",
            "consensus",
            "malicious_confidence",
            "suspicious_confidence",
        ):
            if key in correlation:
                writer.writerow(["Threat Intel", key.replace("_", " ").capitalize(), _cell(correlation[key])])
        writer.writerow(["Threat Intel", "Conflict", _cell(bool(correlation.get("conflict")))])
        for signal in correlation.get("signals") or []:
            if isinstance(signal, dict):
                writer.writerow(
                    [
                        "Threat Intel Signal",
                        _cell(signal.get("provider", "")),
                        _cell(
                            {
                                "status": signal.get("status", ""),
                                "malicious": signal.get("malicious", False),
                                "suspicious": signal.get("suspicious", False),
                                "confidence": signal.get("confidence", 0),
                                "categories": signal.get("categories") or [],
                            }
                        ),
                    ]
                )


def _write_ai_explanation(writer, explanation) -> None:
    """Emit the optional AI explanation block when present."""
    if not isinstance(explanation, dict):
        return
    writer.writerow(["AI Explanation", "Summary", _cell(explanation.get("summary", ""))])
    writer.writerow(["AI Explanation", "Why risky", _cell(explanation.get("why_risky", ""))])
    writer.writerow(["AI Explanation", "Technical explanation", _cell(explanation.get("technical_explanation", ""))])
    for factor in explanation.get("key_risk_factors") or []:
        writer.writerow(["AI Explanation", "Key risk factor", _cell(factor)])
    for action in explanation.get("recommended_actions") or []:
        writer.writerow(["AI Explanation", "Recommended action", _cell(action)])