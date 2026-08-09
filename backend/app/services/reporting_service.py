"""Report-format coordinator.

Selects the existing exporter (JSON/CSV/PDF) for a completed analysis and
returns the rendered bytes plus the media type and a safe download filename.
Route handlers stay thin: no export logic lives in the API layer.
"""

from dataclasses import dataclass
from typing import Literal

from app.modules.reporting import csv as csv_exporter
from app.modules.reporting import json as json_exporter
from app.modules.reporting import pdf as pdf_exporter

ExportFormat = Literal["json", "csv", "pdf"]

MEDIA_TYPES: dict[str, str] = {
    "json": "application/json",
    "csv": "text/csv",
    "pdf": "application/pdf",
}

FILE_EXTENSIONS: dict[str, str] = {
    "json": "json",
    "csv": "csv",
    "pdf": "pdf",
}


class UnsupportedFormatError(ValueError):
    """Raised when the requested export format is not supported."""


class UnsupportedFormatError(ValueError):
    """Raised when the requested export format is not supported."""


@dataclass(frozen=True)
class GeneratedReport:
    """A rendered report ready to be streamed to the client."""

    scan_id: str
    format: ExportFormat
    content: bytes
    media_type: str
    filename: str


def generate_report(analysis, format_: str) -> GeneratedReport:
    """Render an ``AnalysisResponse`` (or its dict) in the requested format.

    The filename derives solely from the validated scan ID — never from the
    target URL — so downloads cannot be coerced into traversing paths.
    """
    if format_ not in MEDIA_TYPES:
        raise UnsupportedFormatError(format_)

    data = analysis.model_dump(mode="json") if hasattr(analysis, "model_dump") else analysis
    scan_id = str(data.get("scan_id", "unknown"))

    if format_ == "json":
        content = json_exporter.generate_json_report(data).encode("utf-8")
    elif format_ == "csv":
        content = csv_exporter.generate_csv_report(data).encode("utf-8")
    else:
        content = pdf_exporter.generate_pdf_report(data)

    return GeneratedReport(
        scan_id=scan_id,
        format=format_,
        content=content,
        media_type=MEDIA_TYPES[format_],
        filename=f"cybershield-{scan_id}.{FILE_EXTENSIONS[format_]}",
    )