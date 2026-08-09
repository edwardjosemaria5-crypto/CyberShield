import json


def generate_json_report(analysis) -> str:
    """Serialize a CyberShield analysis into a pretty-printed JSON report.

    ``analysis`` may be an ``AnalysisResponse`` model or any dict-like
    representation of a scan; str, enum and datetime values are coerced so
    the report always serializes cleanly.
    """
    if hasattr(analysis, "model_dump"):
        data = analysis.model_dump(mode="json")
    else:
        data = analysis
    return json.dumps(data, indent=2, default=str)