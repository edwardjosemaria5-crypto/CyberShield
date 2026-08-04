import json


def generate_json_report(data: dict) -> str:
    """Generate pretty-printed JSON report string."""
    return json.dumps(data, indent=2, default=str)
