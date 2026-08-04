from datetime import datetime


def utc_now() -> str:
    return datetime.utcnow().isoformat()
