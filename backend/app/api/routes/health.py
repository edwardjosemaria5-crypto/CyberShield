from fastapi import APIRouter

from app.core.config import (
    AI_ENABLED,
    API_VERSION,
    GOOGLE_SAFE_BROWSING_API_KEY,
    THREAT_PROVIDER_ENABLED,
    VIRUS_TOTAL_API_KEY,
)

router = APIRouter(tags=["System"])


@router.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {
        "application": "CyberShield",
        "version": "2.0.0",
        "status": "Running",
        "message": "Welcome to CyberShield Professional Security Scanner",
    }


@router.get("/health")
def health() -> dict:
    """Live status plus safe, non-secret configuration presence.

    ``*_configured`` means the relevant configuration/key is present in the
    environment — it says NOTHING about whether the external provider is
    currently reachable. Secret values are never included.
    """
    return {
        "status": "Healthy",
        "application": "CyberShield",
        "version": API_VERSION,
        "threat_intel": {
            "enabled": THREAT_PROVIDER_ENABLED,
            "google_safe_browsing_configured": bool(GOOGLE_SAFE_BROWSING_API_KEY),
            "virustotal_configured": bool(VIRUS_TOTAL_API_KEY),
        },
        "ai": {
            "enabled": AI_ENABLED,
        },
    }
