from fastapi import APIRouter

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
def health() -> dict[str, str]:
    return {
        "status": "Healthy",
        "application": "CyberShield",
    }
