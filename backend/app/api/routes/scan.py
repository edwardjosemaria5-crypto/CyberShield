from fastapi import APIRouter

from app.services.scan_service import run_scan

router = APIRouter(prefix="/scan", tags=["scan"])


@router.get("/{domain}")
def scan_domain(domain: str):
    return run_scan(domain)
