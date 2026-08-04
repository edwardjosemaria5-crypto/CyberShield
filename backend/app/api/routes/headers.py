from fastapi import APIRouter

from app.modules.headers.service import run_headers_check

router = APIRouter(prefix="/headers", tags=["headers"])


@router.get("/{domain}")
def headers(domain: str):
    return run_headers_check(domain)
