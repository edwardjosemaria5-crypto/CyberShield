from fastapi import APIRouter, Path

from app.core.constants import MAX_TARGET_LENGTH
from app.modules.headers.service import run_headers_check

router = APIRouter(prefix="/headers", tags=["headers"])


@router.get("/{domain}")
def headers(domain: str = Path(..., max_length=MAX_TARGET_LENGTH)):
    return run_headers_check(domain)
