from fastapi import APIRouter, Path

from app.core.constants import MAX_TARGET_LENGTH
from app.modules.whois.service import run_whois_check

router = APIRouter(prefix="/whois", tags=["whois"])


@router.get("/{domain}")
def whois_lookup(domain: str = Path(..., max_length=MAX_TARGET_LENGTH)):
    return run_whois_check(domain)
