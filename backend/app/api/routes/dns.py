from fastapi import APIRouter, Path

from app.core.constants import MAX_TARGET_LENGTH
from app.modules.dns.service import run_dns_check

router = APIRouter(prefix="/dns", tags=["dns"])


@router.get("/{domain}")
def dns_lookup(domain: str = Path(..., max_length=MAX_TARGET_LENGTH)):
    return run_dns_check(domain)
