from fastapi import APIRouter

from app.modules.dns.service import run_dns_check

router = APIRouter(prefix="/dns", tags=["dns"])


@router.get("/{domain}")
def dns_lookup(domain: str):
    return run_dns_check(domain)
