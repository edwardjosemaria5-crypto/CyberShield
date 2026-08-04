from fastapi import APIRouter

from app.modules.whois.service import run_whois_check

router = APIRouter(prefix="/whois", tags=["whois"])


@router.get("/{domain}")
def whois_lookup(domain: str):
    return run_whois_check(domain)
