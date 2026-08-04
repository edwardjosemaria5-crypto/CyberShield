from fastapi import APIRouter

from app.services.endpoint_service import threat_intelligence_root_response

router = APIRouter(prefix="/threatintel", tags=["threatintel"])


@router.get("/")
def threatintel_root():
    return threat_intelligence_root_response()
