from fastapi import APIRouter

from app.services.endpoint_service import reputation_root_response

router = APIRouter(prefix="/reputation", tags=["reputation"])


@router.get("/")
def reputation_root():
    return reputation_root_response()
