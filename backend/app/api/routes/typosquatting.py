from fastapi import APIRouter

from app.services.endpoint_service import typosquatting_root_response

router = APIRouter(prefix="/typosquatting", tags=["typosquatting"])


@router.get("/")
def typosquatting_root():
    return typosquatting_root_response()
