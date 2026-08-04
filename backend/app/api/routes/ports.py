from fastapi import APIRouter

from app.services.endpoint_service import ports_root_response

router = APIRouter(prefix="/ports", tags=["ports"])


@router.get("/")
def ports_root():
    return ports_root_response()
