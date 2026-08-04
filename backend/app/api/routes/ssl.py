from fastapi import APIRouter

from app.services.endpoint_service import ssl_root_response

router = APIRouter(prefix="/ssl", tags=["ssl"])


@router.get("/")
def ssl_root():
    return ssl_root_response()
