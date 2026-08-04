from pydantic import BaseModel


class ScanRequest(BaseModel):
    target: str
