from pydantic import BaseModel


class ReportModel(BaseModel):
    summary: str
