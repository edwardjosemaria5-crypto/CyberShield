from app.schemas.module_result import ModuleResult


def parse_url_data(data: ModuleResult) -> dict:
    """Extract the analysis details payload from a url_analysis ModuleResult."""
    return data.model_dump(exclude={"module", "status", "score", "confidence"})