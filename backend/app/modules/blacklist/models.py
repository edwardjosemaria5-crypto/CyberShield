from dataclasses import dataclass


@dataclass
class BlacklistFinding:
    """Legacy container for blacklist results.

    New code should prefer :class:`app.schemas.module_result.ModuleResult`.
    """

    domain: str
    is_blacklisted: bool = False
    blacklisted_on: list[str] | None = None