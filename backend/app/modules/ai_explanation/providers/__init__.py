"""AI provider factory.

Follows the threat-intel adapter factory convention: the concrete provider
is chosen from configuration, and nothing else in the application knows
which provider is wired in. Only one provider exists today.
"""

from app.core.config import AI_API_KEY, AI_MAX_TOKENS, AI_MODEL, AI_PROVIDER, AI_TIMEOUT_SECONDS
from app.modules.ai_explanation.base import AIExplanationProvider

#: Shared (module-level) default provider — built lazily the first time it
#: is requested so tests can inject their own.
_provider: AIExplanationProvider | None = None


def build_provider(
    *,
    provider_name: str = AI_PROVIDER,
    api_key: str = AI_API_KEY,
    model: str = AI_MODEL,
    timeout_seconds: float = AI_TIMEOUT_SECONDS,
    max_tokens: int = AI_MAX_TOKENS,
) -> AIExplanationProvider | None:
    """Return a configured provider, or ``None`` when unsupported/unconfigured.

    Unconfigured (missing ``api_key``) is a normal state: the service layer
    treats it as "AI explanation unavailable" without failing the scan.
    """
    if provider_name != "openai-compatible":
        return None
    from app.modules.ai_explanation.providers.openai_compatible import OpenAICompatibleProvider

    return OpenAICompatibleProvider(
        api_key=api_key or None,
        model=model,
        timeout_seconds=timeout_seconds,
        max_tokens=max_tokens,
        base_url=ai_base_url(),
    )


def ai_base_url() -> str:
    from app.core.config import AI_BASE_URL

    return AI_BASE_URL


def get_default_provider() -> AIExplanationProvider | None:
    """Process-wide default provider (cached)."""
    global _provider
    if _provider is None:
        _provider = build_provider()
    return _provider