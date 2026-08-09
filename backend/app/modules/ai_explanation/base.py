"""AI provider adapter contract.

An AI provider converts a structured evidence package into a dictionary
that the service layer validates against
:class:`~app.schemas.ai_explanation.AIExplanation`.

Conventions (mirroring the threat-intel adapters):

- Concrete providers live in ``providers/`` and never leak into the rest of
  the application beyond this interface.
- ``generate()`` MUST NOT raise for provider-facing problems (timeout,
  HTTP errors, malformed payloads, rate limits, invalid configuration is
  signaled by ``is_configured == False``); it returns ``None`` instead.
  Programming errors may still raise.
- The API key travels only from the caller (environment) into the provider
  request and is never logged or echoed.
- No retries: exactly one attempt per scan.
"""

from abc import ABC, abstractmethod
from typing import Any


class AIExplanationProvider(ABC):
    """Base contract every AI explanation provider must implement."""

    provider: str = "ai"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        timeout_seconds: float = 30.0,
        max_tokens: int = 800,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.max_tokens = max_tokens

    @property
    def is_configured(self) -> bool:
        """True when the adapter can actually reach its provider."""
        return bool(self.api_key)

    @abstractmethod
    def generate(self, evidence: dict[str, Any]) -> dict[str, Any] | None:
        """Ask the model to explain the supplied evidence.

        Returns the raw model output (already a dict) or ``None`` when the
        request could not be completed. Must never raise for provider-facing
        problems.
        """
        raise NotImplementedError