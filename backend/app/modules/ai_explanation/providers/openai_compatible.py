"""OpenAI-compatible chat completions provider for the AI explanation layer.

Implements :class:`~app.modules.ai_explanation.base.AIExplanationProvider`
against the OpenAI Chat Completions HTTP API using the project's existing
``httpx`` dependency (no SDK, no extra requirements). Any OpenAI-compatible
endpoint (OpenAI, Azure-compatible gateways, local inference servers) can be
configured via ``AI_BASE_URL`` / ``AI_MODEL``.

Security / reliability rules:

- The API key comes only from the caller (environment) and travels only in
  the ``Authorization`` header. It is never logged, stored or echoed.
- One attempt per scan, no retries.
- Timeouts, HTTP errors, rate limiting and malformed payloads return
  ``None`` (never raise) — the calling service converts that into "AI
  explanation unavailable".
- The response body is treated as untrusted data: only ``choices[0].
  message.content`` is parsed as JSON; anything else is rejected.
"""

import json
import logging
from typing import Any

import httpx

from app.modules.ai_explanation.base import AIExplanationProvider
from app.modules.ai_explanation.prompts import SYSTEM_PROMPT

logger = logging.getLogger("cybershield.ai.openai")

COMPLETIONS_PATH = "/chat/completions"


class OpenAICompatibleProvider(AIExplanationProvider):
    """Concrete provider hitting an OpenAI-compatible chat endpoint."""

    provider = "openai-compatible"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        timeout_seconds: float = 30.0,
        max_tokens: int = 800,
        base_url: str = "https://api.openai.com/v1",
        transport: Any = None,
    ) -> None:
        """``transport`` is injectable for tests (httpx.MockTransport)."""
        super().__init__(
            api_key=api_key,
            model=model,
            timeout_seconds=timeout_seconds,
            max_tokens=max_tokens,
        )
        self.base_url = base_url.rstrip("/")
        self._transport = transport

    def generate(self, evidence: dict[str, Any]) -> dict[str, Any] | None:
        if not self.is_configured:
            logger.info("AI provider not configured; explanation unavailable.")
            return None

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        "Explain the following CyberShield scan evidence. "
                        "Return ONLY a single JSON object with the keys "
                        "summary, why_risky, key_risk_factors, "
                        "technical_explanation, recommended_actions.\n\n"
                        "EVIDENCE:\n" + json.dumps(evidence, indent=2, sort_keys=True)
                    ),
                },
            ],
            "temperature": 0.2,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
        }

        try:
            client_kwargs: dict[str, Any] = {"timeout": self.timeout_seconds}
            if self._transport is not None:
                client_kwargs["transport"] = self._transport
            with httpx.Client(**client_kwargs) as client:
                response = client.post(
                    f"{self.base_url}{COMPLETIONS_PATH}",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
        except httpx.TimeoutException:
            logger.warning("AI provider timed out.")
            return None
        except httpx.RequestError as exc:
            # NOTE: never log the exception body — it embeds the API key in
            # the request internals; log only the exception class name.
            logger.warning("AI provider request error %s", type(exc).__name__)
            return None

        return self._parse_response(response)

    def _parse_response(self, response: httpx.Response) -> dict[str, Any] | None:
        if response.status_code == 429:
            logger.warning("AI provider rate-limited the request.")
            return None
        if response.status_code in {401, 403}:
            logger.warning("AI provider rejected the API key.")
            return None
        if response.status_code >= 500:
            logger.warning("AI provider reported a server error (%s).", response.status_code)
            return None
        if response.status_code != 200:
            logger.warning("Unexpected AI provider HTTP status %s.", response.status_code)
            return None

        try:
            payload = response.json()
        except ValueError:
            logger.warning("AI provider returned malformed data.")
            return None

        content = self._extract_content(payload)
        if content is None:
            return None
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            logger.warning("AI provider output was not valid JSON.")
            return None
        if not isinstance(parsed, dict):
            logger.warning("AI provider output was not a JSON object.")
            return None
        return parsed

    @staticmethod
    def _extract_content(payload: Any) -> str | None:
        """Pull the assistant message text out of a chat-completions body."""
        if not isinstance(payload, dict):
            return None
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            return None
        first = choices[0]
        if not isinstance(first, dict):
            return None
        message = first.get("message")
        if not isinstance(message, dict):
            return None
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            return None
        return content