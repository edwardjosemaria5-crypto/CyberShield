"""Backend security helpers.

This module owns the outbound-request sanitation helper and the global
response security-header middleware applied to every API response.
"""

from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.requests import Request
from starlette.responses import Response

#: Security headers applied to every API response unless a route has already
#: set that exact header (per-route values always win — e.g. the report-export
#: endpoint sets ``Cache-Control: no-store`` and ``X-Content-Type-Options``
#: itself and must not be overridden).
#
# ``X-Frame-Options: DENY`` — the API is a JSON backend, never framed.
# ``Referrer-Policy: no-referrer`` — no URL/referrer leakage to third parties.
# ``X-Content-Type-Options: nosniff`` — refuse MIME-sniffing of responses.
#
# No Content-Security-Policy or HSTS here: CSP belongs at the SPA/nginx layer,
# and HSTS belongs at the terminating TLS layer, not the plain-HTTP container.
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


def apply_security_headers(response: Response) -> None:
    """Add the global security headers that are not already present.

    Missing headers are appended so route-level headers (e.g. the report
    export's ``Cache-Control`` / ``X-Content-Type-Options``) are preserved
    verbatim rather than overridden.
    """
    for header, value in SECURITY_HEADERS.items():
        if header not in response.headers:
            response.headers[header] = value


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that stamps the API responses with security headers."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)
        apply_security_headers(response)
        return response


def sanitize_domain(domain: str) -> str:
    return domain.strip().lower()
