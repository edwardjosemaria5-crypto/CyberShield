import requests
import urllib3
from urllib3.connectionpool import HTTPSConnectionPool, HTTPConnectionPool
from urllib3.exceptions import HTTPError as Urllib3HTTPError

from app.schemas.finding import Finding
from app.schemas.module_result import ModuleResult, score_to_status
from app.utils.networking import ResolvedTarget, resolve_public_host
from .rules import (
    DEFAULT_CONFIDENCE,
    HEADER_DEFINITIONS,
    HEADER_RECOMMENDATIONS,
    MODULE_NAME,
    grade_for_score,
)


class BlockedTargetError(requests.RequestException):
    """Raised when a target is refused by the outbound safety guard."""


#: Maximum redirect hops followed, including the initial request. Redirects
#: are followed manually (never by requests) so every hop is independently
#: validated and pinned; longer chains are refused outright rather than left
#: to requests' default 30-hop limit.
MAX_REDIRECT_HOPS = 4


def _host_header(target: ResolvedTarget, scheme: str, port: int) -> str:
    """HTTP ``Host`` value for a validated target (never the pinned IP).

    IPv6 literals are bracketed per RFC 3986; default ports are omitted so a
    request on a default port keys off the bare hostname.
    """
    host_part = f"[{target.host}]" if ":" in target.host else target.host
    default_port = 443 if scheme == "https" else 80
    return host_part if port == default_port else f"{host_part}:{port}"


def _headers_with_host(request, target: ResolvedTarget, scheme: str, port: int) -> dict:
    """Request headers with a forced ``Host`` derived from the validated target.

    The ``Host`` value is synthesized only from the parsed/validated hostname,
    so caller-supplied or redirect-derived ``Host`` values can never override
    virtual-host routing or influence which server the pinned connection talks
    to.
    """
    headers = dict(request.headers or {})
    headers["Host"] = _host_header(target, scheme, port)
    return headers


class _PinnedAdapter(requests.adapters.HTTPAdapter):
    """A requests adapter that connects to a validated public IP literal.

    The standard requests stack resolves the URL's hostname inside urllib3 at
    connect time, which re-opens a DNS-rebinding/TOCTOU window after the host
    was validated. This adapter instead resolves+validates once and connects
    to the returned pinned IP literal, while preserving the hostname for the
    ``Host`` header and, for HTTPS, TLS SNI and certificate verification.

    A dedicated, single-use pool is created and closed per request so no pool
    is ever cached keyed by hostname (which would let a later resolution
    bypass the pin).
    """

    def _target(self, url: str) -> tuple[ResolvedTarget | None, str | None]:
        return resolve_public_host(url)

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        target, reason = self._target(request.url)
        if reason:
            raise BlockedTargetError(reason)
        if target is None or not target.addresses:
            raise requests.exceptions.ConnectionError("Unable to resolve target host.")

        scheme = request.url.split("://", 1)[0].lower()
        parsed = requests.utils.urlparse(request.url)
        port = parsed.port or (443 if scheme == "https" else 80)
        address = target.addresses[0]

        pool_cls = HTTPSConnectionPool if scheme == "https" else HTTPConnectionPool
        pool_kwargs = {"host": address, "port": port, "timeout": timeout}
        if scheme == "https":
            # Keep TLS verification against the original hostname while
            # connecting to the pinned IP literal.
            pool_kwargs["server_hostname"] = target.host
            pool_kwargs["assert_hostname"] = target.host
            pool_kwargs["cert_reqs"] = "CERT_REQUIRED" if verify else "CERT_NONE"

        pool = pool_cls(**pool_kwargs)
        try:
            response = pool.urlopen(
                request.method,
                request.path_url,
                headers=_headers_with_host(request, target, scheme, port),
                body=request.body,
                assert_same_host=False,
                redirect=False,
                retries=False,
                preload_content=False if stream else True,
            )
        except Urllib3HTTPError as exc:
            raise requests.exceptions.ConnectionError(str(exc)) from exc
        finally:
            pool.close()

        return self.build_response(request, response)


def _make_session() -> requests.Session:
    session = requests.Session()
    session.mount("https://", _PinnedAdapter())
    session.mount("http://", _PinnedAdapter())
    return session


def _follow_redirects_safely(
    initial_url: str,
    timeout: int = 10,
    max_hops: int = MAX_REDIRECT_HOPS,
) -> "requests.Response":
    """Fetch a URL validating and pinning every hop.

    Requests' automatic redirect following is disabled (``allow_redirects``
    is False at the session level) so redirects can never silently resolve a
    hostname. Each hop is re-entered through the pinned adapter, which
    independently resolves, validates and pins the destination. A hop toward a
    private/reserved address aborts the request, as does a chain longer than
    ``max_hops`` requests (the initial URL plus at most ``max_hops - 1``
    redirects).
    """
    session = _make_session()
    try:
        hop_url = initial_url
        for _ in range(max_hops):
            response = session.get(hop_url, timeout=timeout, allow_redirects=False)
            if response.is_redirect and "location" in response.headers:
                hop_url = requests.utils.requote_uri(
                    requests.compat.urljoin(hop_url, response.headers["location"])
                )
                response.close()
                continue
            return response
        raise requests.TooManyRedirects("Too many redirects")
    finally:
        session.close()


def scan_headers_module(domain: str) -> ModuleResult:
    """Scan a website for the existing set of HTTP security headers."""
    url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    try:
        response = _follow_redirects_safely(url)
    except requests.RequestException as exc:
        return ModuleResult(
            module=MODULE_NAME,
            status="error",
            score=50,
            confidence=100,
            findings=[
                Finding(
                    title="Header scan failed",
                    severity="high",
                    description=f"Unable to fetch headers: {exc}",
                    recommendation="Ensure the target is reachable over HTTPS.",
                )
            ],
            details={"url": url, "error": str(exc)},
        )

    results: dict[str, dict] = {}
    findings: list[Finding] = []

    for header, (severity, weight) in HEADER_DEFINITIONS.items():
        value = response.headers.get(header)
        if value:
            results[header] = {"status": "Present", "risk": "None", "value": value}
        else:
            results[header] = {
                "status": "Missing",
                "risk": severity,
                "recommendation": HEADER_RECOMMENDATIONS[header],
            }
            findings.append(
                Finding(
                    title=f"Missing {header}",
                    severity=severity,
                    description=f"The {header} security header is not set.",
                    recommendation=HEADER_RECOMMENDATIONS[header],
                )
            )

    score = sum(
        weight for header, (_, weight) in HEADER_DEFINITIONS.items()
        if results[header]["status"] == "Present"
    )
    grade = grade_for_score(score)
    present_headers = sum(result["status"] == "Present" for result in results.values())

    return ModuleResult(
        module=MODULE_NAME,
        status=score_to_status(score),
        score=score,
        confidence=DEFAULT_CONFIDENCE,
        findings=findings,
        details={
            "url": response.url,
            "grade": grade,
            "summary": {
                "present_headers": present_headers,
                "missing_headers": len(results) - present_headers,
            },
            "security_headers": results,
        },
    )
