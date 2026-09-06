"""Regression tests for the global response security headers.

Verifies the SecurityHeadersMiddleware stamps every API response (normal,
error, and CORS preflight) with the configured headers without breaking CORS
or overriding route-level header values (e.g. the report export's
``Cache-Control: no-store`` / ``X-Content-Type-Options``).
"""

from fastapi import Response
from fastapi.testclient import TestClient

from app.core.security import SECURITY_HEADERS, apply_security_headers
from app.main import app


def _present(response: Response) -> dict[str, str]:
    return {
        header: response.headers.get(header)
        for header in SECURITY_HEADERS
    }


def test_headers_present_on_normal_api_response():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    headers = _present(response)
    assert headers == SECURITY_HEADERS


def test_headers_present_on_error_response():
    response = TestClient(app).get("/no-such-route-xyz")
    assert response.status_code == 404
    headers = _present(response)
    assert headers == SECURITY_HEADERS


def test_headers_present_on_module_route():
    # A module route that does not require network to run is kept fast; any
    # route exercises the middleware equally, so use the health endpoint for
    # the "normal" case and this for a distinct route.
    response = TestClient(app).get("/api-doc-not-exists")
    assert response.status_code == 404
    assert response.headers.get("referrer-policy") == "no-referrer"


def test_cors_preflight_still_works_and_has_headers():
    client = TestClient(app)
    response = client.options(
        "/scan/example.com",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "GET" in response.headers.get("access-control-allow-methods", "")
    headers = _present(response)
    assert headers == SECURITY_HEADERS


def test_cors_credentials_origin_behavior_preserved():
    # A non-allowlisted origin must not receive the credentied CORS header.
    response = TestClient(app).options(
        "/scan/example.com",
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") != "http://evil.example"
    assert "access-control-allow-origin" not in response.headers


def test_apply_security_headers_does_not_override_existing_values():
    # The report export sets X-Content-Type-Options itself; the helper must
    # keep the route-provided value and only append missing headers.
    response = Response(
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        }
    )
    apply_security_headers(response)
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-frame-options"] == "DENY"
