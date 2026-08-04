"""Service responses for registered placeholder endpoints.

These preserve the existing API contract until their analysis modules are wired in.
"""


def ports_root_response():
    return {"message": "Ports endpoint placeholder"}


def reputation_root_response():
    return {"message": "Reputation endpoint placeholder"}


def ssl_root_response():
    return {"message": "SSL endpoint placeholder"}


def threat_intelligence_root_response():
    return {"message": "Threat intelligence endpoint placeholder"}


def typosquatting_root_response():
    return {"message": "Typosquatting endpoint placeholder"}
