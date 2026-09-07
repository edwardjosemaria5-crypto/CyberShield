"""Infrastructure location intelligence module (v1.1, informational).

Purely informational hosting/location context for the scanned domain's
resolved IPs (ASN, hosting organization, country/region). It is excluded
from risk scoring by construction: the module is deliberately absent from
``MODULE_WEIGHTS``, so it can never affect the Trust Score, verdict, module
penalties or finding severities. See
``docs/v1.1-infrastructure-location.md`` for the full design.
"""
