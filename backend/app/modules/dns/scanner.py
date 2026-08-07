"""DNS record retrieval.

Responsible ONLY for collecting raw DNS records; normalization and scoring
live in the parser and intelligence layers. Re-exports the resolver entry
point so upstream callers and tests keep a single stable import surface.
"""

from app.modules.dns.resolver import resolve_domain

__all__ = ["resolve_domain"]
