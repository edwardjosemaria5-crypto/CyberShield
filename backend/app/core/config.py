"""Configuration defaults for the CyberShield backend."""

import os

API_TITLE = "CyberShield API"
API_VERSION = "2.0.0"

# Database connection. SQLite by default for development; override with
# CYBERSHIELD_DATABASE_URL to point at PostgreSQL later (same SQLAlchemy
# connection string format).
DATABASE_URL = os.environ.get(
    "CYBERSHIELD_DATABASE_URL",
    "sqlite:///cybershield.db",
)