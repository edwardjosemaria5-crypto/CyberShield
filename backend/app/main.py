"""
CyberShield V2
Main FastAPI Application
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import API routes
from app.api.routes import (
    brand_detection,
    dns,
    headers,
    health,
    history,
    ports,
    reputation,
    scan,
    ssl,
    threatintel,
    typosquatting,
    url_analysis,
    whois,
)

# ==========================================================
# Create FastAPI Application
# ==========================================================

app = FastAPI(
    title="CyberShield API",
    description="Professional Cybersecurity Assessment Platform",
    version="2.0.0",
)

# ==========================================================
# Initialize storage (idempotent; keeps existing data)
# ==========================================================

from app.database.connection import init_db  # noqa: E402

init_db()

# ==========================================================
# Configure CORS
# ==========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================================
# Register API Routes
# ==========================================================

app.include_router(health.router)
app.include_router(url_analysis.router)
app.include_router(scan.router)
app.include_router(history.router)
app.include_router(dns.router)
app.include_router(headers.router)
app.include_router(whois.router)
app.include_router(ports.router)
app.include_router(reputation.router)
app.include_router(ssl.router)
app.include_router(threatintel.router)
app.include_router(typosquatting.router)
app.include_router(brand_detection.router)
