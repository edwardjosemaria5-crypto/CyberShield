"""ORM models for the CyberShield database."""

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class Scan(Base):
    """A completed scan persisted as a self-contained snapshot.

    The full ``AnalysisResponse`` is stored as JSON in ``analysis_json`` so
    detailed reports can be reconstructed exactly. The scalar columns mirror
    the top-level fields so list queries stay cheap and indexable. This keeps
    the schema minimal today; selectively normalized tables can be added
    later if advanced querying across findings is ever required.
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    target_url: Mapped[str] = mapped_column(String(2048))
    normalized_url: Mapped[str] = mapped_column(String(2048), default="")
    domain: Mapped[str] = mapped_column(String(255), default="")
    trust_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(40), default="")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    analysis_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(64), index=True)