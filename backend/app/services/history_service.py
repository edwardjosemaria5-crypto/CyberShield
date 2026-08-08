"""Persistent scan history repository.

All SQL lives here; route handlers never touch the database directly. The
repository stores each completed analysis as a JSON snapshot plus a few
scalar columns used for cheap list queries.
"""

import json
import logging

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.connection import SessionLocal
from app.database.models import Scan
from app.schemas.analysis_response import AnalysisResponse
from app.schemas.history import ScanListItem
from app.schemas.summary import SeveritySummary
from app.schemas.verdict import Verdict

logger = logging.getLogger("cybershield.history")


class StoredAnalysisError(Exception):
    """Raised when a persisted snapshot cannot be deserialized."""


def _session_or_owned(session: Session | None) -> tuple[Session, bool]:
    """Return ``(active_session, owns_session)``; caller must close if owned."""
    if session is not None:
        return session, False
    return SessionLocal(), True


def save_scan(analysis: AnalysisResponse, session: Session | None = None) -> str:
    """Persist a completed scan; returns its ``scan_id``."""
    conn, owns = _session_or_owned(session)
    try:
        record = Scan(
            scan_id=analysis.scan_id,
            target_url=analysis.target,
            normalized_url=analysis.normalized_url,
            domain=analysis.domain,
            trust_score=analysis.trust_score,
            confidence=analysis.confidence,
            verdict=analysis.verdict.value if isinstance(analysis.verdict, Verdict) else str(analysis.verdict),
            summary_json=analysis.summary.model_dump_json(),
            analysis_json=analysis.model_dump_json(),
            created_at=analysis.completed_at or analysis.started_at,
        )
        conn.add(record)
        conn.commit()
        return analysis.scan_id
    except Exception:
        conn.rollback()
        raise
    finally:
        if owns:
            conn.close()


def get_scan(scan_id: str, session: Session | None = None) -> AnalysisResponse | None:
    """Load one scan by its unique identifier.

    Returns ``None`` when the scan does not exist. Raises
    :class:`StoredAnalysisError` when the stored snapshot is malformed.
    """
    conn, owns = _session_or_owned(session)
    try:
        record = conn.execute(select(Scan).where(Scan.scan_id == scan_id)).scalar_one_or_none()
        if record is None:
            return None
        try:
            return AnalysisResponse.model_validate_json(record.analysis_json)
        except ValidationError as exc:
            logger.error("Stored analysis for scan %s is malformed: %s", scan_id, exc)
            raise StoredAnalysisError(scan_id) from exc
    finally:
        if owns:
            conn.close()


def list_scans(
    limit: int = 20,
    offset: int = 0,
    session: Session | None = None,
) -> tuple[list[ScanListItem], int]:
    """List scans newest first; returns ``(items, total)``."""
    conn, owns = _session_or_owned(session)
    try:
        records = conn.execute(
            select(Scan).order_by(Scan.id.desc()).limit(limit).offset(offset)
        ).scalars().all()
        total = conn.execute(select(func.count()).select_from(Scan)).scalar_one()
        items = [_list_item(record) for record in records]
        return items, total
    finally:
        if owns:
            conn.close()


def _list_item(record: Scan) -> ScanListItem:
    try:
        summary = SeveritySummary(**json.loads(record.summary_json or "{}"))
    except (json.JSONDecodeError, TypeError, ValidationError):
        summary = SeveritySummary()
    try:
        verdict = Verdict(record.verdict)
    except ValueError:
        verdict = Verdict.TRUSTED
    return ScanListItem(
        scan_id=record.scan_id,
        target=record.target_url,
        normalized_url=record.normalized_url,
        domain=record.domain,
        trust_score=record.trust_score,
        confidence=record.confidence,
        verdict=verdict,
        summary=summary,
        completed_at=record.created_at,
    )