"""ScanManager orchestrates the full URL intelligence pipeline.

The ScanManager is the single entry point for an analysis. It owns the
pipeline order, coordinates the analysis modules, and hands the collected
ModuleResults to the risk engine. Modules never call each other directly;
this orchestrator is the only coordination layer.

Execution model:
- Targets are normalized and validated up front.
- Structural (full-URL) scanners run sequentially first (stage 0).
- Independent domain scanners run concurrently afterwards (stage 1) via
  ``asyncio.gather`` over ``asyncio.to_thread`` since the module scanners
  perform blocking network I/O.
- A failing module is replaced by an error ModuleResult so one broken
  scanner never aborts the whole scan.

The scanner list is injected through dependency injection; by default the
shared :data:`app.modules.registry.MODULE_REGISTRY` is used.
"""

import asyncio
import logging
from collections.abc import Callable, Sequence

from app.modules.base import TARGET_URL, BaseModule
from app.modules.registry import get_module_registry
from app.core.scan_ids import generate_scan_id
from app.risk_engine.engine import calculate_risk_score
from app.schemas.analysis_response import AnalysisResponse
from app.schemas.module_result import ModuleResult
from app.utils.time import utc_now
from app.utils.urls import extract_domain, normalize_url, validate_url

logger = logging.getLogger("cybershield.scan_manager")


class ScanManager:
    """Coordinates the full URL intelligence scan pipeline."""

    def __init__(
        self,
        modules: Sequence[BaseModule] | None = None,
        engine: Callable[[dict[str, ModuleResult]], AnalysisResponse] = calculate_risk_score,
        scan_id_factory: Callable[[], str] = generate_scan_id,
    ):
        self._modules = list(modules) if modules is not None else get_module_registry()
        self._url_modules = [m for m in self._modules if m.target_kind == TARGET_URL]
        self._domain_modules = [m for m in self._modules if m.target_kind != TARGET_URL]
        self._engine = engine
        self._scan_id_factory = scan_id_factory

    async def arun(self, target: str) -> AnalysisResponse:
        """Execute the normalize -> validate -> analyze -> score pipeline.

        Asynchronous entry point; independent modules run concurrently.
        """
        scan_id = self._scan_id_factory()
        started_at = utc_now()
        normalized_url = normalize_url(target)
        domain = extract_domain(normalized_url)
        target_is_valid = validate_url(normalized_url)
        subject = normalized_url if target_is_valid else target

        results: dict[str, ModuleResult] = {}

        # Stage 0: structural (full-URL) modules, sequential.
        for module in self._url_modules:
            results[module.name] = await self._run_module(module, subject)

        # Stage 1: independent domain modules, concurrent.
        if target_is_valid and self._domain_modules:
            completed = await asyncio.gather(
                *(self._run_module(module, domain) for module in self._domain_modules)
            )
            for module, result in zip(self._domain_modules, completed):
                results[module.name] = result

        if not target_is_valid:
            logger.warning("Rejecting invalid target %r during analysis", target)

        response = self._engine(results)
        return response.model_copy(
            update={
                "scan_id": scan_id,
                "target": target,
                "normalized_url": normalized_url,
                "domain": domain,
                "started_at": started_at,
                "completed_at": utc_now(),
            }
        )

    def run(self, target: str) -> AnalysisResponse:
        """Synchronous entry point wrapping :meth:`arun`.

        Suitable for the existing synchronous routes; async callers should
        use :meth:`arun` directly to avoid running a nested event loop.
        """
        return asyncio.run(self.arun(target))

    async def _run_module(self, module: BaseModule, subject: str) -> ModuleResult:
        """Execute one module defensively; failures become error results."""
        try:
            return await asyncio.to_thread(module.run, subject)
        except Exception as exc:  # noqa: BLE001 - pipeline must not abort
            logger.exception("Module %s failed for %s: %s", module.name, subject, exc)
            return ModuleResult(
                module=module.name,
                status="error",
                score=0,
                confidence=0,
                details={"error": str(exc)},
            )


def manage_scan(target: str) -> AnalysisResponse:
    """Convenience entry point preserving the original ScanManager contract."""
    return ScanManager().run(target)