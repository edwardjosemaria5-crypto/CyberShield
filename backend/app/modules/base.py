"""Scanner contract every pipeline module MUST implement.

The ScanManager schedules scanners based on their ``target_kind``:
structural (full-URL) scanners run sequentially first because later scanners
operate on the normalized hostname extracted from their outcome, while
independent domain scanners run concurrently afterwards.

Adding a new intelligence module is a two-step process that never touches
the ScanManager:
1. implement a ``BaseModule`` subclass in ``app.modules.<name>``
2. append an instance of it to ``MODULE_REGISTRY``.
"""

from abc import ABC, abstractmethod

from app.schemas.module_result import ModuleResult

#: Scanners operating on the full normalized URL (run sequentially, stage 0).
TARGET_URL = "url"

#: Scanners operating on the extracted hostname (run concurrently, stage 1).
TARGET_DOMAIN = "domain"


class BaseModule(ABC):
    """Abstract contract for any module participating in the scan pipeline."""

    def __init__(
        self,
        name: str,
        description: str = "",
        target_kind: str = TARGET_DOMAIN,
    ):
        self.name = name
        self.description = description
        self.target_kind = target_kind

    @abstractmethod
    def run(self, target: str) -> ModuleResult:
        """Execute the intelligence check and return a canonical ModuleResult.

        The target is the full URL for :data:`TARGET_URL` scanners or the
        extracted hostname for :data:`TARGET_DOMAIN` scanners. Modules MUST
        never call other modules; the ScanManager owns all coordination.
        """