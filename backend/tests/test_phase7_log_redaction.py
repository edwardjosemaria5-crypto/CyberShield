"""P7-01: credential-bearing scan targets must never reach the logs.

Pinpoints the security requirement that a raw attacker/user-controlled scan
target (which may embed ``user:password@`` userinfo) can never be written to
logs, while normal operational logging stays useful.
"""

import logging

from app.modules.base import BaseModule, TARGET_URL
from app.services.scan_manager import ScanManager

CRED_TARGET = "https://user:password@example.com"
MALFORMED_CRED_TARGET = "https://user:password@example.com invalid"


class FailingURLModule(BaseModule):
    """Structural (full-URL) module that echoes the target before failing.

    The most adversarial case: the exception message itself carries the raw
    credential-bearing target, so any leak through the failure path is caught.
    """

    def __init__(self, template: str = "scan failed for {target}"):
        super().__init__(
            name="failing_url",
            description="test-only failing URL scanner",
            target_kind=TARGET_URL,
        )
        self._template = template

    def run(self, target):
        raise RuntimeError(self._template.format(target=target))


class OKURLModule(BaseModule):
    """Healthy structural module so a scan can complete successfully."""

    def __init__(self):
        super().__init__(
            name="ok_url",
            description="test-only healthy URL scanner",
            target_kind=TARGET_URL,
        )

    def run(self, target):
        from app.schemas.module_result import ModuleResult

        return ModuleResult(module=self.name, score=100, confidence=100)


def _run_with_caplog(caplog, manager, target, level, logger):
    with caplog.at_level(level, logger=logger):
        response = manager.run(target)
    return response, caplog.text


def test_case1_valid_credential_target_never_appears_in_logs(caplog):
    manager = ScanManager(modules=[FailingURLModule()])
    response, text = _run_with_caplog(
        caplog, manager, CRED_TARGET, logging.ERROR, "cybershield.scan_manager"
    )

    assert response.scan_id.startswith("CS-")
    assert "password" not in text
    assert "user:password" not in text
    assert CRED_TARGET not in text
    # Hostname-only context is preserved; the credential is redacted.
    assert "<redacted>@example.com" in text


def test_case2_malformed_credential_target_never_appears_in_logs(caplog):
    manager = ScanManager(modules=[FailingURLModule()])
    response, text = _run_with_caplog(
        caplog, manager, MALFORMED_CRED_TARGET, logging.WARNING, "cybershield.scan_manager"
    )

    assert response.scan_id.startswith("CS-")
    assert "password" not in text
    assert "user:password" not in text
    assert MALFORMED_CRED_TARGET not in text
    # The rejection is logged with a generic label, never the raw string.
    assert "Rejecting invalid target" in text
    assert "<invalid target>" in text


def test_case3_module_failure_with_credential_target_never_leaks(caplog):
    manager = ScanManager(modules=[FailingURLModule()])
    response, text = _run_with_caplog(
        caplog, manager, CRED_TARGET, logging.ERROR, "cybershield.scan_manager"
    )

    failed = next(m for m in response.modules if m.module == "failing_url")
    assert failed.status == "error"
    assert "password" not in text
    assert "user:password" not in text
    assert "password" not in failed.details["error"]
    assert "user:password" not in failed.details["error"]


def test_case4_operational_logging_remains_useful(caplog):
    manager = ScanManager(modules=[FailingURLModule(), OKURLModule()])
    response, text = _run_with_caplog(
        caplog, manager, "example.com", logging.ERROR, "cybershield.scan_manager"
    )

    assert response.scan_id.startswith("CS-")
    assert "example.com" in text  # hostname context preserved
    assert "failing_url" in text  # module identity preserved
    assert "RuntimeError" in text  # exception class preserved


def test_case4b_invalid_target_rejection_is_generic_and_measurable(caplog):
    manager = ScanManager(modules=[OKURLModule()])
    response, text = _run_with_caplog(
        caplog, manager, "/no-host", logging.WARNING, "cybershield.scan_manager"
    )

    assert response.scan_id.startswith("CS-")
    assert "Rejecting invalid target" in text
    assert "length=8" in text
    assert "<invalid target>" in text
    assert "/no-host" not in text