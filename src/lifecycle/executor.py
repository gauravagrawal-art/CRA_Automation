"""RemediationExecutor boundary — MOCK now, real mechanisms later.

Apply never marks a control PASS. Verification / re-evaluation does.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from src.lifecycle.models import RemediationRecord


@runtime_checkable
class RemediationExecutor(Protocol):
    def apply(self, item: RemediationRecord, *, clock: str) -> dict:
        ...

    def verify(
        self,
        item: RemediationRecord,
        *,
        control_id: str,
        finding: str,
        recommended_action: str,
        clock: str,
    ) -> dict:
        ...


class RemediationExecutorBase(ABC):
    @abstractmethod
    def apply(self, item: RemediationRecord, *, clock: str) -> dict:
        ...

    @abstractmethod
    def verify(
        self,
        item: RemediationRecord,
        *,
        control_id: str,
        finding: str,
        recommended_action: str,
        clock: str,
    ) -> dict:
        ...


def _mock_verification_text(finding: str, recommended_action: str) -> str:
    lower = f"{finding} {recommended_action}".lower()
    if "tls" in lower:
        return "Only TLS 1.2 or higher detected. TLS 1.0 no longer detected."
    if "ssh" in lower or "root login" in lower or "empty password" in lower:
        return "SSH hardening verified: root login and empty passwords disabled."
    if "default" in lower and ("admin" in lower or "account" in lower):
        return "Default administrative account is no longer active."
    if "firewall" in lower:
        return "Firewall rules match the approved management-plane baseline."
    return "Mock verification scan confirms the recommended configuration is in place."


class MockRemediationExecutor:
    """Simulates apply + verification. Does not touch real infrastructure.

    Future executors (SSH / API / Manual) must implement the same interface.
    """

    def apply(self, item: RemediationRecord, *, clock: str) -> dict:
        return {
            "ok": True,
            "execution_result": (
                f"Mock apply succeeded for {item.control_id}: "
                f"{item.recommended_action or 'configuration change applied'}."
            ),
            "applied_at": clock,
        }

    def verify(
        self,
        item: RemediationRecord,
        *,
        control_id: str,
        finding: str,
        recommended_action: str,
        clock: str,
    ) -> dict:
        text = _mock_verification_text(finding, recommended_action or item.recommended_action)
        return {
            "ok": True,
            "verification_result": text,
            "verified_at": clock,
        }


_default_executor: RemediationExecutor | None = None


def get_remediation_executor() -> RemediationExecutor:
    global _default_executor
    if _default_executor is None:
        _default_executor = MockRemediationExecutor()
    return _default_executor


def set_remediation_executor(executor: RemediationExecutor | None) -> None:
    global _default_executor
    _default_executor = executor
