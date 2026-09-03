"""RemediationExecutor boundary — allow-listed demo apply, no free-form commands.

Apply never marks a control PASS and never closes a finding. Verification is a
fresh Flow 2 + Flow 3 evidence run compared by the existing Flow 4 verifier.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Protocol, runtime_checkable

from src.config import DEMO_PROVIDER, DEMO_TARGET_ID
from src.lifecycle.demo_operations import (
    get_operation,
    get_operation_for_control,
    patches_for_operation,
)
from src.lifecycle.demo_state import remove_operation, upsert_operation
from src.lifecycle.models import RemediationRecord


@runtime_checkable
class RemediationExecutor(Protocol):
    def apply(
        self,
        item: RemediationRecord,
        *,
        clock: str,
        target_id: str,
        provider: str,
        demo_state_root: Any = None,
    ) -> dict:
        ...

    def rollback(
        self,
        item: RemediationRecord,
        *,
        clock: str,
        target_id: str,
        provider: str,
        demo_state_root: Any = None,
    ) -> dict:
        ...


class RemediationExecutorBase(ABC):
    @abstractmethod
    def apply(
        self,
        item: RemediationRecord,
        *,
        clock: str,
        target_id: str,
        provider: str,
        demo_state_root: Any = None,
    ) -> dict:
        ...

    @abstractmethod
    def rollback(
        self,
        item: RemediationRecord,
        *,
        clock: str,
        target_id: str,
        provider: str,
        demo_state_root: Any = None,
    ) -> dict:
        ...


class AllowlistedDemoExecutor:
    """Applies catalogued fixture patches to nextboss-demo only.

    Refuses non-demo targets, unknown operation IDs, and any caller-supplied
    command string (the interface has no command parameter).
    """

    def apply(
        self,
        item: RemediationRecord,
        *,
        clock: str,
        target_id: str,
        provider: str,
        demo_state_root: Any = None,
    ) -> dict:
        gate = _demo_gate(target_id, provider, item)
        if gate is not None:
            return gate

        operation = get_operation(item.operation_id)
        assert operation is not None  # guarded above
        patches = patches_for_operation(operation)
        doc, digest = upsert_operation(
            target_id,
            operation.operation_id,
            control_id=item.control_id,
            patches=patches,
            applied_at=clock,
            root=demo_state_root,
        )
        return {
            "ok": True,
            "execution_result": (
                f"Demo allow-listed operation {operation.operation_id} applied for "
                f"{item.control_id} on {target_id}. Finding remains OPEN until a "
                f"fresh evidence-backed assessment confirms the control."
            ),
            "applied_at": clock,
            "applied_overlay_hash": digest,
            "operation_id": operation.operation_id,
            "operations_count": len(doc.get("operations") or {}),
        }

    def rollback(
        self,
        item: RemediationRecord,
        *,
        clock: str,
        target_id: str,
        provider: str,
        demo_state_root: Any = None,
    ) -> dict:
        gate = _demo_gate(target_id, provider, item)
        if gate is not None:
            return gate

        remove_operation(target_id, item.operation_id, root=demo_state_root)
        return {
            "ok": True,
            "execution_result": (
                f"Demo operation {item.operation_id} rolled back for {item.control_id}."
            ),
            "rolled_back_at": clock,
        }


def _demo_gate(target_id: str, provider: str, item: RemediationRecord) -> dict | None:
    if target_id != DEMO_TARGET_ID or provider != DEMO_PROVIDER:
        return {
            "ok": False,
            "blocked": True,
            "reason_code": "TARGET_NOT_EXECUTABLE",
            "execution_result": (
                f"Execution is allow-listed only for {DEMO_TARGET_ID} "
                f"({DEMO_PROVIDER}). Target '{target_id}' / provider '{provider}' "
                f"remains advisory-only."
            ),
        }
    if not item.operation_id:
        return {
            "ok": False,
            "blocked": True,
            "reason_code": "OPERATION_NOT_ALLOWLISTED",
            "execution_result": (
                f"No allow-listed demo operation is defined for control "
                f"{item.control_id}."
            ),
        }
    operation = get_operation(item.operation_id)
    if operation is None:
        return {
            "ok": False,
            "blocked": True,
            "reason_code": "OPERATION_NOT_ALLOWLISTED",
            "execution_result": f"Unknown operation_id '{item.operation_id}'.",
        }
    if operation.control_id != item.control_id:
        return {
            "ok": False,
            "blocked": True,
            "reason_code": "OPERATION_CONTROL_MISMATCH",
            "execution_result": (
                f"Operation {item.operation_id} is bound to {operation.control_id}, "
                f"not {item.control_id}."
            ),
        }
    catalog = get_operation_for_control(item.control_id)
    if catalog is None or catalog.operation_id != item.operation_id:
        return {
            "ok": False,
            "blocked": True,
            "reason_code": "OPERATION_NOT_ALLOWLISTED",
            "execution_result": "Operation is not in the control allow-list.",
        }
    return None


# Back-compat name used by older tests / imports.
class MockRemediationExecutor(AllowlistedDemoExecutor):
    """Alias for the allow-listed demo executor."""

    def verify(
        self,
        item: RemediationRecord,
        *,
        control_id: str,
        finding: str,
        recommended_action: str,
        clock: str,
    ) -> dict:
        """Deprecated: in-process verify is no longer part of apply.

        Kept so legacy call sites fail closed without claiming PASS.
        """
        return {
            "ok": False,
            "verification_result": (
                "In-process mock verification is disabled. Collect fresh evidence "
                "and run the deterministic verifier."
            ),
            "verified_at": clock,
        }


_default_executor: RemediationExecutor | None = None


def get_remediation_executor() -> RemediationExecutor:
    global _default_executor
    if _default_executor is None:
        _default_executor = AllowlistedDemoExecutor()
    return _default_executor


def set_remediation_executor(executor: RemediationExecutor | None) -> None:
    global _default_executor
    _default_executor = executor
